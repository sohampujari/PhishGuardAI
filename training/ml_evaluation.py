"""ML Evaluation Script for PhishGuard AI

Runs per-model and ensemble evaluation against the provided training Excel sheet
and optional mockdata directory. Produces:
  - metrics JSON (classification report per model + ensemble)
  - confusion matrices
  - timing / throughput stats
  - calibration summary (Brier score)
  - output markdown summary (ML_DETAILED_REPORT.md) optional

Usage (from project root):
  python ml_evaluation.py --data PS02_Training_set.xlsx --sheet "CSE Genuine domain_vs_phishing " \
      --output metrics.json --report ML_DETAILED_REPORT.md

Options:
  --limit N                Evaluate only first N examples for quick run
  --augment-legit          Augment with synthetic legitimate domains if class imbalance detected
  --mockdir DIR            Path to mockdata directory with domain samples
  --no-report              Skip markdown report generation

"""
from __future__ import annotations
import argparse
import json
import time
import statistics
from pathlib import Path
from typing import List, Dict, Tuple

import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    brier_score_loss,
    roc_auc_score,
    average_precision_score,
    precision_recall_fscore_support,
)
from sklearn.utils import resample

# Assumed available modules (import guarded)
try:
    from enhanced_mongodb_detector import EnhancedPhishGuardDetector
except ImportError as e:
    raise SystemExit(f"Failed to import EnhancedPhishGuardDetector: {e}")


def load_excel_pairs(path: Path, sheet: str) -> List[Tuple[str, str, str]]:
    df = pd.read_excel(path, sheet_name=sheet)
    # Heuristic column name mapping
    cse_col = next((c for c in df.columns if 'cse' in c.lower() and 'domain' in c.lower()), None)
    susp_col = next((c for c in df.columns if (
        ('suspicious' in c.lower() and 'domain' in c.lower()) or
        ('identified' in c.lower() and 'domain' in c.lower()) or
        ('phishing/suspected' in c.lower() and 'domain' in c.lower())
    )), None)
    label_col = next((c for c in df.columns if 'label' in c.lower()), None)
    if not (cse_col and susp_col and label_col):
        raise ValueError(f"Could not infer columns (found: cse={cse_col}, suspicious={susp_col}, label={label_col})")
    pairs = []
    for _, row in df.iterrows():
        cse_domain = str(row[cse_col]).strip()
        susp_domain = str(row[susp_col]).strip()
        raw_label = str(row[label_col]).strip().lower()
        if not cse_domain or not susp_domain or raw_label in ('nan', ''):
            continue
        # Normalize label mapping
        if 'phish' in raw_label:
            label = 'Phishing'
        elif 'suspect' in raw_label:
            label = 'Suspected'
        else:
            label = 'Legitimate'
        pairs.append((cse_domain, susp_domain, label))
    return pairs


def maybe_augment_legitimate(pairs: List[Tuple[str, str, str]], target_ratio: float = 0.25) -> List[Tuple[str, str, str]]:
    phishing = [p for p in pairs if p[2] == 'Phishing']
    suspected = [p for p in pairs if p[2] == 'Suspected']
    legitimate = [p for p in pairs if p[2] == 'Legitimate']
    total = len(pairs)
    legit_ratio = len(legitimate) / total if total else 0
    if legit_ratio >= target_ratio:
        return pairs
    # Synthesize simple legitimate examples
    needed = int(target_ratio * total) - len(legitimate)
    synth = []
    base_domains = [p[0] for p in phishing[:50]] + [p[0] for p in suspected[:50]]
    base_domains = [d for d in base_domains if d and d != 'nan'] or ['example.org']
    for i in range(needed):
        root = base_domains[i % len(base_domains)]
        synth_domain = f"safe-{i}-{root}".lower()
        synth.append((root, synth_domain, 'Legitimate'))
    return pairs + synth


def evaluate(detector: EnhancedPhishGuardDetector, pairs: List[Tuple[str, str, str]], limit: int | None = None) -> Dict:
    if limit:
        pairs = pairs[:limit]
    y_true = []
    y_pred = []
    phishing_prob = []
    # per-model probas
    rf_prob = []
    xgb_prob = []
    nn_prob = []
    rule_prob = []
    times = []
    start = time.time()
    improvement_reasons = {}
    improvement_count = 0
    for cse_domain, susp_domain, label in pairs:
        t0 = time.time()
        res = detector.predict_single_optimized(suspicious_domain=susp_domain, cse_domain=cse_domain, return_details=True)
        times.append(time.time() - t0)
        y_true.append(label)
        y_pred.append(res.get('prediction', 'Suspected'))
        phishing_prob.append(float(res.get('probability', 0.0)))
        if res.get('classification_improved'):
            improvement_count += 1
            reason = res.get('classification_improvement_reason', 'unknown')
            improvement_reasons[reason] = improvement_reasons.get(reason, 0) + 1
        md = res.get('model_details', {})
        rf_prob.append(float(md.get('random_forest_proba', 0.0)))
        xgb_prob.append(float(md.get('xgboost_proba', 0.0)))
        nn_prob.append(float(md.get('neural_network_proba', 0.0)))
        rule_prob.append(float(md.get('rule_engine_proba', 0.0)))
    elapsed = time.time() - start
    # Classification report
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    labels_sorted = sorted(set(y_true) | set(y_pred))
    cm = confusion_matrix(y_true, y_pred, labels=labels_sorted).tolist()
    # Brier score on a binary projection (Phishing vs rest)
    y_true_binary = [1 if y == 'Phishing' else 0 for y in y_true]
    bs = brier_score_loss(y_true_binary, phishing_prob) if phishing_prob else None
    # ROC/PR AUC (binary: phishing vs rest). Guard for single-class edge case.
    try:
        roc_auc = roc_auc_score(y_true_binary, phishing_prob)
    except Exception:
        roc_auc = None
    try:
        pr_auc = average_precision_score(y_true_binary, phishing_prob)
    except Exception:
        pr_auc = None

    # Threshold sweep for phishing decision
    sweep = []
    for thr in [i/20 for i in range(0, 21)]:  # 0.00 to 1.00 step 0.05
        preds_bin = [1 if p >= thr else 0 for p in phishing_prob]
        try:
            p, r, f1, _ = precision_recall_fscore_support(y_true_binary, preds_bin, average='binary', zero_division=0)
        except Exception:
            p = r = f1 = 0.0
        sweep.append({'threshold': thr, 'precision': p, 'recall': r, 'f1': f1})

    # Per-model projections with fixed threshold 0.5
    def model_metrics(name: str, probs: List[float]) -> Dict:
        preds = [('Phishing' if p >= 0.5 else 'Suspected') for p in probs]
        rep = classification_report(y_true, preds, output_dict=True, zero_division=0)
        mat = confusion_matrix(y_true, preds, labels=labels_sorted).tolist()
        brier = brier_score_loss(y_true_binary, probs) if probs else None
        return {'classification_report': rep, 'confusion_matrix': mat, 'brier_score_phishing': brier}

    per_model = {
        'random_forest': model_metrics('random_forest', rf_prob),
        'xgboost': model_metrics('xgboost', xgb_prob),
        'neural_network': model_metrics('neural_network', nn_prob),
        'rule_engine': model_metrics('rule_engine', rule_prob),
    }

    return {
        'count': len(pairs),
        'elapsed_sec': elapsed,
        'avg_prediction_ms': statistics.mean(times) * 1000 if times else 0,
        'throughput_domains_per_sec': len(pairs) / elapsed if elapsed else 0,
        'classification_report': report,
        'labels': labels_sorted,
        'confusion_matrix': cm,
        'brier_score_phishing': bs,
        'roc_auc_phishing': roc_auc,
        'pr_auc_phishing': pr_auc,
        'threshold_sweep': sweep,
        'classification_improvement': {
            'count': improvement_count,
            'reasons': improvement_reasons
        },
        'per_model': per_model,
    }


def write_markdown(report_path: Path, metrics: Dict, args: argparse.Namespace):
    cr = metrics['classification_report']
    lines = []
    lines.append('# ML Detailed Report')
    lines.append('')
    lines.append(f"Run parameters: limit={args.limit} augment_legit={args.augment_legit} sheet=\"{args.sheet}\"")
    lines.append('')
    lines.append('## Summary Metrics')
    lines.append(f"- Samples evaluated: {metrics['count']}")
    lines.append(f"- Avg prediction latency (ms): {metrics['avg_prediction_ms']:.2f}")
    lines.append(f"- Throughput (domains/sec): {metrics['throughput_domains_per_sec']:.2f}")
    if metrics.get('brier_score_phishing') is not None:
        lines.append(f"- Brier score (Phishing vs rest): {metrics['brier_score_phishing']:.4f}")
    if metrics.get('roc_auc_phishing') is not None:
        lines.append(f"- ROC AUC (Phishing vs rest): {metrics['roc_auc_phishing']:.4f}")
    if metrics.get('pr_auc_phishing') is not None:
        lines.append(f"- PR AUC (Phishing vs rest): {metrics['pr_auc_phishing']:.4f}")
    lines.append('')
    lines.append('## Per-Class Performance')
    for label in metrics['labels']:
        if label in cr:
            d = cr[label]
            lines.append(f"- {label}: precision={d['precision']:.4f} recall={d['recall']:.4f} f1={d['f1-score']:.4f} support={d['support']}")
    lines.append('')
    # Threshold sweep table (sampled)
    if metrics.get('threshold_sweep'):
        lines.append('## Threshold Sweep (sampled)')
        header = '| Threshold | Precision | Recall | F1 |'
        sep = '|---:|---:|---:|---:|'
        lines.append(header)
        lines.append(sep)
        for row in metrics['threshold_sweep'][::4]:  # take every 4th to keep it short
            lines.append(f"| {row['threshold']:.2f} | {row['precision']:.3f} | {row['recall']:.3f} | {row['f1']:.3f} |")
        lines.append('')
    lines.append('## Confusion Matrix')
    lines.append('Rows = true, Cols = predicted, labels order: ' + ', '.join(metrics['labels']))
    for row in metrics['confusion_matrix']:
        lines.append('- ' + ', '.join(str(x) for x in row))
    lines.append('')
    # Classification improvement stats
    ci = metrics.get('classification_improvement', {})
    if ci:
        lines.append('## Classification Improvements (post-processing)')
        lines.append(f"- Count: {ci.get('count', 0)}")
        reasons = ci.get('reasons', {})
        for k, v in reasons.items():
            lines.append(f"  - {k}: {v}")
        lines.append('')
    lines.append('## Improvement Suggestions')
    lines.append('- Calibrate ensemble probabilities (Platt scaling or isotonic)')
    lines.append('- Rebalance dataset by adding legitimate samples (done if augment_legit flag)')
    lines.append('- Adjust dynamic threshold narrower band to reduce false downgrades')
    lines.append('- Track ROC/PR AUC for phishing detection; tune thresholds by these curves')
    report_path.write_text('\n'.join(lines))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data', type=Path, required=True, help='Excel file path')
    parser.add_argument('--sheet', type=str, required=True, help='Sheet name to read')
    parser.add_argument('--output', type=Path, default=Path('metrics.json'))
    parser.add_argument('--report', type=Path, default=Path('ML_DETAILED_REPORT.md'))
    parser.add_argument('--limit', type=int, help='Limit number of samples for quick run')
    parser.add_argument('--augment-legit', action='store_true', dest='augment_legit')
    parser.add_argument('--mockdir', type=Path, help='Optional mockdata directory (future use)')
    parser.add_argument('--no-report', action='store_true', dest='no_report')
    parser.add_argument('--disable-downgrade', action='store_true', dest='disable_downgrade',
                        help='Disable downgrade logic to measure raw phishing recall')
    args = parser.parse_args()

    pairs = load_excel_pairs(args.data, args.sheet)
    if args.augment_legit:
        pairs = maybe_augment_legitimate(pairs)

    detector = EnhancedPhishGuardDetector(use_mongodb=False, disable_downgrade=args.disable_downgrade)
    metrics = evaluate(detector, pairs, limit=args.limit)

    # Persist metrics JSON
    args.output.write_text(json.dumps(metrics, indent=2))

    if not args.no_report:
        write_markdown(args.report, metrics, args)

    print(f"Evaluation complete. Samples={metrics['count']} Latency(ms)={metrics['avg_prediction_ms']:.2f} Throughput={metrics['throughput_domains_per_sec']:.2f}")
    print(f"Metrics JSON written to: {args.output}")
    if not args.no_report:
        print(f"Markdown report written to: {args.report}")

if __name__ == '__main__':
    main()
