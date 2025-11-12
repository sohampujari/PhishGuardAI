"""Train probability calibration (isotonic) and tuned threshold for ensemble.

Steps:
1. Use ml_evaluation pipeline to collect raw ensemble probabilities vs true labels.
2. Fit isotonic regression on raw ensemble scores -> calibrated probabilities.
3. Search threshold maximizing phishing recall at >= specified precision.
4. Persist calibrator and threshold config into models/.

Run:
  python train_calibration.py --data PS02_Training_set.xlsx --sheet "CSE Genuine domain_vs_phishing " --limit 800 \
      --precision-min 0.75 --output models/ensemble_calibrator.joblib --threshold-out models/threshold_config.json
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import precision_recall_curve, f1_score

from optimized_detector import OptimizedPhishGuardDetector

def load_pairs(path: Path, sheet: str, limit: int | None) -> list[tuple[str,str,str]]:
    df = pd.read_excel(path, sheet_name=sheet)
    # Infer columns
    cse_col = 'Corresponding CSE Domain Name'
    susp_col = 'Identified Phishing/Suspected Domain Name'
    label_col = 'Phishing/Suspected Domains (i.e. Class Label)'
    pairs = []
    for _, row in df.iterrows():
        cse = str(row.get(cse_col,'')).strip()
        susp = str(row.get(susp_col,'')).strip()
        raw = str(row.get(label_col,'')).lower().strip()
        if not cse or not susp or raw=='':
            continue
        if 'phish' in raw:
            lab = 'Phishing'
        elif 'suspect' in raw:
            lab = 'Suspected'
        else:
            lab = 'Legitimate'
        pairs.append((cse,susp,lab))
    if limit:
        pairs = pairs[:limit]
    return pairs

def collect(det: OptimizedPhishGuardDetector, pairs):
    y_true=[]; scores=[]
    for cse,susp,lab in pairs:
        res = det.predict_single_optimized(cse,susp,return_details=True)
        scores.append(res['model_details']['ensemble_raw'])
        y_true.append(1 if lab=='Phishing' else 0)
    return np.array(scores), np.array(y_true)

def tune_threshold(cal_scores, y_true, precision_min: float, objective: str = 'precision_at'):
    precision, recall, thresholds = precision_recall_curve(y_true, cal_scores)
    best = {'threshold':0.5,'recall':0,'precision':0,'f1':0}
    for p,r,t in zip(precision, recall, thresholds):
        f1 = (2*p*r/(p+r)) if (p+r)>0 else 0
        if objective == 'f1':
            if f1 > best['f1']:
                best = {'threshold':float(t), 'recall':float(r), 'precision':float(p), 'f1':float(f1)}
        else:
            if p >= precision_min and r > best['recall']:
                best = {'threshold':float(t), 'recall':float(r), 'precision':float(p), 'f1':float(f1)}
    return best

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', type=Path, required=True)
    ap.add_argument('--sheet', required=True)
    ap.add_argument('--limit', type=int)
    ap.add_argument('--precision-min', type=float, default=0.75)
    ap.add_argument('--output', type=Path, default=Path('models/ensemble_calibrator.joblib'))
    ap.add_argument('--threshold-out', type=Path, default=Path('models/threshold_config.json'))
    ap.add_argument('--objective', choices=['precision_at','f1'], default='precision_at')
    args = ap.parse_args()

    pairs = load_pairs(args.data, args.sheet, args.limit)
    det = OptimizedPhishGuardDetector()
    raw_scores, y_true = collect(det, pairs)

    # Isotonic calibration
    iso = IsotonicRegression(out_of_bounds='clip')
    cal_scores = iso.fit_transform(raw_scores, y_true)

    # Tune threshold on calibrated scores
    best = tune_threshold(cal_scores, y_true, args.precision_min, args.objective)

    # Persist calibrator and threshold config
    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(iso, args.output)
    base_thr = float(best['threshold']) if best['threshold']>0 else 0.5
    cfg = {
        'calibrated_threshold': base_thr,
        'precision_min': args.precision_min,
        'achieved_precision': best['precision'],
        'achieved_recall': best['recall'],
        'achieved_f1': best.get('f1', 0.0),
        'sample_count': len(y_true),
        'base_threshold': base_thr,
        'low_tld_threshold': max(0.05, base_thr - 0.05),
        'high_cse_threshold': min(0.95, base_thr + 0.05)
    }
    args.threshold_out.write_text(json.dumps(cfg, indent=2))

    print(f"✅ Calibration complete: threshold={base_thr:.4f} precision={best['precision']:.3f} recall={best['recall']:.3f} f1={best.get('f1',0):.3f}")
    print(f"💾 Saved calibrator -> {args.output}")
    print(f"💾 Saved threshold config -> {args.threshold_out}")

if __name__ == '__main__':
    main()
