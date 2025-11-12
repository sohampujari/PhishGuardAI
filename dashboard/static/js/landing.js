// Landing page dynamic behavior: fetch live metrics and animate counters
(function() {
  const $ = (id) => document.getElementById(id);

  // Simple count-up animation
  function animateCount(el, toValue, suffix = '', duration = 800) {
    if (!el) return;
    const from = parseFloat((el.textContent || '0').replace(/[^0-9.]/g, '')) || 0;
    const to = typeof toValue === 'number' ? toValue : parseFloat(String(toValue)) || 0;
    const start = performance.now();
    function tick(now) {
      const p = Math.min(1, (now - start) / duration);
      const val = Math.round((from + (to - from) * p) * 100) / 100;
      el.textContent = `${Number.isInteger(val) ? Math.round(val) : val}${suffix}`;
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  // Fetch stats and update UI
  async function refreshStats() {
    try {
      const [statsRes, perfRes] = await Promise.all([
        fetch('/api/stats'),
        fetch('/api/performance-metrics')
      ]);
      const stats = await statsRes.json();
      const perf = await perfRes.json();
      if (!stats.error) {
        const total = stats?.collection_counts?.detected_domains || 0;
        const cse = stats?.collection_counts?.cse_entities || 0;
        const cls = stats?.classification_breakdown || [];
        const phish = cls.find(c => c._id === 'Phishing')?.count || 0;
        const susp = cls.find(c => c._id === 'Suspected')?.count || 0;
        const legit = cls.find(c => c._id === 'Legitimate')?.count || 0;
        const highShare = total ? Math.round(((phish + susp) / total) * 100) : 0;
        animateCount($('live-total-detections'), total);
        animateCount($('live-cse-count'), cse);
        animateCount($('live-high-share'), highShare);
      }
      if (!perf.error && Array.isArray(perf.response_times) && perf.response_times.length) {
        const avg = perf.response_times.reduce((a,b)=>a+b, 0) / perf.response_times.length;
        $('live-rt').textContent = `${Math.round(avg)} ms`;
        // Also update hero latency badge if present
        const latencyHero = $('metric-latency');
        if (latencyHero) latencyHero.textContent = `${Math.round(avg)} ms`;
      }
    } catch (e) {
      console.warn('Landing metrics refresh failed:', e);
    }
  }

  // Smooth scroll for nav links
  function bindSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(a => {
      a.addEventListener('click', (e) => {
        const href = a.getAttribute('href');
        if (href && href.length > 1) {
          e.preventDefault();
          document.querySelector(href)?.scrollIntoView({ behavior: 'smooth' });
        }
      });
    });
  }

  // Intersection animations (CSS-driven via data-visible)
  function bindRevealOnScroll() {
    const io = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.setAttribute('data-visible', '1');
        }
      });
    }, { threshold: 0.15 });
    document.querySelectorAll('.pg-section .card, .pg-section .benefit, .pg-metrics .metric').forEach(el => io.observe(el));
  }

  // Initialize
  document.addEventListener('DOMContentLoaded', () => {
    bindSmoothScroll();
    bindRevealOnScroll();
    refreshStats();
    // periodic refresh
    setInterval(refreshStats, 30000);

    // Static hero defaults: set model layers and recall badge if available later via model metrics
    fetch('/api/model-metrics').then(r=>r.ok?r.json():{}).then(meta => {
      if (!meta || meta.error) return;
      if (meta?.model_layers) {
        animateCount($('metric-layers'), meta.model_layers);
      }
      if (meta?.pilot_recall) {
        $('metric-recall').textContent = `${Math.round(meta.pilot_recall*100)}%`;
      }
    }).catch(()=>{});
  });
})();
