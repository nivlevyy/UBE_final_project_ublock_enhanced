import { ubolog } from '../console.js';



const LOG = {
  SUCCESS: '✅',
  SAVE: '💾',
  INFO: 'ℹ️',
  NEW: '📥',
  ALERT: '🚨',
  ERROR: '❌',
}; 

const _S_KEY = 'UBE_API_KEY';
const _S_SENT_TODAY = 'UBE_SENT_TODAY_' + (new Date()).toISOString().slice(0,10);

const UBENetwork = {
  _cfg: {
    baseUrl: 'http://127.0.0.1:8000', // later change to the aws url 
    enabled: true,
    threshold: 0.70,
    flushIntervalMs: 10000,
    maxBatchSize: 500,
    timeoutMs: 7000,
    retries: 2
  },
  _apiKey: null,
  _queue: new Set(),
  _timer: null,
  _flushing: false,

  async init(opts = {}) {
    Object.assign(this._cfg, opts || {});
    if (!this._cfg.enabled) return;
    await this.ensureApiKey();
    await this._ensureSentCache();
    this._armTimer();
    ubolog(`${ LOG.SUCCESS} UBE-Net: initialized (${this._cfg.baseUrl})`);
  },

  async ensureApiKey(force = false) {
    if (!force && this._apiKey) return this._apiKey;
    const saved = await browser.storage.local.get(_S_KEY);
    if (saved[_S_KEY] && typeof saved[_S_KEY] === 'string') {
      this._apiKey = saved[_S_KEY];
      return this._apiKey;
    }
    // fetch a new key
    const resp = await this._fetch('/get_api_key', { method: 'GET' });
    const data = await resp.json();
    if (!data?.api_key) throw new Error('No api_key in response');
    this._apiKey = data.api_key;
    await browser.storage.local.set({ [_S_KEY]: this._apiKey });
    ubolog(`${ LOG.SAVE} UBE-Net: API key acquired & saved`);
    return this._apiKey;
  },

  async _ensureSentCache() {
    const curr = await browser.storage.local.get(_S_SENT_TODAY);
    if (!Array.isArray(curr[_S_SENT_TODAY])) {
      await browser.storage.local.set({ [_S_SENT_TODAY]: [] });
    }
  },

  async _alreadySentToday(url) {
    const curr = await browser.storage.local.get(_S_SENT_TODAY);
    const arr = curr[_S_SENT_TODAY] || [];
    return arr.includes(url);
  },

  async _markSentToday(urls) {
    const curr = await browser.storage.local.get(_S_SENT_TODAY);
    const arr = curr[_S_SENT_TODAY] || [];
    const set = new Set(arr);
    for (const u of urls) set.add(u);
    await browser.storage.local.set({ [_S_SENT_TODAY]: Array.from(set) });
  },

  _armTimer() {
    if (this._timer) clearInterval(this._timer);
    this._timer = setInterval(() => this.flushNow(), this._cfg.flushIntervalMs);
  },

  // robust fetch with timeout + base URL
  async _fetch(path, init = {}) {
    const ctrl = new AbortController();
    const id = setTimeout(() => ctrl.abort('timeout'), this._cfg.timeoutMs);
    try {
      const res = await fetch(this._cfg.baseUrl + path, {
        mode: 'cors',
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'follow',
        signal: ctrl.signal,
        ...init
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      return res;
    } finally {
      clearTimeout(id);
    }
  },

  // decide phishing, regardless of shape of "Prediction"
  _isPhishDecision(pred) {
    if (pred == null) return false;
    if (typeof pred === 'boolean') return pred;
    if (typeof pred === 'number') return pred === 1 || pred > 0.5;
    if (typeof pred === 'string') {
      const s = pred.toLowerCase();
      if (s === 'n/a') return false;
      return ['phishing','unsafe','malicious','bad'].some(k => s.includes(k));
    }
    if (typeof pred === 'object') {
      if (pred.isPhishing === true) return true;
      if (typeof pred.label === 'number') return pred.label === 1;
      if (pred?.probabilities?.phishing != null) {
        return Number(pred.probabilities.phishing) >= this._cfg.threshold;
      }
    }
    return false;
  },

  async reportPrediction(url, prediction) {
    if (!this._cfg.enabled) return;
    if (!url || !url.startsWith('http')) return;
    if (!this._isPhishDecision(prediction)) return;

    if (await this._alreadySentToday(url)) {
      ubolog(`${ LOG.INFO} UBE-Net: already sent today, skip: ${url}`);
      return;
    }
    this._queue.add(url);
    ubolog(`${ LOG.NEW} UBE-Net: queued ${url} [size=${this._queue.size}]`);
    if (this._queue.size >= 20) this.flushNow();
  },

  async flushNow() {
    if (this._flushing) return;
    if (this._queue.size === 0) return;

    const batch = Array.from(this._queue).slice(0, this._cfg.maxBatchSize);
    this._flushing = true;

    try {
      await this.ensureApiKey(false);
      const body = JSON.stringify({ daily_urls: batch });
      let attempt = 0, lastErr;

      while (attempt <= this._cfg.retries) {
        try {
          const res = await this._fetch('/submit_new_phish_urls', {
            method: 'PUT',
            headers: {
              'Content-Type': 'application/json',
              'X-API-KEY': this._apiKey
            },
            body
          });
          const data = await res.json().catch(() => ({}));
          ubolog(`${ LOG.SUCCESS} UBE-Net: uploaded ${batch.length} URLs (${data?.content?.count ?? 'n/a'})`);
          // mark sent and remove from queue
          for (const u of batch) this._queue.delete(u);
          await this._markSentToday(batch);
          break;
        } catch (e) {
          lastErr = e;
          if (String(e).includes('401') || String(e).includes('403')) {
            ubolog(`${ LOG.ALERT} UBE-Net: auth failed → re-acquire API key`);
            await this.ensureApiKey(true);
          }
          await new Promise(r => setTimeout(r, (attempt + 1) * 800));
          attempt++;
        }
      }
      if (attempt > this._cfg.retries && lastErr) {
        ubolog(`${ LOG.ERROR} UBE-Net: upload failed: ${lastErr}`);
      }
    } finally {
      this._flushing = false;
    }
  }
};

export { UBENetwork };
