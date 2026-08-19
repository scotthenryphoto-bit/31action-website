window.ACTION_API = {
  base: 'https://api.31action.com'
};

window.ActionAPI = {
  base() {
    return (window.ACTION_API && window.ACTION_API.base || 'https://api.31action.com').replace(/\/+$/, '');
  },
  async request(path, options = {}) {
    const opts = Object.assign({ credentials: 'include' }, options);
    if (!opts.method || String(opts.method).toUpperCase() === 'GET') {
      opts.cache = 'no-store';
    }
    const response = await fetch(this.base() + path, opts);
    let data = null;
    const text = await response.text();
    try { data = text ? JSON.parse(text) : {}; }
    catch (e) { data = { ok:false, error:text || response.statusText }; }
    if (!response.ok) {
      const err = new Error(data.error || `Request failed (${response.status})`);
      err.status = response.status;
      err.data = data;
      throw err;
    }
    return data;
  },
  galleries() {
    return this.request('/api/galleries');
  },
  gallery(id) {
    return this.request('/api/galleries/' + encodeURIComponent(id));
  },
  portfolio(category) {
    const q = category ? '?category=' + encodeURIComponent(category) : '';
    return this.request('/api/portfolio' + q);
  },
  homePortfolio() {
    return this.request('/api/portfolio?home=1');
  },
  legacyPortfolioSettings() {
    return this.request('/api/portfolio-legacy-settings', { cache: 'no-store' });
  },
  landingSlides() {
    return this.request('/api/landing-slides', { cache: 'no-store' });
  },
  siteContent() {
    return this.request('/api/site-content');
  },
  seo() {
    return this.request('/api/seo');
  },
  pricing() {
    return this.request('/api/pricing');
  }
};
