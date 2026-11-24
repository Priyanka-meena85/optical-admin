const app = require('../server');
const { initDB } = require('../db');

let isInitialized = false;

module.exports = async (req, res) => {
  if (!isInitialized) {
    try {
      await initDB();
      isInitialized = true;
    } catch (err) {
      console.warn('[Vercel Serverless] DB initialization note:', err.message);
    }
  }

  // Ensure path starts with /api so Express routes match regardless of rewrite style
  if (req.url && !req.url.startsWith('/api') && !req.url.startsWith('/uploads')) {
    req.url = '/api' + (req.url.startsWith('/') ? req.url : '/' + req.url);
  }

  return app(req, res);
};
