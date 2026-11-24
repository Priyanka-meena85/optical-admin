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
  return app(req, res);
};
