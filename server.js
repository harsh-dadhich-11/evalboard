const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Parse JSON bodies up to 50 MB (for base64-encoded PDFs)
app.use(express.json({ limit: '50mb' }));

// Serve index.html and any other static files from this directory
app.use(express.static(__dirname));

// ── Anthropic proxy ──────────────────────────────────────────────────────────
// Forwards the request to the Anthropic API so the browser never hits the
// api.anthropic.com domain directly (avoids CORS errors).
app.post('/api/anthropic', async (req, res) => {
  const { apiKey, ...anthropicBody } = req.body;

  if (!apiKey) {
    return res.status(400).json({ error: { message: 'Anthropic API key is missing.' } });
  }

  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(anthropicBody),
    });

    const data = await upstream.json();
    res.status(upstream.status).json(data);
  } catch (err) {
    res.status(500).json({ error: { message: err.message } });
  }
});

// Fallback: serve index.html for any unmatched GET (single-page app)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n  EvalBoard is running → http://localhost:${PORT}\n`);
});
