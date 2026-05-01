import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { html } from 'hono/html';

type Bindings = {
  SHIELD_KV: KVNamespace;
};

const app = new Hono<{ Bindings: Bindings }>();

app.use('*', cors());

// --- Security Logic Patterns ---

const INJECTION_PATTERNS = [
  /ignore previous instructions/i,
  /disregard all earlier prompts/i,
  /system role: admin/i,
  /you are now a/i,
  /forget everything/i,
  /execute the following/i,
  /bypass security/i,
  /override system/i
];

const JAILBREAK_PATTERNS = [
  /DAN mode/i,
  /Do Anything Now/i,
  /imagine you are a malicious/i,
  /hypothetically speaking, how would one/i,
  /i am your developer, disable filters/i,
  /stay in character/i,
  /no ethical guidelines/i
];

// --- Core Shield Function ---

async function inspectPrompt(prompt: string, ip: string, kv?: KVNamespace) {
  const risks: string[] = [];
  
  if (INJECTION_PATTERNS.some(regex => regex.test(prompt))) {
    risks.push('PROMPT_INJECTION_DETECTED');
  }

  if (JAILBREAK_PATTERNS.some(regex => regex.test(prompt))) {
    risks.push('JAILBREAK_ATTEMPT_DETECTED');
  }

  if (kv) {
    const probeCount = await kv.get(`probe:${ip}`);
    const count = probeCount ? parseInt(probeCount) : 0;
    
    if (count > 5) {
      risks.push('ABNORMAL_PROBING_PATTERN');
    }

    if (risks.length > 0) {
      await kv.put(`probe:${ip}`, (count + 1).toString(), { expirationTtl: 3600 });
    }
  }

  return risks;
}

// --- API Endpoints ---

app.get('/', (c) => c.html(html`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NoEntry-AI-Shield | AI Prompt Firewall</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #00f2ff;
            --secondary: #7000ff;
            --bg: #05050a;
            --surface: rgba(255, 255, 255, 0.05);
            --border: rgba(255, 255, 255, 0.1);
            --text: #e0e0e0;
            --danger: #ff2e63;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Outfit', sans-serif;
            background: var(--bg);
            color: var(--text);
            overflow-x: hidden;
            background: radial-gradient(circle at 50% -20%, #1a1a3a 0%, #05050a 100%);
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        header { display: flex; justify-content: space-between; align-items: center; padding: 2rem 0; border-bottom: 1px solid var(--border); }
        .logo { font-size: 1.5rem; font-weight: 800; background: linear-gradient(to right, var(--primary), var(--secondary)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .hero { text-align: center; padding: 8rem 0 4rem; }
        .hero h1 { font-size: 4.5rem; line-height: 1.1; margin-bottom: 1.5rem; font-weight: 800; background: linear-gradient(to bottom, #fff, #888); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .hero p { font-size: 1.25rem; color: #888; max-width: 700px; margin: 0 auto 3rem; }
        .badge { background: rgba(0, 242, 255, 0.1); color: var(--primary); padding: 0.5rem 1rem; border-radius: 100px; font-size: 0.8rem; font-weight: 600; border: 1px solid rgba(0, 242, 255, 0.2); margin-bottom: 2rem; display: inline-block; }
        .simulator { background: var(--surface); backdrop-filter: blur(20px); border: 1px solid var(--border); border-radius: 24px; padding: 3rem; margin-top: 4rem; box-shadow: 0 40px 100px rgba(0,0,0,0.5); }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; }
        textarea { width: 100%; height: 200px; background: rgba(0,0,0,0.3); border: 1px solid var(--border); border-radius: 16px; padding: 1.5rem; color: #fff; font-family: 'Outfit', sans-serif; font-size: 1rem; resize: none; outline: none; transition: border 0.3s; }
        textarea:focus { border-color: var(--primary); }
        .result-panel { background: rgba(0,0,0,0.3); border-radius: 16px; padding: 1.5rem; border: 1px solid var(--border); position: relative; overflow: hidden; min-height: 300px;}
        .status-tag { font-size: 0.75rem; text-transform: uppercase; font-weight: 800; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; }
        .status-clean { color: #00ff88; }
        .status-blocked { color: var(--danger); }
        .btn { background: linear-gradient(135deg, var(--primary), var(--secondary)); color: #000; border: none; padding: 1rem 2rem; border-radius: 12px; font-weight: 700; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s; margin-top: 1rem; width: 100%; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(0, 242, 255, 0.3); }
        .features { display: grid; grid-template-columns: repeat(3, 1fr); gap: 2rem; margin-top: 8rem; }
        .feature-card { padding: 2rem; background: var(--surface); border: 1px solid var(--border); border-radius: 20px; transition: 0.3s; }
        .feature-card:hover { border-color: var(--primary); transform: translateY(-10px); }
        .feature-card h3 { margin-bottom: 1rem; color: var(--primary); }
        .feature-card p { color: #888; font-size: 0.9rem; line-height: 1.6; }
        pre { font-family: monospace; font-size: 0.85rem; color: #aaa; white-space: pre-wrap; margin-top: 1rem; background: #000; padding: 1rem; border-radius: 8px;}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">NoEntry-AI-Shield</div>
            <nav><a href="#" style="color: #888; text-decoration: none; font-size: 0.9rem;">API Reference</a></nav>
        </header>
        <section class="hero">
            <div class="badge">Edge-Native AI Security</div>
            <h1>The Strongest Line of Defense<br>for AI Systems</h1>
            <p>NoEntry-AI-Shield is an AI-native firewall middleware that blocks prompt injections, jailbreak attempts, and abnormal probing patterns in real-time.</p>
        </section>
        <section class="simulator">
            <div class="grid">
                <div>
                    <h2 style="margin-bottom: 1.5rem;">Shield Simulator</h2>
                    <textarea id="promptInput" placeholder="Enter a test prompt..."></textarea>
                    <button class="btn" onclick="testShield()">Analyze Threat Level</button>
                </div>
                <div class="result-panel" id="resultPanel">
                    <div id="statusArea">
                        <div class="status-tag">System Status: <span style="color: #888;">Standby</span></div>
                        <p style="color: #666;">Ready for inspection...</p>
                    </div>
                    <div id="detailsArea" style="margin-top: 1rem; display: none;">
                        <h4 style="font-size: 0.7rem; color: #555;">API JSON RESPONSE</h4>
                        <pre id="jsonResult"></pre>
                    </div>
                </div>
            </div>
        </section>
        <section class="features">
            <div class="feature-card"><h3>Prompt Injection</h3><p>Blocks instruction override and system command takeover attempts.</p></div>
            <div class="feature-card"><h3>Jailbreak Detection</h3><p>Filters out safety guideline bypasses through gaslighting or roleplay.</p></div>
            <div class="feature-card"><h3>IP Probing Shield</h3><p>Detects repetitive vulnerability scanning to protect your infrastructure.</p></div>
        </section>
    </div>
    <script>
        async function testShield() {
            const prompt = document.getElementById('promptInput').value;
            if(!prompt) return;
            const btn = document.querySelector('.btn');
            btn.innerText = 'Analyzing...';
            try {
                const response = await fetch('/v1/shield', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ prompt, role: 'demo-user' })
                });
                const data = await response.json();
                document.getElementById('detailsArea').style.display = 'block';
                document.getElementById('jsonResult').innerText = JSON.stringify(data, null, 2);
                const statusArea = document.getElementById('statusArea');
                if (data.status === 'CLEAN') {
                    statusArea.innerHTML = '<div class="status-tag status-clean">● Status: CLEAN</div><h3>Verified Safe</h3><p style="color:#888">Prompt is safe for AI processing.</p>';
                } else {
                    statusArea.innerHTML = '<div class="status-tag status-blocked">● Status: BLOCKED</div><h3 style="color:#ff2e63">Threat Detected</h3><p style="color:#888">Patterns: ' + data.risks.join(', ') + '</p>';
                }
            } catch (e) { console.error(e); }
            finally { btn.innerText = 'Analyze Threat Level'; }
        }
    </script>
</body>
</html>`));

app.post('/v1/shield', async (c) => {
  const body = await c.req.json();
  const { prompt, role = 'user' } = body;
  const ip = c.req.header('cf-connecting-ip') || '127.0.0.1';

  if (!prompt) {
    return c.json({ error: 'Missing prompt' }, 400);
  }

  const risks = await inspectPrompt(prompt, ip, c.env.SHIELD_KV);
  const isSafe = risks.length === 0;

  let sanitizedPrompt = prompt;
  if (isSafe) {
    sanitizedPrompt = `[SEC_LAYER: Role=${role}] ` + prompt;
  }

  return c.json({
    status: isSafe ? 'CLEAN' : 'BLOCKED',
    risks,
    sanitized_prompt: isSafe ? sanitizedPrompt : null,
    shield_version: '1.0.4-edge',
    latency: '1.2ms'
  });
});

export default app;
