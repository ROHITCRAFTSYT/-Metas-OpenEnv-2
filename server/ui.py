"""SOC Triage Gym — Browser UI served at GET /ui"""

UI_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Triage Gym — OpenEnv</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0e1a;color:#e0e6f0;font-family:'Courier New',monospace;min-height:100vh}
header{background:#0d1117;border-bottom:1px solid #1e3a5f;padding:18px 40px;display:flex;align-items:center;gap:14px}
.logo{font-size:26px}
h1{font-size:20px;color:#58a6ff;font-weight:700}
.tagline{color:#8b949e;font-size:12px;margin-top:2px}
.badge{background:#1f6feb22;border:1px solid #1f6feb;color:#58a6ff;font-size:11px;padding:2px 8px;border-radius:12px;margin-left:4px}
.container{max-width:1240px;margin:0 auto;padding:24px 40px}
.grid2{display:grid;grid-template-columns:280px 1fr;gap:20px;margin-bottom:20px}
.panel{background:#0d1117;border:1px solid #1e3a5f;border-radius:8px;padding:18px}
.panel h3{color:#58a6ff;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:14px;border-bottom:1px solid #1e3a5f;padding-bottom:7px}
label{color:#8b949e;font-size:12px;display:block;margin-bottom:4px;margin-top:10px}
label:first-of-type{margin-top:0}
select,input{width:100%;padding:8px 12px;border-radius:5px;font-family:inherit;font-size:13px;background:#161b22;border:1px solid #30363d;color:#e0e6f0;margin-bottom:4px}
.btn{width:100%;padding:9px 14px;border-radius:5px;font-family:inherit;font-size:13px;cursor:pointer;font-weight:600;margin-top:10px;border:none}
.btn-primary{background:#1f6feb;color:#fff}
.btn-primary:hover{background:#388bfd}
.btn-primary:disabled{background:#21262d;color:#484f58;cursor:not-allowed}
.btn-secondary{background:transparent;border:1px solid #30363d;color:#8b949e;margin-top:6px}
.btn-secondary:hover{border-color:#58a6ff;color:#58a6ff}
.btn-secondary:disabled{opacity:0.4;cursor:not-allowed}
.stat{display:flex;justify-content:space-between;margin-bottom:7px;font-size:12px}
.sl{color:#8b949e}.sv{color:#e0e6f0;font-weight:600}
.sv.g{color:#3fb950}.sv.r{color:#f85149}.sv.a{color:#d29922}
.bar{background:#21262d;border-radius:3px;height:6px;margin:6px 0}
.bar-fill{height:100%;border-radius:3px;background:linear-gradient(90deg,#1f6feb,#3fb950);transition:width .4s}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:#161b22;color:#8b949e;text-transform:uppercase;font-size:10px;letter-spacing:.5px;padding:9px 11px;text-align:left}
td{padding:9px 11px;border-bottom:1px solid #1e3a5f;vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:#161b2240}
.sev-critical{color:#f85149;font-weight:700}
.sev-high{color:#ff7b72}
.sev-medium{color:#d29922}
.sev-low{color:#58a6ff}
.sev-info{color:#8b949e}
.cls-true_positive{color:#3fb950}
.cls-false_positive{color:#f85149}
.cls-benign_true_positive{color:#d29922}
.cls-unclassified{color:#484f58}
.log{background:#050810;border:1px solid #1e3a5f;border-radius:5px;padding:14px;font-size:11px;height:200px;overflow-y:auto;line-height:1.7}
.log .ts{color:#484f58}
.log .act{color:#58a6ff}
.log .ok{color:#3fb950}
.log .err{color:#f85149}
.log .sys{color:#8b949e}
.bk-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px}
.bk-item{background:#161b22;border-radius:6px;padding:12px}
.bk-label{color:#8b949e;font-size:10px;text-transform:uppercase;margin-bottom:3px}
.bk-val{color:#e0e6f0;font-size:20px;font-weight:700}
.bk-bar{background:#21262d;border-radius:2px;height:3px;margin-top:5px}
.bk-bar-fill{height:100%;border-radius:2px;background:#1f6feb}
.feedback{background:#161b22;border-radius:5px;padding:10px 12px;font-size:11px;color:#8b949e;line-height:1.6;margin-top:10px}
.big-score{text-align:center;padding:10px 0 16px}
.big-score .num{font-size:52px;font-weight:700}
.big-score .sub{color:#8b949e;font-size:12px}
.empty{text-align:center;color:#484f58;padding:30px;font-size:13px}
.banner{padding:9px 14px;border-radius:5px;margin-bottom:16px;font-size:12px;display:none}
.bi{background:#1f6feb22;border:1px solid #1f6feb;color:#58a6ff}
.bs{background:#3fb95022;border:1px solid #3fb950;color:#3fb950}
.be{background:#f8514922;border:1px solid #f85149;color:#f85149}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px}
.dot-g{background:#3fb950;box-shadow:0 0 5px #3fb950}
.dot-a{background:#d29922}
.dot-r{background:#f85149}
.dot-grey{background:#484f58}
.tabs{display:flex;gap:0;border-bottom:1px solid #1e3a5f;margin-bottom:14px}
.tab{padding:7px 14px;font-size:12px;cursor:pointer;color:#8b949e;border-bottom:2px solid transparent;margin-bottom:-1px}
.tab.active{color:#58a6ff;border-bottom-color:#58a6ff}
</style>
</head>
<body>
<header>
  <div class="logo">🛡️</div>
  <div>
    <h1>SOC Triage Gym</h1>
    <div class="tagline">Security Operations Center — OpenEnv RL Training Environment</div>
  </div>
  <div style="margin-left:auto;display:flex;gap:6px;align-items:center">
    <span class="badge">OpenEnv</span>
    <span class="badge">v0.1.0</span>
    <span id="hb" class="badge" style="color:#484f58">● offline</span>
  </div>
</header>

<div class="container">
  <div id="banner" class="banner"></div>

  <div class="grid2">
    <!-- Left: controls + stats -->
    <div>
      <div class="panel" style="margin-bottom:16px">
        <h3>🎯 Configuration</h3>
        <label>Task</label>
        <select id="task">
          <option value="phishing">🎣 Phishing Triage (Easy)</option>
          <option value="lateral_movement">🔄 Lateral Movement (Medium)</option>
          <option value="queue_management">📋 Queue Management (Hard)</option>
        </select>
        <label>Random Seed</label>
        <select id="seed">
          <option value="42">42 (default)</option>
          <option value="123">123</option>
          <option value="777">777</option>
          <option value="2024">2024</option>
        </select>
        <button class="btn btn-primary" onclick="doReset()">▶ Start Episode</button>
        <button class="btn btn-secondary" id="runBtn" onclick="doBaseline()" disabled>🤖 Run Heuristic Agent</button>
      </div>

      <div class="panel">
        <h3>📊 Episode State</h3>
        <div id="estats">
          <div class="empty">Start an episode to see state</div>
        </div>
      </div>
    </div>

    <!-- Right: score -->
    <div class="panel">
      <h3>🏆 Score Breakdown</h3>
      <div id="scorePanel">
        <div class="empty">Run the agent to see scores</div>
      </div>
    </div>
  </div>

  <!-- Alert queue -->
  <div class="panel" style="margin-bottom:20px">
    <h3>🚨 Alert Queue</h3>
    <div id="alertTable">
      <div class="empty">No active episode</div>
    </div>
  </div>

  <!-- Log -->
  <div class="panel">
    <h3>📝 Investigation Log</h3>
    <div class="log" id="logBox">
      <span class="sys">// Waiting to start...</span>
    </div>
  </div>
</div>

<script>
const B = '';

function ts() { return new Date().toLocaleTimeString(); }

function log(msg, cls='sys') {
  const el = document.getElementById('logBox');
  if (el.querySelector('.sys') && el.querySelector('.sys').textContent.includes('Waiting')) el.innerHTML = '';
  el.innerHTML += `<div><span class="ts">[${ts()}]</span> <span class="${cls}">${msg}</span></div>`;
  el.scrollTop = el.scrollHeight;
}

function banner(msg, type='i') {
  const el = document.getElementById('banner');
  el.textContent = msg; el.className = `banner b${type}`; el.style.display = 'block';
  if (type === 's') setTimeout(() => el.style.display='none', 5000);
}

function sev(s) { return `sev-${(s||'info').toLowerCase()}`; }

function renderAlerts(alerts) {
  if (!alerts || !alerts.length) return '<div class="empty">No alerts</div>';
  let h = `<table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Source</th><th>Classification</th></tr></thead><tbody>`;
  for (const a of alerts) {
    const c = (a.classification || 'unclassified').toLowerCase().replace(' ','_');
    h += `<tr>
      <td style="color:#484f58;font-size:10px">${(a.alert_id||'').substring(0,10)}…</td>
      <td>${a.title||''}</td>
      <td class="${sev(a.severity)}">${(a.severity||'').toUpperCase()}</td>
      <td style="color:#8b949e">${a.source_system||''}</td>
      <td class="cls-${c}"><span class="dot ${c==='true_positive'?'dot-r':c==='false_positive'?'dot-g':c==='benign_true_positive'?'dot-a':'dot-grey'}"></span>${c}</td>
    </tr>`;
  }
  return h + '</tbody></table>';
}

function renderStats(s) {
  if (!s) return '';
  const pct = s.max_steps > 0 ? Math.round(s.step_count / s.max_steps * 100) : 0;
  const rc = s.cumulative_reward >= 0 ? 'g' : 'r';
  return `
    <div class="stat"><span class="sl">Task</span><span class="sv">${s.task_id||'—'}</span></div>
    <div class="stat"><span class="sl">Steps</span><span class="sv">${s.step_count} / ${s.max_steps}</span></div>
    <div class="bar"><div class="bar-fill" style="width:${pct}%"></div></div>
    <div class="stat"><span class="sl">Reward</span><span class="sv ${rc}">${(s.cumulative_reward||0).toFixed(3)}</span></div>
    <div class="stat"><span class="sl">Classified</span><span class="sv">${s.classified_count||0} / ${s.alert_count||0}</span></div>
    <div class="stat"><span class="sl">Done</span><span class="sv ${s.done?'g':'a'}">${s.done?'✅ Yes':'⏳ In Progress'}</span></div>`;
}

function renderScore(data) {
  if (!data) return '';
  const sc = data.score || 0;
  const col = sc >= 0.65 ? '#3fb950' : sc >= 0.35 ? '#d29922' : '#f85149';
  const bd = data.breakdown || {};
  let bkHtml = '';
  if (Object.keys(bd).length) {
    bkHtml = '<div class="bk-grid">';
    for (const [k,v] of Object.entries(bd)) {
      const pct = Math.round(v * 100);
      const lbl = k.replace(/_/g,' ').replace(/\\b\\w/g, c => c.toUpperCase());
      bkHtml += `<div class="bk-item">
        <div class="bk-label">${lbl}</div>
        <div class="bk-val">${pct}<span style="font-size:12px;color:#8b949e">%</span></div>
        <div class="bk-bar"><div class="bk-bar-fill" style="width:${pct}%"></div></div>
      </div>`;
    }
    bkHtml += '</div>';
  }
  const fb = data.feedback ? `<div class="feedback">💬 ${data.feedback}</div>` : '';
  return `<div class="big-score">
    <div class="num" style="color:${col}">${(sc*100).toFixed(1)}<span style="font-size:18px;color:#8b949e">%</span></div>
    <div class="sub">Final Score — ${data.task_id||''} · ${data.steps_used||0} steps</div>
  </div>${bkHtml}${fb}`;
}

async function doReset() {
  const task = document.getElementById('task').value;
  const seed = parseInt(document.getElementById('seed').value);
  document.getElementById('logBox').innerHTML = '';
  document.getElementById('scorePanel').innerHTML = '<div class="empty">Run the agent to see scores</div>';
  banner(`Starting episode: ${task} (seed=${seed})…`, 'i');
  log(`Starting episode — task=${task} seed=${seed}`, 'act');
  try {
    const r = await fetch('/reset', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({task_id:task,seed})});
    if (!r.ok) throw new Error(await r.text());
    const obs = await r.json();
    document.getElementById('alertTable').innerHTML = renderAlerts(obs.alert_queue || []);
    const sr = await fetch('/state');
    const st = await sr.json();
    document.getElementById('estats').innerHTML = renderStats(st);
    log(`Episode ready — ${(obs.alert_queue||[]).length} alerts, ${st.max_steps} step budget`, 'ok');
    document.getElementById('runBtn').disabled = false;
    banner(`Episode started! ${(obs.alert_queue||[]).length} alerts in queue.`, 's');
  } catch(e) { banner(`Error: ${e.message}`, 'e'); log(e.message,'err'); }
}

async function doBaseline() {
  const task = document.getElementById('task').value;
  const seed = parseInt(document.getElementById('seed').value);
  document.getElementById('runBtn').disabled = true;
  banner('Running heuristic agent…', 'i');
  log('Heuristic agent starting investigation…', 'act');
  try {
    const r = await fetch('/baseline', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({task_id:task,seed})});
    if (!r.ok) throw new Error(await r.text());
    const res = await r.json();
    log(`Agent finished — ${res.steps_used} steps used`, 'act');
    log(`Score: ${((res.score||0)*100).toFixed(1)}%`, res.score >= 0.5 ? 'ok' : 'err');
    if (res.breakdown) {
      for (const [k,v] of Object.entries(res.breakdown)) {
        log(`  ${k.replace(/_/g,' ')}: ${(v*100).toFixed(1)}%`, 'sys');
      }
    }
    if (res.feedback) log(`Feedback: ${res.feedback}`, 'sys');
    document.getElementById('scorePanel').innerHTML = renderScore(res);
    const sr = await fetch('/state');
    const st = await sr.json();
    document.getElementById('estats').innerHTML = renderStats(st);
    const ar = await fetch('/api/alerts?limit=30');
    const ad = await ar.json();
    document.getElementById('alertTable').innerHTML = renderAlerts(ad.alerts||[]);
    banner(`Agent complete! Score: ${((res.score||0)*100).toFixed(1)}%`, res.score>=0.5?'s':'i');
  } catch(e) { banner(`Error: ${e.message}`, 'e'); log(e.message,'err'); document.getElementById('runBtn').disabled=false; }
}

window.onload = async () => {
  try {
    const r = await fetch('/health');
    const h = await r.json();
    document.getElementById('hb').textContent = `● ${h.status}`;
    document.getElementById('hb').style.color = '#3fb950';
    log(`Server online — ${h.env} v${h.version}`, 'ok');
    log('Select a task and click "Start Episode" to begin', 'sys');
  } catch(e) { log('Cannot reach server', 'err'); }
};
</script>
</body>
</html>"""
