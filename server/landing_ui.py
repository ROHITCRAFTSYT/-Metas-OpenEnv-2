"""Distinct Hugging Face Space UI served at / and /ui."""

UI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Triage Gym</title>
<style>
:root{
  --bg:#0c1117;
  --bg2:#121923;
  --panel:#f3eee2;
  --panel-2:#e7dfcf;
  --paper:#fffaf1;
  --ink:#18222d;
  --muted:#5f6f7e;
  --line:#b9aa8a;
  --accent:#c96d43;
  --accent-2:#275d7e;
  --accent-3:#1d7f67;
  --good:#15835f;
  --warn:#b87a1d;
  --bad:#bb4e4e;
  --shadow:0 24px 60px rgba(0,0,0,.22);
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  color:var(--ink);
  font-family:Georgia,"Times New Roman",serif;
  background:
    radial-gradient(circle at top left, rgba(201,109,67,.16), transparent 28%),
    linear-gradient(180deg, var(--bg) 0, var(--bg2) 220px, #d8d1c3 220px, #e7dfcf 100%);
}
.shell{max-width:1200px;margin:0 auto;padding:24px 18px 46px}
.frame{
  background:linear-gradient(180deg, rgba(255,250,241,.98), rgba(243,238,226,.97));
  border:1px solid rgba(255,255,255,.28);
  border-radius:32px;
  box-shadow:var(--shadow);
  padding:24px;
  position:relative;
  overflow:hidden;
}
.frame::before{
  content:"";
  position:absolute;
  inset:0 0 auto 0;
  height:8px;
  background:linear-gradient(90deg, var(--accent), var(--accent-2), var(--accent-3));
}
.hero{
  display:grid;
  grid-template-columns:1.45fr .85fr;
  gap:18px;
  margin-bottom:18px;
}
.hero-main{
  background:
    radial-gradient(circle at top right, rgba(39,93,126,.12), transparent 32%),
    linear-gradient(180deg, #fffaf1, #efe6d5);
  border:1px solid #d6c7aa;
  border-radius:28px;
  padding:24px;
}
.eyebrow{
  display:inline-flex;
  align-items:center;
  gap:8px;
  padding:8px 14px;
  border-radius:999px;
  border:1px solid #d7c4a5;
  background:#fff4de;
  color:#8e5b23;
  font-size:12px;
  letter-spacing:.14em;
  text-transform:uppercase;
}
.eyebrow::before{
  content:"";
  width:8px;
  height:8px;
  border-radius:50%;
  background:var(--accent);
}
h1{
  margin:18px 0 12px;
  font-size:78px;
  line-height:.88;
  letter-spacing:-.06em;
  max-width:720px;
}
.lede{
  max-width:700px;
  color:#36516c;
  font-size:19px;
  line-height:1.6;
  margin:0;
}
.hero-strip{
  display:grid;
  grid-template-columns:repeat(3,minmax(0,1fr));
  gap:12px;
  margin-top:22px;
}
.strip-card{
  background:rgba(255,255,255,.5);
  border:1px solid #d8c8ac;
  border-radius:18px;
  padding:14px;
}
.strip-kicker{
  color:#7a6a57;
  font-size:11px;
  letter-spacing:.12em;
  text-transform:uppercase;
}
.strip-value{
  margin-top:8px;
  font-size:32px;
  font-weight:700;
  line-height:1;
}
.hero-side{
  display:grid;
  gap:14px;
}
.bulletin,.card{
  background:linear-gradient(180deg, var(--panel), var(--paper));
  border:1px solid #d0c0a2;
  border-radius:24px;
  padding:18px;
}
.bulletin{
  background:
    linear-gradient(135deg, rgba(201,109,67,.12), transparent 44%),
    linear-gradient(180deg, #f5ecdc, #ece3d2);
}
.bulletin-head{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  margin-bottom:12px;
}
.stamp{
  display:inline-flex;
  padding:5px 10px;
  border-radius:999px;
  background:#1f2f3d;
  color:#f7f0e2;
  font-size:11px;
  letter-spacing:.12em;
  text-transform:uppercase;
}
.card h2,.card h3,.bulletin h2{
  margin:0 0 8px;
  font-size:17px;
}
.card > *{
  min-width:0;
}
.card p,.card li,.card label,.card span,.card code,.bulletin p{
  font-size:15px;
  line-height:1.58;
}
.muted{color:var(--muted)}
.mono{font-family:Consolas,"Courier New",monospace}
.status-row{display:flex;align-items:center;gap:10px}
.dot{width:10px;height:10px;border-radius:50%;background:#b8aa8a}
.dot.live{background:var(--good)}
.top-grid{
  display:grid;
  grid-template-columns:repeat(3,minmax(220px,1fr));
  gap:16px;
  margin-bottom:16px;
}
.top-grid .card:nth-child(2){
  background:
    linear-gradient(135deg, rgba(39,93,126,.10), transparent 44%),
    linear-gradient(180deg, var(--paper), #f0e7d8);
}
.scenario-band{
  margin-bottom:16px;
}
.section-label{
  margin:0 0 10px;
  color:#80684e;
  font-size:12px;
  letter-spacing:.16em;
  text-transform:uppercase;
}
.mid-grid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
  gap:14px;
}
.task-card{
  cursor:pointer;
  transition:transform .16s ease,border-color .16s ease,background .16s ease,box-shadow .16s ease;
  background:
    linear-gradient(180deg, rgba(255,255,255,.72), rgba(244,236,221,.95));
}
.task-card:hover{transform:translateY(-3px)}
.task-card.active{
  background:
    linear-gradient(180deg, rgba(39,93,126,.08), rgba(29,127,103,.12)),
    linear-gradient(180deg, rgba(255,255,255,.84), rgba(244,236,221,.98));
  border-color:#7f9f9b;
  box-shadow:0 12px 26px rgba(39,93,126,.10);
}
.task-meta{
  display:flex;
  justify-content:space-between;
  align-items:flex-start;
  gap:12px;
  margin-bottom:10px;
}
.task-grade{
  color:#9b6b34;
  font-size:12px;
  letter-spacing:.12em;
  text-transform:uppercase;
}
.pill{
  display:inline-flex;
  padding:4px 10px;
  border-radius:999px;
  background:#efe3ca;
  color:#6f624d;
  font-size:12px;
}
.pill.live{background:#ddeee7;color:#165f4a}
.bottom-grid{
  display:grid;
  grid-template-columns:minmax(0,1.35fr) minmax(320px,.8fr);
  gap:16px;
  align-items:start;
}
.stack{display:grid;gap:16px}
.controls{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
  gap:14px;
  margin-top:8px;
}
label{
  display:block;
  margin-bottom:6px;
  color:var(--muted);
  font-size:13px;
}
select,button{
  width:100%;
  border-radius:14px;
  border:1px solid #cdbb9b;
  padding:12px 14px;
  font:inherit;
}
select{background:#fffdf7}
.actions{display:flex;gap:12px;margin-top:14px}
.actions > *{
  flex:1 1 0;
}
button{
  cursor:pointer;
  font-weight:700;
  transition:transform .15s ease,opacity .15s ease,background .15s ease;
}
button:hover{transform:translateY(-1px)}
button:disabled{opacity:.5;cursor:not-allowed;transform:none}
.primary{
  background:linear-gradient(135deg, #1c2d3d, #274b67);
  color:#fff;
  border-color:#1c2d3d;
}
.secondary{
  background:#f2e8d8;
  color:var(--ink);
}
.metric{
  font-size:36px;
  font-weight:700;
  line-height:1;
  margin:8px 0 4px;
}
.score{
  font-size:clamp(42px, 6vw, 76px);
  line-height:.9;
  letter-spacing:-.06em;
  overflow-wrap:anywhere;
}
.good{color:var(--good)}
.warn{color:var(--warn)}
.bad{color:var(--bad)}
.stat-list{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  gap:12px;
}
.stat-item{
  padding:14px;
  border:1px solid #d9cbb2;
  border-radius:16px;
  background:rgba(255,255,255,.56);
  min-width:0;
  overflow:hidden;
}
.stat-item .muted{
  display:block;
  overflow-wrap:anywhere;
}
.stat-item .metric{
  font-size:clamp(28px, 4vw, 36px);
  overflow-wrap:anywhere;
}
.score-breakdown{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
  gap:12px;
}
.score-caption{
  margin:8px 0 14px;
  overflow-wrap:anywhere;
}
.progress{
  width:100%;
  height:10px;
  background:#e8dbc2;
  border-radius:999px;
  overflow:hidden;
  margin-top:10px;
}
.progress > div{
  height:100%;
  background:linear-gradient(90deg, var(--accent), var(--accent-2), var(--accent-3));
}
.reward-bars{
  display:flex;
  align-items:flex-end;
  gap:8px;
  height:150px;
  margin-top:12px;
}
.reward-col{
  flex:1;
  display:flex;
  flex-direction:column;
  align-items:center;
  justify-content:flex-end;
  gap:8px;
}
.reward-bar{
  width:100%;
  max-width:24px;
  border-radius:999px;
  background:#d1cabf;
}
.reward-bar.pos{background:linear-gradient(180deg,#ecae7c,#c96d43)}
.reward-bar.neg{background:linear-gradient(180deg,#c58a8a,#bb4e4e)}
.chain{
  display:flex;
  gap:10px;
  overflow:auto;
  padding-bottom:4px;
}
.chain-node{
  min-width:150px;
  border:1px solid #d8c7a8;
  border-radius:18px;
  padding:12px;
  background:#fff9ef;
}
.queue{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
  gap:12px;
}
.alert{
  border:1px solid #d8c7a8;
  border-radius:18px;
  padding:14px;
  background:#fffaf2;
  position:relative;
}
.alert::before{
  content:"";
  position:absolute;
  left:0;
  top:14px;
  bottom:14px;
  width:4px;
  border-radius:999px;
  background:linear-gradient(180deg, var(--accent), var(--accent-2));
}
.alert > *{margin-left:10px}
.alert strong,.alert .mono,.alert .muted{
  overflow-wrap:anywhere;
}
.alert-top{
  display:flex;
  flex-wrap:wrap;
  gap:8px;
  margin:10px 0 8px;
}
.log{
  background:linear-gradient(180deg, #161d25, #12171e);
  color:#dce7ef;
  border:1px solid #314250;
  border-radius:18px;
  padding:14px;
  height:280px;
  overflow:auto;
  font-family:Consolas,"Courier New",monospace;
  font-size:13px;
  line-height:1.6;
  overflow-wrap:anywhere;
}
.empty{color:var(--muted);padding:18px 0}
.banner{
  display:none;
  margin-bottom:16px;
  padding:14px 16px;
  border-radius:16px;
  border:1px solid #d2bea0;
  background:#fffaf1;
}
.banner.info{display:block;background:#f2ebdd}
.banner.success{display:block;background:#e7f3eb;border-color:#b8d0c1}
.banner.error{display:block;background:#fae9e7;border-color:#dbb2ae}
@media (max-width: 1180px){
  .bottom-grid{
    grid-template-columns:1fr;
  }
}
@media (max-width: 980px){
  .hero,.top-grid,.hero-strip{grid-template-columns:1fr}
  .actions{flex-direction:column}
  h1{font-size:52px}
}
</style>
</head>
<body>
<div class="shell">
  <div class="frame">
    <section class="hero">
      <div class="hero-main">
        <div class="eyebrow">Security Simulation Desk</div>
        <h1>SOC Triage Gym</h1>
        <p class="lede">A distinct operations-style interface for evaluating analyst agents across phishing, kill chains, noisy queues, and insider threat investigations. Start an episode, inspect the queue, and grade the baseline without dropping into raw endpoint output.</p>
        <div class="hero-strip">
          <div class="strip-card">
            <div class="strip-kicker">Scenarios</div>
            <div class="strip-value">4</div>
            <div class="muted">easy to expert tasks</div>
          </div>
          <div class="strip-card">
            <div class="strip-kicker">Workflow</div>
            <div class="strip-value mono">REST</div>
            <div class="muted">reset, step, state, baseline</div>
          </div>
          <div class="strip-card">
            <div class="strip-kicker">Focus</div>
            <div class="strip-value">SOC</div>
            <div class="muted">triage quality and signal handling</div>
          </div>
        </div>
      </div>
      <div class="hero-side">
        <div class="bulletin">
          <div class="bulletin-head">
            <h2>Operations Bulletin</h2>
            <span class="stamp">Live App</span>
          </div>
          <p class="muted">This Space is designed like a field desk rather than a product brochure: quick launch controls, readable status, and direct evidence of how the environment behaves.</p>
        </div>
        <div class="card">
          <h2>What Agents Can Do</h2>
          <p class="mono">enrich_indicator, query_logs, correlate_alerts, check_asset, check_user, classify_alert, map_technique, recommend_action, escalate</p>
        </div>
      </div>
    </section>

    <div id="banner" class="banner"></div>

    <div class="top-grid">
      <div class="card">
        <h2>Status</h2>
        <div class="status-row">
          <div id="statusDot" class="dot"></div>
          <span id="statusText">Waiting for server health check</span>
        </div>
      </div>
      <div class="card">
        <h2>API Surface</h2>
        <p>Interactive docs and the standard <span class="mono">/reset</span>, <span class="mono">/step</span>, <span class="mono">/state</span>, and <span class="mono">/metadata</span> endpoints remain available behind the UI.</p>
      </div>
      <div class="card">
        <h2>Design Mode</h2>
        <p>This theme intentionally mixes incident-desk cues, darker telemetry accents, and warmer paper panels so it reads as its own identity.</p>
      </div>
    </div>

    <div class="scenario-band">
      <p class="section-label">Scenario Board</p>
      <div class="mid-grid" id="taskGrid">
      <div class="card task-card active" data-task="phishing">
        <div class="task-meta"><div><div class="task-grade">Easy</div><h3>Phishing</h3></div><span class="pill">15 step budget</span></div>
        <p>Resolve a single phishing alert with enrichment, evidence gathering, and clean classification.</p>
      </div>
      <div class="card task-card" data-task="lateral_movement">
        <div class="task-meta"><div><div class="task-grade">Medium</div><h3>Lateral Movement</h3></div><span class="pill">30 step budget</span></div>
        <p>Reconstruct a multi-alert intrusion path across credential theft, movement, staging, and exfiltration.</p>
      </div>
      <div class="card task-card" data-task="queue_management">
        <div class="task-meta"><div><div class="task-grade">Hard</div><h3>Queue Management</h3></div><span class="pill">60 step budget</span></div>
        <p>Work through a realistic noisy queue where true positives hide inside false-positive traffic.</p>
      </div>
      <div class="card task-card" data-task="insider_threat">
        <div class="task-meta"><div><div class="task-grade">Expert</div><h3>Insider Threat</h3></div><span class="pill">80 step budget</span></div>
        <p>Investigate the largest scenario with mixed intent signals, hidden chains, and higher analyst pressure.</p>
      </div>
      </div>
    </div>

    <div class="bottom-grid">
      <div class="stack">
        <div class="card" style="margin-bottom:16px;">
          <h2>Launch Evaluation</h2>
          <div class="controls">
            <div>
              <label for="task">Scenario</label>
              <select id="task">
                <option value="phishing">Phishing</option>
                <option value="lateral_movement">Lateral Movement</option>
                <option value="queue_management">Queue Management</option>
                <option value="insider_threat">Insider Threat</option>
              </select>
            </div>
            <div>
              <label for="seed">Seed</label>
              <select id="seed">
                <option value="42">42</option>
                <option value="123">123</option>
                <option value="256">256</option>
                <option value="789">789</option>
                <option value="1024">1024</option>
              </select>
            </div>
          </div>
          <div class="actions">
            <button class="primary" onclick="doReset()">Start Episode</button>
            <button class="secondary" id="runBtn" onclick="doBaseline()" disabled>Run Heuristic Agent</button>
          </div>
        </div>

        <div class="card" style="margin-bottom:16px;">
          <h2>Episode State</h2>
          <div id="statePanel" class="empty">Start an episode to load state, step budget, and classification progress.</div>
        </div>

        <div class="card" style="margin-bottom:16px;">
          <h2>Alert Queue</h2>
          <div id="alertPanel" class="empty">The active queue will appear here once an episode starts.</div>
        </div>

        <div class="card">
          <h2>Kill Chain View</h2>
          <div id="chainPanel" class="empty">Correlated scenarios will render a simple chain view here.</div>
        </div>
      </div>

      <div class="stack">
        <div class="card" style="margin-bottom:16px;">
          <h2>Grader Result</h2>
          <div id="scorePanel" class="empty">Run the heuristic agent to see the final score and breakdown.</div>
        </div>

        <div class="card" style="margin-bottom:16px;">
          <h2>Reward Trace</h2>
          <div id="rewardPanel" class="empty">Reward bars appear after the baseline run.</div>
        </div>

        <div class="card">
          <h2>Investigation Log</h2>
          <div id="logBox" class="log">[system] waiting for launch...</div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
let alertData = [];
let stepRewards = [];

function q(id){ return document.getElementById(id); }
function titleize(v){ return (v || '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()); }
function log(msg){
  const now = new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
  const box = q('logBox');
  if (box.textContent.includes('waiting for launch')) box.textContent = '';
  box.innerHTML += `[${now}] ${msg}<br>`;
  box.scrollTop = box.scrollHeight;
}
function showBanner(message, type){
  const el = q('banner');
  el.textContent = message;
  el.className = `banner ${type}`;
}
function scoreClass(score){
  if (score >= 0.65) return 'good';
  if (score >= 0.35) return 'warn';
  return 'bad';
}
function clsKey(v){
  const value = (v || 'unclassified').toLowerCase().replace(/ /g, '_');
  if (value === 'true_positive') return 'True Positive';
  if (value === 'false_positive') return 'False Positive';
  if (value === 'benign_true_positive') return 'Benign True Positive';
  return 'Unclassified';
}
function syncTask(task){
  q('task').value = task;
  document.querySelectorAll('.task-card').forEach(card => {
    card.classList.toggle('active', card.dataset.task === task);
  });
}
document.querySelectorAll('.task-card').forEach(card => {
  card.addEventListener('click', () => syncTask(card.dataset.task));
});
q('task').addEventListener('change', e => syncTask(e.target.value));

function renderState(state){
  const progress = state.max_steps ? Math.round((state.step_count / state.max_steps) * 100) : 0;
  return `<div class="stat-list">
    <div class="stat-item"><div class="muted">Task</div><div class="metric">${titleize(state.task_id)}</div></div>
    <div class="stat-item"><div class="muted">Reward</div><div class="metric ${state.cumulative_reward >= 0 ? 'good' : 'bad'}">${(state.cumulative_reward || 0).toFixed(3)}</div></div>
    <div class="stat-item"><div class="muted">Classified</div><div class="metric">${state.classified_count || 0}/${state.alert_count || 0}</div></div>
    <div class="stat-item"><div class="muted">Status</div><div class="metric">${state.done ? 'Done' : 'Live'}</div></div>
  </div>
  <div style="margin-top:14px;" class="muted">Steps used: ${state.step_count} / ${state.max_steps}</div>
  <div class="progress"><div style="width:${progress}%"></div></div>`;
}

function renderAlerts(alerts){
  if (!alerts || !alerts.length) return '<div class="empty">No alerts available.</div>';
  return `<div class="queue">${alerts.map(alert => `
    <div class="alert">
      <strong>${alert.title || 'Untitled Alert'}</strong>
      <div class="alert-top">
        <span class="pill">${(alert.severity || 'info').toUpperCase()}</span>
        <span class="pill">${clsKey(alert.classification)}</span>
      </div>
      <div class="muted">${alert.source_system || 'Unknown Source'}</div>
      <div class="mono" style="margin-top:8px;">${alert.alert_id || ''}</div>
    </div>`).join('')}</div>`;
}

function renderChain(alerts){
  if (!alerts || alerts.length <= 1) return '<div class="empty">Single-alert tasks do not render a chain.</div>';
  return `<div class="chain">${alerts.map(alert => `
    <div class="chain-node">
      <strong>${(alert.title || 'Alert').substring(0, 28)}</strong>
      <div class="muted">${clsKey(alert.classification)}</div>
    </div>`).join('<div style="align-self:center;color:#b39d74;">&rarr;</div>')}</div>`;
}

function renderRewards(rewards){
  if (!rewards.length) return '<div class="empty">No reward trace yet.</div>';
  const maxAbs = Math.max(...rewards.map(v => Math.abs(v)), 0.01);
  return `<div class="reward-bars">${rewards.map((reward, idx) => {
    const height = Math.max(16, Math.round((Math.abs(reward) / maxAbs) * 110));
    return `<div class="reward-col">
      <div class="reward-bar ${reward >= 0 ? 'pos' : 'neg'}" style="height:${height}px" title="${reward.toFixed(3)}"></div>
      <div class="muted">${idx + 1}</div>
    </div>`;
  }).join('')}</div>`;
}

function renderScore(result){
  const breakdown = result.breakdown || {};
  const klass = scoreClass(result.score || 0);
  return `<div class="${klass} score">${((result.score || 0) * 100).toFixed(1)}%</div>
    <p class="muted score-caption">${titleize(result.task_id)} | ${result.steps_used || 0} steps used</p>
    <div class="score-breakdown">${Object.entries(breakdown).map(([key, value]) => `
      <div class="stat-item">
        <div class="muted">${titleize(key)}</div>
        <div class="metric">${Math.round(value * 100)}%</div>
      </div>`).join('')}</div>
    ${result.feedback ? `<p style="margin-top:14px;">${result.feedback}</p>` : ''}`;
}

async function refreshState(){
  const response = await fetch('/state');
  const state = await response.json();
  q('statePanel').innerHTML = renderState(state);
  return state;
}

async function doReset(){
  const task = q('task').value;
  const seed = parseInt(q('seed').value, 10);
  q('runBtn').disabled = true;
  q('scorePanel').innerHTML = '<div class="empty">Run the heuristic agent to see the final score and breakdown.</div>';
  q('rewardPanel').innerHTML = '<div class="empty">Reward bars appear after the baseline run.</div>';
  showBanner(`Starting ${titleize(task)} with seed ${seed}...`, 'info');
  log(`starting episode for ${task} seed=${seed}`);
  try {
    const response = await fetch('/reset', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({task_id: task, seed})
    });
    if (!response.ok) throw new Error(await response.text());
    const observation = await response.json();
    alertData = observation.alert_queue || [];
    q('alertPanel').innerHTML = renderAlerts(alertData);
    q('chainPanel').innerHTML = renderChain(alertData);
    const state = await refreshState();
    q('runBtn').disabled = false;
    showBanner(`Episode ready with ${alertData.length} alerts and ${state.max_steps} available steps.`, 'success');
    log(`episode ready with ${alertData.length} alerts`);
  } catch (error) {
    showBanner(`Error: ${error.message}`, 'error');
    log(`error: ${error.message}`);
  }
}

async function doBaseline(){
  const task = q('task').value;
  const seed = parseInt(q('seed').value, 10);
  q('runBtn').disabled = true;
  showBanner(`Running heuristic baseline for ${titleize(task)}...`, 'info');
  log(`running baseline for ${task}`);
  try {
    const response = await fetch('/baseline', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({task_id: task, seed})
    });
    if (!response.ok) throw new Error(await response.text());
    const result = await response.json();
    q('scorePanel').innerHTML = renderScore(result);
    stepRewards = Object.values(result.breakdown || {}).map(v => v * 0.3);
    if (result.score) stepRewards.push(result.score);
    q('rewardPanel').innerHTML = renderRewards(stepRewards);
    await refreshState();
    const alertsResponse = await fetch('/api/alerts?limit=30');
    const alertsPayload = await alertsResponse.json();
    alertData = alertsPayload.alerts || alertData;
    q('alertPanel').innerHTML = renderAlerts(alertData);
    q('chainPanel').innerHTML = renderChain(alertData);
    showBanner(`Baseline complete. Final score ${((result.score || 0) * 100).toFixed(1)}%.`, 'success');
    log(`baseline finished with score ${((result.score || 0) * 100).toFixed(1)}%`);
  } catch (error) {
    showBanner(`Error: ${error.message}`, 'error');
    log(`error: ${error.message}`);
    q('runBtn').disabled = false;
  }
}

window.onload = async () => {
  syncTask(q('task').value);
  try {
    const response = await fetch('/health');
    const health = await response.json();
    q('statusDot').classList.add('live');
    q('statusText').textContent = `Running and ready for evaluation | ${health.env} v${health.version}`;
    log(`server online`);
  } catch (error) {
    q('statusText').textContent = 'Server health check failed';
    log('health check failed');
  }
};
</script>
</body>
</html>"""


