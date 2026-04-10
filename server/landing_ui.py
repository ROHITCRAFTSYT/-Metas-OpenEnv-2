"""Editorial Hugging Face Space UI served at / and /ui."""

UI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Triage Gym</title>
<style>
:root{
  --bg:#f6eedb;
  --paper:#fffaf0;
  --panel:#fffdf8;
  --ink:#1f2d3a;
  --muted:#596b7b;
  --line:#d8cbb2;
  --soft:#ece1cb;
  --accent:#1f8f6a;
  --accent-soft:#dff3eb;
  --blue:#406999;
  --good:#0f9b61;
  --warn:#b67b17;
  --bad:#c45151;
  --shadow:0 18px 40px rgba(86, 70, 39, .10);
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:linear-gradient(180deg,#fff7e6 0%, #f6eedb 100%);
  color:var(--ink);
  font-family:Georgia,"Times New Roman",serif;
}
.shell{max-width:1120px;margin:0 auto;padding:28px 18px 44px}
.frame{
  background:rgba(255,250,240,.85);
  border:1px solid var(--line);
  border-radius:28px;
  box-shadow:var(--shadow);
  padding:28px;
}
.eyebrow{
  display:inline-flex;
  padding:8px 14px;
  border-radius:999px;
  background:var(--accent-soft);
  color:#0b6d50;
  font-size:14px;
  letter-spacing:.04em;
  text-transform:uppercase;
}
h1{
  margin:14px 0 10px;
  font-size:70px;
  line-height:.95;
  letter-spacing:-.04em;
}
.lede{
  max-width:760px;
  color:var(--blue);
  font-size:18px;
  line-height:1.55;
  margin-bottom:26px;
}
.top-grid,.mid-grid,.bottom-grid{
  display:grid;
  gap:16px;
}
.top-grid{grid-template-columns:repeat(3,minmax(0,1fr));margin-bottom:16px}
.mid-grid{grid-template-columns:repeat(4,minmax(0,1fr));margin-bottom:16px}
.bottom-grid{grid-template-columns:1.2fr .8fr}
.card{
  background:var(--panel);
  border:1px solid var(--line);
  border-radius:22px;
  padding:18px;
  box-shadow:0 8px 22px rgba(86,70,39,.05);
}
.card h2,.card h3{
  margin:0 0 8px;
  font-size:17px;
}
.card p,.card li,.card label,.card span,.card code{
  font-size:15px;
  line-height:1.55;
}
.muted{color:var(--muted)}
.mono{font-family:Consolas,"Courier New",monospace}
.status-row{display:flex;align-items:center;gap:10px}
.dot{
  width:10px;height:10px;border-radius:50%;
  background:#b8aa8a;
}
.dot.live{background:var(--good)}
.task-card{
  cursor:pointer;
  transition:transform .16s ease,border-color .16s ease,box-shadow .16s ease;
}
.task-card:hover{transform:translateY(-2px)}
.task-card.active{
  border-color:#9bcbb9;
  box-shadow:0 12px 26px rgba(31,143,106,.10);
  background:#fcfffb;
}
.task-meta{
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:12px;
  margin-bottom:10px;
}
.pill{
  display:inline-flex;
  padding:4px 10px;
  border-radius:999px;
  background:#f2ead9;
  color:var(--muted);
  font-size:12px;
}
.pill.live{background:var(--accent-soft);color:#0b6d50}
.controls{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:14px;
  margin-top:8px;
}
label{display:block;margin-bottom:6px;color:var(--muted)}
select,button{
  width:100%;
  border-radius:16px;
  border:1px solid var(--line);
  padding:12px 14px;
  font:inherit;
}
select{background:#fffef9}
.actions{
  display:flex;
  gap:12px;
  margin-top:14px;
}
button{
  cursor:pointer;
  font-weight:700;
  transition:transform .15s ease,opacity .15s ease;
}
button:hover{transform:translateY(-1px)}
button:disabled{opacity:.5;cursor:not-allowed;transform:none}
.primary{
  background:#203142;
  color:#fff;
  border-color:#203142;
}
.secondary{
  background:#f6f0e3;
  color:var(--ink);
}
.metric{
  font-size:36px;
  font-weight:700;
  line-height:1;
  margin:8px 0 4px;
}
.score{
  font-size:72px;
  line-height:.9;
  letter-spacing:-.05em;
}
.good{color:var(--good)}
.warn{color:var(--warn)}
.bad{color:var(--bad)}
.stat-list{
  display:grid;
  grid-template-columns:repeat(2,minmax(0,1fr));
  gap:12px;
}
.stat-item{
  padding:14px;
  border:1px solid var(--soft);
  border-radius:16px;
  background:#fffcf6;
}
.progress{
  width:100%;
  height:10px;
  background:#efe5d3;
  border-radius:999px;
  overflow:hidden;
  margin-top:10px;
}
.progress > div{
  height:100%;
  background:linear-gradient(90deg,#2f5e8f,#1f8f6a);
}
.reward-bars{
  display:flex;
  align-items:flex-end;
  gap:8px;
  height:140px;
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
  max-width:26px;
  border-radius:10px 10px 4px 4px;
  background:#d1cabf;
}
.reward-bar.pos{background:linear-gradient(180deg,#7bcfac,#179360)}
.reward-bar.neg{background:linear-gradient(180deg,#dd8e8e,#c45151)}
.chain{
  display:flex;
  gap:10px;
  overflow:auto;
  padding-bottom:4px;
}
.chain-node{
  min-width:140px;
  border:1px solid var(--soft);
  border-radius:16px;
  padding:12px;
  background:#fffdf8;
}
.queue{
  display:grid;
  grid-template-columns:repeat(2,minmax(0,1fr));
  gap:12px;
}
.alert{
  border:1px solid var(--soft);
  border-radius:16px;
  padding:14px;
  background:#fffdf8;
}
.alert-top{
  display:flex;
  flex-wrap:wrap;
  gap:8px;
  margin:10px 0 8px;
}
.log{
  background:#f8f3e8;
  border:1px solid var(--soft);
  border-radius:16px;
  padding:14px;
  height:280px;
  overflow:auto;
  font-family:Consolas,"Courier New",monospace;
  font-size:13px;
  line-height:1.6;
}
.empty{
  color:var(--muted);
  padding:18px 0;
}
.banner{
  display:none;
  margin-bottom:16px;
  padding:14px 16px;
  border-radius:16px;
  border:1px solid var(--line);
  background:#fffdf8;
}
.banner.info{display:block;background:#f3efe5}
.banner.success{display:block;background:#eef8f1;border-color:#bfe1ce}
.banner.error{display:block;background:#fff0ef;border-color:#e4b8b5}
@media (max-width: 940px){
  h1{font-size:50px}
  .top-grid,.mid-grid,.bottom-grid,.queue,.controls,.stat-list{grid-template-columns:1fr}
  .actions{flex-direction:column}
}
</style>
</head>
<body>
<div class="shell">
  <div class="frame">
    <div class="eyebrow">OpenEnv Space</div>
    <h1>SOC Triage Gym</h1>
    <div class="lede">A readable Hugging Face Space dashboard for a SOC analyst environment. Launch an episode, inspect the queue, and run the heuristic agent without landing on raw API JSON.</div>

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
        <h2>Supported actions</h2>
        <p class="mono">enrich_indicator, query_logs, correlate_alerts, check_asset, check_user, classify_alert, map_technique, recommend_action, escalate</p>
      </div>
      <div class="card">
        <h2>API</h2>
        <p>Interactive docs and standard <span class="mono">/reset</span>, <span class="mono">/step</span>, <span class="mono">/state</span>, and <span class="mono">/metadata</span> endpoints remain available.</p>
      </div>
    </div>

    <div class="mid-grid" id="taskGrid">
      <div class="card task-card active" data-task="phishing">
        <div class="task-meta"><h3>Easy</h3><span class="pill">15 step budget</span></div>
        <p>Resolve a single phishing alert with enrichment, evidence gathering, and clean classification.</p>
      </div>
      <div class="card task-card" data-task="lateral_movement">
        <div class="task-meta"><h3>Medium</h3><span class="pill">30 step budget</span></div>
        <p>Reconstruct a multi-alert intrusion path across credential theft, movement, staging, and exfiltration.</p>
      </div>
      <div class="card task-card" data-task="queue_management">
        <div class="task-meta"><h3>Hard</h3><span class="pill">60 step budget</span></div>
        <p>Work through a realistic noisy queue where true positives hide inside false-positive traffic.</p>
      </div>
      <div class="card task-card" data-task="insider_threat">
        <div class="task-meta"><h3>Expert</h3><span class="pill">80 step budget</span></div>
        <p>Investigate the largest scenario with mixed intent signals, hidden chains, and higher analyst pressure.</p>
      </div>
    </div>

    <div class="bottom-grid">
      <div>
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

      <div>
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
    </div>`).join('<div style="align-self:center;color:#b39d74;">→</div>')}</div>`;
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
    <p class="muted" style="margin:8px 0 14px;">${titleize(result.task_id)} · ${result.steps_used || 0} steps used</p>
    <div class="stat-list">${Object.entries(breakdown).map(([key, value]) => `
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
    q('statusText').textContent = `Running and ready for evaluation · ${health.env} v${health.version}`;
    log(`server online`);
  } catch (error) {
    q('statusText').textContent = 'Server health check failed';
    log('health check failed');
  }
};
</script>
</body>
</html>"""
