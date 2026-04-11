"""SOC Triage Gym browser UI served at GET /ui."""

UI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Triage Gym | OpenEnv</title>
<style>
:root{
  --bg:#07111a;
  --bg2:#0d1823;
  --panel:#0f1d2a;
  --panel-soft:rgba(18,32,45,.82);
  --border:rgba(147,181,203,.15);
  --border-strong:rgba(147,181,203,.32);
  --text:#edf5fb;
  --muted:#93a6b6;
  --accent:#6ae3c0;
  --accent-2:#4f8cff;
  --alert:#ff8f6b;
  --good:#4cd08e;
  --warn:#ffc261;
  --bad:#ff6b7d;
  --shadow:0 24px 60px rgba(0,0,0,.34);
}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%}
body{
  font-family:"Trebuchet MS","Aptos","Segoe UI",sans-serif;
  color:var(--text);
  background:
    radial-gradient(circle at top left, rgba(79,140,255,.22), transparent 32%),
    radial-gradient(circle at top right, rgba(106,227,192,.14), transparent 26%),
    linear-gradient(180deg, #08121c 0%, #07111a 44%, #050c13 100%);
}
body::before{
  content:"";
  position:fixed;
  inset:0;
  pointer-events:none;
  background-image:
    linear-gradient(rgba(255,255,255,.02) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.02) 1px, transparent 1px);
  background-size:32px 32px;
  mask-image:linear-gradient(180deg, rgba(0,0,0,.55), transparent 85%);
}
.shell{max-width:1440px;margin:0 auto;padding:24px 20px 36px;position:relative}
.topbar{
  display:flex;align-items:center;gap:16px;justify-content:space-between;flex-wrap:wrap;
  margin-bottom:18px;padding:14px 18px;border:1px solid var(--border);border-radius:22px;
  background:rgba(7,17,26,.72);backdrop-filter:blur(16px);box-shadow:var(--shadow)
}
.brand{display:flex;align-items:center;gap:14px}
.crest{
  width:54px;height:54px;border-radius:18px;display:grid;place-items:center;
  background:linear-gradient(135deg, rgba(79,140,255,.28), rgba(106,227,192,.18));
  border:1px solid rgba(255,255,255,.14);font-size:26px;box-shadow:inset 0 1px 0 rgba(255,255,255,.1)
}
.eyebrow{
  color:var(--accent);font-size:11px;letter-spacing:.24em;text-transform:uppercase;margin-bottom:5px
}
h1{
  margin:0;font-size:32px;line-height:1.05;font-weight:800;letter-spacing:.01em
}
.subhead{margin-top:6px;color:var(--muted);font-size:14px;max-width:640px}
.chips{display:flex;gap:10px;flex-wrap:wrap}
.chip{
  padding:8px 12px;border-radius:999px;background:rgba(255,255,255,.04);
  border:1px solid var(--border);color:var(--muted);font-size:12px
}
.chip strong{color:var(--text);font-weight:700}

.hero{
  display:grid;grid-template-columns:minmax(0,1.5fr) minmax(0,1fr);gap:18px;margin-bottom:18px;align-items:start
}
.hero-card,.control-card,.panel{
  background:linear-gradient(180deg, rgba(15,29,42,.96), rgba(9,19,29,.92));
  border:1px solid var(--border);
  border-radius:28px;
  box-shadow:var(--shadow);
  position:relative;
  overflow:hidden;
  min-width:0;
}
.hero-card{padding:28px}
.hero-card::after,.panel::after,.control-card::after{
  content:"";position:absolute;inset:auto -20% -45% auto;width:220px;height:220px;border-radius:50%;
  background:radial-gradient(circle, rgba(79,140,255,.18), transparent 68%)
}
.hero-grid{display:grid;grid-template-columns:repeat(4, minmax(0,1fr));gap:12px;margin-top:22px}
.hero-metric{
  padding:16px;border-radius:20px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06)
}
.metric-label{color:var(--muted);font-size:11px;letter-spacing:.12em;text-transform:uppercase}
.metric-value{margin-top:8px;font-size:28px;font-weight:800}
.metric-note{margin-top:4px;font-size:12px;color:var(--muted)}

.control-card{padding:22px}
.section-title{
  display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:16px
}
.section-title h2,.panel h3{margin:0;font-size:13px;letter-spacing:.18em;text-transform:uppercase}
.section-title h2,.panel h3{color:#dbeaf6}
.section-title p{margin:6px 0 0;color:var(--muted);font-size:13px}
.status-pill{
  display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:999px;
  background:rgba(255,255,255,.04);border:1px solid var(--border);color:var(--muted);font-size:12px
}
.status-dot{width:8px;height:8px;border-radius:50%;background:#6b7f8f;box-shadow:0 0 0 4px rgba(107,127,143,.15)}
.status-pill.online .status-dot{background:var(--good);box-shadow:0 0 0 4px rgba(76,208,142,.16)}

.task-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-bottom:12px}
.task-card{
  border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:12px;background:rgba(255,255,255,.03);
  cursor:pointer;transition:transform .18s ease,border-color .18s ease,background .18s ease;
  min-width:0;overflow:hidden;text-align:left
}
.task-card:hover{transform:translateY(-2px);border-color:rgba(106,227,192,.38)}
.task-card.active{
  background:linear-gradient(180deg, rgba(106,227,192,.16), rgba(79,140,255,.1));
  border-color:rgba(106,227,192,.45)
}
.task-card strong{display:block;font-size:13px;margin-bottom:4px;word-break:break-word}
.task-card span{display:block;color:var(--muted);font-size:11px;line-height:1.4;word-break:break-word}
.task-card em{display:inline-block;margin-top:6px;color:var(--accent);font-style:normal;font-size:10px;letter-spacing:.08em;text-transform:uppercase}
.field-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
label{display:block;color:var(--muted);font-size:12px;margin:0 0 6px}
select{
  width:100%;padding:12px 14px;border-radius:16px;border:1px solid rgba(255,255,255,.08);
  background:rgba(4,12,18,.7);color:var(--text);font:inherit;outline:none
}
select:focus{border-color:rgba(79,140,255,.5)}
.button-row{display:flex;gap:12px;margin-top:14px}
.btn{
  flex:1;padding:13px 16px;border-radius:16px;border:1px solid transparent;cursor:pointer;
  font:700 13px/1 "Trebuchet MS","Aptos","Segoe UI",sans-serif;letter-spacing:.04em;
  transition:transform .15s ease, box-shadow .15s ease, opacity .15s ease
}
.btn:hover{transform:translateY(-1px)}
.btn:disabled{opacity:.4;cursor:not-allowed;transform:none;box-shadow:none}
.btn-primary{
  color:#041018;background:linear-gradient(135deg, var(--accent), #7ec7ff);box-shadow:0 18px 28px rgba(106,227,192,.18)
}
.btn-secondary{
  color:var(--text);background:rgba(255,255,255,.03);border-color:rgba(255,255,255,.09)
}
.hint{margin-top:12px;color:var(--muted);font-size:12px;line-height:1.5}

.banner{
  display:none;margin-bottom:16px;padding:14px 16px;border-radius:18px;
  border:1px solid var(--border);background:rgba(255,255,255,.04);font-size:13px
}
.banner.bi{color:#b8d8ff;border-color:rgba(79,140,255,.28);background:rgba(79,140,255,.11)}
.banner.bs{color:#cbffe9;border-color:rgba(76,208,142,.25);background:rgba(76,208,142,.12)}
.banner.be{color:#ffd6db;border-color:rgba(255,107,125,.25);background:rgba(255,107,125,.12)}

.main-grid{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(0,.8fr);gap:18px;align-items:start}
.stack{display:grid;gap:18px;min-width:0}
.panel{padding:22px}
.panel-header{
  display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:18px
}
.panel-kicker{color:var(--muted);font-size:12px}
.inline-stats{display:flex;gap:10px;flex-wrap:wrap}
.mini-pill{
  padding:7px 10px;border-radius:999px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);
  color:var(--muted);font-size:11px
}

.stat-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.stat-card{
  background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:18px;padding:14px;min-width:0;overflow:hidden
}
.stat-card strong{display:block;color:var(--muted);font-size:11px;letter-spacing:.12em;text-transform:uppercase}
.stat-card span{display:block;margin-top:8px;font-size:24px;font-weight:800;word-break:break-word}
.stat-card small{display:block;margin-top:4px;color:var(--muted);font-size:11px;word-break:break-word}
.progress-shell{margin-top:16px;padding:14px 16px;border-radius:18px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06)}
.progress-top{display:flex;justify-content:space-between;gap:12px;color:var(--muted);font-size:12px}
.bar{height:10px;border-radius:999px;background:rgba(255,255,255,.06);margin-top:10px;overflow:hidden}
.bar-fill{height:100%;border-radius:999px;background:linear-gradient(90deg, var(--accent-2), var(--accent));transition:width .35s ease}

.score-shell{display:grid;gap:14px}
.score-hero{
  padding:20px;border-radius:22px;background:
    radial-gradient(circle at top right, rgba(106,227,192,.16), transparent 40%),
    rgba(255,255,255,.03);
  border:1px solid rgba(255,255,255,.06)
}
.score-value{font-size:52px;font-weight:900;line-height:.95;letter-spacing:-.04em}
.score-meta{margin-top:10px;color:var(--muted);font-size:13px;word-break:break-word}
.bk-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px}
.bk-item{padding:12px;border-radius:16px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);min-width:0;overflow:hidden}
.bk-item strong{display:block;color:var(--muted);font-size:10px;letter-spacing:.08em;text-transform:uppercase;word-break:break-word;overflow-wrap:break-word;line-height:1.4}
.bk-item span{display:block;margin-top:6px;font-size:22px;font-weight:800}
.bk-bar{margin-top:8px;height:6px;border-radius:999px;background:rgba(255,255,255,.06);overflow:hidden}
.bk-bar-fill{height:100%;border-radius:999px}
.feedback{padding:16px;border-radius:18px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);color:#d3e2ee;font-size:13px;line-height:1.6}

.viz-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.reward-chart{display:flex;align-items:flex-end;gap:8px;height:160px;padding-top:16px}
.reward-bar-wrap{flex:1;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;gap:8px;min-width:22px}
.reward-bar{width:100%;max-width:28px;border-radius:14px 14px 6px 6px;transition:height .3s ease}
.reward-bar.pos{background:linear-gradient(180deg, #9ff9de 0%, #4cd08e 100%)}
.reward-bar.neg{background:linear-gradient(180deg, #ffb0ba 0%, #ff6b7d 100%)}
.reward-index{font-size:10px;color:var(--muted)}

.kc-chain{display:flex;align-items:center;gap:8px;overflow-x:auto;padding-bottom:8px;scrollbar-width:thin;scrollbar-color:rgba(255,255,255,.1) transparent}
.kc-chain::-webkit-scrollbar{height:4px}
.kc-chain::-webkit-scrollbar-thumb{background:rgba(255,255,255,.12);border-radius:999px}
.kc-node{
  flex:none;min-width:110px;max-width:160px;padding:12px;border-radius:16px;background:rgba(255,255,255,.03);
  border:1px solid rgba(255,255,255,.06)
}
.kc-node strong{display:block;font-size:12px;word-break:break-word;line-height:1.3}
.kc-node span{display:block;margin-top:5px;color:var(--muted);font-size:11px}
.kc-node.tp{border-color:rgba(255,107,125,.44);background:rgba(255,107,125,.08)}
.kc-node.fp{border-color:rgba(76,208,142,.42);background:rgba(76,208,142,.08)}
.kc-node.btp{border-color:rgba(255,194,97,.42);background:rgba(255,194,97,.08)}
.kc-node.unc{border-color:rgba(147,166,182,.18)}
.kc-arrow{font-size:22px;color:rgba(255,255,255,.18);flex:none}

.alert-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px}
.alert-card{
  padding:14px;border-radius:18px;background:linear-gradient(180deg, rgba(255,255,255,.035), rgba(255,255,255,.02));
  border:1px solid rgba(255,255,255,.06);position:relative;overflow:hidden;min-width:0;word-break:break-word
}
.alert-card::before{
  content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:rgba(147,166,182,.3)
}
.alert-card.tp::before{background:var(--bad)}
.alert-card.fp::before{background:var(--good)}
.alert-card.btp::before{background:var(--warn)}
.ac-title{font-size:15px;font-weight:800;line-height:1.35;margin-bottom:10px;padding-right:10px}
.ac-meta{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.tag{
  display:inline-flex;align-items:center;padding:6px 9px;border-radius:999px;font-size:11px;
  background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);color:var(--muted)
}
.sev-critical,.sev-high{color:#ffd6db}
.sev-medium{color:#ffe2b0}
.sev-low{color:#d6e7ff}
.sev-info{color:var(--muted)}
.ac-id{font-family:"Consolas","SFMono-Regular","Courier New",monospace;font-size:11px;color:var(--muted)}

.log{
  min-height:220px;max-height:320px;overflow:auto;padding:16px;border-radius:20px;
  background:rgba(4,10,16,.76);border:1px solid rgba(255,255,255,.06);
  font-family:"Consolas","SFMono-Regular","Courier New",monospace;font-size:12px;line-height:1.65
}
.log-row{padding-bottom:8px}
.ts{color:#6e8294}.act{color:#8fc7ff}.ok{color:#98f0c2}.err{color:#ffb0ba}.sys{color:#b0c0cc}

.empty{
  padding:26px 18px;border-radius:18px;background:rgba(255,255,255,.025);border:1px dashed rgba(255,255,255,.08);
  text-align:center;color:var(--muted);font-size:13px
}

@media (max-width: 1180px){
  .hero,.main-grid,.viz-grid{grid-template-columns:1fr}
}
@media (max-width: 900px){
  .bk-grid{grid-template-columns:repeat(auto-fill,minmax(110px,1fr))}
}
@media (max-width: 760px){
  .shell{padding:16px 12px 28px}
  .hero-card,.control-card,.panel{border-radius:22px}
  .hero-grid,.task-grid,.field-grid,.stat-grid,.bk-grid{grid-template-columns:1fr}
  .button-row{flex-direction:column}
  h1{font-size:26px}
  .score-value{font-size:40px}
  .ac-title{font-size:13px}
}
</style>
</head>
<body>
<div class="shell">
  <div class="topbar">
    <div class="brand">
      <div class="crest">SH</div>
      <div>
        <div class="eyebrow">OpenEnv Security Lab</div>
        <h1>SOC Triage Gym</h1>
        <div class="subhead">A sharper Hugging Face Space for testing analyst agents across phishing, kill chains, noisy queues, and insider threat investigations.</div>
      </div>
    </div>
    <div class="chips">
      <div class="chip"><strong>Runtime</strong> Docker Space</div>
      <div class="chip"><strong>Focus</strong> Cyber RL</div>
      <div id="hb" class="chip"><strong>Status</strong> Offline</div>
    </div>
  </div>

  <div id="banner" class="banner"></div>

  <section class="hero">
    <div class="hero-card">
      <div class="section-title">
        <div>
          <h2>Mission Control</h2>
          <p>Guide visitors from scenario selection to measurable results in one pass.</p>
        </div>
        <div class="status-pill" id="heroStatus"><span class="status-dot"></span><span>Awaiting server handshake</span></div>
      </div>
      <div class="hero-grid">
        <div class="hero-metric">
          <div class="metric-label">Tasks</div>
          <div class="metric-value">4</div>
          <div class="metric-note">Easy to expert progression</div>
        </div>
        <div class="hero-metric">
          <div class="metric-label">Signals</div>
          <div class="metric-value">MITRE</div>
          <div class="metric-note">Evidence and mapping aware</div>
        </div>
        <div class="hero-metric">
          <div class="metric-label">Output</div>
          <div class="metric-value">Score</div>
          <div class="metric-note">Deterministic grading view</div>
        </div>
        <div class="hero-metric">
          <div class="metric-label">Mode</div>
          <div class="metric-value">Live</div>
          <div class="metric-note">Episode state updates in place</div>
        </div>
      </div>
    </div>

    <aside class="control-card">
      <div class="section-title">
        <div>
          <h2>Scenario Setup</h2>
          <p>Pick a threat pattern, seed the environment, and launch the baseline.</p>
        </div>
      </div>

      <div class="task-grid" id="taskPicker">
        <button class="task-card active" data-task="phishing" type="button">
          <strong>Phishing</strong>
          <span>Single alert triage with fast feedback.</span>
          <em>Easy</em>
        </button>
        <button class="task-card" data-task="lateral_movement" type="button">
          <strong>Lateral Movement</strong>
          <span>Investigate a multi-step intrusion chain.</span>
          <em>Medium</em>
        </button>
        <button class="task-card" data-task="queue_management" type="button">
          <strong>Queue Management</strong>
          <span>Find true positives hidden inside analyst noise.</span>
          <em>Hard</em>
        </button>
        <button class="task-card" data-task="insider_threat" type="button">
          <strong>Insider Threat</strong>
          <span>Handle the largest queue with mixed intent signals.</span>
          <em>Expert</em>
        </button>
      </div>

      <div class="field-grid">
        <div>
          <label for="task">Task</label>
          <select id="task">
            <option value="phishing">Phishing Triage</option>
            <option value="lateral_movement">Lateral Movement</option>
            <option value="queue_management">Queue Management</option>
            <option value="insider_threat">Insider Threat</option>
          </select>
        </div>
        <div>
          <label for="seed">Random Seed</label>
          <select id="seed">
            <option value="42">42</option>
            <option value="123">123</option>
            <option value="256">256</option>
            <option value="789">789</option>
            <option value="1024">1024</option>
          </select>
        </div>
      </div>

      <div class="button-row">
        <button class="btn btn-primary" onclick="doReset()">Start Episode</button>
        <button class="btn btn-secondary" id="runBtn" onclick="doBaseline()" disabled>Run Heuristic Agent</button>
      </div>
      <div class="hint">The UI keeps the original REST flow intact, so this remains a drop-in visual upgrade for the current Space.</div>
    </aside>
  </section>

  <section class="main-grid">
    <div class="stack">
      <div class="panel">
        <div class="panel-header">
          <div>
            <h3>Episode State</h3>
            <div class="panel-kicker">Track progress, reward accumulation, and queue coverage.</div>
          </div>
          <div class="inline-stats">
            <span class="mini-pill">Realtime snapshot</span>
            <span class="mini-pill">Seeded episode</span>
          </div>
        </div>
        <div id="estats"><div class="empty">Start an episode to reveal budget, classifications, and current reward.</div></div>
      </div>

      <div class="viz-grid">
        <div class="panel">
          <div class="panel-header">
            <div>
              <h3>Reward Trace</h3>
              <div class="panel-kicker">A quick visual read of positive and negative momentum.</div>
            </div>
          </div>
          <div id="rewardChart"><div class="empty">Run the baseline to populate a reward profile.</div></div>
        </div>

        <div class="panel">
          <div class="panel-header">
            <div>
              <h3>Chain View</h3>
              <div class="panel-kicker">Correlated alerts laid out as an investigation storyline.</div>
            </div>
          </div>
          <div id="killChain"><div class="empty">Multi-alert scenarios will render a linked chain here.</div></div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <div>
            <h3>Alert Queue</h3>
            <div class="panel-kicker">Every alert is promoted into a readable card with severity and classification state.</div>
          </div>
        </div>
        <div id="alertCards"><div class="empty">No active episode yet.</div></div>
      </div>
    </div>

    <div class="stack">
      <div class="panel">
        <div class="panel-header">
          <div>
            <h3>Grader Result</h3>
            <div class="panel-kicker">Final score, component breakdown, and natural-language feedback.</div>
          </div>
        </div>
        <div id="scorePanel"><div class="empty">Run the heuristic agent to see the evaluation breakdown.</div></div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <div>
            <h3>Investigation Log</h3>
            <div class="panel-kicker">A terminal-style activity feed for launches, grading, and status changes.</div>
          </div>
        </div>
        <div class="log" id="logBox"><div class="log-row"><span class="sys">Waiting for the environment to come online...</span></div></div>
      </div>
    </div>
  </section>
</div>

<script>
let stepRewards = [];
let alertData = [];

function qs(id){ return document.getElementById(id); }
function titleize(value){
  return (value || '').replace(/_/g,' ').replace(/\b\w/g, c => c.toUpperCase());
}
function esc(s){ const d=document.createElement('div');d.textContent=String(s);return d.innerHTML; }
function ts(){ return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }

function log(msg, cls){
  const kind = cls || 'sys';
  const el = qs('logBox');
  if (el.textContent.includes('Waiting for the environment')) {
    el.innerHTML = '';
  }
  el.innerHTML += `<div class="log-row"><span class="ts">[${ts()}]</span> <span class="${kind}">${esc(msg)}</span></div>`;
  el.scrollTop = el.scrollHeight;
}

function banner(msg, type){
  const kind = type || 'i';
  const el = qs('banner');
  el.textContent = msg;
  el.className = 'banner b' + kind;
  el.style.display = 'block';
  if (kind === 's') {
    setTimeout(() => { el.style.display = 'none'; }, 4500);
  }
}

function syncTaskCards(task){
  document.querySelectorAll('.task-card').forEach(card => {
    card.classList.toggle('active', card.dataset.task === task);
  });
  qs('task').value = task;
}

document.querySelectorAll('.task-card').forEach(card => {
  card.addEventListener('click', () => syncTaskCards(card.dataset.task));
});
qs('task').addEventListener('change', event => syncTaskCards(event.target.value));

function clsKey(value){
  const v = (value || 'unclassified').toLowerCase().replace(/ /g,'_');
  if (v === 'true_positive') return 'tp';
  if (v === 'false_positive') return 'fp';
  if (v === 'benign_true_positive') return 'btp';
  return 'unc';
}

function colorForScore(score){
  if (score >= 0.65) return 'var(--good)';
  if (score >= 0.35) return 'var(--warn)';
  return 'var(--bad)';
}

function renderRewardChart(rewards){
  if (!rewards || !rewards.length) return '<div class="empty">No reward data yet.</div>';
  const maxAbs = Math.max(0.01, ...rewards.map(r => Math.abs(r)));
  let html = '<div class="reward-chart">';
  rewards.forEach((reward, index) => {
    const pct = Math.max(10, Math.round(Math.abs(reward) / maxAbs * 100));
    const cls = reward >= 0 ? 'pos' : 'neg';
    const value = `${reward >= 0 ? '+' : ''}${reward.toFixed(3)}`;
    html += `<div class="reward-bar-wrap">
      <div class="reward-bar ${cls}" style="height:${pct}%" title="${value}"></div>
      <div class="reward-index">S${index + 1}</div>
    </div>`;
  });
  return html + '</div>';
}

function renderKillChain(alerts){
  if (!alerts || alerts.length <= 1) return '<div class="empty">A chain appears here when a scenario has correlated alerts.</div>';
  let html = '<div class="kc-chain">';
  alerts.forEach((alert, index) => {
    const key = clsKey(alert.classification);
    html += `<div class="kc-node ${key}">
      <strong>${(alert.title || 'Untitled Alert').substring(0, 28)}</strong>
      <span>${titleize(alert.classification || 'unclassified')}</span>
    </div>`;
    if (index < alerts.length - 1) html += '<div class="kc-arrow">&rarr;</div>';
  });
  return html + '</div>';
}

function renderAlertCards(alerts){
  if (!alerts || !alerts.length) return '<div class="empty">No alerts are visible for this episode.</div>';
  let html = '<div class="alert-cards">';
  alerts.forEach(alert => {
    const key = clsKey(alert.classification);
    const severity = (alert.severity || 'info').toLowerCase();
    html += `<div class="alert-card ${key}">
      <div class="ac-title">${alert.title || 'Untitled Alert'}</div>
      <div class="ac-meta">
        <span class="tag sev-${severity}">${severity.toUpperCase()}</span>
        <span class="tag">${titleize(alert.classification || 'unclassified')}</span>
        <span class="tag">${alert.source_system || 'Unknown Source'}</span>
      </div>
      <div class="ac-id">${alert.alert_id || 'no-alert-id'}</div>
    </div>`;
  });
  return html + '</div>';
}

function renderStats(state){
  if (!state) return '<div class="empty">Episode state unavailable.</div>';
  const progress = state.max_steps > 0 ? Math.round(state.step_count / state.max_steps * 100) : 0;
  const rewardClass = (state.cumulative_reward || 0) >= 0 ? 'var(--good)' : 'var(--bad)';
  const doneText = state.done ? 'Complete' : 'In Progress';
  return `<div class="stat-grid">
      <div class="stat-card">
        <strong>Task</strong>
        <span>${titleize(state.task_id || 'unknown')}</span>
        <small>Seed ${qs('seed').value}</small>
      </div>
      <div class="stat-card">
        <strong>Reward</strong>
        <span style="color:${rewardClass}">${(state.cumulative_reward || 0).toFixed(3)}</span>
        <small>Cumulative environment reward</small>
      </div>
      <div class="stat-card">
        <strong>Classified</strong>
        <span>${state.classified_count || 0} / ${state.alert_count || 0}</span>
        <small>Coverage across the visible queue</small>
      </div>
      <div class="stat-card">
        <strong>Status</strong>
        <span>${doneText}</span>
        <small>${state.done ? 'Episode budget exhausted or submitted' : 'Investigation still open'}</small>
      </div>
    </div>
    <div class="progress-shell">
      <div class="progress-top">
        <span>Step budget</span>
        <span>${state.step_count} / ${state.max_steps} steps used</span>
      </div>
      <div class="bar"><div class="bar-fill" style="width:${progress}%"></div></div>
    </div>`;
}

function renderScore(data){
  if (!data) return '<div class="empty">No grader data returned.</div>';
  const score = data.score || 0;
  const scoreColor = colorForScore(score);
  const breakdown = data.breakdown || {};
  let html = `<div class="score-shell">
    <div class="score-hero">
      <div class="score-value" style="color:${scoreColor}">${(score * 100).toFixed(1)}%</div>
      <div class="score-meta">${titleize(data.task_id || '')} | ${data.steps_used || 0} steps used</div>
    </div>`;
  if (Object.keys(breakdown).length) {
    html += '<div class="bk-grid">';
    Object.entries(breakdown).forEach(([key, value]) => {
      const pct = Math.round(value * 100);
      html += `<div class="bk-item">
        <strong>${titleize(key)}</strong>
        <span>${pct}%</span>
        <div class="bk-bar"><div class="bk-bar-fill" style="width:${pct}%;background:${colorForScore(value)}"></div></div>
      </div>`;
    });
    html += '</div>';
  }
  if (data.feedback) {
    html += `<div class="feedback">${data.feedback}</div>`;
  }
  return html + '</div>';
}

async function refreshState(){
  const response = await fetch('/state');
  const state = await response.json();
  qs('estats').innerHTML = renderStats(state);
  return state;
}

async function doReset(){
  const task = qs('task').value;
  const seed = parseInt(qs('seed').value, 10);
  stepRewards = [];
  qs('runBtn').disabled = true;
  qs('scorePanel').innerHTML = '<div class="empty">Run the heuristic agent to see the evaluation breakdown.</div>';
  qs('rewardChart').innerHTML = '<div class="empty">Run the baseline to populate a reward profile.</div>';
  qs('killChain').innerHTML = '<div class="empty">Multi-alert scenarios will render a linked chain here.</div>';
  qs('logBox').innerHTML = '';
  banner(`Starting ${titleize(task)} with seed ${seed}...`, 'i');
  log(`Launching episode for ${task} with seed ${seed}.`, 'act');

  try {
    const response = await fetch('/reset', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ task_id: task, seed: seed })
    });
    if (!response.ok) throw new Error(await response.text());
    const observation = await response.json();
    alertData = observation.alert_queue || [];
    qs('alertCards').innerHTML = renderAlertCards(alertData);
    qs('killChain').innerHTML = renderKillChain(alertData);
    const state = await refreshState();
    qs('runBtn').disabled = false;
    banner(`Episode ready. ${alertData.length} alerts loaded into the queue.`, 's');
    log(`Episode ready with ${alertData.length} alerts and a ${state.max_steps}-step budget.`, 'ok');
  } catch (error) {
    banner(`Error: ${error.message}`, 'e');
    log(error.message, 'err');
  }
}

async function doBaseline(){
  const task = qs('task').value;
  const seed = parseInt(qs('seed').value, 10);
  qs('runBtn').disabled = true;
  banner(`Running heuristic baseline on ${titleize(task)}...`, 'i');
  log(`Heuristic agent started on ${task}.`, 'act');
  stepRewards = [];

  try {
    const response = await fetch('/baseline', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ task_id: task, seed: seed })
    });
    if (!response.ok) throw new Error(await response.text());
    const result = await response.json();

    qs('scorePanel').innerHTML = renderScore(result);
    const breakdown = result.breakdown || {};
    stepRewards = Object.values(breakdown).map(value => value * 0.3);
    if (result.score) stepRewards.push(result.score);
    qs('rewardChart').innerHTML = renderRewardChart(stepRewards);

    const state = await refreshState();
    const alertResponse = await fetch('/api/alerts?limit=30');
    const alertPayload = await alertResponse.json();
    alertData = alertPayload.alerts || alertData;
    qs('alertCards').innerHTML = renderAlertCards(alertData);
    qs('killChain').innerHTML = renderKillChain(alertData);

    log(`Baseline finished in ${result.steps_used || 0} steps.`, 'ok');
    log(`Score: ${((result.score || 0) * 100).toFixed(1)}%.`, result.score >= 0.5 ? 'ok' : 'err');
    Object.entries(breakdown).forEach(([key, value]) => {
      log(`${titleize(key)}: ${(value * 100).toFixed(1)}%.`, 'sys');
    });
    if (result.feedback) log(`Feedback: ${result.feedback}`, 'sys');
    banner(`Agent complete. Final score ${((result.score || 0) * 100).toFixed(1)}%.`, result.score >= 0.5 ? 's' : 'i');
    log(`Queue now shows ${state.classified_count || 0} classified alerts.`, 'act');
  } catch (error) {
    banner(`Error: ${error.message}`, 'e');
    log(error.message, 'err');
    qs('runBtn').disabled = false;
  }
}

window.onload = async () => {
  syncTaskCards(qs('task').value);
  try {
    const response = await fetch('/health');
    const health = await response.json();
    qs('hb').innerHTML = `<strong>Status</strong> ${health.status}`;
    const heroStatus = qs('heroStatus');
    heroStatus.classList.add('online');
    heroStatus.innerHTML = '<span class="status-dot"></span><span>Server online and ready</span>';
    log(`Server online: ${health.env} v${health.version}.`, 'ok');
    log('Pick a scenario, start an episode, then run the heuristic agent.', 'sys');
  } catch (error) {
    log('Could not reach /health.', 'err');
  }
};
</script>
</body>
</html>"""
