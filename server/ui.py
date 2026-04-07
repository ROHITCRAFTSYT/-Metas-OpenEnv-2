"""SOC Triage Gym — Browser UI served at GET /ui"""

UI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Triage Gym — OpenEnv</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#080b14;color:#c9d1d9;font-family:'Segoe UI','Courier New',monospace;min-height:100vh}
header{background:linear-gradient(90deg,#0d1117 60%,#0f1923);border-bottom:1px solid #1b2838;padding:14px 28px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.logo{font-size:28px;filter:drop-shadow(0 0 6px #58a6ff55)}
h1{font-size:19px;color:#58a6ff;font-weight:700;letter-spacing:.5px}
.tagline{color:#6e7681;font-size:11px;margin-top:1px}
.badge{background:#1f6feb18;border:1px solid #1f6feb55;color:#58a6ff;font-size:10px;padding:2px 7px;border-radius:10px;margin-left:3px}
.hdr-right{margin-left:auto;display:flex;gap:6px;align-items:center}

.container{max-width:1320px;margin:0 auto;padding:18px 24px}
@media(max-width:900px){.container{padding:12px 10px}}

/* Responsive grid */
.grid-top{display:grid;grid-template-columns:270px 1fr;gap:16px;margin-bottom:16px}
@media(max-width:900px){.grid-top{grid-template-columns:1fr}}

.grid-mid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
@media(max-width:900px){.grid-mid{grid-template-columns:1fr}}

.panel{background:#0d1117;border:1px solid #1b2838;border-radius:8px;padding:16px;overflow:hidden}
.panel h3{color:#58a6ff;font-size:10px;text-transform:uppercase;letter-spacing:1.2px;margin-bottom:12px;border-bottom:1px solid #1b2838;padding-bottom:6px;display:flex;align-items:center;gap:6px}

label{color:#6e7681;font-size:11px;display:block;margin-bottom:3px;margin-top:8px}
label:first-of-type{margin-top:0}
select,input{width:100%;padding:7px 10px;border-radius:5px;font-family:inherit;font-size:12px;background:#161b22;border:1px solid #21262d;color:#c9d1d9;margin-bottom:2px;transition:border .2s}
select:focus,input:focus{outline:none;border-color:#58a6ff}
.btn{width:100%;padding:8px 12px;border-radius:5px;font-family:inherit;font-size:12px;cursor:pointer;font-weight:600;margin-top:8px;border:none;transition:all .15s}
.btn-primary{background:linear-gradient(135deg,#1f6feb,#388bfd);color:#fff;box-shadow:0 2px 8px #1f6feb33}
.btn-primary:hover{background:linear-gradient(135deg,#388bfd,#58a6ff);box-shadow:0 4px 14px #1f6feb55}
.btn-primary:disabled{background:#21262d;color:#484f58;cursor:not-allowed;box-shadow:none}
.btn-secondary{background:transparent;border:1px solid #21262d;color:#8b949e;margin-top:5px}
.btn-secondary:hover{border-color:#58a6ff;color:#58a6ff}
.btn-secondary:disabled{opacity:.35;cursor:not-allowed}

/* Stats */
.stat{display:flex;justify-content:space-between;margin-bottom:6px;font-size:11px}
.sl{color:#6e7681}.sv{color:#c9d1d9;font-weight:600}
.sv.g{color:#3fb950}.sv.r{color:#f85149}.sv.a{color:#d29922}
.bar{background:#161b22;border-radius:3px;height:5px;margin:5px 0}
.bar-fill{height:100%;border-radius:3px;background:linear-gradient(90deg,#1f6feb,#3fb950);transition:width .4s}

/* Score */
.big-score{text-align:center;padding:8px 0 14px}
.big-score .num{font-size:48px;font-weight:800;letter-spacing:-1px}
.big-score .sub{color:#6e7681;font-size:11px}
.bk-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px}
.bk-item{background:#161b22;border-radius:6px;padding:10px}
.bk-label{color:#6e7681;font-size:9px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:2px}
.bk-val{color:#c9d1d9;font-size:18px;font-weight:700}
.bk-bar{background:#21262d;border-radius:2px;height:3px;margin-top:4px}
.bk-bar-fill{height:100%;border-radius:2px;transition:width .4s}
.feedback{background:#161b22;border-radius:5px;padding:8px 10px;font-size:10px;color:#6e7681;line-height:1.5;margin-top:8px}

/* Reward chart */
.reward-chart{display:flex;align-items:flex-end;gap:2px;height:60px;padding:4px 0}
.reward-bar{flex:1;min-width:3px;max-width:18px;border-radius:2px 2px 0 0;transition:height .3s}
.reward-bar.pos{background:linear-gradient(0deg,#238636,#3fb950)}
.reward-bar.neg{background:linear-gradient(0deg,#f85149,#da3633);border-radius:0 0 2px 2px;align-self:flex-start}

/* Kill chain vis */
.kc-chain{display:flex;align-items:center;gap:0;overflow-x:auto;padding:6px 0}
.kc-node{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:6px 10px;font-size:10px;text-align:center;min-width:80px;white-space:nowrap;position:relative}
.kc-node.tp{border-color:#f85149;background:#f8514910;color:#f85149}
.kc-node.fp{border-color:#3fb950;background:#3fb95010;color:#3fb950}
.kc-node.btp{border-color:#d29922;background:#d2992210;color:#d29922}
.kc-node.unc{border-color:#30363d;color:#6e7681}
.kc-arrow{color:#30363d;font-size:16px;padding:0 2px;flex-shrink:0}

/* Alert cards */
.alert-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px}
.alert-card{background:#161b22;border-radius:6px;padding:10px 12px;border-left:3px solid #30363d;transition:transform .1s}
.alert-card:hover{transform:translateY(-1px)}
.alert-card.tp{border-left-color:#f85149}
.alert-card.fp{border-left-color:#3fb950}
.alert-card.btp{border-left-color:#d29922}
.alert-card.unc{border-left-color:#484f58}
.ac-title{font-size:12px;font-weight:600;margin-bottom:4px;color:#c9d1d9}
.ac-meta{font-size:10px;color:#6e7681;display:flex;gap:10px;flex-wrap:wrap}
.ac-sev{font-weight:700;text-transform:uppercase}
.sev-critical{color:#f85149}.sev-high{color:#ff7b72}.sev-medium{color:#d29922}.sev-low{color:#58a6ff}.sev-info{color:#6e7681}
.ac-cls{font-weight:600}
.cls-tp{color:#f85149}.cls-fp{color:#3fb950}.cls-btp{color:#d29922}.cls-unc{color:#484f58}
.ac-id{font-size:9px;color:#484f58;font-family:monospace}

/* Log */
.log{background:#050810;border:1px solid #1b2838;border-radius:5px;padding:10px;font-size:10px;height:170px;overflow-y:auto;line-height:1.65}
.log .ts{color:#484f58}.log .act{color:#58a6ff}.log .ok{color:#3fb950}.log .err{color:#f85149}.log .sys{color:#6e7681}

/* Banner */
.banner{padding:8px 12px;border-radius:5px;margin-bottom:14px;font-size:11px;display:none}
.bi{background:#1f6feb18;border:1px solid #1f6feb55;color:#58a6ff}
.bs{background:#3fb95018;border:1px solid #3fb95055;color:#3fb950}
.be{background:#f8514918;border:1px solid #f8514955;color:#f85149}

.empty{text-align:center;color:#484f58;padding:24px;font-size:12px}
</style>
</head>
<body>
<header>
  <div class="logo">&#x1f6e1;&#xfe0f;</div>
  <div>
    <h1>SOC Triage Gym</h1>
    <div class="tagline">Security Operations Center &mdash; OpenEnv RL Environment</div>
  </div>
  <div class="hdr-right">
    <span class="badge">OpenEnv</span>
    <span class="badge">v0.1.0</span>
    <span id="hb" class="badge" style="color:#484f58">&#x25cf; offline</span>
  </div>
</header>

<div class="container">
  <div id="banner" class="banner"></div>

  <div class="grid-top">
    <!-- LEFT: controls + stats -->
    <div>
      <div class="panel" style="margin-bottom:12px">
        <h3>&#x1f3af; Configuration</h3>
        <label>Task</label>
        <select id="task">
          <option value="phishing">Phishing Triage (Easy)</option>
          <option value="lateral_movement">Lateral Movement (Medium)</option>
          <option value="queue_management">Queue Management (Hard)</option>
        </select>
        <label>Random Seed</label>
        <select id="seed">
          <option value="42">42 (default)</option>
          <option value="123">123</option>
          <option value="256">256</option>
          <option value="789">789</option>
          <option value="1024">1024</option>
        </select>
        <button class="btn btn-primary" onclick="doReset()">&#x25b6; Start Episode</button>
        <button class="btn btn-secondary" id="runBtn" onclick="doBaseline()" disabled>&#x1f916; Run Heuristic Agent</button>
      </div>
      <div class="panel">
        <h3>&#x1f4ca; Episode State</h3>
        <div id="estats"><div class="empty">Start an episode to see state</div></div>
      </div>
    </div>

    <!-- RIGHT: score + grader breakdown -->
    <div class="panel">
      <h3>&#x1f3c6; Score &amp; Grader Breakdown</h3>
      <div id="scorePanel"><div class="empty">Run the agent to see scores</div></div>
    </div>
  </div>

  <!-- Reward chart + Kill chain -->
  <div class="grid-mid">
    <div class="panel">
      <h3>&#x1f4c8; Step Rewards</h3>
      <div id="rewardChart"><div class="empty">No rewards yet</div></div>
    </div>
    <div class="panel">
      <h3>&#x1f517; Kill Chain / Alert Connections</h3>
      <div id="killChain"><div class="empty">Run investigation to see connections</div></div>
    </div>
  </div>

  <!-- Alert cards -->
  <div class="panel" style="margin-bottom:14px">
    <h3>&#x1f6a8; Alert Queue</h3>
    <div id="alertCards"><div class="empty">No active episode</div></div>
  </div>

  <!-- Log -->
  <div class="panel">
    <h3>&#x1f4dd; Investigation Log</h3>
    <div class="log" id="logBox">
      <span class="sys">// Waiting to start...</span>
    </div>
  </div>
</div>

<script>
/* ---- state ---- */
let stepRewards = [];
let alertData = [];

function ts(){return new Date().toLocaleTimeString();}

function log(msg,cls){
  cls=cls||'sys';
  const el=document.getElementById('logBox');
  if(el.querySelector('.sys')&&el.textContent.includes('Waiting'))el.innerHTML='';
  el.innerHTML+=`<div><span class="ts">[${ts()}]</span> <span class="${cls}">${msg}</span></div>`;
  el.scrollTop=el.scrollHeight;
}

function banner(msg,type){
  type=type||'i';
  const el=document.getElementById('banner');
  el.textContent=msg;el.className='banner b'+type;el.style.display='block';
  if(type==='s')setTimeout(()=>el.style.display='none',5000);
}

/* ---- Reward chart (CSS bars) ---- */
function renderRewardChart(rewards){
  if(!rewards||!rewards.length)return '<div class="empty">No rewards yet</div>';
  const maxAbs=Math.max(0.01,...rewards.map(r=>Math.abs(r)));
  let h='<div class="reward-chart">';
  for(const r of rewards){
    const pct=Math.round(Math.abs(r)/maxAbs*100);
    const cls=r>=0?'pos':'neg';
    const title='reward: '+(r>=0?'+':'')+r.toFixed(3);
    h+=`<div class="reward-bar ${cls}" style="height:${Math.max(4,pct)}%" title="${title}"></div>`;
  }
  return h+'</div>';
}

/* ---- Kill chain / connections vis ---- */
function renderKillChain(alerts){
  if(!alerts||alerts.length<=1)return '<div class="empty">Single alert or no data</div>';
  let h='<div class="kc-chain">';
  for(let i=0;i<alerts.length;i++){
    const a=alerts[i];
    const c=clsKey(a.classification);
    const label=(a.title||'').substring(0,22);
    h+=`<div class="kc-node ${c}" title="${a.alert_id}">${label}</div>`;
    if(i<alerts.length-1)h+='<div class="kc-arrow">&#x2192;</div>';
  }
  return h+'</div>';
}

/* ---- Alert cards ---- */
function clsKey(c){
  c=(c||'unclassified').toLowerCase().replace(/ /g,'_');
  if(c==='true_positive')return'tp';
  if(c==='false_positive')return'fp';
  if(c==='benign_true_positive')return'btp';
  return'unc';
}

function renderAlertCards(alerts){
  if(!alerts||!alerts.length)return '<div class="empty">No alerts</div>';
  let h='<div class="alert-cards">';
  for(const a of alerts){
    const ck=clsKey(a.classification);
    const sev=(a.severity||'info').toLowerCase();
    const clsLabel=(a.classification||'unclassified').replace(/_/g,' ');
    h+=`<div class="alert-card ${ck}">
      <div class="ac-title">${a.title||'—'}</div>
      <div class="ac-meta">
        <span class="ac-sev sev-${sev}">${sev}</span>
        <span class="ac-cls cls-${ck}">${clsLabel}</span>
        <span>${a.source_system||''}</span>
      </div>
      <div class="ac-id">${a.alert_id||''}</div>
    </div>`;
  }
  return h+'</div>';
}

/* ---- Stats ---- */
function renderStats(s){
  if(!s)return'';
  const pct=s.max_steps>0?Math.round(s.step_count/s.max_steps*100):0;
  const rc=s.cumulative_reward>=0?'g':'r';
  return`
    <div class="stat"><span class="sl">Task</span><span class="sv">${s.task_id||'—'}</span></div>
    <div class="stat"><span class="sl">Steps</span><span class="sv">${s.step_count} / ${s.max_steps}</span></div>
    <div class="bar"><div class="bar-fill" style="width:${pct}%"></div></div>
    <div class="stat"><span class="sl">Reward</span><span class="sv ${rc}">${(s.cumulative_reward||0).toFixed(3)}</span></div>
    <div class="stat"><span class="sl">Classified</span><span class="sv">${s.classified_count||0} / ${s.alert_count||0}</span></div>
    <div class="stat"><span class="sl">Done</span><span class="sv ${s.done?'g':'a'}">${s.done?'Yes':'In Progress'}</span></div>`;
}

/* ---- Score ---- */
function renderScore(data){
  if(!data)return'';
  const sc=data.score||0;
  const col=sc>=0.65?'#3fb950':sc>=0.35?'#d29922':'#f85149';
  const bd=data.breakdown||{};
  let bkHtml='';
  if(Object.keys(bd).length){
    bkHtml='<div class="bk-grid">';
    for(const[k,v]of Object.entries(bd)){
      const pct=Math.round(v*100);
      const lbl=k.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
      const barCol=pct>=65?'#3fb950':pct>=35?'#d29922':'#f85149';
      bkHtml+=`<div class="bk-item">
        <div class="bk-label">${lbl}</div>
        <div class="bk-val">${pct}<span style="font-size:11px;color:#6e7681">%</span></div>
        <div class="bk-bar"><div class="bk-bar-fill" style="width:${pct}%;background:${barCol}"></div></div>
      </div>`;
    }
    bkHtml+='</div>';
  }
  const fb=data.feedback?`<div class="feedback">${data.feedback}</div>`:'';
  return`<div class="big-score">
    <div class="num" style="color:${col}">${(sc*100).toFixed(1)}<span style="font-size:16px;color:#6e7681">%</span></div>
    <div class="sub">Final Score &mdash; ${data.task_id||''} &middot; ${data.steps_used||0} steps</div>
  </div>${bkHtml}${fb}`;
}

/* ---- Actions ---- */
async function doReset(){
  const task=document.getElementById('task').value;
  const seed=parseInt(document.getElementById('seed').value);
  stepRewards=[];
  document.getElementById('logBox').innerHTML='';
  document.getElementById('scorePanel').innerHTML='<div class="empty">Run the agent to see scores</div>';
  document.getElementById('rewardChart').innerHTML='<div class="empty">No rewards yet</div>';
  document.getElementById('killChain').innerHTML='<div class="empty">Run investigation to see connections</div>';
  banner('Starting episode: '+task+' (seed='+seed+')...','i');
  log('Starting episode — task='+task+' seed='+seed,'act');
  try{
    const r=await fetch('/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({task_id:task,seed:seed})});
    if(!r.ok)throw new Error(await r.text());
    const obs=await r.json();
    alertData=obs.alert_queue||[];
    document.getElementById('alertCards').innerHTML=renderAlertCards(alertData);
    document.getElementById('killChain').innerHTML=renderKillChain(alertData);
    const sr=await fetch('/state');const st=await sr.json();
    document.getElementById('estats').innerHTML=renderStats(st);
    log('Episode ready — '+alertData.length+' alerts, '+st.max_steps+' step budget','ok');
    document.getElementById('runBtn').disabled=false;
    banner('Episode started! '+alertData.length+' alerts in queue.','s');
  }catch(e){banner('Error: '+e.message,'e');log(e.message,'err');}
}

async function doBaseline(){
  const task=document.getElementById('task').value;
  const seed=parseInt(document.getElementById('seed').value);
  document.getElementById('runBtn').disabled=true;
  banner('Running heuristic agent...','i');
  log('Heuristic agent starting investigation...','act');
  stepRewards=[];
  try{
    const r=await fetch('/baseline',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({task_id:task,seed:seed})});
    if(!r.ok)throw new Error(await r.text());
    const res=await r.json();
    log('Agent finished — '+res.steps_used+' steps used','act');
    log('Score: '+((res.score||0)*100).toFixed(1)+'%',res.score>=0.5?'ok':'err');
    if(res.breakdown){
      for(const[k,v]of Object.entries(res.breakdown)){
        log('  '+k.replace(/_/g,' ')+': '+(v*100).toFixed(1)+'%','sys');
      }
    }
    if(res.feedback)log('Feedback: '+res.feedback,'sys');
    document.getElementById('scorePanel').innerHTML=renderScore(res);

    /* Fake step rewards from breakdown for chart (we don't have per-step data from /baseline) */
    const bd=res.breakdown||{};
    stepRewards=Object.values(bd).map(v=>v*0.3);
    if(res.score)stepRewards.push(res.score);
    document.getElementById('rewardChart').innerHTML=renderRewardChart(stepRewards);

    const sr=await fetch('/state');const st=await sr.json();
    document.getElementById('estats').innerHTML=renderStats(st);
    const ar=await fetch('/api/alerts?limit=30');const ad=await ar.json();
    alertData=ad.alerts||[];
    document.getElementById('alertCards').innerHTML=renderAlertCards(alertData);
    document.getElementById('killChain').innerHTML=renderKillChain(alertData);
    banner('Agent complete! Score: '+((res.score||0)*100).toFixed(1)+'%',res.score>=0.5?'s':'i');
  }catch(e){banner('Error: '+e.message,'e');log(e.message,'err');document.getElementById('runBtn').disabled=false;}
}

window.onload=async()=>{
  try{
    const r=await fetch('/health');const h=await r.json();
    document.getElementById('hb').innerHTML='&#x25cf; '+h.status;
    document.getElementById('hb').style.color='#3fb950';
    log('Server online — '+h.env+' v'+h.version,'ok');
    log('Select a task and click "Start Episode" to begin','sys');
  }catch(e){log('Cannot reach server','err');}
};
</script>
</body>
</html>"""
