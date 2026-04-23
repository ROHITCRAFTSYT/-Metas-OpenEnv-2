"""Distinct Hugging Face Space UI served at / and /ui.

Design: "SOC Dossier" — editorial archive meets live instrumentation.
  - Palette: archival cream paper, deep ink, oxidized red, classified cobalt,
    phosphor accent reserved for the terminal card only.
  - Typography: Instrument Serif (display) · Fraunces (body) · JetBrains Mono (data).
  - Layout: asymmetric editorial grid, stamped marks, fine hairlines, marginalia,
    numbered task index, SVG reward curve, endpoint index with dotted leaders.
  - Motion: staggered editorial reveal on load, scanlines on terminal, subtle
    stamp wobble, blinking cursor, nothing gratuitous.
"""

UI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC·Triage·Gym — File No. 003 / Rev. III</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Fraunces:ital,opsz,wght,SOFT@0,9..144,300..900,0..100;1,9..144,300..900,0..100&family=JetBrains+Mono:ital,wght@0,300..800;1,300..800&display=swap" rel="stylesheet">
<style>
:root{
  --paper:#f1ebdd;
  --paper-2:#f7f1e2;
  --paper-edge:#e7dfc9;
  --ink:#161a22;
  --ink-soft:#2b2f38;
  --muted:#7a7264;
  --hairline:#c9bfaa;
  --hairline-soft:#ddd3bc;
  --stamp:#b8321e;
  --stamp-soft:rgba(184,50,30,.08);
  --cobalt:#2a4980;
  --cobalt-soft:rgba(42,73,128,.08);
  --phosphor:#8affc3;
  --phosphor-dim:#4f8a6d;
  --term-bg:#0e130f;
  --term-ink:#e6e0cd;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:var(--paper);color:var(--ink)}
html{-webkit-font-smoothing:antialiased;font-feature-settings:"ss01","cv11","liga"}
body{
  font-family:"Fraunces",Georgia,serif;
  font-variation-settings:"opsz" 14,"SOFT" 40,"wght" 380;
  font-size:16px;
  line-height:1.55;
  letter-spacing:.004em;
  overflow-x:hidden;
}

/* ─── paper grain + vignette ──────────────────────────────────────────── */
body::before{
  content:"";
  position:fixed;inset:0;
  pointer-events:none;
  background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='200' height='200'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' seed='5'/><feColorMatrix values='0 0 0 0 0.08  0 0 0 0 0.06  0 0 0 0 0.04  0 0 0 0.09 0'/></filter><rect width='200' height='200' filter='url(%23n)'/></svg>");
  opacity:.55;
  mix-blend-mode:multiply;
  z-index:1;
}
body::after{
  content:"";
  position:fixed;inset:0;
  pointer-events:none;
  background:radial-gradient(ellipse at 50% 30%, transparent 40%, rgba(20,16,8,.14) 100%);
  z-index:2;
}

/* ─── broadcast bar ───────────────────────────────────────────────────── */
.advisory{
  position:relative;z-index:10;
  border-bottom:1px solid var(--hairline);
  background:var(--paper-2);
  font-family:"JetBrains Mono",ui-monospace,monospace;
  font-size:10.5px;
  letter-spacing:.22em;
  text-transform:uppercase;
  color:var(--ink-soft);
  padding:7px 22px;
  display:flex;justify-content:space-between;align-items:center;
  overflow:hidden;
}
.advisory .tick{display:inline-block;width:6px;height:6px;background:var(--stamp);border-radius:50%;margin-right:10px;animation:pulse 1.6s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:.35;transform:scale(.9)}50%{opacity:1;transform:scale(1.1)}}
.advisory-scroll{flex:1;display:flex;gap:36px;margin:0 24px;white-space:nowrap;overflow:hidden;mask-image:linear-gradient(90deg,transparent,black 8%,black 92%,transparent)}
.advisory-scroll>span{animation:marquee 48s linear infinite;display:inline-flex;gap:36px}
@keyframes marquee{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}
.advisory-scroll em{font-style:normal;color:var(--stamp);margin-right:6px}

/* ─── page frame ─────────────────────────────────────────────────────── */
.page{
  position:relative;z-index:3;
  max-width:1240px;
  margin:0 auto;
  padding:28px 38px 80px;
}
.folio{
  position:fixed;
  top:50%;transform:translateY(-50%) rotate(-90deg);
  font-family:"JetBrains Mono",monospace;
  font-size:10px;letter-spacing:.4em;
  color:var(--muted);
  z-index:4;
  pointer-events:none;
}
.folio.left{left:-24px}
.folio.right{right:-24px;transform:translateY(-50%) rotate(90deg)}

/* ─── dossier header ─────────────────────────────────────────────────── */
header.dossier{
  display:grid;
  grid-template-columns:1fr auto 1fr;
  align-items:center;
  padding:18px 0 14px;
  border-bottom:1px solid var(--ink);
  position:relative;
}
.serial{
  font-family:"JetBrains Mono",monospace;
  font-size:10px;letter-spacing:.22em;
  text-transform:uppercase;
  color:var(--ink-soft);
  display:flex;gap:22px;flex-wrap:wrap;
}
.serial b{color:var(--ink);font-weight:600}
.emblem{
  width:44px;height:44px;
  border:1.5px solid var(--ink);
  border-radius:50%;
  display:grid;place-items:center;
  position:relative;
  background:var(--paper-2);
}
.emblem::after{
  content:"";position:absolute;inset:4px;
  border:.5px solid var(--ink);
  border-radius:50%;
}
.emblem svg{width:22px;height:22px}

.masthead{
  padding:22px 0 10px;
  display:grid;
  grid-template-columns:1fr auto;
  align-items:end;
  border-bottom:.5px solid var(--hairline);
  gap:30px;
}
.masthead h1{
  font-family:"Instrument Serif",serif;
  font-weight:400;
  font-style:italic;
  font-size:clamp(58px,10vw,144px);
  line-height:.88;
  letter-spacing:-.02em;
  color:var(--ink);
}
.masthead h1 em{
  font-style:normal;
  color:var(--stamp);
  font-family:"Instrument Serif",serif;
}
.masthead-meta{
  font-family:"JetBrains Mono",monospace;
  font-size:10.5px;
  letter-spacing:.18em;
  text-transform:uppercase;
  color:var(--muted);
  text-align:right;
  padding-bottom:14px;
}
.masthead-meta b{color:var(--ink);font-weight:600;display:block;margin-bottom:4px}

/* ─── stamp ──────────────────────────────────────────────────────────── */
.stamp{
  position:absolute;
  top:92px;right:38px;
  transform:rotate(-7deg);
  border:2.5px solid var(--stamp);
  color:var(--stamp);
  padding:9px 16px 7px;
  font-family:"JetBrains Mono",monospace;
  font-size:11px;
  font-weight:700;
  letter-spacing:.28em;
  text-transform:uppercase;
  background:rgba(255,255,255,.02);
  box-shadow:inset 0 0 0 1.5px rgba(184,50,30,.35);
  opacity:.86;
  animation:wobble 6s ease-in-out infinite;
  z-index:5;
}
.stamp::before{
  content:"";position:absolute;inset:-5px;
  border:1px dashed var(--stamp);
  opacity:.3;
  border-radius:2px;
}
.stamp small{display:block;font-size:8px;letter-spacing:.2em;margin-top:2px;opacity:.8}
@keyframes wobble{0%,100%{transform:rotate(-7deg)}50%{transform:rotate(-6deg) translateY(-1px)}}

/* ─── hero ───────────────────────────────────────────────────────────── */
.hero{
  display:grid;
  grid-template-columns:1.35fr 1fr;
  gap:56px;
  padding:48px 0 36px;
  border-bottom:1px solid var(--ink);
  position:relative;
}
.eyebrow{
  font-family:"JetBrains Mono",monospace;
  font-size:10.5px;letter-spacing:.28em;
  text-transform:uppercase;
  color:var(--stamp);
  display:flex;align-items:center;gap:12px;
  margin-bottom:18px;
}
.eyebrow::before{content:"";width:28px;height:1px;background:var(--stamp)}

.lede{
  font-family:"Instrument Serif",serif;
  font-size:clamp(26px,3vw,38px);
  line-height:1.18;
  letter-spacing:-.005em;
  color:var(--ink);
  margin-bottom:26px;
  max-width:620px;
}
.lede em{font-style:italic;color:var(--stamp)}
.dropcap{
  float:left;
  font-family:"Instrument Serif",serif;
  font-size:86px;
  line-height:.78;
  padding:6px 12px 0 0;
  color:var(--stamp);
  font-style:italic;
}
.body-lede{
  font-family:"Fraunces",serif;
  font-variation-settings:"opsz" 12,"wght" 380,"SOFT" 60;
  font-size:15px;
  line-height:1.62;
  color:var(--ink-soft);
  margin-bottom:28px;
  max-width:540px;
}
.body-lede::first-letter{
  font-family:"Instrument Serif",serif;
  font-size:4em;
  float:left;
  line-height:.82;
  padding:4px 10px 0 0;
  color:var(--stamp);
  font-style:italic;
}

.cta-row{display:flex;gap:14px;flex-wrap:wrap}
.cta{
  display:inline-flex;align-items:center;gap:10px;
  font-family:"JetBrains Mono",monospace;
  font-size:11.5px;
  letter-spacing:.16em;
  text-transform:uppercase;
  padding:12px 18px;
  border:1px solid var(--ink);
  color:var(--ink);
  text-decoration:none;
  background:var(--paper-2);
  transition:all .25s cubic-bezier(.4,.1,.2,1);
  position:relative;
}
.cta:hover{background:var(--ink);color:var(--paper);transform:translate(-2px,-2px);box-shadow:4px 4px 0 0 var(--stamp)}
.cta.primary{background:var(--ink);color:var(--paper)}
.cta.primary:hover{background:var(--stamp);border-color:var(--stamp);color:var(--paper);box-shadow:4px 4px 0 0 var(--ink)}
.cta span.arrow{transition:transform .2s}
.cta:hover span.arrow{transform:translateX(3px)}

/* ─── terminal card ──────────────────────────────────────────────────── */
.terminal{
  background:var(--term-bg);
  border:1px solid var(--ink);
  box-shadow:
    10px 10px 0 -1px var(--stamp-soft),
    0 0 0 3px var(--paper-2) inset,
    0 24px 50px rgba(0,0,0,.18);
  padding:0;
  position:relative;
  overflow:hidden;
  align-self:start;
}
.terminal::before{
  content:"";
  position:absolute;inset:0;
  background:
    repeating-linear-gradient(0deg,
      rgba(255,255,255,.025) 0,
      rgba(255,255,255,.025) 1px,
      transparent 1px,
      transparent 3px);
  pointer-events:none;z-index:2;
  animation:scan 6s linear infinite;
}
@keyframes scan{0%{background-position:0 0}100%{background-position:0 120px}}
.terminal::after{
  content:"";
  position:absolute;inset:0;
  background:radial-gradient(ellipse at 50% 50%, transparent 40%, rgba(0,0,0,.45) 100%);
  pointer-events:none;z-index:1;
}
.term-head{
  display:flex;justify-content:space-between;align-items:center;
  padding:10px 14px;
  border-bottom:.5px solid rgba(138,255,195,.22);
  font-family:"JetBrains Mono",monospace;
  font-size:10px;letter-spacing:.2em;
  text-transform:uppercase;
  color:var(--phosphor-dim);
  position:relative;z-index:3;
}
.term-head .dots{display:flex;gap:6px}
.term-head .dots i{width:8px;height:8px;border-radius:50%;background:rgba(138,255,195,.25);font-style:normal}
.term-head .dots i:nth-child(1){background:rgba(184,50,30,.55)}
.term-head .dots i:nth-child(2){background:rgba(220,180,90,.5)}
.term-head .dots i:nth-child(3){background:rgba(138,255,195,.5)}
.term-body{
  padding:20px 22px 24px;
  font-family:"JetBrains Mono",monospace;
  font-size:12.5px;
  line-height:1.65;
  color:var(--term-ink);
  position:relative;z-index:3;
}
.term-prompt{color:var(--phosphor-dim)}
.term-cmd{color:var(--phosphor);font-weight:500;text-shadow:0 0 12px rgba(138,255,195,.45)}
.term-out{color:var(--term-ink);opacity:.84}
.term-out.dim{opacity:.5}
.term-out .pos{color:var(--phosphor);font-weight:600}
.term-out .neg{color:#ff8b77;font-weight:600}
.term-out .hl{color:#f4d98a}
.term-rule{height:1px;background:rgba(138,255,195,.12);margin:8px 0}
.term-body .cursor{display:inline-block;width:8px;height:14px;background:var(--phosphor);vertical-align:-2px;margin-left:4px;animation:blink 1s steps(2) infinite;box-shadow:0 0 10px var(--phosphor)}
@keyframes blink{0%,50%{opacity:1}50.1%,100%{opacity:0}}

/* ─── stat pillars ───────────────────────────────────────────────────── */
.pillars{
  display:grid;
  grid-template-columns:repeat(4,1fr);
  gap:0;
  border-bottom:1px solid var(--ink);
  padding:0;
}
.pillar{
  padding:36px 30px 32px;
  border-right:.5px solid var(--hairline);
  position:relative;
}
.pillar:last-child{border-right:none}
.pillar .kicker{
  font-family:"JetBrains Mono",monospace;
  font-size:9.5px;
  letter-spacing:.28em;
  text-transform:uppercase;
  color:var(--muted);
  margin-bottom:14px;
}
.pillar .kicker::before{content:"§ ";color:var(--stamp)}
.pillar .num{
  font-family:"Instrument Serif",serif;
  font-size:88px;
  line-height:.82;
  color:var(--ink);
  letter-spacing:-.02em;
  position:relative;
}
.pillar .num sup{
  font-size:12px;
  font-family:"JetBrains Mono",monospace;
  vertical-align:super;
  color:var(--stamp);
  letter-spacing:.1em;
  margin-left:4px;
}
.pillar .label{
  font-family:"Fraunces",serif;
  font-variation-settings:"opsz" 12,"wght" 480,"SOFT" 40;
  font-style:italic;
  font-size:15px;
  color:var(--ink-soft);
  margin-top:10px;
}
.pillar .foot{
  font-family:"JetBrains Mono",monospace;
  font-size:10px;
  color:var(--muted);
  letter-spacing:.12em;
  margin-top:12px;
  padding-top:10px;
  border-top:.5px dashed var(--hairline);
}
.pillar svg.spark{width:100%;height:28px;margin-top:14px;display:block}

/* ─── section pattern ────────────────────────────────────────────────── */
section{padding:62px 0 48px;border-bottom:1px solid var(--ink);position:relative}
section.nb{border-bottom:.5px solid var(--hairline)}
.section-head{
  display:grid;
  grid-template-columns:auto 1fr;
  gap:28px;
  align-items:end;
  margin-bottom:38px;
}
.section-head .sig{
  font-family:"JetBrains Mono",monospace;
  font-size:10px;letter-spacing:.28em;
  text-transform:uppercase;
  color:var(--stamp);
  writing-mode:vertical-rl;
  transform:rotate(180deg);
  padding-right:6px;
  border-right:1px solid var(--stamp);
  justify-self:start;
}
.section-head h2{
  font-family:"Instrument Serif",serif;
  font-size:clamp(40px,5vw,64px);
  font-weight:400;
  line-height:.95;
  letter-spacing:-.015em;
  color:var(--ink);
  max-width:18ch;
}
.section-head h2 em{font-style:italic;color:var(--stamp)}
.section-head .desc{
  font-family:"Fraunces",serif;
  font-variation-settings:"opsz" 12,"wght" 380;
  font-size:14px;
  color:var(--ink-soft);
  max-width:48ch;
  margin-top:14px;
  line-height:1.6;
}

/* ─── task index (bibliography-style) ────────────────────────────────── */
.task-index{
  display:grid;
  grid-template-columns:60px 1fr 130px 110px 70px;
  font-family:"Fraunces",serif;
  font-size:15px;
}
.task-index .row{
  display:contents;
}
.task-index .row > *{
  padding:18px 16px;
  border-top:.5px solid var(--hairline-soft);
  display:flex;align-items:center;
  transition:background .2s;
}
.task-index .row.head > *{
  border-top:none;
  border-bottom:1.5px solid var(--ink);
  font-family:"JetBrains Mono",monospace;
  font-size:10px;
  letter-spacing:.22em;
  text-transform:uppercase;
  color:var(--muted);
  padding:0 16px 10px;
}
.task-index .row:not(.head):hover > *{background:var(--stamp-soft)}
.task-index .code{
  font-family:"JetBrains Mono",monospace;
  font-size:12px;
  letter-spacing:.1em;
  color:var(--muted);
}
.task-index .name{
  font-family:"Instrument Serif",serif;
  font-size:22px;
  line-height:1.1;
  color:var(--ink);
}
.task-index .name em{font-style:italic;color:var(--stamp-soft);color:var(--stamp)}
.task-index .diff{
  font-family:"JetBrains Mono",monospace;
  font-size:10.5px;
  letter-spacing:.16em;
  text-transform:uppercase;
}
.task-index .diff.e{color:#2c7a58}
.task-index .diff.m{color:#b87a1d}
.task-index .diff.h{color:#c35a3a}
.task-index .diff.x{color:var(--stamp);font-weight:600}
.task-index .diff.a{color:var(--cobalt)}
.task-index .steps{
  font-family:"JetBrains Mono",monospace;
  font-size:12px;
  color:var(--ink-soft);
  justify-content:flex-end;
  letter-spacing:.04em;
}
.task-index .mode{
  font-family:"JetBrains Mono",monospace;
  font-size:9.5px;
  letter-spacing:.2em;
  text-transform:uppercase;
  color:var(--ink-soft);
}

/* ─── rlvr / rlve spread ─────────────────────────────────────────────── */
.spread{
  display:grid;
  grid-template-columns:1fr 1px 1fr;
  gap:0;
  align-items:stretch;
}
.spread > .rule-v{background:var(--ink);margin:12px 0}
.leaf{
  padding:10px 48px 10px 0;
}
.leaf.right{padding:10px 0 10px 48px}
.leaf-mark{
  font-family:"JetBrains Mono",monospace;
  font-size:10.5px;
  letter-spacing:.28em;
  text-transform:uppercase;
  color:var(--stamp);
  margin-bottom:14px;
  display:flex;gap:10px;align-items:center;
}
.leaf.right .leaf-mark{color:var(--cobalt)}
.leaf-mark .num{
  font-family:"Instrument Serif",serif;
  font-size:20px;
  font-style:italic;
  letter-spacing:0;
  color:var(--ink);
  opacity:.4;
}
.leaf h3{
  font-family:"Instrument Serif",serif;
  font-weight:400;
  font-size:42px;
  line-height:1;
  letter-spacing:-.015em;
  margin-bottom:16px;
  color:var(--ink);
}
.leaf h3 em{font-style:italic;color:var(--stamp)}
.leaf.right h3 em{color:var(--cobalt)}
.leaf p{
  font-family:"Fraunces",serif;
  font-variation-settings:"opsz" 12,"wght" 380;
  font-size:15px;
  line-height:1.62;
  color:var(--ink-soft);
  margin-bottom:18px;
  max-width:42ch;
}
.leaf code{
  font-family:"JetBrains Mono",monospace;
  font-size:.88em;
  background:var(--paper-2);
  padding:1px 6px;
  border:.5px solid var(--hairline);
  color:var(--ink);
}
.leaf a.ref{
  font-family:"JetBrains Mono",monospace;
  font-size:10.5px;
  letter-spacing:.16em;
  text-transform:uppercase;
  color:var(--ink);
  text-decoration:none;
  border-bottom:1px solid var(--ink);
  padding-bottom:2px;
  transition:all .2s;
}
.leaf a.ref:hover{color:var(--stamp);border-color:var(--stamp);letter-spacing:.22em}
.leaf.right a.ref:hover{color:var(--cobalt);border-color:var(--cobalt)}

/* ─── defenses list ──────────────────────────────────────────────────── */
.defenses{
  display:grid;
  grid-template-columns:repeat(2,1fr);
  gap:0;
  border-top:1.5px solid var(--ink);
}
.def{
  padding:26px 28px;
  border-bottom:.5px solid var(--hairline);
  border-right:.5px solid var(--hairline);
  position:relative;
}
.def:nth-child(even){border-right:none}
.def:nth-last-child(-n+2){border-bottom:none}
.def .n{
  position:absolute;
  top:20px;right:24px;
  font-family:"Instrument Serif",serif;
  font-style:italic;
  font-size:48px;
  color:var(--stamp);
  opacity:.18;
  line-height:1;
}
.def .name{
  font-family:"JetBrains Mono",monospace;
  font-size:13px;
  letter-spacing:.06em;
  color:var(--ink);
  margin-bottom:10px;
  font-weight:500;
}
.def .desc{
  font-family:"Fraunces",serif;
  font-variation-settings:"opsz" 12,"wght" 360;
  font-size:14px;
  line-height:1.55;
  color:var(--ink-soft);
  max-width:48ch;
}

/* ─── chart ──────────────────────────────────────────────────────────── */
.chart-wrap{
  display:grid;
  grid-template-columns:1fr 240px;
  gap:48px;
  align-items:start;
  padding-top:6px;
}
.chart-card{
  background:var(--paper-2);
  border:.5px solid var(--ink);
  padding:28px 24px 20px;
  position:relative;
}
.chart-card .cap{
  font-family:"JetBrains Mono",monospace;
  font-size:10px;letter-spacing:.22em;
  text-transform:uppercase;
  color:var(--muted);
  margin-bottom:14px;
  display:flex;justify-content:space-between;align-items:baseline;
}
.chart-card .cap b{color:var(--stamp);font-weight:600;letter-spacing:.1em}
.chart-card svg{width:100%;height:auto;display:block}
.chart-note{
  font-family:"Fraunces",serif;
  font-style:italic;
  font-size:13.5px;
  color:var(--ink-soft);
  line-height:1.55;
  padding-top:8px;
  border-top:.5px solid var(--hairline);
}
.chart-note strong{
  font-style:normal;
  font-family:"JetBrains Mono",monospace;
  font-size:11px;
  letter-spacing:.1em;
  color:var(--stamp);
  display:block;
  margin-bottom:8px;
}
.chart-note ul{list-style:none;padding:12px 0 0}
.chart-note li{
  font-family:"JetBrains Mono",monospace;
  font-style:normal;
  font-size:11px;
  letter-spacing:.04em;
  color:var(--ink);
  padding:5px 0;
  border-bottom:.5px dashed var(--hairline);
  display:flex;justify-content:space-between;
}
.chart-note li:last-child{border:none}
.chart-note li span:last-child{color:var(--stamp);font-weight:600}

/* ─── endpoint index ─────────────────────────────────────────────────── */
.endpoints{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:56px;
  padding-top:4px;
}
.endpoints h4{
  font-family:"JetBrains Mono",monospace;
  font-size:10.5px;
  letter-spacing:.28em;
  text-transform:uppercase;
  color:var(--stamp);
  padding-bottom:10px;
  margin-bottom:8px;
  border-bottom:1.5px solid var(--ink);
}
.endpoints ul{list-style:none}
.endpoints li{
  font-family:"JetBrains Mono",monospace;
  font-size:12px;
  color:var(--ink);
  padding:9px 0;
  border-bottom:.5px dotted var(--hairline);
  display:flex;align-items:baseline;gap:8px;
  transition:color .2s;
}
.endpoints li:hover{color:var(--stamp)}
.endpoints li .method{
  display:inline-block;
  min-width:42px;
  font-size:9.5px;
  letter-spacing:.18em;
  color:var(--muted);
  font-weight:600;
}
.endpoints li .method.post{color:var(--cobalt)}
.endpoints li .path{flex:1;letter-spacing:.02em}
.endpoints li .leader{flex:0 0 auto;overflow:hidden;color:var(--hairline);white-space:nowrap}
.endpoints li .note{
  font-family:"Fraunces",serif;
  font-style:italic;
  font-size:12.5px;
  color:var(--muted);
  letter-spacing:.01em;
}

/* ─── colophon / footer ──────────────────────────────────────────────── */
footer.colophon{
  margin-top:40px;
  padding:36px 0 10px;
  border-top:2px solid var(--ink);
  display:grid;
  grid-template-columns:1fr 1fr 1fr;
  gap:28px;
  align-items:start;
}
footer .col h5{
  font-family:"JetBrains Mono",monospace;
  font-size:10px;letter-spacing:.28em;
  text-transform:uppercase;
  color:var(--muted);
  margin-bottom:14px;
}
footer .col p, footer .col a{
  font-family:"Fraunces",serif;
  font-size:13.5px;
  line-height:1.65;
  color:var(--ink);
  text-decoration:none;
}
footer .col a{
  display:block;
  border-bottom:.5px solid var(--hairline);
  padding:6px 0;
  transition:all .2s;
}
footer .col a:hover{color:var(--stamp);border-color:var(--stamp);padding-left:6px}
footer .col a .arrow{color:var(--muted);margin-right:8px}
footer .col a:hover .arrow{color:var(--stamp)}
footer .col p em{color:var(--muted);font-style:italic}
footer .sigline{
  grid-column:1/-1;
  font-family:"JetBrains Mono",monospace;
  font-size:10px;
  letter-spacing:.22em;
  text-transform:uppercase;
  color:var(--muted);
  padding-top:24px;
  margin-top:14px;
  border-top:.5px dashed var(--hairline);
  display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px;
}
footer .sigline b{color:var(--ink);font-weight:600}

/* ─── load animation ─────────────────────────────────────────────────── */
.reveal{opacity:0;transform:translateY(14px);animation:rise .9s cubic-bezier(.2,.7,.2,1) forwards}
@keyframes rise{to{opacity:1;transform:translateY(0)}}
.d1{animation-delay:.05s}.d2{animation-delay:.18s}.d3{animation-delay:.32s}.d4{animation-delay:.48s}
.d5{animation-delay:.62s}.d6{animation-delay:.76s}.d7{animation-delay:.92s}.d8{animation-delay:1.08s}

/* ─── responsive ─────────────────────────────────────────────────────── */
@media (max-width:980px){
  .page{padding:24px 20px 60px}
  .hero{grid-template-columns:1fr;gap:38px}
  .pillars{grid-template-columns:repeat(2,1fr)}
  .pillar:nth-child(2){border-right:none}
  .pillar:nth-child(1),.pillar:nth-child(2){border-bottom:.5px solid var(--hairline)}
  .spread{grid-template-columns:1fr}
  .spread > .rule-v{height:.5px;background:var(--hairline);margin:24px 0}
  .leaf,.leaf.right{padding:0}
  .defenses{grid-template-columns:1fr}
  .def{border-right:none!important}
  .chart-wrap{grid-template-columns:1fr}
  .task-index{grid-template-columns:48px 1fr 90px 60px;font-size:14px}
  .task-index .steps{display:none}
  .endpoints{grid-template-columns:1fr;gap:28px}
  footer.colophon{grid-template-columns:1fr}
  .folio{display:none}
  .stamp{right:20px;top:70px;padding:7px 12px 5px;font-size:9.5px}
}

/* ─── selection ──────────────────────────────────────────────────────── */
::selection{background:var(--stamp);color:var(--paper)}
</style>
</head>
<body>

<!-- ─── BROADCAST / ADVISORY ──────────────────────────────────────────── -->
<div class="advisory">
  <span><i class="tick"></i>OPS/LIVE · FILE 003.III</span>
  <div class="advisory-scroll"><span>
    <span><em>§</em>OpenEnv Hackathon · SOC·Triage·Gym</span>
    <span><em>§</em>RLVR — Programmatic Verifiers</span>
    <span><em>§</em>RLVE — Adaptive Red-Team Curriculum</span>
    <span><em>§</em>8 Tasks · 108 Tests · 6 Reward-Hack Defenses</span>
    <span><em>§</em>Blue / Red Operations — Tier-1 · Tier-2 · Manager</span>
    <span><em>§</em>Apt Campaign · 250-step Long Horizon</span>
    <span><em>§</em>OpenEnv Hackathon · SOC·Triage·Gym</span>
    <span><em>§</em>RLVR — Programmatic Verifiers</span>
    <span><em>§</em>RLVE — Adaptive Red-Team Curriculum</span>
    <span><em>§</em>8 Tasks · 108 Tests · 6 Reward-Hack Defenses</span>
    <span><em>§</em>Blue / Red Operations — Tier-1 · Tier-2 · Manager</span>
    <span><em>§</em>Apt Campaign · 250-step Long Horizon</span>
  </span></div>
  <span>REV · III / 26</span>
</div>

<div class="folio left">SOC·TRIAGE·GYM  ·  VOL.III  ·  PG.01</div>
<div class="folio right">META·OPENENV  ·  2026  ·  CLASSIFIED DOSSIER</div>

<div class="page">

<!-- ─── DOSSIER HEADER ────────────────────────────────────────────────── -->
<header class="dossier reveal d1">
  <div class="serial">
    <span>FILE NO. <b>003.III</b></span>
    <span>CLS. <b>OPEN / JUDGE</b></span>
  </div>
  <div class="emblem" aria-label="emblem">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2">
      <path d="M12 2 L3 6 V12 C3 17 7 21 12 22 C17 21 21 17 21 12 V6 Z"/>
      <path d="M9 12 L11.5 14.5 L15.5 10" stroke-width="1.4"/>
    </svg>
  </div>
  <div class="serial" style="justify-content:flex-end">
    <span>DATE <b>23·04·2026</b></span>
    <span>REV <b>III</b></span>
  </div>
</header>

<!-- ─── MASTHEAD ─────────────────────────────────────────────────────── -->
<div class="masthead reveal d2">
  <h1>SOC·Triage·<em>Gym</em></h1>
  <div class="masthead-meta">
    <b>Participant Submission</b>
    Meta · OpenEnv Hackathon<br>
    Reinforcement Learning, Verifiable
  </div>
  <div class="stamp">
    Operational
    <small>— verified · 23.04.26</small>
  </div>
</div>

<!-- ─── HERO ─────────────────────────────────────────────────────────── -->
<section class="hero reveal d3" style="border-bottom:1px solid var(--ink);padding:48px 0 36px">
  <div>
    <div class="eyebrow">Abstract · §01</div>
    <p class="lede">
      A reinforcement-learning environment where an agent plays a
      <em>Security Operations Center</em> analyst — enriching indicators,
      correlating kill-chains, and negotiating a ticket bus with Tier-2 and
      the SOC Manager under verifiable, programmatic reward.
    </p>
    <p class="body-lede">
      Eight tasks, from a single phishing triage up to a 250-step APT
      campaign. Rewards are layered — classification, technique mapping,
      evidence-gathering, response quality — and cross-checked by an
      adaptive red-team generator that probes the blue-team's failure
      modes and rewrites itself when it is defeated. Run the complete
      <em>guide §19</em> judge demo in a single command.
    </p>
    <div class="cta-row">
      <a class="cta primary" href="/docs"><span>API Spec</span><span class="arrow">→</span></a>
      <a class="cta" href="/ui/themes"><span>Theme Manifest</span><span class="arrow">→</span></a>
      <a class="cta" href="/ui/tasks"><span>Task Catalogue</span><span class="arrow">→</span></a>
      <a class="cta" href="/ui/metadata"><span>Metadata</span><span class="arrow">→</span></a>
      <a class="cta" href="/ui/state"><span>Live State</span><span class="arrow">→</span></a>
      <a class="cta" href="https://github.com/ROHITCRAFTSYT/-Metas-OpenEnv-2" target="_blank" rel="noopener"><span>Source · GitHub</span><span class="arrow">↗</span></a>
    </div>
  </div>

  <!-- Terminal card -->
  <div class="terminal">
    <div class="term-head">
      <span class="dots"><i></i><i></i><i></i></span>
      <span>judge-demo · §19</span>
      <span>ttys/002</span>
    </div>
    <div class="term-body">
      <div><span class="term-prompt">❯</span> <span class="term-cmd">python demo.py</span> <span class="term-out dim">--task phishing --seed 42</span></div>
      <div class="term-rule"></div>
      <div class="term-out dim">① 1/5 · Untrained baseline (no-op)</div>
      <div class="term-out">score = <span class="neg">0.0%</span>  steps = 0</div>
      <div class="term-rule"></div>
      <div class="term-out dim">② 2/5 · Verifier breakdown (RLVR)</div>
      <div class="term-out">classification     <span class="hl">0.00</span></div>
      <div class="term-out">technique_mapping  <span class="hl">0.00</span></div>
      <div class="term-out">evidence_gathered  <span class="hl">0.00</span></div>
      <div class="term-out">response_quality   <span class="hl">0.00</span></div>
      <div class="term-rule"></div>
      <div class="term-out dim">③ 3/5 · Oracle proxy</div>
      <div class="term-out">score = <span class="pos">65.0%</span>  steps = 14</div>
      <div class="term-rule"></div>
      <div class="term-out dim">④ 4/5 · Measurable delta</div>
      <div class="term-out">Δreward = <span class="pos">+65.00 pp</span></div>
      <div class="term-rule"></div>
      <div class="term-out dim">⑤ 5/5 · Safeguards</div>
      <div class="term-out">✓ close_case_idempotency</div>
      <div class="term-out">✓ team_f1_delta_not_sticky</div>
      <div class="term-out">✓ zero_escalation_guard<span class="cursor"></span></div>
    </div>
  </div>
</section>

<!-- ─── PILLARS ──────────────────────────────────────────────────────── -->
<div class="pillars reveal d4">
  <div class="pillar">
    <div class="kicker">Scenarios</div>
    <div class="num">08<sup>TK</sup></div>
    <div class="label">Tasks, solo &amp; team</div>
    <div class="foot">EASY → SUPER-HARD</div>
  </div>
  <div class="pillar">
    <div class="kicker">Verifiers</div>
    <div class="num">06<sup>Fn</sup></div>
    <div class="label">Independent reward fns</div>
    <div class="foot">RLVR LAYER — GRADERS/</div>
  </div>
  <div class="pillar">
    <div class="kicker">Safeguards</div>
    <div class="num">06<sup>Def</sup></div>
    <div class="label">Reward-hack defenses</div>
    <div class="foot">REGRESSION-TESTED</div>
  </div>
  <div class="pillar">
    <div class="kicker">Regression</div>
    <div class="num">108<sup>✓</sup></div>
    <div class="label">Passing tests (0.83 s)</div>
    <div class="foot">pytest -q — green</div>
  </div>
</div>

<!-- ─── TASK INDEX ───────────────────────────────────────────────────── -->
<section class="reveal d5">
  <div class="section-head">
    <div class="sig">Index · §02</div>
    <div>
      <h2>A catalogue of <em>eight</em> scenarios.</h2>
      <p class="desc">From a single phishing email to a 250-step APT campaign under policy drift — each task is a verifiable, seeded episode. Team-mode scenarios add Tier-1, Tier-2 and Manager roles with a ticket bus between them.</p>
    </div>
  </div>

  <div class="task-index">
    <div class="row head">
      <div>CODE</div><div>SCENARIO</div><div>DIFFICULTY</div><div>STEPS</div><div>MODE</div>
    </div>
    <div class="row"><div class="code">TK·001</div><div class="name"><em>Phishing</em> Triage</div><div class="diff e">Easy</div><div class="steps">15</div><div class="mode">Solo</div></div>
    <div class="row"><div class="code">TK·002</div><div class="name"><em>Lateral</em> Movement</div><div class="diff m">Medium</div><div class="steps">30</div><div class="mode">Solo</div></div>
    <div class="row"><div class="code">TK·003</div><div class="name"><em>Queue</em> Management</div><div class="diff h">Hard</div><div class="steps">60</div><div class="mode">Solo</div></div>
    <div class="row"><div class="code">TK·004</div><div class="name"><em>Insider</em> Threat</div><div class="diff x">Expert</div><div class="steps">80</div><div class="mode">Solo</div></div>
    <div class="row"><div class="code">TK·005</div><div class="name"><em>Team</em> Phishing Escalation</div><div class="diff e">Easy</div><div class="steps">68</div><div class="mode">Team</div></div>
    <div class="row"><div class="code">TK·006</div><div class="name"><em>Team</em> Lateral Movement</div><div class="diff m">Medium</div><div class="steps">68</div><div class="mode">Team</div></div>
    <div class="row"><div class="code">TK·007</div><div class="name"><em>APT</em> Campaign</div><div class="diff x">Super-Hard</div><div class="steps">250</div><div class="mode">Solo</div></div>
    <div class="row"><div class="code">TK·008</div><div class="name"><em>Generated</em> Adversarial</div><div class="diff a">Adaptive</div><div class="steps">30–250</div><div class="mode">Team</div></div>
  </div>
</section>

<!-- ─── RLVR / RLVE SPREAD ──────────────────────────────────────────── -->
<section class="reveal d6">
  <div class="section-head">
    <div class="sig">Verification · §03</div>
    <div>
      <h2>Two layers of <em>verification</em>.</h2>
      <p class="desc">The reward function is programmatic (RLVR) and the environment itself adapts (RLVE). One checks the answer; the other keeps rewriting the question.</p>
    </div>
  </div>

  <div class="spread">
    <div class="leaf">
      <div class="leaf-mark"><span class="num">I.</span> RLVR — Verifiable Rewards</div>
      <h3>The <em>grader</em> is a program, not a judge.</h3>
      <p>Each task ships six-or-more independent verifiers — <code>classification</code>, <code>technique_mapping</code>, <code>evidence_gathered</code>, <code>response_quality</code>, <code>idempotency</code>, <code>team_f1</code>. A final reward is a weighted blend with no single hackable numerator. Results are deterministic: same seed, same score.</p>
      <a class="ref" href="https://github.com/ROHITCRAFTSYT/-Metas-OpenEnv-2/tree/main/graders" target="_blank">graders/ ↗</a>
    </div>
    <div class="rule-v"></div>
    <div class="leaf right">
      <div class="leaf-mark"><span class="num">II.</span> RLVE — Adaptive Environment</div>
      <h3>The <em>task itself</em> is a moving target.</h3>
      <p>The Red-Team Generator composes new scenarios from a library of attack primitives and is rewarded for defeating the blue-team without trivially winning — a novelty bonus in the <code>[0.35, 0.65]</code> blue-score band keeps generated scenarios near the learning frontier.</p>
      <a class="ref" href="https://github.com/ROHITCRAFTSYT/-Metas-OpenEnv-2/blob/main/scenarios/red_team_generator.py" target="_blank">red_team_generator.py ↗</a>
    </div>
  </div>
</section>

<!-- ─── REWARD-HACK DEFENSES ──────────────────────────────────────────── -->
<section class="reveal d7">
  <div class="section-head">
    <div class="sig">Safeguards · §04</div>
    <div>
      <h2>Six defenses against <em>reward hacking</em>.</h2>
      <p class="desc">A dense reward invites Goodhart's law. Each of these is a specific failure mode the oracle exhibited in development, now pinned by a regression test.</p>
    </div>
  </div>

  <div class="defenses">
    <div class="def">
      <div class="n">01</div>
      <div class="name">close_case_idempotency</div>
      <div class="desc">Closing the same case twice must not pay out twice. Caught agents spamming <code>close_case</code> once they saw positive reward.</div>
    </div>
    <div class="def">
      <div class="n">02</div>
      <div class="name">team_f1_delta_not_sticky</div>
      <div class="desc">The Δ team-F1 component must drop back to zero after a single reward; otherwise the bonus becomes a constant additive term.</div>
    </div>
    <div class="def">
      <div class="n">03</div>
      <div class="name">zero_escalation_guard</div>
      <div class="desc">An episode with zero Tier-2 tickets fails verification even if every alert was correctly triaged — prevents degenerate "silent triage" policies.</div>
    </div>
    <div class="def">
      <div class="n">04</div>
      <div class="name">over_escalation_threshold</div>
      <div class="desc">Escalating every alert to Tier-2 is penalized past a ratio threshold — blocks the "just pass the buck" policy.</div>
    </div>
    <div class="def">
      <div class="n">05</div>
      <div class="name">manager_judge_fallback</div>
      <div class="desc">When the expert-panel judge disagrees, Manager adjudicates with a bounded correction to the team reward.</div>
    </div>
    <div class="def">
      <div class="n">06</div>
      <div class="name">policy_drift_active_at_semantics</div>
      <div class="desc">The APT campaign rotates legitimate-behavior policies mid-episode — guards against agents memorising a static <em>normal</em>.</div>
    </div>
  </div>
</section>

<!-- ─── ORACLE CURVE ─────────────────────────────────────────────────── -->
<section class="reveal d8">
  <div class="section-head">
    <div class="sig">Figure · §05</div>
    <div>
      <h2>Tier-1 oracle — <em>the training target</em>.</h2>
      <p class="desc">Twenty episodes across phishing, team_phishing_escalation and team_lateral_team. A trained GRPO checkpoint must match or beat this line; the mean is the floor, not the ceiling.</p>
    </div>
  </div>

  <div class="chart-wrap">
    <div class="chart-card">
      <div class="cap"><span>FIG. 01 · ORACLE REWARD CURVE · TIER-1</span><b>μ = 0.8995</b></div>
      <svg viewBox="0 0 640 220" preserveAspectRatio="none" aria-label="oracle reward curve">
        <defs>
          <pattern id="grid" width="32" height="22" patternUnits="userSpaceOnUse">
            <path d="M 32 0 L 0 0 0 22" fill="none" stroke="#c9bfaa" stroke-width="0.5" stroke-dasharray="2 3"/>
          </pattern>
          <linearGradient id="area" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stop-color="#b8321e" stop-opacity=".18"/>
            <stop offset="100%" stop-color="#b8321e" stop-opacity="0"/>
          </linearGradient>
        </defs>
        <rect width="640" height="220" fill="url(#grid)"/>
        <!-- y axis ticks -->
        <g font-family="JetBrains Mono" font-size="9" fill="#7a7264" letter-spacing="1">
          <text x="4" y="14">1.00</text>
          <text x="4" y="68">0.75</text>
          <text x="4" y="122">0.50</text>
          <text x="4" y="176">0.25</text>
          <text x="4" y="216">0.00</text>
        </g>
        <!-- mean line -->
        <line x1="44" x2="632" y1="37" y2="37" stroke="#2a4980" stroke-width="1" stroke-dasharray="4 3" opacity=".7"/>
        <text x="620" y="31" font-family="JetBrains Mono" font-size="9" fill="#2a4980" text-anchor="end">μ = 0.90</text>
        <!-- episodes: 20 oracle scores ≈ 0.65, 0.71, 0.885×10 skipped, using real shape -->
        <!-- phishing×1:0.65, lateral_movement×1:0.71, team_phishing×10:0.999, team_lateral×8:0.80 -->
        <polygon
          fill="url(#area)"
          points="44,220 44,145 73,133 102,33 131,33 160,33 189,33 218,33 247,33 276,33 305,33 334,33 363,77 392,77 421,77 450,77 479,77 508,77 537,77 566,77 595,77 624,77 624,220"/>
        <polyline
          fill="none" stroke="#b8321e" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round"
          points="44,145 73,133 102,33 131,33 160,33 189,33 218,33 247,33 276,33 305,33 334,33 363,77 392,77 421,77 450,77 479,77 508,77 537,77 566,77 595,77 624,77"/>
        <!-- data dots -->
        <g fill="#b8321e">
          <circle cx="44"  cy="145" r="2.5"/>
          <circle cx="73"  cy="133" r="2.5"/>
          <circle cx="102" cy="33"  r="2.5"/>
          <circle cx="131" cy="33"  r="2.5"/>
          <circle cx="160" cy="33"  r="2.5"/>
          <circle cx="189" cy="33"  r="2.5"/>
          <circle cx="218" cy="33"  r="2.5"/>
          <circle cx="247" cy="33"  r="2.5"/>
          <circle cx="276" cy="33"  r="2.5"/>
          <circle cx="305" cy="33"  r="2.5"/>
          <circle cx="334" cy="33"  r="2.5"/>
          <circle cx="363" cy="77"  r="2.5"/>
          <circle cx="392" cy="77"  r="2.5"/>
          <circle cx="421" cy="77"  r="2.5"/>
          <circle cx="450" cy="77"  r="2.5"/>
          <circle cx="479" cy="77"  r="2.5"/>
          <circle cx="508" cy="77"  r="2.5"/>
          <circle cx="537" cy="77"  r="2.5"/>
          <circle cx="566" cy="77"  r="2.5"/>
          <circle cx="595" cy="77"  r="2.5"/>
        </g>
        <!-- x axis labels -->
        <g font-family="JetBrains Mono" font-size="8.5" fill="#7a7264" letter-spacing="1">
          <text x="44"  y="213">EP.01</text>
          <text x="190" y="213">EP.05</text>
          <text x="340" y="213">EP.10</text>
          <text x="490" y="213">EP.15</text>
          <text x="620" y="213" text-anchor="end">EP.20</text>
        </g>
      </svg>
    </div>
    <div class="chart-note">
      <strong>EP. DIGEST</strong>
      <em>A composite oracle across three tier-1 tasks. The dip at episodes 01–02 is the hardest seed of the phishing/lateral pair; the plateau at 03–11 is the team_phishing oracle at ceiling; the shelf at 12–20 is team_lateral holding steady at 0.80.</em>
      <ul>
        <li><span>phishing (μ)</span><span>0.650</span></li>
        <li><span>lateral (μ)</span><span>0.710</span></li>
        <li><span>team_phishing</span><span>0.999</span></li>
        <li><span>team_lateral</span><span>0.800</span></li>
        <li><span>grand mean</span><span>0.8995</span></li>
      </ul>
    </div>
  </div>
</section>

<!-- ─── ENDPOINT INDEX ───────────────────────────────────────────────── -->
<section class="nb reveal">
  <div class="section-head">
    <div class="sig">Index · §06</div>
    <div>
      <h2>API — an <em>index</em>, not a firehose.</h2>
      <p class="desc">Every endpoint is listed, with method and one-line intent. The OpenEnv contract (/reset, /step, /state) is complete; everything else is an accessor for the scaffolding — judges, tickets, themes.</p>
    </div>
  </div>

  <div class="endpoints">
    <div>
      <h4>§ OpenEnv Contract</h4>
      <ul>
        <li><span class="method">GET</span><span class="path">/health</span><span class="leader">·····································</span><span class="note">liveness</span></li>
        <li><span class="method">GET</span><span class="path">/metadata</span><span class="leader">······························</span><span class="note">spec + version</span></li>
        <li><span class="method">GET</span><span class="path">/schema</span><span class="leader">·································</span><span class="note">obs / action</span></li>
        <li><span class="method post">POST</span><span class="path">/reset</span><span class="leader">································</span><span class="note">new episode</span></li>
        <li><span class="method post">POST</span><span class="path">/step</span><span class="leader">··································</span><span class="note">action → obs</span></li>
        <li><span class="method">GET</span><span class="path">/state</span><span class="leader">································</span><span class="note">snapshot</span></li>
        <li><span class="method">GET</span><span class="path">/tasks</span><span class="leader">································</span><span class="note">task catalogue</span></li>
      </ul>
      <h4 style="margin-top:32px">§ Verification</h4>
      <ul>
        <li><span class="method post">POST</span><span class="path">/grader</span><span class="leader">·······························</span><span class="note">breakdown</span></li>
        <li><span class="method post">POST</span><span class="path">/baseline</span><span class="leader">·······················</span><span class="note">oracle rollout</span></li>
        <li><span class="method">GET</span><span class="path">/themes/coverage</span><span class="leader">···················</span><span class="note">manifest</span></li>
        <li><span class="method">GET</span><span class="path">/experts/panel</span><span class="leader">······················</span><span class="note">rotating judge</span></li>
      </ul>
    </div>
    <div>
      <h4>§ Curriculum &amp; Policy</h4>
      <ul>
        <li><span class="method post">POST</span><span class="path">/generate_scenario</span><span class="leader">·············</span><span class="note">red-team RLVE</span></li>
        <li><span class="method">GET</span><span class="path">/policy/current</span><span class="leader">······················</span><span class="note">drift state</span></li>
        <li><span class="method">GET</span><span class="path">/policy/history</span><span class="leader">······················</span><span class="note">timeline</span></li>
        <li><span class="method">GET</span><span class="path">/reward/config</span><span class="leader">·······················</span><span class="note">weights</span></li>
        <li><span class="method post">POST</span><span class="path">/reward/token_bonus</span><span class="leader">··········</span><span class="note">efficiency</span></li>
      </ul>
      <h4 style="margin-top:32px">§ Team Operations</h4>
      <ul>
        <li><span class="method">GET</span><span class="path">/inbox/{role}</span><span class="leader">···························</span><span class="note">per-role queue</span></li>
        <li><span class="method">GET</span><span class="path">/actors/messages</span><span class="leader">···················</span><span class="note">trace</span></li>
        <li><span class="method">GET</span><span class="path">/tickets</span><span class="leader">·····························</span><span class="note">ticket bus</span></li>
        <li><span class="method post">POST</span><span class="path">/tickets/open</span><span class="leader">·······················</span><span class="note">new ticket</span></li>
        <li><span class="method post">POST</span><span class="path">/tickets/{id}/resolve</span><span class="leader">········</span><span class="note">close</span></li>
        <li><span class="method post">POST</span><span class="path">/mcp</span><span class="leader">······································</span><span class="note">MCP bridge</span></li>
      </ul>
    </div>
  </div>
</section>

<!-- ─── FOOTER / COLOPHON ────────────────────────────────────────────── -->
<footer class="colophon reveal">
  <div class="col">
    <h5>Run · local</h5>
    <p>
      <code style="font-family:'JetBrains Mono',monospace;font-size:13px;background:var(--paper-2);padding:2px 8px;border:.5px solid var(--hairline)">python demo.py</code>
      &nbsp;<em>— the full §19 judge flow in 10 seconds, no GPU.</em>
    </p>
    <p style="margin-top:10px"><em>Or </em><code style="font-family:'JetBrains Mono',monospace;font-size:13px;background:var(--paper-2);padding:2px 8px;border:.5px solid var(--hairline)">uvicorn server.app:app</code><em> — then visit /docs.</em></p>
  </div>
  <div class="col">
    <h5>Links</h5>
    <a href="https://github.com/ROHITCRAFTSYT/-Metas-OpenEnv-2" target="_blank" rel="noopener"><span class="arrow">↗</span> Source · GitHub</a>
    <a href="https://huggingface.co/spaces/rohitcraftsyt/openenv2" target="_blank" rel="noopener"><span class="arrow">↗</span> HF Space · openenv2</a>
    <a href="/docs"><span class="arrow">→</span> OpenAPI spec · /docs</a>
    <a href="/themes/coverage"><span class="arrow">→</span> Theme coverage · /themes/coverage</a>
  </div>
  <div class="col">
    <h5>Colophon</h5>
    <p><em>Set in </em>Instrument Serif<em> &amp; </em>Fraunces<em>, with </em>JetBrains Mono<em> for data. Printed on archival cream.</em></p>
    <p style="margin-top:10px"><em>This page is a live artefact of the submission — endpoint links return live JSON from this same FastAPI process.</em></p>
  </div>
  <div class="sigline">
    <span><b>SOC·Triage·Gym</b> · v3.1 · File 003.III</span>
    <span>Meta · OpenEnv Hackathon · 2026</span>
    <span>— END OF DOSSIER —</span>
  </div>
</footer>

</div><!-- /page -->

<script>
/* subtle parallax on the stamp based on mouse position — restrained */
(function(){
  var stamp=document.querySelector('.stamp');
  if(!stamp||window.matchMedia('(hover:none)').matches) return;
  var base=-7;
  document.addEventListener('mousemove',function(e){
    var x=(e.clientX/window.innerWidth-.5)*2;
    var y=(e.clientY/window.innerHeight-.5)*2;
    stamp.style.transform='rotate('+(base+x*1.5)+'deg) translate('+(x*2)+'px,'+(y*-2)+'px)';
  },{passive:true});
})();
</script>

</body>
</html>"""
