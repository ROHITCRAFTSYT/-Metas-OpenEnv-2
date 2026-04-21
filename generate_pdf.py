"""Generate SOC Triage Gym Hackathon Presentation PDF."""
import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, cm
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas as canvasmod
from reportlab.lib import colors

# ── Colour palette ──────────────────────────────────────────────
BG_DARK    = HexColor("#0c1117")
ACCENT_1   = HexColor("#c96d43")   # warm orange
ACCENT_2   = HexColor("#275d7e")   # steel blue
ACCENT_3   = HexColor("#1d7f67")   # teal green
INK        = HexColor("#18222d")
MUTED      = HexColor("#5f6f7e")
PAPER      = HexColor("#fffaf1")
PANEL      = HexColor("#f3eee2")
LINE       = HexColor("#d6c7aa")
GOOD       = HexColor("#15835f")
WARN       = HexColor("#b87a1d")
BAD        = HexColor("#bb4e4e")
WHITE      = white
BLACK      = black

# ── Page dimensions ─────────────────────────────────────────────
W, H = A4
MARGIN = 20*mm

# ── Custom page background ─────────────────────────────────────
def page_bg(canvas, doc):
    canvas.saveState()
    # warm paper background
    canvas.setFillColor(PAPER)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)
    # top accent bar
    canvas.setFillColor(ACCENT_2)
    canvas.rect(0, H - 8*mm, W, 8*mm, fill=1, stroke=0)
    canvas.setFillColor(ACCENT_1)
    canvas.rect(0, H - 8*mm, W * 0.35, 8*mm, fill=1, stroke=0)
    canvas.setFillColor(ACCENT_3)
    canvas.rect(W * 0.35, H - 8*mm, W * 0.15, 8*mm, fill=1, stroke=0)
    # footer
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawCentredString(W/2, 12*mm, f"SOC Triage Gym  |  OpenEnv Hackathon 2026  |  Page {doc.page}")
    canvas.restoreState()

def title_page_bg(canvas, doc):
    canvas.saveState()
    # dark background
    canvas.setFillColor(BG_DARK)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)
    # accent gradient strip
    canvas.setFillColor(ACCENT_1)
    canvas.rect(0, H*0.52, W, 6*mm, fill=1, stroke=0)
    canvas.setFillColor(ACCENT_3)
    canvas.rect(0, H*0.52 - 3*mm, W, 3*mm, fill=1, stroke=0)
    canvas.restoreState()

# ── Styles ──────────────────────────────────────────────────────
def make_styles():
    s = {}
    s["title_main"] = ParagraphStyle("title_main",
        fontName="Helvetica-Bold", fontSize=42, leading=48,
        textColor=WHITE, alignment=TA_LEFT, spaceAfter=8*mm)
    s["title_sub"] = ParagraphStyle("title_sub",
        fontName="Helvetica", fontSize=16, leading=22,
        textColor=HexColor("#93a6b6"), alignment=TA_LEFT, spaceAfter=4*mm)
    s["title_detail"] = ParagraphStyle("title_detail",
        fontName="Helvetica", fontSize=11, leading=16,
        textColor=HexColor("#6e8294"), alignment=TA_LEFT)
    s["h1"] = ParagraphStyle("h1",
        fontName="Helvetica-Bold", fontSize=22, leading=28,
        textColor=ACCENT_2, spaceBefore=6*mm, spaceAfter=4*mm)
    s["h2"] = ParagraphStyle("h2",
        fontName="Helvetica-Bold", fontSize=15, leading=20,
        textColor=INK, spaceBefore=5*mm, spaceAfter=3*mm)
    s["h3"] = ParagraphStyle("h3",
        fontName="Helvetica-Bold", fontSize=12, leading=16,
        textColor=ACCENT_1, spaceBefore=3*mm, spaceAfter=2*mm)
    s["body"] = ParagraphStyle("body",
        fontName="Helvetica", fontSize=10.5, leading=15,
        textColor=INK, alignment=TA_JUSTIFY, spaceAfter=2.5*mm)
    s["body_bold"] = ParagraphStyle("body_bold",
        fontName="Helvetica-Bold", fontSize=10.5, leading=15,
        textColor=INK, spaceAfter=2.5*mm)
    s["bullet"] = ParagraphStyle("bullet",
        fontName="Helvetica", fontSize=10.5, leading=15,
        textColor=INK, leftIndent=14*mm, bulletIndent=6*mm,
        spaceAfter=1.5*mm, bulletFontName="Helvetica-Bold",
        bulletFontSize=10, bulletColor=ACCENT_1)
    s["bullet_2"] = ParagraphStyle("bullet_2",
        fontName="Helvetica", fontSize=10, leading=14,
        textColor=MUTED, leftIndent=22*mm, bulletIndent=14*mm,
        spaceAfter=1*mm, bulletFontName="Helvetica",
        bulletFontSize=8, bulletColor=MUTED)
    s["code"] = ParagraphStyle("code",
        fontName="Courier", fontSize=9, leading=13,
        textColor=INK, backColor=PANEL, leftIndent=4*mm,
        rightIndent=4*mm, spaceBefore=2*mm, spaceAfter=2*mm,
        borderPadding=(3*mm, 3*mm, 3*mm, 3*mm))
    s["callout"] = ParagraphStyle("callout",
        fontName="Helvetica", fontSize=10.5, leading=15,
        textColor=ACCENT_2, leftIndent=6*mm, borderPadding=(3*mm, 3*mm, 3*mm, 3*mm),
        backColor=HexColor("#eef4f8"), spaceAfter=3*mm, spaceBefore=2*mm)
    s["caption"] = ParagraphStyle("caption",
        fontName="Helvetica-Oblique", fontSize=9, leading=13,
        textColor=MUTED, alignment=TA_CENTER, spaceAfter=3*mm)
    s["toc_item"] = ParagraphStyle("toc_item",
        fontName="Helvetica", fontSize=12, leading=20,
        textColor=INK, leftIndent=6*mm, spaceAfter=1*mm)
    return s

# ── Helper builders ─────────────────────────────────────────────
def hr():
    return HRFlowable(width="100%", thickness=0.5, color=LINE,
                      spaceBefore=3*mm, spaceAfter=3*mm)

def metric_table(data, col_widths=None):
    """Create a styled metric table. data = list of lists."""
    if col_widths is None:
        n = len(data[0]) if data else 1
        col_widths = [(W - 2*MARGIN) / n] * n
    t = Table(data, colWidths=col_widths, repeatRows=1)
    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT_2),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME",  (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",  (0, 0), (-1, 0), 10),
        ("FONTNAME",  (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",  (0, 1), (-1, -1), 10),
        ("TEXTCOLOR", (0, 1), (-1, -1), INK),
        ("BACKGROUND",(0, 1), (-1, -1), WHITE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PANEL]),
        ("GRID",      (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN",    (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",(0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0,0),(-1,-1), 6),
        ("LEFTPADDING",(0,0),(-1,-1), 8),
    ]
    t.setStyle(TableStyle(style_commands))
    return t

def info_box(text, style, bg=HexColor("#e7dfcf")):
    """Highlighted info box."""
    t = Table([[Paragraph(text, style)]], colWidths=[W - 2*MARGIN])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), bg),
        ("BOX", (0,0), (-1,-1), 0.5, LINE),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING", (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
    ]))
    return t


# ── DOCUMENT BUILDER ────────────────────────────────────────────
def build_pdf(output_path):
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN + 8*mm, bottomMargin=MARGIN + 6*mm,
        title="SOC Triage Gym - Hackathon Guide",
        author="SOC-Triage-Gym Team",
        subject="OpenEnv Hackathon 2026 Presentation Guide",
    )
    S = make_styles()
    story = []
    CW = W - 2*MARGIN  # content width

    # ════════════════════════════════════════════════════════════
    # PAGE 1 — TITLE
    # ════════════════════════════════════════════════════════════
    story.append(Spacer(1, 55*mm))
    story.append(Paragraph("SOC Triage Gym", S["title_main"]))
    story.append(Paragraph(
        "A Reinforcement Learning Environment for<br/>"
        "Security Operations Center Analyst Training",
        S["title_sub"]))
    story.append(Spacer(1, 12*mm))
    story.append(Paragraph(
        "OpenEnv Hackathon 2026  |  Built on Meta's OpenEnv Framework<br/>"
        "Hosted on Hugging Face Spaces  |  Docker + FastAPI + Pydantic v2",
        S["title_detail"]))
    story.append(Spacer(1, 8*mm))
    story.append(Paragraph(
        "Team: SOC-Triage-Gym  |  Repository: github.com/ROHITCRAFTSYT/-Metas-OpenEnv-2",
        S["title_detail"]))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # PAGE 2 — TABLE OF CONTENTS
    # ════════════════════════════════════════════════════════════
    story.append(Paragraph("Table of Contents", S["h1"]))
    story.append(hr())
    toc_items = [
        ("1.", "What Is SOC Triage Gym?"),
        ("2.", "The Problem We Solve"),
        ("3.", "Use Case and Target Audience"),
        ("4.", "How It Works (Architecture)"),
        ("5.", "The Four Scenarios (Easy to Expert)"),
        ("6.", "Reward System and Grading"),
        ("7.", "Tools Available to Agents"),
        ("8.", "Baseline Agent and Benchmarks"),
        ("9.", "API Endpoints and MCP Integration"),
        ("10.", "Technology Stack"),
        ("11.", "Quick-Start Guide"),
        ("12.", "Key Differentiators"),
        ("13.", "Future Roadmap"),
        ("14.", "Quick Reference Cheat Sheet"),
    ]
    for num, title in toc_items:
        story.append(Paragraph(
            f'<b><font color="{ACCENT_1.hexval()}">{num}</font></b>  {title}',
            S["toc_item"]))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 1 — WHAT IS SOC TRIAGE GYM?
    # ════════════════════════════════════════════════════════════
    story.append(Paragraph("1. What Is SOC Triage Gym?", S["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "SOC Triage Gym is an <b>OpenEnv-compatible reinforcement learning environment</b> "
        "that simulates the day-to-day workflow of a Security Operations Center (SOC) analyst. "
        "It provides a structured, deterministic sandbox where AI agents can learn to investigate "
        "security alerts, gather evidence, classify threats, and recommend response actions, "
        "all while being graded on accuracy, efficiency, and investigative thoroughness.",
        S["body"]))
    story.append(Spacer(1, 2*mm))
    story.append(info_box(
        '<b>In one sentence:</b> It is a gym where AI agents learn to be SOC analysts by '
        'triaging security alerts across four increasingly difficult real-world scenarios.',
        S["body"], HexColor("#eef4f8")))
    story.append(Spacer(1, 2*mm))

    story.append(Paragraph("Key Facts at a Glance", S["h2"]))
    facts_data = [
        ["Attribute", "Detail"],
        ["Framework", "Meta's OpenEnv (openenv-core >= 0.2.0)"],
        ["Tasks", "4 scenarios: Phishing, Lateral Movement, Queue Management, Insider Threat"],
        ["Alerts", "1 to 30 per scenario, with realistic noise (up to 53% false positives)"],
        ["Actions", "11 action types: enrich, query, correlate, classify, escalate, etc."],
        ["Grading", "Multi-dimensional: classification accuracy, technique mapping, evidence, efficiency"],
        ["Determinism", "Seed-based scenario generation ensures 100% reproducible results"],
        ["Deployment", "Docker container on Hugging Face Spaces with interactive web UI"],
        ["Baseline", "Heuristic rule-based agent averages ~79% across all scenarios"],
        ["Tests", "31/31 pytest tests pass covering all components"],
    ]
    story.append(metric_table(facts_data, [CW*0.22, CW*0.78]))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 2 — THE PROBLEM WE SOLVE
    # ════════════════════════════════════════════════════════════
    story.append(Paragraph("2. The Problem We Solve", S["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Security Operations Centers face a critical challenge: <b>alert fatigue</b>. "
        "Modern SOC teams receive thousands of alerts daily, and up to 80% are false positives. "
        "Analysts must rapidly triage each alert, investigate evidence, correlate across systems, "
        "and decide on a response. This is mentally exhausting, error-prone, and expensive.",
        S["body"]))
    story.append(Spacer(1, 2*mm))

    story.append(Paragraph("Real-World SOC Pain Points", S["h2"]))
    pain_points = [
        ("<b>Alert Fatigue:</b> Analysts burn out processing 1000+ daily alerts, most of which are noise.",),
        ("<b>Missed True Positives:</b> Critical threats slip through when analysts are overwhelmed.",),
        ("<b>Inconsistent Triage:</b> Quality varies by analyst experience, time of day, and workload.",),
        ("<b>Training Gap:</b> New analysts need months of mentorship before handling complex incidents.",),
        ("<b>No RL Benchmark:</b> Unlike Atari or MuJoCo, cybersecurity lacked a standard RL environment.",),
    ]
    for pp in pain_points:
        story.append(Paragraph(pp[0], S["bullet"], bulletText="\u2022"))

    story.append(Spacer(1, 3*mm))
    story.append(info_box(
        '<b>Our Solution:</b> SOC Triage Gym provides a standardized, deterministic, and graded '
        'environment where AI agents can practice SOC triage at four difficulty levels, '
        'from single-alert phishing to 30-alert insider threat investigations with 53% noise.',
        S["body"], HexColor("#e7f3eb")))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 3 — USE CASE AND TARGET AUDIENCE
    # ════════════════════════════════════════════════════════════
    story.append(Paragraph("3. Use Case and Target Audience", S["h1"]))
    story.append(hr())

    story.append(Paragraph("Who Is This For?", S["h2"]))
    audiences = [
        ("<b>AI/ML Researchers:</b> Train and benchmark RL agents on a realistic cybersecurity task "
         "with dense reward signals and deterministic reproducibility.",),
        ("<b>Cybersecurity Teams:</b> Evaluate AI-assisted triage tools before deployment in production SOCs. "
         "Compare LLM agents (GPT-4, Llama, Claude) head-to-head on identical scenarios.",),
        ("<b>SOC Training Programs:</b> Use as a simulated lab for analyst onboarding. "
         "New analysts can practice triage workflows without touching production systems.",),
        ("<b>Security Vendors:</b> Benchmark your SOAR/XDR automation against the heuristic baseline "
         "and graded rubrics to quantify your product's triage quality.",),
        ("<b>Hackathon Participants:</b> Build an agent that beats the 79% baseline and compete on "
         "the OpenEnv leaderboard.",),
    ]
    for a in audiences:
        story.append(Paragraph(a[0], S["bullet"], bulletText="\u2022"))

    story.append(Spacer(1, 3*mm))
    story.append(Paragraph("Primary Use Cases", S["h2"]))
    uc_data = [
        ["Use Case", "Description"],
        ["RL Agent Training", "Train agents with step-level reward feedback on realistic SOC workflows"],
        ["LLM Agent Evaluation", "Compare GPT-4 vs Claude vs Llama on identical seeded scenarios"],
        ["Analyst Training Sim", "Safe sandbox for junior SOC analysts to practice triage"],
        ["Product Benchmarking", "Quantify SOAR/XDR automation quality against graded rubrics"],
        ["Research Publication", "Reproducible, deterministic benchmarks for academic papers"],
    ]
    story.append(metric_table(uc_data, [CW*0.28, CW*0.72]))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 4 — ARCHITECTURE
    # ════════════════════════════════════════════════════════════
    story.append(Paragraph("4. How It Works (Architecture)", S["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "SOC Triage Gym follows the standard reinforcement learning loop: "
        "the agent observes the environment state, selects an action, the environment transitions, "
        "and the agent receives a reward. The twist is that actions are SOC investigation steps, "
        "observations are alert queues with evidence, and rewards reflect triage quality.",
        S["body"]))

    story.append(Paragraph("Core Loop", S["h2"]))
    story.append(info_box(
        '<font face="Courier" size="9">'
        'Agent  ---(SOCAction)---> Environment ---(SOCObservation + reward)---> Agent<br/>'
        '<br/>'
        '1. POST /reset(task_id, seed)  =>  Initial observation (alert queue)<br/>'
        '2. POST /step(action)          =>  Updated observation + reward<br/>'
        '3. Repeat until done or budget exhausted<br/>'
        '4. POST /grader                =>  Final score with breakdown'
        '</font>',
        S["body"], PANEL))

    story.append(Paragraph("Component Map", S["h2"]))
    arch_data = [
        ["Component", "File(s)", "Role"],
        ["Data Models", "models.py", "Pydantic v2 contracts: SOCAction, SOCObservation, GroundTruth"],
        ["FastAPI Server", "server/app.py", "REST + MCP endpoints, thread-safe singleton environment"],
        ["Environment", "server/environment.py", "State machine: reset, step, dispatch, reward calculation"],
        ["Scenarios", "scenarios/*.py", "Seed-based alert/evidence generators (4 difficulty levels)"],
        ["Graders", "graders/*.py", "Multi-dimensional scoring (classification, technique, evidence, efficiency)"],
        ["Tools", "tools/*.py", "Pure functions: enrichment, log query, correlation, asset/user lookup"],
        ["Baseline Agent", "baseline_agent.py", "Deterministic heuristic agent (rule-based SOC analyst)"],
        ["LLM Harness", "inference.py", "OpenAI-compatible LLM agent runner with prompt engineering"],
        ["Client SDK", "client.py", "Python HTTP wrapper (SOCTriageClient)"],
        ["Benchmark", "benchmark.py", "Multi-seed reproducibility validator"],
        ["Web Dashboard", "server/landing_ui.py", "Interactive HTML/JS UI for Hugging Face Spaces"],
        ["MITRE ATT&CK DB", "data/mitre_attack.py", "Technique ID validation database"],
    ]
    story.append(metric_table(arch_data, [CW*0.18, CW*0.26, CW*0.56]))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 5 — THE FOUR SCENARIOS
    # ════════════════════════════════════════════════════════════
    story.append(Paragraph("5. The Four Scenarios", S["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "SOC Triage Gym features a progressive difficulty curriculum. "
        "Each scenario generates a unique set of alerts, enrichment databases, log databases, "
        "asset inventories, and user directories, all seeded for deterministic reproduction.",
        S["body"]))
    story.append(Spacer(1, 2*mm))

    # ── Scenario 1: Phishing ──
    story.append(Paragraph("Scenario 1: Phishing Triage", S["h2"]))
    story.append(Paragraph('<font color="#9b6b34"><b>DIFFICULTY: EASY  |  1 Alert  |  15 Step Budget</b></font>', S["body"]))
    story.append(Paragraph(
        "A single phishing email with a macro-enabled attachment. The agent must enrich indicators "
        "(sender email, C2 domain, file hash), query email gateway and endpoint logs, classify the "
        "alert as True Positive, map MITRE ATT&CK technique T1566.001 (Spearphishing Attachment), "
        "and recommend containment actions.",
        S["body"]))
    story.append(Paragraph("Grading weights: Classification 40%, Technique 20%, Evidence 20%, Response 20%", S["bullet_2"]))
    story.append(Spacer(1, 2*mm))

    # ── Scenario 2: Lateral Movement ──
    story.append(Paragraph("Scenario 2: Lateral Movement", S["h2"]))
    story.append(Paragraph('<font color="#9b6b34"><b>DIFFICULTY: MEDIUM  |  5 Alerts  |  30 Step Budget</b></font>', S["body"]))
    story.append(Paragraph(
        "A full kill chain: Phishing Email -> Credential Dumping -> RDP Lateral Movement -> "
        "Data Staging -> Exfiltration. All 5 alerts are True Positives. The agent must correlate "
        "them into a coherent attack narrative, map all 5 MITRE techniques (T1566.001, T1003.001, "
        "T1021.001, T1074.001, T1041), and trace the attacker's path from initial access to data theft.",
        S["body"]))
    story.append(Paragraph(
        "Grading weights: Classification 30%, Technique 20%, Kill Chain 20%, Response 20%, Efficiency 10%",
        S["bullet_2"]))
    story.append(Spacer(1, 2*mm))

    # ── Scenario 3: Queue Management ──
    story.append(Paragraph("Scenario 3: Queue Management", S["h2"]))
    story.append(Paragraph('<font color="#9b6b34"><b>DIFFICULTY: HARD  |  20 Alerts  |  60 Step Budget</b></font>', S["body"]))
    story.append(Paragraph(
        "A realistic noisy queue with <b>5 True Positives</b> forming 2 attack chains, "
        "<b>3 Benign True Positives</b> (approved pen test, scheduled backup, etc.), and "
        "<b>12 False Positives</b> (geo-blocking, CDN anomalies, scanner noise). "
        "The agent must find the needles in the haystack while dismissing 75% of alerts as noise.",
        S["body"]))
    story.append(Paragraph(
        "Grading weights: F1 Score 30%, Attack Chains 20%, TP Coverage 20%, Efficiency 15%, Response 15%",
        S["bullet_2"]))
    story.append(Spacer(1, 2*mm))

    # ── Scenario 4: Insider Threat ──
    story.append(Paragraph("Scenario 4: Insider Threat", S["h2"]))
    story.append(Paragraph('<font color="#9b6b34"><b>DIFFICULTY: EXPERT  |  30 Alerts  |  80 Step Budget</b></font>', S["body"]))
    story.append(Paragraph(
        "The largest scenario: <b>9 True Positives</b> across 3 concurrent attack chains "
        "(unauthorized data theft, compromised vendor account, disgruntled employee), "
        "<b>5 Benign True Positives</b>, and <b>16 False Positives</b> (53% noise rate). "
        "Requires parallel investigation of multiple threats with complex behavioral patterns.",
        S["body"]))
    story.append(Paragraph(
        "Grading weights: F1 Score 25%, Attack Chains 25%, TP Coverage 20%, Efficiency 15%, Response 15%",
        S["bullet_2"]))

    story.append(Spacer(1, 3*mm))
    scenario_summary = [
        ["Scenario", "Alerts", "Budget", "TPs", "FPs", "Chains", "Difficulty"],
        ["Phishing", "1", "15", "1", "0", "0", "Easy"],
        ["Lateral Movement", "5", "30", "5", "0", "1", "Medium"],
        ["Queue Management", "20", "60", "5", "12", "2", "Hard"],
        ["Insider Threat", "30", "80", "9", "16", "3", "Expert"],
    ]
    story.append(metric_table(scenario_summary))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 6 — REWARD SYSTEM
    # ════════════════════════════════════════════════════════════
    story.append(Paragraph("6. Reward System and Grading", S["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "SOC Triage Gym uses a <b>dense reward signal</b> at every step, not just at the end. "
        "This means agents get immediate feedback on whether each investigation action was useful, "
        "enabling faster learning than sparse-reward environments.",
        S["body"]))

    story.append(Paragraph("Step-Level Rewards", S["h2"]))
    reward_data = [
        ["Action", "Good Outcome", "Bad Outcome"],
        ["Enrich Indicator", "+0.10 to +0.12 (relevant)", "-0.03 (irrelevant/duplicate)"],
        ["Query Logs", "+0.10 (relevant source)", "-0.05 (irrelevant)"],
        ["Correlate Alerts", "+0.20 (+0.10 kill-chain bonus)", "-0.03 (no shared indicator)"],
        ["Check Asset", "+0.05 (seen in logs)", "-0.03 (not in evidence)"],
        ["Check User", "+0.05 (in evidence)", "-0.03 (not in evidence)"],
        ["Classify Alert", "+0.30 (correct)", "-0.20 (wrong), -0.10 (no evidence)"],
        ["Map Technique", "+0.05 (valid MITRE ID)", "-0.02 (invalid ID)"],
        ["Recommend Action", "+0.08 (expected action)", "+0.05 (no_action on FP)"],
        ["Escalate", "+0.05 (TP escalation)", "-0.10 (FP escalation)"],
        ["Repeated Action", "n/a", "-0.05 per repeat (max -0.20)"],
    ]
    story.append(metric_table(reward_data, [CW*0.22, CW*0.39, CW*0.39]))

    story.append(Paragraph("Final Score Components", S["h2"]))
    story.append(Paragraph(
        "When the agent submits its investigation, the task-specific grader evaluates across "
        "multiple dimensions and produces a weighted score between 0.0 and 1.0:",
        S["body"]))

    grade_dims = [
        ("<b>Classification Accuracy:</b> Did the agent correctly label alerts as TP/FP/BTP?",),
        ("<b>Technique Mapping:</b> Were the correct MITRE ATT&CK techniques identified?",),
        ("<b>Evidence Completeness:</b> Were relevant log sources queried?",),
        ("<b>Kill Chain Reconstruction:</b> Were correlated alerts linked in correct order?",),
        ("<b>Response Quality:</b> Were recommended actions appropriate for each alert?",),
        ("<b>Efficiency:</b> Budget utilization bonus (<=75% budget used = 1.0x multiplier, >90% = 0.7x).",),
    ]
    for g in grade_dims:
        story.append(Paragraph(g[0], S["bullet"], bulletText="\u2022"))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 7 — TOOLS
    # ════════════════════════════════════════════════════════════
    story.append(Paragraph("7. Tools Available to Agents", S["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "Agents interact with the environment through 11 action types. Each action corresponds to "
        "a realistic SOC investigation step:",
        S["body"]))

    tools_data = [
        ["Action", "What It Does", "Real-World Equivalent"],
        ["enrich_indicator", "Look up threat intel on an IP, domain, hash, or email", "VirusTotal / AlienVault OTX query"],
        ["query_logs", "Search SIEM logs (firewall, proxy, DNS, endpoint, auth, etc.)", "Splunk / Sentinel log search"],
        ["correlate_alerts", "Find shared indicators between two alerts", "XDR alert correlation"],
        ["check_asset", "Look up hostname in asset inventory", "CMDB / asset management query"],
        ["check_user", "Look up username for risk and privilege info", "Active Directory / IAM query"],
        ["classify_alert", "Label alert as TP, FP, or BTP with confidence", "Analyst triage decision"],
        ["map_technique", "Assign MITRE ATT&CK technique ID to an alert", "Threat intelligence mapping"],
        ["recommend_action", "Suggest response (isolate, block, disable account, etc.)", "SOAR playbook action"],
        ["escalate", "Escalate alert to higher severity", "Tier 2/3 escalation"],
        ["submit_investigation", "Finalize and trigger grading", "Close investigation ticket"],
        ["noop", "Skip a step (useful for budget management)", "No action"],
    ]
    story.append(metric_table(tools_data, [CW*0.18, CW*0.42, CW*0.40]))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 8 — BASELINE AND BENCHMARKS
    # ════════════════════════════════════════════════════════════
    story.append(Paragraph("8. Baseline Agent and Benchmarks", S["h1"]))
    story.append(hr())
    story.append(Paragraph(
        "SOC Triage Gym ships with a <b>deterministic heuristic baseline agent</b> that acts as a "
        "rule-based SOC analyst. It uses title keyword matching, indicator maliciousness scoring, "
        "and log evidence to make classification decisions. No randomness or LLM calls are involved.",
        S["body"]))

    story.append(Paragraph("Baseline Agent Strategy", S["h2"]))
    baseline_steps = [
        ("<b>Step 1 - Enrich:</b> Look up high-severity indicators (skip private IPs, limit to 2 per type).",),
        ("<b>Step 2 - Query Logs:</b> Search smart log sources based on alert title patterns.",),
        ("<b>Step 3 - Correlate:</b> Find shared indicators with other alerts in the queue.",),
        ("<b>Step 4 - Classify:</b> Use malicious indicator count + log evidence to decide TP/FP/BTP.",),
        ("<b>Step 5 - Map Technique:</b> Pattern-match alert titles to MITRE ATT&CK technique IDs.",),
        ("<b>Step 6 - Recommend:</b> Choose response action based on classification and threat type.",),
        ("<b>Step 7 - Submit:</b> Finalize investigation when all alerts are classified.",),
    ]
    for bs in baseline_steps:
        story.append(Paragraph(bs[0], S["bullet"], bulletText="\u2022"))

    story.append(Spacer(1, 3*mm))
    story.append(Paragraph("Benchmark Results (Seed 42)", S["h2"]))
    bench_data = [
        ["Task", "Score", "Steps Used", "Budget", "Challenge"],
        ["Phishing", "65.0%", "~10", "15", "Single alert, full evidence gathering required"],
        ["Lateral Movement", "71.0%", "~20", "30", "5-alert kill chain correlation"],
        ["Queue Management", "88.5%", "~35", "60", "20-alert queue with 75% false positives"],
        ["Insider Threat", "92.0%", "~45", "80", "30-alert queue with 3 concurrent chains"],
    ]
    story.append(metric_table(bench_data, [CW*0.20, CW*0.10, CW*0.12, CW*0.10, CW*0.48]))

    story.append(Spacer(1, 3*mm))
    story.append(info_box(
        '<b>Overall Baseline Average: ~79%</b>  -- '
        'This leaves significant room for improvement by LLM-powered agents or better RL policies. '
        'Can your agent beat the baseline?',
        S["body"], HexColor("#fef3e2")))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 9 — API AND MCP
    # ════════════════════════════════════════════════════════════
    story.append(Paragraph("9. API Endpoints and MCP Integration", S["h1"]))
    story.append(hr())

    story.append(Paragraph("REST API Endpoints", S["h2"]))
    api_data = [
        ["Method", "Endpoint", "Description"],
        ["GET", "/health", "Server health check"],
        ["POST", "/reset", "Start a new episode (task_id + seed)"],
        ["POST", "/step", "Execute an action and get next observation"],
        ["GET", "/state", "Get current environment state metadata"],
        ["GET", "/tasks", "List available tasks with descriptions"],
        ["GET", "/tasks/{task_id}", "Get specific task details"],
        ["POST", "/grader", "Grade current state without terminating"],
        ["POST", "/baseline", "Run heuristic agent to completion and return score"],
        ["GET", "/metadata", "Environment metadata (OpenEnv compliant)"],
        ["GET", "/schema", "Action and observation JSON schemas"],
        ["POST", "/mcp", "MCP JSON-RPC 2.0 endpoint"],
        ["GET", "/api/alerts", "REST tool: list current alert queue"],
        ["GET", "/threat-intel/{type}/{indicator}", "REST tool: enrichment lookup"],
        ["GET", "/logs/{source}", "REST tool: log query"],
    ]
    story.append(metric_table(api_data, [CW*0.10, CW*0.38, CW*0.52]))

    story.append(Spacer(1, 3*mm))
    story.append(Paragraph("MCP (Model Context Protocol)", S["h2"]))
    story.append(Paragraph(
        "The <b>/mcp</b> endpoint implements JSON-RPC 2.0 for AI tool use. "
        "Agents like Claude, GPT-4, and Gemini can call SOC tools directly via MCP. "
        "Supported methods: <font face='Courier'>tools/list</font> (discover tools) "
        "and <font face='Courier'>tools/call</font> (execute a tool by name with arguments).",
        S["body"]))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 10 — TECH STACK
    # ════════════════════════════════════════════════════════════
    story.append(Paragraph("10. Technology Stack", S["h1"]))
    story.append(hr())
    tech_data = [
        ["Layer", "Technology", "Purpose"],
        ["Language", "Python 3.11+", "Core runtime"],
        ["Web Framework", "FastAPI", "Async HTTP server with auto-generated OpenAPI docs"],
        ["Data Validation", "Pydantic v2", "Type-safe request/response models"],
        ["Server", "Uvicorn", "ASGI server for production deployment"],
        ["HTTP Client", "HTTPX", "Async HTTP client for agent harness"],
        ["LLM Framework", "OpenAI SDK", "Compatible with any OpenAI-API-compatible endpoint"],
        ["MCP", "FastMCP >= 3.2.0", "Model Context Protocol for AI tool calling"],
        ["Containerization", "Docker", "Reproducible deployment on Hugging Face Spaces"],
        ["Testing", "Pytest + pytest-asyncio", "31 tests covering all components"],
        ["Security Intel", "MITRE ATT&CK", "Built-in technique validation database"],
        ["Package Manager", "uv", "Fast dependency resolution and lockfile"],
    ]
    story.append(metric_table(tech_data, [CW*0.17, CW*0.28, CW*0.55]))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 11 — QUICK START
    # ════════════════════════════════════════════════════════════
    story.append(Paragraph("11. Quick-Start Guide", S["h1"]))
    story.append(hr())

    story.append(Paragraph("Option A: Use the Live Hugging Face Space", S["h2"]))
    story.append(Paragraph(
        "Visit <b>huggingface.co/spaces/rohitcraftsyt/openenv2</b> in your browser. "
        "Select a scenario, click Start Episode, then Run Heuristic Agent to see the full cycle.",
        S["body"]))

    story.append(Paragraph("Option B: Run Locally", S["h2"]))
    story.append(Paragraph(
        '<font face="Courier" size="9">'
        '# Clone and install<br/>'
        'git clone https://github.com/ROHITCRAFTSYT/-Metas-OpenEnv-2.git<br/>'
        'cd -Metas-OpenEnv-2<br/>'
        'pip install -e .<br/><br/>'
        '# Start the server<br/>'
        'uvicorn server.app:app --host 0.0.0.0 --port 7860<br/><br/>'
        '# Run the baseline agent<br/>'
        'curl -X POST http://localhost:7860/baseline \\<br/>'
        '  -H "Content-Type: application/json" \\<br/>'
        '  -d \'{"task_id":"phishing","seed":42}\'<br/><br/>'
        '# Run the benchmark<br/>'
        'python benchmark.py<br/><br/>'
        '# Run an LLM agent<br/>'
        'export OPENAI_API_KEY=sk-...<br/>'
        'python inference.py'
        '</font>',
        S["body"]))

    story.append(Paragraph("Option C: Use the Python Client", S["h2"]))
    story.append(Paragraph(
        '<font face="Courier" size="9">'
        'from client import SOCTriageClient<br/><br/>'
        'with SOCTriageClient("http://localhost:7860") as client:<br/>'
        '    obs = client.reset(task_id="phishing", seed=42)<br/>'
        '    while not obs.done:<br/>'
        '        action = my_agent.decide(obs)<br/>'
        '        obs = client.step(action)<br/>'
        '    print(f"Final reward: {obs.cumulative_reward}")'
        '</font>',
        S["body"]))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 12 — DIFFERENTIATORS
    # ════════════════════════════════════════════════════════════
    story.append(Paragraph("12. Key Differentiators", S["h1"]))
    story.append(hr())

    diffs = [
        ("<b>Realistic Domain Fidelity:</b> Not a toy problem. Alerts, evidence, kill chains, and MITRE "
         "ATT&CK integration mirror actual SOC analyst workflows.",),
        ("<b>Dense Reward Signal:</b> Step-level feedback (+0.10 for good enrichment, -0.20 for wrong "
         "classification) enables gradient-based learning, unlike sparse end-of-episode rewards.",),
        ("<b>100% Deterministic:</b> Instance-level RNG (never global random.seed()) guarantees that same "
         "seed = identical scenario = identical grading. Critical for reproducible research.",),
        ("<b>Progressive Curriculum:</b> Four tasks from Easy (1 alert) to Expert (30 alerts, 3 chains, 53% "
         "noise) let agents train on a natural difficulty progression.",),
        ("<b>Multi-Interface:</b> REST API + MCP JSON-RPC + Python client + interactive web UI. "
         "Works with any LLM, any RL framework, or direct human interaction.",),
        ("<b>Production-Ready:</b> Docker deployment, health checks, thread-safe environment, "
         "31/31 tests passing, security policy, Hugging Face Space hosting.",),
        ("<b>OpenEnv Compliant:</b> Passes all openenv-core validation checks. Drop-in compatible with the "
         "OpenEnv ecosystem for standardized agent evaluation.",),
        ("<b>Strong but Beatable Baseline:</b> The 79% heuristic baseline proves the task is non-trivial "
         "but leaves room for smarter agents to improve.",),
    ]
    for d in diffs:
        story.append(Paragraph(d[0], S["bullet"], bulletText="\u2022"))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 13 — ROADMAP
    # ════════════════════════════════════════════════════════════
    story.append(Paragraph("13. Future Roadmap", S["h1"]))
    story.append(hr())
    roadmap = [
        ("<b>More Scenarios:</b> Ransomware, supply chain attack, DDoS triage, cloud misconfiguration.",),
        ("<b>Multi-Agent Support:</b> Simulate a SOC team with Tier 1/2/3 analyst roles and handoff.",),
        ("<b>Dynamic Difficulty:</b> Adaptive noise rates based on agent performance.",),
        ("<b>Real SIEM Integration:</b> Plug into actual Splunk/Sentinel data for hybrid training.",),
        ("<b>Leaderboard:</b> Public scoreboard for comparing agents across seeds and tasks.",),
        ("<b>Curriculum Learning:</b> Auto-promote agents from Easy to Expert as they improve.",),
        ("<b>Adversarial Mode:</b> Red team agent that adapts its attack patterns to evade the blue team.",),
    ]
    for r in roadmap:
        story.append(Paragraph(r[0], S["bullet"], bulletText="\u2022"))
    story.append(PageBreak())

    # ════════════════════════════════════════════════════════════
    # SECTION 14 — CHEAT SHEET
    # ════════════════════════════════════════════════════════════
    story.append(Paragraph("14. Quick Reference Cheat Sheet", S["h1"]))
    story.append(hr())

    story.append(Paragraph("Investigation Workflow (Tell the Judges This)", S["h2"]))
    story.append(info_box(
        '<font face="Courier" size="9">'
        '1. ENRICH  -->  Look up suspicious indicators in threat intel<br/>'
        '2. QUERY   -->  Search SIEM logs for corroborating evidence<br/>'
        '3. CORRELATE -> Link alerts that share indicators (IPs, domains, users)<br/>'
        '4. CHECK   -->  Verify assets and users involved<br/>'
        '5. CLASSIFY --> Label each alert as True/False/Benign Positive<br/>'
        '6. MAP     -->  Assign MITRE ATT&CK technique IDs<br/>'
        '7. RESPOND -->  Recommend containment actions<br/>'
        '8. SUBMIT  -->  Finalize and get your score'
        '</font>',
        S["body"], PANEL))

    story.append(Spacer(1, 3*mm))
    story.append(Paragraph("Elevator Pitch (30 Seconds)", S["h2"]))
    story.append(info_box(
        '"SOC Triage Gym is a reinforcement learning environment where AI agents learn to be '
        'cybersecurity analysts. It simulates realistic alert triage across four difficulty levels, '
        'from single-email phishing to 30-alert insider threat investigations with 53% noise. '
        'Agents get step-level reward feedback on every investigation action, and are graded on '
        'classification accuracy, MITRE ATT&CK mapping, evidence gathering, and response quality. '
        'Our heuristic baseline scores 79% -- can your agent do better?"',
        S["body"], HexColor("#eef4f8")))

    story.append(Spacer(1, 3*mm))
    story.append(Paragraph("Key Numbers to Remember", S["h2"]))
    numbers_data = [
        ["Number", "What It Means"],
        ["4 tasks", "Phishing, Lateral Movement, Queue Management, Insider Threat"],
        ["11 actions", "enrich, query, correlate, check_asset, check_user, classify, map, recommend, escalate, submit, noop"],
        ["30 alerts", "Maximum queue size (Insider Threat scenario)"],
        ["53% FP rate", "Highest false positive rate (Insider Threat)"],
        ["79% baseline", "Average heuristic agent score across all tasks"],
        ["31/31 tests", "Full test coverage passing"],
        ["100% deterministic", "Same seed = identical results, always"],
        ["~4,500 lines", "Core codebase size (not counting tests or UI)"],
    ]
    story.append(metric_table(numbers_data, [CW*0.25, CW*0.75]))

    story.append(Spacer(1, 6*mm))
    story.append(info_box(
        '<b>Good luck at the hackathon! You have built something genuinely useful '
        'for the cybersecurity and AI research communities.</b>',
        S["body"], HexColor("#e7f3eb")))

    # ── BUILD ───────────────────────────────────────────────────
    doc.build(story,
              onFirstPage=title_page_bg,
              onLaterPages=page_bg)
    print(f"PDF generated: {output_path}")


if __name__ == "__main__":
    build_pdf(r"D:\openenv-2\SOC_Triage_Gym_Hackathon_Guide.pdf")
