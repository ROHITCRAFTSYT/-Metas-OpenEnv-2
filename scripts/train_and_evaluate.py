"""
Unattended driver: train GRPO on tier1, save checkpoint, evaluate vs oracle,
emit the judge-ready plot. Run after setting up the Colab/GPU environment.

Usage (Colab, after notebook cells 1-4 have run):
    !python scripts/train_and_evaluate.py

Produces:
    checkpoints/soc_grpo_tier1/            — LoRA adapter (reloadable)
    trained_vs_baseline.png                — eval plot for README / demo
    trained_vs_baseline.csv                — raw per-episode scores
    training_summary.json                  — metrics for demo.py to read
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

SERVER_URL = os.environ.get("SERVER_URL", "http://localhost:7860")
ROLE = os.environ.get("ROLE", "tier1")
MODEL_NAME = os.environ.get("MODEL_NAME", "Qwen/Qwen2.5-1.5B-Instruct")
CKPT_DIR = ROOT / "checkpoints" / f"soc_grpo_{ROLE}"
EVAL_SEEDS = list(range(100, 115))  # held-out, not in training


def ensure_server() -> subprocess.Popen | None:
    """Start the env server if not already up. Returns the process (to terminate later) or None."""
    probe = httpx.Client(base_url=SERVER_URL, timeout=3.0)
    try:
        if probe.get("/health").status_code == 200:
            print(f"[server] already running at {SERVER_URL}")
            return None
    except Exception:
        pass

    print(f"[server] starting uvicorn on {SERVER_URL} ...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "server.app:app",
         "--host", "0.0.0.0", "--port", "7860"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    for _ in range(30):
        time.sleep(2)
        if proc.poll() is not None:
            err = proc.stderr.read(3000).decode(errors="replace")
            raise RuntimeError(f"server exited early:\n{err}")
        try:
            if probe.get("/health").status_code == 200:
                print("[server] ready")
                return proc
        except Exception:
            continue
    proc.terminate()
    raise RuntimeError("server never became healthy")


def train_policy() -> None:
    """Run GRPO training via the train_grpo.train() entrypoint."""
    from train_grpo import train as grpo_train

    print(f"\n[train] GRPO on role={ROLE} model={MODEL_NAME}")
    grpo_train(
        role=ROLE,
        model_name=MODEL_NAME,
        num_train_epochs=3,
        output_dir=str(CKPT_DIR),
        use_unsloth=True,
    )
    print(f"[train] checkpoint saved to {CKPT_DIR}")


def evaluate() -> dict:
    """Load the trained adapter, run held-out eval on tier1 tasks, compare vs oracle."""
    from train_grpo import (
        TIER1_TASKS, ROLE_SYSTEM_PROMPTS,
        run_episode, parse_action_from_text, format_obs_prompt, oracle_action,
    )
    import torch
    from unsloth import FastLanguageModel

    client = httpx.Client(base_url=SERVER_URL, timeout=180.0)

    # 1) Oracle baseline
    print("\n[eval] oracle baseline ...")
    oracle_scores = []
    for task in TIER1_TASKS:
        for seed in EVAL_SEEDS:
            s, _ = run_episode(client, task_id=task, seed=seed, role_to_train=ROLE)
            oracle_scores.append(max(0.0, float(s)))
            print(f"  oracle  {task} seed={seed}: {oracle_scores[-1]:.4f}")
    oracle_avg = sum(oracle_scores) / len(oracle_scores)

    # 2) Trained policy
    print("\n[eval] loading trained checkpoint ...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=str(CKPT_DIR),
        max_seq_length=768,
        dtype=None,
        load_in_4bit=True,
    )
    FastLanguageModel.for_inference(model)

    if not getattr(tokenizer, "chat_template", None):
        tokenizer.chat_template = (
            "{% for message in messages %}"
            "<|im_start|>{{ message['role'] }}\n{{ message['content'] }}<|im_end|>\n"
            "{% endfor %}"
            "{% if add_generation_prompt %}<|im_start|>assistant\n{% endif %}"
        )

    def run_trained(task_id: str, seed: int) -> float:
        obs = client.post("/reset", json={"task_id": task_id, "seed": seed, "mode": "team"}).json()
        step = 0
        while not obs.get("done") and step < 80:
            step += 1
            role = obs.get("current_role") or "tier1"
            if role == ROLE:
                prompt = format_obs_prompt(obs, role, step)
                messages = [
                    {"role": "system", "content": ROLE_SYSTEM_PROMPTS[ROLE]},
                    {"role": "user", "content": prompt},
                ]
                enc = tokenizer.apply_chat_template(
                    messages, tokenize=True, add_generation_prompt=True, return_tensors="pt"
                )
                input_ids = enc if torch.is_tensor(enc) else enc["input_ids"]
                input_ids = input_ids.to(model.device)
                with torch.no_grad():
                    out = model.generate(
                        input_ids=input_ids, max_new_tokens=128, do_sample=False,
                        pad_token_id=tokenizer.pad_token_id or tokenizer.eos_token_id,
                    )
                text = tokenizer.decode(out[0][input_ids.shape[1]:], skip_special_tokens=True)
                action = parse_action_from_text(text, role) or {"action_type": "noop", "role": role}
            else:
                action = oracle_action(obs)
            resp = client.post("/step", content=json.dumps(action),
                               headers={"Content-Type": "application/json"})
            if resp.status_code != 200:
                break
            obs = resp.json()
        return float(obs.get("task_score") or obs.get("cumulative_reward", 0.0))

    print("\n[eval] trained policy ...")
    trained_scores = []
    for task in TIER1_TASKS:
        for seed in EVAL_SEEDS:
            s = run_trained(task, seed)
            trained_scores.append(max(0.0, s))
            print(f"  trained {task} seed={seed}: {trained_scores[-1]:.4f}")
    trained_avg = sum(trained_scores) / len(trained_scores)

    return {
        "oracle_scores": oracle_scores,
        "trained_scores": trained_scores,
        "oracle_avg": oracle_avg,
        "trained_avg": trained_avg,
        "n_episodes": len(trained_scores),
        "role": ROLE,
        "model_name": MODEL_NAME,
        "eval_seeds": EVAL_SEEDS,
    }


def emit_artifacts(summary: dict) -> None:
    import csv
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    # CSV
    csv_path = ROOT / "trained_vs_baseline.csv"
    with csv_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["episode", "oracle", "trained"])
        for i, (o, t) in enumerate(zip(summary["oracle_scores"], summary["trained_scores"])):
            w.writerow([i + 1, o, t])

    # JSON summary for demo.py
    (ROOT / "training_summary.json").write_text(json.dumps({
        "role": summary["role"],
        "model_name": summary["model_name"],
        "oracle_avg": summary["oracle_avg"],
        "trained_avg": summary["trained_avg"],
        "delta": summary["trained_avg"] - summary["oracle_avg"],
        "n_episodes": summary["n_episodes"],
    }, indent=2))

    # Plot
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle(f"GRPO Training Results — role={summary['role']}",
                 fontsize=14, fontweight="bold")

    ax = axes[0]
    ax.bar(["Oracle baseline", "GRPO trained"],
           [summary["oracle_avg"], summary["trained_avg"]],
           color=["#4C72B0", "#DD8452"], alpha=0.85, edgecolor="black")
    ax.set_ylim(0, max(1.0, summary["trained_avg"] * 1.2))
    ax.set_ylabel("Episode score")
    ax.set_title("Mean held-out score")
    ax.axhline(0.5, linestyle="--", color="gray", alpha=0.5)
    for i, v in enumerate([summary["oracle_avg"], summary["trained_avg"]]):
        ax.text(i, v + 0.01, f"{v:.3f}", ha="center", fontweight="bold")

    ax2 = axes[1]
    x = range(1, summary["n_episodes"] + 1)
    ax2.plot(x, summary["oracle_scores"], "o-", alpha=0.5,
             label="Oracle", color="#4C72B0")
    ax2.plot(x, summary["trained_scores"], "s-", alpha=0.75,
             label="GRPO trained", color="#DD8452")
    w = min(5, summary["n_episodes"])
    if summary["n_episodes"] >= w and w >= 2:
        sm = np.convolve(summary["trained_scores"], np.ones(w) / w, mode="valid")
        ax2.plot(range(w, summary["n_episodes"] + 1), sm, linewidth=2.5,
                 color="#C44E52", label="Trained (smoothed)")
    ax2.set_xlabel("Held-out episode")
    ax2.set_ylabel("Score")
    ax2.set_title("Per-episode (held-out seeds 100–114 × 2 tasks)")
    ax2.legend()
    plt.tight_layout()
    fig.savefig(ROOT / "trained_vs_baseline.png", dpi=150, bbox_inches="tight")

    print(f"\n[artifacts] wrote:")
    print(f"  {ROOT / 'trained_vs_baseline.png'}")
    print(f"  {csv_path}")
    print(f"  {ROOT / 'training_summary.json'}")
    print(f"\n[summary] oracle={summary['oracle_avg']:.4f}  "
          f"trained={summary['trained_avg']:.4f}  "
          f"delta={summary['trained_avg'] - summary['oracle_avg']:+.4f}")


def main() -> None:
    proc = ensure_server()
    try:
        train_policy()
        summary = evaluate()
        emit_artifacts(summary)
        print("\n[done] next:")
        print("  git add checkpoints/ trained_vs_baseline.* training_summary.json")
        print("  git commit -m 'Add trained tier1 checkpoint + eval artifacts'")
        print("  git push")
    finally:
        if proc is not None:
            proc.terminate()


if __name__ == "__main__":
    main()
