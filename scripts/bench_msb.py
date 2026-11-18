# /// script
# requires-python = ">=3.10"
# dependencies = ["pyarrow"]
# ///
"""Score decloak on MaliciousSkillBench (https://huggingface.co/datasets/ProtectSkills/MaliciousSkillBench).

Downloads the pinned revision once into .bench/msb/, writes each skill's frozen
text to its own SKILL.md, scans the tree with the decloak CLI, and reports
per-skill precision / recall / false-positive rate at each severity threshold.

The default is the source-disjoint test split (839 malicious, 545 benign), the
held-out partition other scanners publish. Tune rules on train/validation only.

    uv run scripts/bench_msb.py [--bin ./decloak] [--split source_disjoint] [--part test]
    uv run scripts/bench_msb.py --part validation --judge-bin ./decloak-judge --judge-only

Benchmark text is CC-BY-4.0 metadata over third-party skills; nothing is
committed to this repository.
"""
import argparse
import collections
import json
import os
import shutil
import subprocess
import urllib.request

import pyarrow.parquet as pq

REPO = "ProtectSkills/MaliciousSkillBench"
REVISION = "d4b42ce5766a6e0359c987cf59c1007cb3795a90"
FILES = ["primary.parquet", "splits/source_disjoint.parquet", "splits/m_structural_disjoint.parquet",
         "splits/random.parquet", "splits/source_balanced_random.parquet"]
SEV = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(ROOT, ".bench", "msb")


def fetch():
    for f in FILES:
        dst = os.path.join(CACHE, f)
        if os.path.exists(dst):
            continue
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        url = f"https://huggingface.co/datasets/{REPO}/resolve/{REVISION}/{f}"
        print("downloading", url)
        with urllib.request.urlopen(url, timeout=120) as r, open(dst + ".part", "wb") as out:
            shutil.copyfileobj(r, out)
        os.replace(dst + ".part", dst)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=os.path.join(ROOT, "decloak"))
    ap.add_argument("--split", default="source_disjoint")
    ap.add_argument("--part", default="test", choices=["train", "validation", "test"])
    ap.add_argument("--policy", action="store_true", help="enable decloak's --policy rule stream")
    ap.add_argument("--judge-bin", help="path to decloak-judge; unions LLM verdicts with static findings")
    ap.add_argument("--judge-only", action="store_true", help="score judge findings only (requires --judge-bin)")
    ap.add_argument("--judge-model", help="judge model name (default: judge's own env/config)")
    ap.add_argument("--judge-provider", default="opencode", choices=["openai", "opencode"],
                    help="provider preset for the judge (default: opencode)")
    ap.add_argument("--judge-workers", type=int, default=4, help="concurrent judge requests")
    ap.add_argument("--breakdown", action="store_true", help="break HIGH+ recall down by source and category")
    ap.add_argument("--json", action="store_true", help="print the full report as JSON")
    args = ap.parse_args()

    fetch()
    split = pq.read_table(os.path.join(CACHE, "splits", f"{args.split}.parquet")).to_pylist()
    ids = {r["benchmark_id"] for r in split if r["split"] == args.part}
    cols = ["benchmark_id", "label", "skill_text", "public_skill_text"]
    if args.breakdown:
        cols += ["source_name", "provenance", "evidence_type", "attack_categories"]
    rows = {r["benchmark_id"]: r for r in pq.read_table(
        os.path.join(CACHE, "primary.parquet"), columns=cols).to_pylist() if r["benchmark_id"] in ids}

    work = os.path.join(CACHE, "work", f"{args.split}-{args.part}")
    shutil.rmtree(work, ignore_errors=True)
    for bid, r in rows.items():
        os.makedirs(os.path.join(work, bid))
        with open(os.path.join(work, bid, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write(r["skill_text"] or r["public_skill_text"] or "")

    extra = ["--policy"] if args.policy else []
    findings = []
    if not args.judge_only:
        out = subprocess.run([args.bin, "scan", work, "--fail-on", "low", "-f", "json", *extra],
                             capture_output=True, text=True, check=False)
        if out.returncode not in (0, 1):
            raise SystemExit(f"decloak failed ({out.returncode}): {out.stderr}")
        findings = json.loads(out.stdout)
        findings = findings.get("findings", findings) if isinstance(findings, dict) else findings

    judge_count = 0
    if args.judge_bin:
        judge_cmd = [args.judge_bin, "scan", work, "--fail-on", "low", "-f", "json",
                     "--workers", str(args.judge_workers), "--provider", args.judge_provider, *extra]
        if args.judge_model:
            judge_cmd += ["--model", args.judge_model]
        jout = subprocess.run(judge_cmd, capture_output=True, text=True, check=False)
        if jout.returncode not in (0, 1):
            raise SystemExit(f"decloak-judge failed ({jout.returncode}): {jout.stderr}")
        jfindings = json.loads(jout.stdout)
        jfindings = jfindings.get("findings", jfindings) if isinstance(jfindings, dict) else jfindings
        judge_count = len(jfindings)
        findings = list(findings) + list(jfindings)

    worst = collections.defaultdict(int)
    for f in findings:
        bid = os.path.basename(os.path.dirname(f["file_path"]))
        worst[bid] = max(worst[bid], SEV[f["severity"]])

    mal = sum(int(r["label"]) == 1 for r in rows.values())
    report = {"benchmark": f"{REPO}@{REVISION[:7]}", "split": f"{args.split}/{args.part}",
              "malicious": mal, "benign": len(rows) - mal, "thresholds": {}}
    if args.judge_bin:
        report["judge"] = {"binary": args.judge_bin, "model": args.judge_model,
                           "only": args.judge_only, "findings": judge_count}
    print(f"{report['benchmark']} {report['split']}: {mal} malicious, {len(rows) - mal} benign")
    if args.judge_bin:
        print(f"judge: {judge_count} findings from {args.judge_bin}"
              + (f" (model {args.judge_model})" if args.judge_model else "")
              + (" [judge-only]" if args.judge_only else ""))
    print(f"{'threshold':10} {'recall':>7} {'FPR':>6} {'precision':>9} {'F1':>6}")
    for name, t in (("LOW+", 1), ("MEDIUM+", 2), ("HIGH+", 3), ("CRITICAL", 4)):
        tp = sum(int(r["label"]) == 1 and worst[b] >= t for b, r in rows.items())
        fp = sum(int(r["label"]) == 0 and worst[b] >= t for b, r in rows.items())
        rec, fpr = tp / mal, fp / (len(rows) - mal)
        prec = tp / (tp + fp) if tp + fp else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        report["thresholds"][name] = {"tp": tp, "fp": fp, "recall": rec, "fpr": fpr, "precision": prec, "f1": f1}
        print(f"{name:10} {rec:7.1%} {fpr:6.1%} {prec:9.1%} {f1:6.1%}")
    if args.breakdown:
        high = 3
        groups = {"source_name": collections.defaultdict(list), "evidence_type": collections.defaultdict(list),
                  "provenance": collections.defaultdict(list)}
        for bid, r in rows.items():
            for key, acc in groups.items():
                acc[(r.get(key) or "unknown", int(r["label"]))].append(worst[bid] >= high)
        report["breakdown"] = {}
        for key, acc in groups.items():
            names = sorted({n for n, _ in acc})
            print(f"\n{key} (HIGH+):")
            print(f"  {'group':40} {'mal n':>6} {'recall':>7} {'ben n':>6} {'FPR':>6}")
            report["breakdown"][key] = {}
            for name in names:
                m = acc.get((name, 1), [])
                b = acc.get((name, 0), [])
                rec = sum(m) / len(m) if m else 0.0
                fpr = sum(b) / len(b) if b else 0.0
                report["breakdown"][key][name] = {"mal": len(m), "recall": rec, "ben": len(b), "fpr": fpr}
                print(f"  {name[:40]:40} {len(m):6d} {rec:7.1%} {len(b):6d} {fpr:6.1%}")
    if args.json:
        print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
