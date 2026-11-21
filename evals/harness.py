"""Run the labeled scenarios through the detectors and report FP / FN.

    python -m evals.harness

Each scenario's events are split into actors and linked into campaigns exactly as the live
scorer does (actor_key -> evaluate -> campaign link -> combine -> verdict). An attack passes
only if EVERY actor in it reaches its target, so a distributed attack that leaves 19 of 20
IPs free fails. A benign scenario fails if ANY of its actors is slowed or blocked.
Exit code is non-zero on any miss or hard false positive.
"""
from __future__ import annotations

import sys
from collections import defaultdict

from aa_ai import campaigns, detectors
from aa_ai.scoring import BLOCK, TARPIT, WATCH, actor_key, combine, evaluate, verdict

from .scenarios import all_scenarios

LEVEL = {"allow": 0, "watch": 1, "tarpit": 2, "block": 3}
DECOY_PREFIX = "/api/v1/internal/ops"

# What the defence SHOULD do to each attacker. "block" = hard-stop; "challenge" = reach at
# least watch, where the edge silently challenges (a script fails, a browser passes). A
# scraper, a lone spoofed browser, or a client that only reads the API map and walks it
# (no attack payload, no misses) is style, not intent: challenge, never a hard block.
EXPECT = {
    "recon_then_walk": "challenge", "idor_walk": "block", "credential_stuffing": "block",
    "injection_fuzz": "block", "retry_after_ignorer": "block", "tool_fingerprint": "block",
    "decoy_touch": "block", "honey_replay": "block",
    "scrape_flood": "challenge", "spoofed_browser": "challenge",
    # evasion-aware: the attacker adapts to the detectors
    "human_paced_idor": "block", "slow_and_low_idor": "block", "jittered_credential_spray": "block",
    "ua_rotating_idor": "block", "distributed_idor": "block", "distributed_injection": "block",
    "jittered_injection": "block",
}
MIN_LEVEL = {"block": LEVEL["tarpit"], "challenge": LEVEL["watch"]}


def _prime():
    detectors.DECOY_PREFIXES.add(DECOY_PREFIX)
    detectors.HONEY_IDS.update({"731000001"})   # not used by scenarios; honey tag handled via extra


def score_actors(events) -> list[tuple[str, float, str, list]]:
    """(actor, score, verdict, signals) per actor, campaigns linked as the live scorer links them."""
    groups: dict[str, list] = defaultdict(list)
    for e in events:
        groups[actor_key(e)].append(e)
    for evs in groups.values():
        evs.sort(key=lambda e: e.ts)
    byfp: dict[str, dict] = defaultdict(dict)
    for k, evs in groups.items():
        fp = campaigns.actor_fp(evs)
        if fp:
            byfp[fp][k] = evs
    camp = {}
    for members in byfp.values():
        camp.update(campaigns.link(members))
    out = []
    for k, evs in groups.items():
        sigs = evaluate(evs) + ([camp[k]] if k in camp else [])
        s = combine(sigs)
        out.append((k, s, verdict(s), sigs))
    return out


def score(events) -> tuple[float, str, list]:
    """The scenario's least-caught actor for attacks is reported by run(); this is the worst one."""
    k, s, v, sigs = max(score_actors(events), key=lambda r: (LEVEL[r[2]], r[1]))
    return s, v, sigs


def run(seed: int = 0) -> dict:
    _prime()
    rows, det_hits, det_attacks = [], {}, 0
    misses, hard_fp, challenged_benign = [], [], []
    tp = attacks = benign = 0
    for name, is_attack, events in all_scenarios(seed):
        actors = score_actors(events)
        if is_attack:     # judged by its LEAST-caught actor: every IP has to be stopped
            k, s, v, sigs = min(actors, key=lambda r: (LEVEL[r[2]], r[1]))
        else:             # judged by its MOST-punished actor
            k, s, v, sigs = max(actors, key=lambda r: (LEVEL[r[2]], r[1]))
        lvl = LEVEL[v]
        if is_attack:
            attacks += 1
            want = MIN_LEVEL[EXPECT.get(name, "block")]
            ok = lvl >= want
            tp += ok
            if not ok:
                misses.append(name)
            det_attacks += 1
            for sg in {sg.name for a in actors for sg in a[3]}:
                det_hits[sg] = det_hits.get(sg, 0) + 1
        else:
            benign += 1
            ok = lvl < LEVEL["tarpit"]            # must not be hard-stopped
            if not ok:
                hard_fp.append(name)
            if lvl == LEVEL["watch"]:             # would be silently challenged (ok for browsers)
                challenged_benign.append(name)
        rows.append({"name": name, "attack": is_attack, "score": round(s, 3), "verdict": v,
                     "expect": EXPECT.get(name, "-") if is_attack else "allow", "ok": ok,
                     "actors": len(actors), "signals": [sg.name for sg in sigs]})
    return {
        "rows": rows, "attacks": attacks, "benign": benign,
        "misses": misses, "hard_fp": hard_fp, "challenged_benign": challenged_benign,
        "fn_rate": round(len(misses) / attacks, 3) if attacks else 0.0,
        "fp_rate": round(len(hard_fp) / benign, 3) if benign else 0.0,
        "recall": round(tp / attacks, 3) if attacks else 0.0,
        "det_recall": {k: round(v / det_attacks, 2) for k, v in sorted(det_hits.items(), key=lambda x: -x[1])},
    }


def report(res: dict) -> str:
    out = ["Undertow detection eval", "=" * 66,
           f"thresholds: watch {WATCH} / tarpit {TARPIT} / block {BLOCK}", ""]
    out.append(f"{'scenario':<27}{'label':<8}{'actors':>6}{'score':>7}  {'verdict':<8}{'want':<11}{'result'}")
    out.append("-" * 78)
    for r in sorted(res["rows"], key=lambda r: (not r["attack"], r["name"])):
        mark = "OK" if r["ok"] else ("MISS" if r["attack"] else "HARD FALSE POSITIVE")
        want = r["expect"] if r["attack"] else "allow/watch"
        out.append(f"{r['name']:<27}{'attack' if r['attack'] else 'benign':<8}{r['actors']:>6}{r['score']:>7.2f}  "
                   f"{r['verdict']:<8}{want:<11}{mark}")
    out += ["", f"attacks missed (false negative): {len(res['misses'])}/{res['attacks']}  "
            f"(rate {res['fn_rate']})" + (f"  -> {', '.join(res['misses'])}" if res['misses'] else ""),
            f"benign hard-blocked (false positive): {len(res['hard_fp'])}/{res['benign']}  (rate {res['fp_rate']})"
            + (f"  -> {', '.join(res['hard_fp'])}" if res['hard_fp'] else ""),
            f"recall on attacks: {res['recall']}"]
    if res["challenged_benign"]:
        out.append(f"benign that would be silently challenged (fine for browsers; allow-list real "
                   f"non-browser clients): {', '.join(res['challenged_benign'])}")
    out += ["", "per-detector recall on attacks:"]
    for k, v in res["det_recall"].items():
        out.append(f"  {k:<24} {v}")
    return "\n".join(out)


def main() -> int:
    res = run()
    print(report(res))
    if res["misses"] or res["hard_fp"]:
        print("\nFAIL:", ", ".join(res["misses"] + res["hard_fp"]))
        return 1
    print("\nPASS: every attack met its target verdict; no benign hard-blocked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
