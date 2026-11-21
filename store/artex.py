"""ARTEX ramp: many ARTEX-shaped agents, varied techniques, at a level you change live.

    python -m store.artex https://xxxx.cloudfront.net

Each wave it reads an intensity level (0-6) and runs that many agents in parallel against
YOUR OWN Northwind store. Every agent picks its own technique profile (recon, idor,
credential, injection, scrape, mixed) and its own client identity, so the defense is
tested against variety, not one scripted attack. Change the level live to ramp up or down:

    aws ssm put-parameter --name /undertow/artex/level --type String --overwrite --value 4

Levels (agents, pause scale):
    0 off · 1 (1, slow) · 2 (2) · 3 (3) · 4 (5) · 5 (8, fast) · 6 FLOOD (ARTEX_MAX, minimal pause)

This is a test harness against your own target: it refuses non-store hosts and caps agents
at ARTEX_MAX (default 50).
"""
from __future__ import annotations

import os
import random
import sys
import threading
import time

from .attack_sim import PROFILES, is_store, run_agent

MAX_AGENTS = int(os.environ.get("ARTEX_MAX", 50))
LEVELS = {0: (0, 1.0), 1: (1, 2.0), 2: (2, 1.4), 3: (3, 1.0), 4: (5, 0.6), 5: (8, 0.35), 6: (MAX_AGENTS, 0.1)}

# a pool of distinct, non-browser client identities (Undertow keys actors by /24 + User-Agent,
# so each agent shows up as its own attacker; browser UAs would collapse to one via JA4).
_CLIENTS = ["python-httpx", "Go-http-client", "curl", "aiohttp", "okhttp", "Apache-HttpClient",
            "node-fetch", "scan-probe", "python-requests", "libwww-perl", "Java-http", "ruby-faraday",
            "axios", "got", "undici", "httpie", "Wget", "PostmanRuntime", "insomnia", "rest-client"]
UAS = [f"{c}/{1 + i % 5}.{i % 9}.{i % 7}" for i, c in enumerate(_CLIENTS * 3)][:MAX_AGENTS]


def read_level(default: int) -> int:
    name = os.environ.get("ARTEX_SSM", "/undertow/artex/level")
    try:
        import boto3
        v = boto3.client("ssm").get_parameter(Name=name)["Parameter"]["Value"]
        return max(0, min(6, int(v)))
    except Exception:  # noqa: BLE001 - no SSM access or not set: fall back to the env level
        try:
            return max(0, min(6, int(os.environ.get("ARTEX_LEVEL", default))))
        except ValueError:
            return default


def wave(base: str, agents: int, think: float, seconds: float) -> dict:
    results, threads = [], []
    lock = threading.Lock()

    def one(i):
        out = run_agent(base, seconds=seconds, think=think, tag=f"a{i}", verbose=True,
                        ua=UAS[i % len(UAS)], profile=random.choice(PROFILES))
        with lock:
            results.append(out)

    n = min(agents, MAX_AGENTS)
    for i in range(n):
        t = threading.Thread(target=one, args=(i,), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(min(0.4, 6.0 / n))   # stagger; tighter for big floods
    for t in threads:
        t.join()
    by_profile: dict[str, int] = {}
    for r in results:
        by_profile[r["profile"]] = by_profile.get(r["profile"], 0) + 1
    return {"requests": sum(r["requests"] for r in results), "cell": sum(r["cell"] for r in results),
            "throttled": sum(r["throttled"] for r in results), "agents": len(results), "profiles": by_profile}


def main(base: str):
    if not is_store(base):
        sys.exit("refusing: that host is not the Northwind store")
    total = float(os.environ.get("ARTEX_DURATION", 1800))
    wave_s = float(os.environ.get("ARTEX_WAVE", 45))
    deadline = time.time() + total
    print(f"ARTEX ramp against {base} — up to {MAX_AGENTS} agents, varied techniques. "
          f"Change the level any time (aws ssm put-parameter --name "
          f"{os.environ.get('ARTEX_SSM', '/undertow/artex/level')} --type String --overwrite --value N)", flush=True)
    while time.time() < deadline:
        level = read_level(1)
        agents, think = LEVELS[level]
        if agents == 0:
            print("== level 0: idle ==", flush=True)
            time.sleep(wave_s)
            continue
        label = "FLOOD" if level == 6 else f"level {level}"
        print(f"== {label}: {min(agents, MAX_AGENTS)} agents ==", flush=True)
        out = wave(base, agents, think, wave_s if level < 6 else 0)
        mix = ", ".join(f"{k}:{v}" for k, v in sorted(out["profiles"].items()))
        print(f"== wave done: {out['agents']} agents ({mix}), {out['requests']} requests, "
              f"{out['cell']} from the padded cell, {out['throttled']} throttled ==", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
