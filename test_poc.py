#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json, time, statistics
from sign_verify import Signer, Verifier, now_ms
import base64

def p95(xs): 
    xs = sorted(xs); 
    return xs[int(0.95*(len(xs)-1))] if xs else 0.0

def main():
    # 準備 signer / verifier
    import sys, json
    with open("ml_dsa_sec.json","r",encoding="utf-8") as f: sec = json.load(f)
    with open("ml_dsa_pub.json","r",encoding="utf-8") as f: pub = json.load(f)
    s = Signer(sec)
    v = Verifier({pub["pubkey_id"]: pub}, window_ms=2000)

    lat_ok = []
    results = {k: {"pass":0,"fail":0} for k in ["correct","tamper","wrong_key","expired","replay"]}

    # 1) correct ×10
    for _ in range(10):
        signed = s.sign_message(s.make_cmd(0.1,0.2))
        t0 = time.perf_counter_ns()
        ok, code = v.verify(signed)
        dt = (time.perf_counter_ns()-t0)/1e6
        if ok: lat_ok.append(dt); results["correct"]["pass"]+=1
        else: results["correct"]["fail"]+=1

    # 2) tamper ×10
    for _ in range(10):
        signed = s.sign_message(s.make_cmd(0.1,0.2))
        signed["payload"]["linear"]["x"] += 1e-4
        ok, code = v.verify(signed)
        results["tamper"]["pass" if not ok else "fail"] += 1

    # 3) wrong_key ×10
    for _ in range(10):
        signed = s.sign_message(s.make_cmd(0.1,0.2))
        signed["pubkey_id"] = "someone-else"
        ok, code = v.verify(signed)
        results["wrong_key"]["pass" if not ok else "fail"] += 1

    # 4) expired ×10
    for _ in range(10):
        signed = s.sign_message(s.make_cmd(0.1,0.2))
        signed["ts"] = signed["ts"] - 10_000
        ok, code = v.verify(signed)
        results["expired"]["pass" if not ok else "fail"] += 1

    # 5) replay ×10
    for _ in range(10):
        signed = s.sign_message(s.make_cmd(0.1,0.2))
        ok1,_ = v.verify(signed)
        ok2,code2 = v.verify(signed)
        if ok1 and (not ok2) and code2=="ERR_REPLAY":
            results["replay"]["pass"] += 2
        else:
            results["replay"]["fail"] += 1

    print("\n=== FR‑3 PoC (keys from JSON) ===")
    print(f"Verify latency: avg={statistics.mean(lat_ok):.3f} ms, p95≈{p95(lat_ok):.3f} ms, samples={len(lat_ok)}")
    for k in results:
        print(f"{k:>10}: pass={results[k]['pass']:>3}  fail={results[k]['fail']:>3}")

if __name__ == "__main__":
    main()