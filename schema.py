#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FR‑3 Minimal PoC — single file (Python 3.12)

What this file gives you:
1) Message schema (JSON): {topic, seq, ts, nonce, pubkey_id, payload, signature}
2) Canonical JSON serialization (stable + compact) before signing
3) ML‑DSA (Dilithium) sign / verify using oqs (Open Quantum Safe)
4) Verifier checks: whitelist(pubkey_id) + timestamp window (±2 s) + nonce anti‑replay + signature
5) A tiny test runner: correct / tamper / wrong key / expired / replay

Run (after installing deps):
  uv add oqs   # or: pip install oqs  (if build fails on macOS: brew install liboqs first)
  python schema.pt

Notes:
- This PoC is ROS2‑agnostic; later you can import Verifier.verify() inside a ROS2 node.
- Keys are generated in memory for simplicity; see TODO at bottom to persist to files.
"""
from __future__ import annotations
import json, time, secrets, base64, statistics, sys
from typing import Any, Dict, Tuple

# --- dependency check --------------------------------------------------------
try:
    import oqs  # PyOQS binding
except Exception:
    print("[ERROR] Missing 'oqs'. Install with 'uv add oqs' (or 'pip install oqs').\n"
          "If it fails on macOS, install liboqs first: 'brew install liboqs' then retry.")
    sys.exit(1)

# --- canonical JSON ----------------------------------------------------------
def canon(obj: Any) -> bytes:
    """Stable, compact JSON bytes for signing/verification."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

# --- time/nonce helpers ------------------------------------------------------
def now_ms() -> int:
    return int(time.time() * 1000)

def new_nonce(nbytes: int = 12) -> str:
    return base64.b64encode(secrets.token_bytes(nbytes)).decode()

# --- select a Dilithium/ML-DSA scheme that exists in your oqs build ---------
# To improve compatibility, we try multiple oqs API versions
if hasattr(oqs, 'get_enabled_sig_mechanisms'):
    # latest liboqs-python
    AVAILABLE = set(oqs.get_enabled_sig_mechanisms())
elif hasattr(oqs, 'Signature') and hasattr(oqs.Signature, 'algorithms'):
    # old pyoqs < 0.9
    AVAILABLE = set(oqs.Signature.algorithms)
elif hasattr(oqs, 'get_enabled_sigs'):
    # old pyoqs >= 0.9
    AVAILABLE = set(oqs.get_enabled_sigs())
else:
    AVAILABLE = set()

_PREF = [
    "Dilithium3",  # common in oqs >= 0.9
    "Dilithium2",
    "ML-DSA-65",   # naming in newer oqs builds
    "ML-DSA-44",
    "Dilithium5",
]
SCHEME = next((s for s in _PREF if s in AVAILABLE), None)
if not SCHEME:
    print("[ERROR] No Dilithium/ML‑DSA scheme available in oqs build.\n"
          f"Enabled sigs (first 20): {sorted(AVAILABLE)[:20]}\n"
          "Reinstall oqs/liboqs with Dilithium enabled.")
    sys.exit(2)

# --- in‑memory keypair (for PoC) --------------------------------------------
_SIGNER = oqs.Signature(SCHEME)
_PUBKEY: bytes = _SIGNER.generate_keypair()
_SECKEY: bytes = _SIGNER.export_secret_key()

PUBKEY_ID = "controller-01"
TRUSTLIST: Dict[str, Dict[str, Any]] = {PUBKEY_ID: {"alg": SCHEME, "pubkey": _PUBKEY}}

# --- message schema ----------------------------------------------------------
_SIGNED_FIELDS = ["topic", "seq", "ts", "payload", "nonce", "pubkey_id"]

def make_cmd(linear_x: float, angular_z: float, pubkey_id: str = PUBKEY_ID) -> Dict[str, Any]:
    """Build a minimal /cmd_vel command message (unsigned)."""
    return {
        "topic": "/cmd_vel",
        "seq": now_ms() % 1_000_000,
        "ts": now_ms(),
        "payload": {
            "linear": {"x": float(linear_x), "y": 0.0, "z": 0.0},
            "angular": {"x": 0.0, "y": 0.0, "z": float(angular_z)},
        },
        "nonce": new_nonce(),
        "pubkey_id": pubkey_id,
    }

# --- signing -----------------------------------------------------------------

def sign_message(msg: Dict[str, Any]) -> Dict[str, Any]:
    to_sign = {k: msg[k] for k in _SIGNED_FIELDS}
    sig = _SIGNER.sign(canon(to_sign))
    out = dict(msg)
    out["signature"] = base64.b64encode(sig).decode()
    return out

# --- verifier ----------------------------------------------------------------
class Verifier:
    def __init__(self, trustlist: Dict[str, Dict[str, Any]], window_ms: int = 2000):
        self.window_ms = window_ms
        # pubkey_id -> (alg, pk)
        self.keyring: Dict[str, Tuple[str, bytes]] = {}
        for pid, meta in trustlist.items():
            self.keyring[pid] = (meta.get("alg", SCHEME), meta["pubkey"]) 
        self.seen: set[Tuple[str, str]] = set()  # (pubkey_id, nonce)

    def verify(self, signed: Dict[str, Any]) -> Tuple[bool, str]:
        # 1) whitelist
        pid = signed.get("pubkey_id")
        if pid not in self.keyring:
            return False, "ERR_NO_SUCH_PUBKEY_ID"
        # 2) timestamp window
        ts = int(signed.get("ts", 0))
        if abs(now_ms() - ts) > self.window_ms:
            return False, "ERR_TS_WINDOW"
        # 3) anti‑replay (per pubkey_id)
        nonce = str(signed.get("nonce", ""))
        key = (pid, nonce)
        if key in self.seen:
            return False, "ERR_REPLAY"
        # 4) signature
        try:
            sig = base64.b64decode(signed.get("signature", ""))
        except Exception:
            return False, "ERR_BAD_BASE64"
        part = {k: signed[k] for k in _SIGNED_FIELDS}
        alg, pk = self.keyring[pid]
        try:
            with oqs.Signature(alg) as v:
                ok = v.verify(canon(part), sig, pk)
        except Exception:
            return False, "ERR_VERIFY_EXCEPTION"
        if not ok:
            return False, "ERR_BAD_SIGNATURE"
        # mark nonce only after successful verification
        self.seen.add(key)
        return True, "OK"

# --- tiny self‑tests ---------------------------------------------------------

def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    return s[max(0, int(0.95 * (len(s) - 1)))]

def run_self_tests() -> None:
    v = Verifier(TRUSTLIST, window_ms=2000)
    lat_ok_ms: list[float] = []
    results = {k: {"pass": 0, "fail": 0} for k in ["correct", "tamper", "wrong_key", "expired", "replay"]}

    # 1) correct ×10
    for _ in range(10):
        signed = sign_message(make_cmd(0.1, 0.2))
        t0 = time.perf_counter_ns()
        ok, code = v.verify(signed)
        dt = (time.perf_counter_ns() - t0) / 1e6
        if ok:
            results["correct"]["pass"] += 1
            lat_ok_ms.append(dt)
        else:
            results["correct"]["fail"] += 1

    # 2) tamper ×10 (modify payload after signing)
    for _ in range(10):
        s2 = sign_message(make_cmd(0.1, 0.2))
        s2["payload"]["linear"]["x"] += 1e-4
        ok, code = v.verify(s2)
        results["tamper"]["pass" if not ok else "fail"] += 1

    # 3) wrong pubkey_id ×10
    for _ in range(10):
        s3 = sign_message(make_cmd(0.1, 0.2))
        s3["pubkey_id"] = "unknown-operator"
        ok, code = v.verify(s3)
        results["wrong_key"]["pass" if not ok else "fail"] += 1

    # 4) expired ×10 (ts - 10s)
    for _ in range(10):
        s4 = sign_message(make_cmd(0.1, 0.2))
        s4["ts"] -= 10_000
        ok, code = v.verify(s4)
        results["expired"]["pass" if not ok else "fail"] += 1

    # 5) replay ×10 (second verify must fail)
    for _ in range(10):
        s5 = sign_message(make_cmd(0.1, 0.2))
        ok1, c1 = v.verify(s5)
        ok2, c2 = v.verify(s5)
        if ok1 and (not ok2) and c2 == "ERR_REPLAY":
            results["replay"]["pass"] += 2  # count both conditions as pass
        else:
            results["replay"]["fail"] += 1

    avg = statistics.mean(lat_ok_ms) if lat_ok_ms else 0.0
    print("\n=== FR‑3 PoC (ML‑DSA) ===")
    print(f"Scheme: {SCHEME}")
    print(f"Verify latency: avg={avg:.3f} ms, p95≈{_p95(lat_ok_ms):.3f} ms, samples={len(lat_ok_ms)}")
    for k in ["correct", "tamper", "wrong_key", "expired", "replay"]:
        print(f"{k:>10}: pass={results[k]['pass']:>3}  fail={results[k]['fail']:>3}")
    print("\nExpected: only 'correct' passes; others should be rejected by the verifier.")

# --- entrypoint --------------------------------------------------------------
if __name__ == "__main__":
    run_self_tests()

# --- TODO (next):
# 1) Persist keys to files (e.g., ml_dsa_pk.bin/ml_dsa_sk.bin) and load on startup.
# 2) Replace in‑memory nonce set with Redis + TTL for multi‑process/multi‑machine.
# 3) Wrap Verifier.verify() into an rclpy node that subscribes /cmd_vel_signed and forwards to /cmd_vel on success.
# 4) Add /pqc/status topic for detailed error codes (ERR_TS_WINDOW / ERR_REPLAY / ERR_BAD_SIGNATURE / ERR_NO_SUCH_PUBKEY_ID).
