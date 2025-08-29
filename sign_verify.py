#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json, base64, time, secrets, argparse, sys
from typing import Any, Dict, Tuple

try:
    import oqs
except Exception:
    print("[ERROR] Can't import oqs (PyOQS).")
    sys.exit(1)

SIGNED_FIELDS = ["topic", "seq", "ts", "payload", "nonce", "pubkey_id"]

def canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def now_ms() -> int: return int(time.time() * 1000)
def new_nonce(nbytes: int = 12) -> str: 
    import base64, secrets
    return base64.b64encode(secrets.token_bytes(nbytes)).decode()

def load_pub(pub_path: str) -> dict:
    with open(pub_path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_sec(sec_path: str) -> dict:
    with open(sec_path, "r", encoding="utf-8") as f:
        return json.load(f)

class Signer:
    def __init__(self, secdoc: dict):
        self.alg = secdoc["alg"]
        self.pubkey_id = secdoc["pubkey_id"]
        self.secret = base64.b64decode(secdoc["secret_b64"])
        # The secret key is passed to the constructor to create a stateful signer object
        self._signer = oqs.Signature(self.alg, self.secret)

    def make_cmd(self, linear_x: float, angular_z: float, pubkey_id: str | None = None) -> dict:
        return {
            "topic": "/cmd_vel",
            "seq": now_ms() % 1_000_000,
            "ts": now_ms(),
            "payload": {
                "linear": {"x": float(linear_x), "y": 0.0, "z": 0.0},
                "angular": {"x": 0.0, "y": 0.0, "z": float(angular_z)},
            },
            "nonce": new_nonce(),
            "pubkey_id": pubkey_id or self.pubkey_id,
        }

    def sign_message(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        part = {k: msg[k] for k in SIGNED_FIELDS}
        payload = canon(part)
        # The stateful _signer object already holds the secret key
        sig = self._signer.sign(payload)
        out = dict(msg)
        out["signature"] = base64.b64encode(sig).decode()
        return out

class Verifier:
    def __init__(self, pubdocs: dict[str, dict], window_ms: int = 2000):
        # pubdocs: pubkey_id -> pubdoc
        self.window_ms = window_ms
        self.keyring: dict[str, Tuple[str, bytes]] = {}
        for pid, d in pubdocs.items():
            self.keyring[pid] = (d["alg"], base64.b64decode(d["pubkey_b64"]))
        # (pubkey_id, nonce) -> timestamp
        self.seen: dict[Tuple[str, str], int] = {}

    def verify(self, signed: Dict[str, Any]) -> Tuple[bool, str]:
        pid = signed.get("pubkey_id")
        if pid not in self.keyring:
            return False, "ERR_NO_SUCH_PUBKEY_ID"
        try:
            ts = int(signed.get("ts", 0))
        except (TypeError, ValueError):
            return False, "ERR_BAD_TS"
        if abs(now_ms() - ts) > self.window_ms:
            return False, "ERR_TS_WINDOW"
        nonce = str(signed.get("nonce", ""))
        key = (pid, nonce)
        now = now_ms()
        # 清理過期的 nonce，避免記憶體洩漏
        expiry = now - self.window_ms
        self.seen = {k: t for k, t in self.seen.items() if t >= expiry}
        if key in self.seen:
            return False, "ERR_REPLAY"
        try:
            sig = base64.b64decode(signed.get("signature", ""), validate=True)
        except Exception:
            return False, "ERR_BAD_BASE64"
        missing = [k for k in SIGNED_FIELDS if k not in signed]
        if missing:
            return False, "ERR_MISSING_FIELDS"
        part = {k: signed[k] for k in SIGNED_FIELDS}
        alg, pk = self.keyring[pid]
        try:
            with oqs.Signature(alg) as v:
                ok = v.verify(canon(part), sig, pk)
        except Exception:
            return False, "ERR_VERIFY_EXCEPTION"
        if not ok:
            return False, "ERR_BAD_SIGNATURE"
        self.seen[key] = now
        return True, "OK"

def cli():
    ap = argparse.ArgumentParser(description="Sign/Verify demo using ML‑DSA JSON keys")
    ap.add_argument("--pub", help="ml_dsa_pub.json", required=True)
    ap.add_argument("--sec", help="ml_dsa_sec.json (for signing)")
    ap.add_argument("--mode", choices=["sign","verify"], required=True)
    ap.add_argument("--in", dest="infile", help="input JSON (when mode=verify)")
    ap.add_argument("--out", dest="outfile", help="output JSON (when mode=sign)")
    args = ap.parse_args()

    if args.mode == "sign":
        if not args.sec:
            raise SystemExit("--sec is required for sign mode")
        secdoc = load_sec(args.sec)
        signer = Signer(secdoc)
        msg = signer.make_cmd(0.1, 0.2)
        signed = signer.sign_message(msg)
        data = json.dumps(signed, ensure_ascii=False, indent=2)
        if args.outfile:
            with open(args.outfile, "w", encoding="utf-8") as f: f.write(data)
            print(f"[OK] wrote {args.outfile}")
        else:
            print(data)
    else:
        pubdoc = load_pub(args.pub)
        with open(args.infile, "r", encoding="utf-8") as f:
            signed = json.load(f)
        v = Verifier({pubdoc["pubkey_id"]: pubdoc}, window_ms=2000)
        ok, code = v.verify(signed)
        print({"ok": ok, "code": code})

if __name__ == "__main__":
    cli()

# 先產生金鑰
#python keygen.py --pubkey-id controller-01

# 簽一筆 /cmd_vel 指令（存檔）
#python sign_verify.py --mode sign --sec ml_dsa_sec.json --pub ml_dsa_pub.json --out signed_cmd.json

# 驗證那筆指令
#python sign_verify.py --mode verify --pub ml_dsa_pub.json --in signed_cmd.json