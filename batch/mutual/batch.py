import ipaddress
import argparse
import hashlib
import json
import os
import secrets
import socket
import struct
import subprocess
import threading
import time
import signal
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from observer import Observer
from native_proof import NativeProof
from mutual_binding import client_binding, server_binding

P = argparse.ArgumentParser()
P.add_argument("role", choices=["client", "server"])
P.add_argument("--iface", required=True)
P.add_argument("--client-ip", required=True)
P.add_argument("--server-ip", required=True)
P.add_argument("--main-port", type=int, default=19443)
P.add_argument("--control-port", type=int, default=19447)
P.add_argument("--epoch", required=True)
P.add_argument("--out", required=True)
P.add_argument("--period", type=float, default=5)
A = P.parse_args()
if (
    not 1 <= A.main_port <= 65535
    or not 1 <= A.control_port <= 65535
    or A.main_port == A.control_port
    or A.period <= 0
):
    P.error("invalid ports or period")
ipaddress.IPv4Address(A.server_ip)
ipaddress.IPv4Address(A.client_ip)
if not __debug__:
    P.error("Python optimization disables protocol assertions; run without -O")
O = Path(A.out)
O.mkdir(exist_ok=False)
OBS = Observer(A.iface, A.server_ip, A.client_ip, A.role == "server", A.main_port)
STOP = False
BATCHES = []
SEEN = {}
ASSIGNED = set()
EPOCH = A.epoch
PROOF = NativeProof(True)


def stop(*_):
    global STOP
    STOP = True


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)


def binding(request):
    canonical = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha512(b"tcpra/batch-audit/v1\0" + canonical).hexdigest()


def recv(s, n):
    b = b""
    while len(b) < n:
        v = s.recv(n - len(b))
        if not v:
            raise RuntimeError("short control read")
        b += v
    return b


def read(s):
    n = struct.unpack("!I", recv(s, 4))[0]
    if n > 4 * 1024 * 1024:
        raise ValueError("control frame too large")
    return json.loads(recv(s, n))


def write(s, v):
    b = json.dumps(v, separators=(",", ":")).encode()
    s.sendall(struct.pack("!I", len(b)) + b)


def proof(mode, digest, path):
    t = time.monotonic_ns()
    PROOF(mode, digest, path)
    return time.monotonic_ns() - t


def server():
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((A.server_ip, A.control_port))
    listener.listen(8)
    listener.settimeout(0.2)
    (O / "READY").write_text("ready\n")
    while not STOP:
        try:
            s, peer = listener.accept()
        except socket.timeout:
            continue
        with s:
            s.settimeout(10)
            try:
                if peer[0] != A.client_ip:
                    raise ValueError("wrong control source")
                req = read(s)
                assert (
                    set(req) == {"epoch", "seq", "challenge", "ids", "count"}
                    and req["epoch"] == EPOCH
                )
                ids = req["ids"]
                assert (
                    ids == sorted(set(ids)) and len(ids) == req["count"] and 0 < len(ids) <= 10000
                )
                assert (
                    isinstance(req["seq"], int)
                    and req["seq"] >= 1
                    and len(bytes.fromhex(req["challenge"])) == 32
                )
                assert all(len(bytes.fromhex(x)) == 32 for x in ids)
                seq = req["seq"]
                assert seq not in SEEN, "no replay or duplicate sequence"
                assert not ASSIGNED.intersection(ids), "observation reused in another batch"
                deadline = time.monotonic() + 3
                while not set(ids) <= set(OBS.snapshot()) and time.monotonic() < deadline:
                    time.sleep(0.01)
                assert set(ids) <= set(OBS.snapshot()), "manifest contains unobserved SH"
                manifest = {**req, "server_challenge": secrets.token_hex(32)}
                cd = client_binding(manifest)
                write(s, {"ok": True, "seq": seq, "server_challenge": manifest["server_challenge"]})
                received = read(s)
                assert set(received) == {"seq", "client_report"} and received["seq"] == seq
                client_report = bytes.fromhex(received["client_report"])
                assert len(client_report) == 2548
                cp = O / f"client-report-{seq}.bin"
                cp.write_bytes(client_report)
                cv_ns = proof("verify", cd, cp)
                client_verified_ns = time.monotonic_ns()
                digest = server_binding(manifest, client_report)
                path = O / f"report-{seq}.bin"
                report_ns = proof("generate", digest, path)
                response = {
                    "ok": True,
                    "digest": digest,
                    "report": path.read_bytes().hex(),
                    "count": len(ids),
                    "seq": seq,
                    "client_verified": True,
                }
                SEEN[seq] = {"digest": digest}
                ASSIGNED.update(ids)
                (O / f"manifest-{seq}.json").write_text(json.dumps(manifest, indent=2) + "\n")
                BATCHES.append(
                    {
                        "seq": seq,
                        "count": len(ids),
                        "digest": digest,
                        "client_digest": cd,
                        "client_verified": True,
                        "client_verify_ns": cv_ns,
                        "client_verified_ns": client_verified_ns,
                        "report_call_ns": report_ns,
                        "created_ns": time.monotonic_ns(),
                    }
                )
                write(s, response)
            except Exception as e:
                BATCHES.append({"error": repr(e)})
                write(s, {"ok": False, "error": repr(e)})
    listener.close()


def client():
    seq = 0
    next_tick = time.monotonic() + A.period
    (O / "READY").write_text("ready\n")
    while True:
        if not STOP and time.monotonic() < next_tick:
            time.sleep(0.02)
            continue
        rows = OBS.snapshot()
        ids = sorted(set(rows) - ASSIGNED)
        if ids:
            seq += 1
            req = {
                "epoch": EPOCH,
                "seq": seq,
                "challenge": secrets.token_hex(32),
                "ids": ids,
                "count": len(ids),
            }
            start = time.monotonic_ns()
            submitted_utc = time.time_ns()
            digest = binding(req)
            with socket.socket() as s:
                s.settimeout(10)
                s.bind((A.client_ip, 0))
                s.connect((A.server_ip, A.control_port))
                write(s, req)
                challenge = read(s)
                if not challenge["ok"]:
                    raise RuntimeError(challenge["error"])
                assert (
                    challenge["seq"] == seq
                    and len(bytes.fromhex(challenge["server_challenge"])) == 32
                )
                manifest = {**req, "server_challenge": challenge["server_challenge"]}
                cd = client_binding(manifest)
                cp = O / f"client-report-{seq}.bin"
                generate_digest = cd
                client_report_ns = proof("generate", generate_digest, cp)
                client_report = bytearray(cp.read_bytes())
                write(s, {"seq": seq, "client_report": client_report.hex()})
                response = read(s)
            if not response["ok"]:
                raise RuntimeError(response["error"])
            digest = server_binding(manifest, client_report)
            assert (
                response["digest"] == digest
                and response["seq"] == seq
                and response["count"] == len(ids)
                and response["client_verified"] is True
            )
            report = bytearray.fromhex(response["report"])
            verify_digest = digest
            path = O / f"report-{seq}.bin"
            path.write_bytes(report)
            verify_ns = proof("verify", verify_digest, path)
            end = time.monotonic_ns()
            (O / f"manifest-{seq}.json").write_text(json.dumps(manifest, indent=2) + "\n")
            BATCHES.append(
                {
                    "seq": seq,
                    "count": len(ids),
                    "digest": digest,
                    "client_digest": cd,
                    "client_report_generated": True,
                    "client_report_ns": client_report_ns,
                    "server_report_verified": True,
                    "control_verify_ns": end - start,
                    "verify_call_ns": verify_ns,
                    "oldest_record_to_verified_ns": end - min(rows[k]["observed_ns"] for k in ids),
                    "completed_ns": end,
                    "submitted_utc_ns": submitted_utc,
                    "completed_utc_ns": time.time_ns(),
                    "tail_flush": STOP,
                }
            )
            ASSIGNED.update(ids)
        if STOP:
            if not set(OBS.snapshot()) - ASSIGNED:
                break
            continue
        next_tick += A.period
        if next_tick < time.monotonic():
            next_tick = time.monotonic() + A.period


error = None
try:
    if A.role == "server":
        server()
    else:
        client()
except Exception as exc:
    error = repr(exc)
finally:
    try:
        PROOF.close()
    except Exception as exc:
        error = error or repr(exc)
    OBS.save(O / "observations.json")
    (O / "batches.json").write_text(
        json.dumps(
            {
                "mutual_ra": True,
                "proof_backend": PROOF.backend,
                "role": A.role,
                "epoch": EPOCH,
                "period_s": A.period,
                "batches": BATCHES,
                "assigned": len(ASSIGNED),
                "unassigned": sorted(set(OBS.snapshot()) - ASSIGNED),
                "error": error,
            },
            indent=2,
        )
        + "\n"
    )
if error:
    raise RuntimeError(error)
