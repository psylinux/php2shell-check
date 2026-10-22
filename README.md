# php2shell-check

A non-destructive exploitability checker for **PHP2Shell**, the heap use-after-free in PHP's `session.upload_progress` handler:

- **CVE-2026-109618** — `post_bytes_processed` stale pointer write
- **CVE-2026-109619** — `current_file_bytes_processed` stale pointer write

The PHP project fixed both on 21 Oct 2026 in **8.2.35, 8.3.36, 8.4.27 and 8.5.12**. PHP 8.1 and older get no upstream fix.

`php2shell_check.py` does **not** drop a webshell, run commands, or solve a challenge. It only tests whether the preconditions for the use-after-free are present, using three independent oracles plus a benign fingerprint. Single file, Python 3.8+, standard library only.

> **Related:** for a passive, single-request version check (no payload, safe to run against production at a low rate), see [psylinux/php2shell-nuclei-template](https://github.com/psylinux/php2shell-nuclei-template/).

## What it checks

The UAF needs the timed stall between multipart `FILE_DATA` chunks to actually reach the PHP process, and `session.upload_progress` to be active. The script confirms both without corrupting the target:

| Mode | Oracle | Reads |
|---|---|---|
| `probe` | Benign fingerprint | Headers, PHP detection, a fast multipart POST with `PHP_SESSION_UPLOAD_PROGRESS`, `Set-Cookie`. No stall. |
| `trigger` | Crash oracle | Fires the real UAF trigger (multi-phase multipart upload, stalls > `min_freq` between `FILE_DATA` chunks, optional heap spray and multi-stall) and watches for crash signals: 5xx / resets on the POST, plus a health `GET` after each round. |
| `lock` | Session-lock oracle | While an upload with `PHP_SESSION_UPLOAD_PROGRESS` is stalled, sends a concurrent request with the same `PHPSESSID`. If the rfc1867 handler initialized the session mid-parse, that request blocks on the session `flock`. A control run without the progress field must stay fast. |
| `stream` | Worker-occupancy oracle | Parks N stalled uploads (12 by default, adjustable) and times a probe `GET`. Fast `GET` = the front-end buffers the body (stall never reaches PHP, UAF dead); slow `GET` ≈ stall time = streaming (UAF path open). |

## Usage

```bash
# full battery (default): probe, trigger, lock, stream
python3 php2shell_check.py --url https://www.example.com/index.php

# individual modes
python3 php2shell_check.py --url https://www.example.com/index.php --mode trigger --rounds 5 --spray 16 --stalls 3 -v
python3 php2shell_check.py --url https://www.example.com/index.php --mode lock
python3 php2shell_check.py --url https://www.example.com/index.php --mode stream --conns 12 --stream-stall 6

# self-signed TLS labs
python3 php2shell_check.py --url https://www.example.com/index.php --no-verify
```

`--url` is required. Run this only against hosts you own or are authorized to test.

## Options

```
--url URL              target PHP URL (required, e.g. https://www.example.com/index.php)
--mode {all,probe,trigger,lock,stream}   which test(s) to run (default: all)
--rounds N             trigger rounds (default: 3)
--stall SEC            stall between phases in trigger mode, > min_freq (default: 1.6)
--stalls N             stall gaps per trigger round (default: 1)
--spray N              heap spray parts per round (default: 16)
--lock-stall SEC       stall used by the lock oracle (default: 4.0)
--conns N              parallel stalled uploads for the stream test (default: 12)
--stream-stall SEC     stall duration for the stream test (default: 6.0)
--no-verify            disable TLS certificate verification (labs / self-signed only)
-v, --verbose
```

## Verdict

The script prints a final verdict by cross-referencing the oracles:

| Signal | Verdict |
|---|---|
| Crash observed in `trigger` | **VULNERABLE** — memory corruption reached (worker crash). |
| `stream` = streaming **and** `lock` positive | **LIKELY VULNERABLE** — the stall reaches PHP and `upload_progress` initializes the session mid-parse; no crash yet (silent write). A tuned heap groom could turn this into RCE. |
| `stream` = buffering | **NOT EXPLOITABLE via this vector** — the front-end buffers the body, so the timed stall never reaches PHP. The PHP binary may still carry the bug: patch anyway. |
| otherwise | **INCONCLUSIVE** — see per-mode output; raise `--stream-stall` / `--conns`. |

A buffering front end is defense in depth, not a fix: the PHP build may still be vulnerable through another entry point.

## The vulnerability

PHP's `ext/session/session.c` rfc1867 upload-progress handler caches raw `zval*` pointers into the session HashTable (`arData`). When a multipart upload stalls longer than `session.upload_progress.min_freq` (default 1 s), a second `FILE_DATA` event re-runs `php_session_rfc1867_update()` → `php_session_initialize()` → `php_session_track_init()`, which frees the HashTable. The cached pointers now reference freed `arData` slots, and the next `ZVAL_LONG` write (storing `bytes_processed`) writes through those stale pointers — a heap use-after-free.

### Affected versions

| Branch | Vulnerable through | Fixed in |
|---|---|---|
| PHP 8.2 | 8.2.34 | **8.2.35** |
| PHP 8.3 | 8.3.35 | **8.3.36** |
| PHP 8.4 | 8.4.26 | **8.4.27** |
| PHP 8.5 | 8.5.11 | **8.5.12** |
| PHP ≤ 8.1 | all | no backport — EOL |

Distribution packages may be fixed while still showing an older upstream version. Check the package changelog for the CVE IDs before treating a header version as conclusive.

## Mitigation

Immediate, no patch required:

```ini
; php.ini
session.upload_progress.enabled = Off
```

Or update PHP to the fixed release for your branch (8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+). The vendor fix removes the long-lived `zval*` cache and re-derives the target pointer on each write instead of caching it across the stall window.

## References

- [GHSA-w8hw-w9fx-j79w (CVE-2026-109618)](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [php.net security advisory (21 Oct 2026)](https://www.php.net/)
- Passive version check: [php2shell-nuclei-template](https://github.com/psylinux/php2shell-nuclei-template/)

## Legal

This code is for authorized security testing, research, and education only. The author is not responsible for any unauthorized use. Run it only against systems you own or have explicit written permission to test.

## Author

Marcos Azevedo ([@psylinux](https://github.com/psylinux))

## License

[MIT](LICENSE)
