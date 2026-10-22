# php2shell-check

A non-destructive exploitability checker for **PHP2Shell**, the heap use-after-free in PHP's `session.upload_progress` handler:

- **CVE-2026-109618**: `post_bytes_processed` stale pointer write
- **CVE-2026-109619**: `current_file_bytes_processed` stale pointer write

The PHP project fixed both on 21 Oct 2026 in **8.2.35, 8.3.36, 8.4.27 and 8.5.12**. PHP 8.1 and older get no upstream fix.

`php2shell_check.py` does **not** drop a webshell or run commands on the target. It only tests whether the preconditions for the use-after-free are present, using three independent oracles plus a benign fingerprint. Single file, Python 3.8+, standard library only.

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
| Crash observed in `trigger` | **VULNERABLE**: memory corruption reached (worker crash). |
| `stream` = streaming **and** `lock` positive | **LIKELY VULNERABLE**: the stall reaches PHP and `upload_progress` initializes the session mid-parse; no crash yet (silent write). A tuned heap groom could turn this into RCE. |
| `stream` = buffering | **NOT EXPLOITABLE via this vector**: the front-end buffers the body, so the timed stall never reaches PHP. The PHP binary may still carry the bug: patch anyway. |
| otherwise | **INCONCLUSIVE**: see per-mode output; raise `--stream-stall` / `--conns`. |

A buffering front end is defense in depth, not a fix: the PHP build may still be vulnerable through another entry point.

## The vulnerability

PHP's `ext/session/session.c` rfc1867 upload-progress handler caches raw `zval*` pointers into the session HashTable (`arData`). When a multipart upload stalls longer than `session.upload_progress.min_freq` (default 1 s), a second `FILE_DATA` event re-runs `php_session_rfc1867_update()` → `php_session_initialize()` → `php_session_track_init()`, which frees the HashTable. The cached pointers now reference freed `arData` slots, and the next `ZVAL_LONG` write (storing `bytes_processed`) writes through those stale pointers, a heap use-after-free.

### Affected versions

| Branch | Vulnerable through | Fixed in |
|---|---|---|
| PHP 8.2 | 8.2.34 | **8.2.35** |
| PHP 8.3 | 8.3.35 | **8.3.36** |
| PHP 8.4 | 8.4.26 | **8.4.27** |
| PHP 8.5 | 8.5.11 | **8.5.12** |
| PHP ≤ 8.1 | all | no backport (EOL) |

Distribution packages may be fixed while still showing an older upstream version. Check the package changelog for the CVE IDs before treating a header version as conclusive.

## Conditions for exploitation

A positive verdict from this tool means the `session.upload_progress` use-after-free path is reachable. That is one precondition, not a full exploit. "php2shell" is really a family of at least five independent RCE chains that share the `rfc1867` upload-progress entry point but need different additional conditions, so a host can be exploitable through one chain and immune to another. The table summarizes what each chain requires to reach code execution.

| Chain | Mechanism | Pre-auth | SAPI | Needs from the app / host |
|---|---|:--:|---|---|
| A | Upload-progress stores the raw multipart filename in the session file; an LFI then includes it | Yes | any | an LFI sink, plus a known or guessable session save path |
| B | `var_destroy` UAF, then handler overwrite via `/proc/self/mem` | No | any | the app calls `unserialize()` on attacker input |
| C | FPM `PS(serializer)` leaks across requests; the filename injects a serialized object; `__destruct` fires | Yes | FPM | an endpoint that sets `serialize_handler = php_serialize`, and an autoloaded `__destruct` gadget |
| D | Oversized multipart OOMs mid-request; `longjmp` skips cleanup; request shutdown branches on stale `EG()` | Yes | mod_php | nothing from the app (only a hittable `memory_limit`) |
| E | A session-decode OOM leaves `BG(unserialize)` dirty; a later request's upload-progress handler consumes it | Yes | FPM | a `session_start()` endpoint as producer; the consumer can be any endpoint |

### What it takes to actually get a shell

**Injection chains (A, C): no memory-corruption skill required.** These are the routes most likely to yield a shell on a real target. They turn the upload-progress filename-storage behaviour plus one application-level primitive (a local file include for A, or a `__destruct` gadget on FPM for C) directly into RCE, with no ASLR leak and no binary offsets, and they are deterministic. Chain A also survives a fully patched PHP, because the fix does not sanitize filenames stored by `session.upload_progress`; only fixing the application's LFI closes it.

**Memory-corruption chains (D, E): zero application dependency, but fragile.** Chain D is pre-auth RCE against any unpatched Apache mod_php with no application bug at all, and Chain E is the FPM equivalent. Turning these from a crash into a shell needs every one of:

- Unpatched PHP (below 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, or an EOL branch)
- A hittable `memory_limit`, so the parser OOMs mid-operation (no `Content-Length` to bypass `post_max_size`, plus header or nested-array amplification)
- Matching per-build offsets (`zif_system`, `zval_ptr_dtor`) for the exact version, OS and architecture; without them you only crash
- A working ASLR leak (the out-of-bounds read that surfaces heap pointers in the `Set-Cookie` header)
- A stable single worker (mod_php for D; FPM with worker reuse such as `pm.max_children = 1`, or connection pinning, for E) and a way to recover it between attempts

### Conditions that block every chain

- **The front end buffers the request body** instead of streaming it to PHP (for example nginx with the default `proxy_request_buffering on` / `fastcgi_request_buffering on`). The timed stall and the OOM never reach PHP. This is the single biggest real-world filter, and it is exactly what the `stream` oracle in this tool measures.
- **Patched PHP** closes every chain except A.
- **`memory_limit = -1`** is counterintuitively protective: it removes the predictable allocation failure the OOM chains rely on. Do not substitute `RLIMIT_AS` / `RLIMIT_DATA`, which fail through the same vulnerable path.
- **No LFI, no `unserialize` sink, no `__destruct` gadget, and no matching offsets**: you are left with crashes and info leaks, not a shell.

### Cross-cutting facts

- `session.upload_progress.enabled = Off` is **not** a fix for CVE-2026-109618 (the OOM corruption path); it only closes CVE-2026-109619 session paths. CVE-2026-109619 itself has three arms: `session.upload_progress`, `fatal_error_backtraces` (PHP 8.5 only), and OPcache shared memory (patch only).
- PHP 8.4's `request_parse_body()` parses `multipart/form-data` on GET, PUT, PATCH and DELETE, so POST-only WAF rules can be bypassed.
- This checker verifies reachability of the upload-progress vector only. A "not exploitable via this vector" verdict does not clear a host of Chain D (OOM corruption) or the other variants, so patch regardless of the verdict.

Sources: the PHP advisories ([GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)), [Sansec](https://sansec.io/research/php2shell), and [Wiz](https://www.wiz.io/blog/php2shell-php-rce).

## Mitigation

**Updating PHP is the only complete fix.** The official advisories are explicit: patching is "the only complete mitigation" for CVE-2026-109618 and "the only reliable mitigation" for CVE-2026-109619. Update to the fixed release for your branch:

| Branch | Fixed in |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

PHP 8.1 and older get no php.net release. The PHP security team published source patches for 7.4, 8.0 and 8.1, and several distributions backported the fix while keeping their package version (e.g. a package still labelled `8.1.34`). The official `php` Docker image gets no fix for 8.1 or older; rebuild on a supported branch.

### If you cannot patch immediately

The settings below are **partial stopgaps only**: none closes the vulnerability on its own, and a PHP core maintainer warned that disabling upload progress alone is not enough. Apply them administratively, restart every worker, and still patch as soon as you can.

```ini
; php.ini  (or php_admin_flag / php_admin_value in the FPM pool)

; Closes the confirmed upload-progress trigger (a CVE-2026-109619 path).
; This is what php2shell_check.py probes for.
session.upload_progress.enabled = 0

; Removes another CVE-2026-109619 trigger (PHP 8.5).
fatal_error_backtraces = 0

; Primary config mitigation for CVE-2026-109618, but the advisory calls it
; "not a complete mitigation", and with no cap a single request can exhaust
; all server memory. Monitor usage and restore the limit once patched.
memory_limit = -1

; Keep the request-body surface small.
post_max_size = 8M
max_input_nesting_level = 32
```

Every known trigger is a `multipart/form-data` request, so blocking those at the web server is a further stopgap, but it does not address the out-of-memory corruption path (CVE-2026-109618).

> **Note on scope:** this checker probes the `session.upload_progress` use-after-free, which the PHP advisory lists as one confirmed path of **CVE-2026-109619**. A "not exploitable via this vector" verdict does **not** clear the host of CVE-2026-109618 (OOM corruption) or of other variants PHP warns about. Patch regardless of the verdict.

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
