# php2shell-scanner

Remote **detector** for **CVE-2026-109618 / CVE-2026-109619** ("php2shell") — the unauthenticated
PHP core RCE in `session.upload_progress`. It **does not exploit** anything (no shells); it drives the
vulnerable code into a visible error and reads the reaction.

> ⚠️ **Authorized testing only.** The probe is designed to trigger a memory-exhaustion error, so it can
> transiently spike memory or fail a PHP worker. Run only against systems you own or are authorized to
> test. Do **not** mass-scan third parties. For truly zero-impact checks on hosts you control, prefer a
> version/config check (`php -v` + fixed-version comparison).

## Detection method
1. **Version check (zero impact):** read `X-Powered-By`; PHP below the fixed patch level → vulnerable.
2. **Escalating multipart probes (1→20 MiB):** a part whose field name is a 62-level nested array with an
   empty `filename=` (hits the `upload_progress` path), after a tiny control request.
3. **Verdict signals:** in-band `Allowed memory size … exhausted` fatal, empty HTTP 500 vs. a control that
   had a body, `502/503/504`, empty-200, or a dropped connection → **VULNERABLE**. Plain 5xx/rejections are ignored.

Fixed versions: `8.2.35 / 8.3.36 / 8.4.27 / 8.5.12`. Branches ≤ 8.1 are EOL.

Method after Assetnote's `php2shell-scanner`; original research by the **Calif team** (https://calif.io/php2shell/).

## Install
```
pip install -r requirements.txt
```

## Usage
```
python3 scanner.py -u https://host.you.own            # single target
python3 scanner.py -l hosts.txt -t 20 -o results.json # list + JSON output
python3 scanner.py -u https://host --path /app.php    # custom path
python3 scanner.py -u https://host --max-mib 6        # lower impact (smaller probes)
python3 scanner.py -u https://host -k -H "Cookie: a=b"
```

## Options
`-u/--url`, `-l/--list`, `--path`, `-t/--threads`, `--timeout`, `--max-mib` (cap probe size),
`-k/--insecure`, `-H/--header` (repeatable), `-o/--output` (JSON), `-q/--quiet`.
