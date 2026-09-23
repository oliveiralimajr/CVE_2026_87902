# CVE-2026-87902 — WordPress Scanner & PoC

A Python scanner for **CVE-2026-87902**, a critical (CVSS 9.2) unauthenticated
path traversal in WordPress core that lets an attacker include and execute any
readable `.php` file on the server, outside the active theme directory.

Feed it a list of URLs and it will tell you which sites run WordPress, which
ones are vulnerable, and — if you ask for it — prove the impact all the way to
RCE, with an interactive shell on top.

## What the vulnerability is

The bug lives in WordPress's page-template resolution (`get_page_template()`).
The `pagename` candidate template is built after `urldecode()` but never goes
through `validate_file()`, so a double-encoded traversal
(`templates%252F%252E%252E%252F...`) survives sanitization and the template
loader walks out of the theme directory, including whatever `.php` file the
attacker points to. No authentication, no user interaction.

Fixed in **7.1.2** (plus backports); affected versions go back to **4.7.0**.

## Conditions for exploitation

1. **WordPress 4.7.0 – 7.1.1** without the patch;
2. Active **classic theme with a top-level `page-*` directory** (commonly
   `page-templates/`) — block themes don't reach the vulnerable code path, so
   a "not vulnerable" result on a block-theme site isn't conclusive;
3. A **published page without its own assigned template** — its `page_id`
   pairs with the crafted `pagename`;
4. Target file must **end in `.php`** and be readable by the web server user
   (raw file reads like `/etc/passwd` don't work — the resolver appends
   `.php` and stream wrappers are blocked);
5. No WAF dropping the traversal probe.

For full **RCE**, additionally:

6. A readable `.php` that does something useful when included — typically
   **`/usr/local/lib/php/pearcmd.php`** (default in official PHP Docker images
   and stock cPanel on PHP < 8.5);
7. **`register_argc_argv=On`** (off by default from PHP 8.5 on);
8. **Linux host** — Windows is immune (Win32 lexical path handling).

Without 6–7 it's still an unauthenticated LFI of arbitrary existing `.php`
files — anything that lets an attacker control the contents of a `.php` on the
host (permissive upload plugin, editable theme files...) chains into RCE.

## What the scanner does

| Mode | What happens |
|---|---|
| default | Detects WordPress + safe, non-destructive vulnerability check (3 requests, no payload execution) |
| `--exploit` | On confirmed vulnerable sites: includes `wp-login.php` (login form rendered on the front page) and `wp-config.php` (silently executed) as conclusive LFI evidence |
| `--rce` | Full chain via pearcmd: writes and executes a shell, runs `id; head -3 /etc/passwd`, reports the user |
| `--console` | Interactive shell prompt on top of the RCE (`exit` removes the shell from the server) |

```bash
pip install requests

python3 cve_2026_87902_scanner.py sites.txt                     # scan only
python3 cve_2026_87902_scanner.py sites.txt --exploit -o out.json
python3 cve_2026_87902_scanner.py sites.txt --rce
python3 cve_2026_87902_scanner.py sites.txt --console
```

Extra flags: `-t N` threads (default 5), `-o file.json` for the full report
(version, theme, page ID used, status, evidence payloads, RCE output).

## Detection notes

- All probes are sent as **POST with a raw query string** — `redirect_canonical()`
  301-redirects GETs on pretty-permalink sites and drops `page_id`, which used
  to cause false inconclusives. GET fallback kicks in when POST redirects.
- Page IDs are enumerated from six sources (REST API, `rest_route` fallback,
  `page-id-N` body classes, `?page_id=` links, sitemaps, low-ID probing), each
  validated before use.
- The scanner probes the active theme for a `page-*` directory with a
  404-control, telling apart "directory exists, listing forbidden" from "WAF
  blocks everything". Negative results on themes without the directory are
  reported as inconclusive.
- Sites where the WAF blocks the traversal probe are reported as `PROTEGIDO`
  rather than guessed.

## Legal

Only run this against systems you own or have explicit written authorization
to test (e.g. a bug bounty scope). The exploit mode executes code on the
target — know your program's rules before using it.

## References

- [Wordfence PSA](https://www.wordfence.com/blog/2026/09/psa-critical-unauthenticated-path-traversal-vulnerability-patched-in-wordpress-core/)
- [Hadrian — working PoC and detection template](https://hadrian.io/vulnerability-alerts/cve-2026-87902-working-poc-wordpress-critical-path-traversal)
- [SecurityOnline coverage](https://securityonline.info/wordpress-rce-vulnerability-cve-2026-87902)
