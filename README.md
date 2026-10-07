<div align="center">
  <img src="./banner.svg" alt="vhost-scanner" width="800">
</div>

# vhost-scanner

Discover HTTP virtual hosts on a target you own or are explicitly authorized to test by sending candidate `Host` headers to one target IP address or hostname.

> **Authorized use only.** Obtain permission before scanning. This tool makes HTTP requests to the specified target and is not designed for stealth or evasion.

## Requirements

- Python 3.10 or newer
- No third-party dependencies

## Usage

```text
python vhost_scanner.py TARGET DOMAIN [options]
```

For example, on an authorized test system:

```text
python vhost_scanner.py 192.0.2.10 example.com --port 8080 --threads 5 --rate-limit 2 --out results.json
```

`TARGET` is the address to connect to; `DOMAIN` is the base domain used to build the `Host` header candidates. The built-in wordlist includes common subdomain labels, followed by the base domain itself. A custom wordlist should contain one subdomain label (or name) per line; blank lines and lines beginning with `#` are ignored.

| Option | Default | Description |
| --- | ---: | --- |
| `--port` | `80` | Target port, from 1 to 65535 |
| `--ssl` | off | Use HTTPS; defaults port 80 to 443 when `--port` is omitted |
| `--wordlist` | built-in | UTF-8 custom subdomain list, limited to 10,000 unique entries |
| `--threads` | `10` | Concurrent workers, from 1 to 100 |
| `--timeout` | `8` seconds | Per-request timeout, from 0.1 to 300 seconds |
| `--rate-limit` | `10` requests/second | Maximum HTTP request start rate (0.001-100), including baseline and confirmation requests |
| `--ua` | scanner identifier | Set the HTTP User-Agent |
| `--out` | none | Write confirmed findings as a JSON array |

The scanner establishes a baseline using three requests for nonexistent hostnames and stops if those responses are inconsistent. A candidate that differs from the baseline is requested a second time and is reported only when the response fingerprint is repeatable. Responses are capped at 64 KiB for fingerprinting and title extraction. HTTP error responses are inspected, but redirects are not followed. HTTPS certificate verification is disabled because the connection target can be an IP while the requested virtual host is supplied in the `Host` header.

Network errors are printed to stderr and produce exit status `2`; invalid arguments use argparse's standard nonzero exit. Findings contain the host, status, response length, whether the response was truncated, page title, and `Server` header.

## Tests

Run the local regression suite with:

```text
python -m unittest discover -s tests -v
```

## Author

**Omar Khalid** — [omareldemery.com](https://omareldemery.com) | [@amooryx](https://github.com/amooryx)
