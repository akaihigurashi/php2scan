<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.png">
    <img alt="php2scan" src="docs/logo-light.png" width="334">
  </picture>
</h1>

Checks whether websites are affected by **PHP2Shell** (CVE-2026-109618 /
CVE-2026-109619), the critical remote code execution vulnerability in PHP.
Part of [shouldipanic.ch](https://shouldipanic.ch).

php2scan comes in two forms:

- **`php2scan.py`**: a single Python file with no dependencies for checking your
  own servers: IP ranges, port scan, vhost discovery and PHP/CMS fingerprinting.
  See [Command line](#command-line).
- **A web page** (Docker image) where anyone can check one website, with abuse
  protection. It runs at [php2scan.shouldipanic.ch](https://php2scan.shouldipanic.ch).

On the web page, visitors enter a hostname and confirm they are allowed to check it. The service
loads the site's start page like a browser would and reports:

- whether the site runs PHP, and which version it reveals
- which PHP applications it uses (WordPress, Nextcloud, Joomla, TYPO3, Magento,
  phpMyAdmin and about 430 more)
- whether the visible PHP version includes the PHP2Shell fix
- what gave it away, and how to stop revealing it

![Result for a site running PHP 8.3.35 with Nextcloud](docs/screenshot.png)

## Run it with Docker

```bash
docker run -d --name php2scan --restart unless-stopped \
  -p 127.0.0.1:8088:8088 \
  -e PANIC_ORIGIN=https://scan.example.ch \
  -v php2scan-data:/data \
  ghcr.io/akaihigurashi/php2scan:latest
```

Or with Compose: download [`docker-compose.yml`](docker-compose.yml), set
`PANIC_ORIGIN` to your public address, then:

```bash
docker compose up -d
```

The container listens on port 8088 on localhost only. Put a reverse proxy with
TLS in front of it; an nginx example is in [`deploy/nginx.conf`](deploy/nginx.conf).

### Updates

```bash
docker compose pull && docker compose up -d
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PANIC_ORIGIN` | – | Public address, e.g. `https://scan.example.ch`. Requests from other origins are refused. **Set it.** |
| `PANIC_OPERATOR` | – | Optional: name shown in a contact section at the bottom of the page |
| `PANIC_CONTACT` | – | Optional: contact e-mail shown in that section |
| `PANIC_IMPRINT_URL` | – | Optional link to an existing imprint page |
| `PANIC_TRUSTED_PROXY` | `127.0.0.1,::1` | Proxy addresses or networks whose `X-Real-IP` header is trusted |
| `PANIC_DENY_HOSTS` | – | Domains (incl. subdomains) that may never be checked, comma-separated |
| `PANIC_DENY_IPS` | – | Additional target IPs that may never be checked |
| `PANIC_AUDIT_DIR` | `/data/audit` | Daily audit log files |
| `PANIC_RETENTION_DAYS` | `30` | Audit files older than this are deleted |

In the Compose setup, nginx on the host reaches the container through the Docker
network gateway `172.30.250.1`, which is why that address is the trusted proxy.
The older `CMSWEB_*` names still work.

## Abuse protection

- Visitors must confirm they are authorized; every check is logged with time,
  IP address, browser and the consent wording they accepted.
- Requests from VPNs, Tor, proxies and hosting networks are refused (public
  lists, refreshed automatically).
- Per-visitor rate limit and result caching. Limits are constants at the top of
  [`web.py`](web.py).
- Only hostnames are accepted. Every address they resolve to must be public, the
  connection is pinned to the checked address, and redirects are only followed on
  the same server, so the service can't be pointed at internal networks.
- Some websites are never checked: large well-known services, the 100 most
  visited websites ([Tranco](https://tranco-list.eu) ranking, refreshed weekly),
  government and military sites, sites in or hosted in a list of countries, and
  the server the checker itself runs on (the domain from `PANIC_ORIGIN` and its
  addresses). The lists are at the top of [`web.py`](web.py).
- Visitors from that list of countries can't use the service.
- The container runs as an unprivileged user with a read-only filesystem.

### Handling misuse

1. Copy the relevant audit files before they expire:
   `docker compose cp php2scan:/data/audit/audit-2026-10-26.jsonl .`
2. Block the visitor at the reverse proxy if needed.
3. Report it to the visitor's network provider (`whois <ip> | grep -i abuse`) and,
   in Switzerland, to the Federal Office for Cyber Security
   ([ncsc.admin.ch](https://www.ncsc.admin.ch)) or the cantonal police.

## Command line

```bash
curl -LO https://github.com/akaihigurashi/php2scan/releases/latest/download/php2scan.py
python3 php2scan.py 203.0.113.10
```

Python 3.8 or newer, nothing to install. For each IP it scans 20 common web
ports, discovers the vhosts on it (TLS certificates, redirects, reverse DNS,
passive DNS, certificate transparency, your own name list) and checks every one.

```bash
python3 php2scan.py 198.51.100.0/24                      # whole IP range
python3 php2scan.py shop.example.ch@203.0.113.10         # one known vhost on a specific IP
python3 php2scan.py 203.0.113.0/24 --names domains.txt   # + hostnames from your own data
python3 php2scan.py 203.0.113.10 -p all -o out.csv       # all 65535 ports, CSV output
python3 php2scan.py -h                                   # all options
```

Only scan systems you are authorized to test. (php2scan.py was called cmsscan.py
before; it works the same.)

## How it's built

The scanner engine (fetching, fingerprinting, port scan, vhost discovery, web
server) lives in [panic-core](https://github.com/akaihigurashi/panic-core).
Everything specific to PHP2Shell is in [`check.py`](check.py). `php2scan.py` and
`web.py` are generated from both:

```bash
git clone https://github.com/akaihigurashi/panic-core ../panic-core
python3 ../panic-core/bundle.py check.py
docker build -t php2scan .
```

Every push to `main` builds the image for amd64 and arm64 and publishes it to the
GitHub Container Registry. A version tag (`v2.0.0`) also creates a release with
`php2scan.py` attached.

## License

GPL-3.0, see [LICENSE](LICENSE). The application fingerprints include data from
[webappanalyzer](https://github.com/enthec/webappanalyzer) (GPL-3.0).
