#!/usr/bin/env python3
"""
cmsweb.py - public "check my website" frontend for cmsscan.

A visitor enters ONE hostname and confirms they are authorized to have it checked.
The server then makes the same few requests a browser would (HTTPS, falling back
to HTTP, following redirects only on the same server) and reports PHP / CMS
findings. No port scan, no IP ranges, no vhost probing.

Abuse protection:
  * authorization checkbox (logged with time, client IP, consent version)
  * client IPs from VPNs, Tor, proxies and datacenters are refused
    (public lists, refreshed automatically)
  * heavy rate limits per client, per target and globally, plus a concurrency cap
  * results per hostname are cached, so a target can't be hammered through us
  * targets: hostnames only, must resolve to PUBLIC IPs only (no internal /
    private / loopback addresses), connection pinned to the checked IP
    (no DNS rebinding), redirects only within the same server
  * same-origin check on the API (no driving scans from other websites)

Standard library only. Runs behind nginx (see deploy/), e.g.:
    python3 cmsweb.py --origin https://scan.example.ch
"""
import argparse
import bisect
import collections
import concurrent.futures as cf
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cmsscan  # noqa: E402  (detection engine, used unchanged)

CONSENT_VERSION = "2026-10-26.4"   # bump whenever the consent / rules text on the page changes

# --- limits ---------------------------------------------------------------
CLIENT_LIMITS = [(5, 3600)]                         # per visitor: 5 checks per hour
MAX_CONCURRENT = 3                                  # scans running at the same time
CACHE_TTL = 3600                                    # same hostname -> cached result for an hour
SCAN_TIMEOUT = 45                                   # hard cap per scan (seconds)
HTTP_TIMEOUT = 6                                    # per request inside a scan

# --- blocklists for CLIENT addresses (who is asking) -------------------------
BLOCKLISTS = {
    "vpn": ["https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"],
    "datacenter": ["https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt"],
    "tor": ["https://check.torproject.org/torbulkexitlist",
            "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst"],
}
BLOCKLIST_REFRESH = 6 * 3600

# --- targets that are NEVER checked (hard-coded, not configurable) ------------
# Well-known organisations, governments and militaries: the domain and all subdomains.
NEVER_CHECK_DOMAINS = {
    # search, cloud, software
    "google.com", "google.ch", "googleapis.com", "gstatic.com", "googleusercontent.com", "youtube.com",
    "gmail.com", "android.com", "blogger.com", "blogspot.com", "withgoogle.com", "appspot.com", "goo.gl",
    "microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "office365.com",
    "windows.net", "windows.com", "azure.com", "azurewebsites.net", "bing.com", "msn.com", "skype.com",
    "linkedin.com", "github.com", "github.io", "githubusercontent.com", "xbox.com", "sharepoint.com",
    "apple.com", "icloud.com", "me.com", "mzstatic.com",
    "amazon.com", "amazon.de", "amazon.co.uk", "amazonaws.com", "cloudfront.net", "aws.amazon.com", "a2z.com",
    "meta.com", "facebook.com", "fb.com", "fbcdn.net", "instagram.com", "whatsapp.com", "whatsapp.net",
    "messenger.com", "threads.net",
    "x.com", "twitter.com", "t.co", "twimg.com", "tiktok.com", "snapchat.com", "reddit.com", "pinterest.com",
    "discord.com", "discord.gg", "telegram.org", "t.me", "signal.org", "zoom.us", "slack.com",
    "cloudflare.com", "cloudflare.net", "akamai.com", "akamai.net", "akamaiedge.net", "fastly.com",
    "fastly.net", "oracle.com", "ibm.com", "sap.com", "salesforce.com", "adobe.com", "cisco.com",
    "intel.com", "nvidia.com", "amd.com", "samsung.com", "dell.com", "hp.com", "vmware.com", "broadcom.com",
    "openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "mozilla.org", "wikipedia.org",
    "wikimedia.org", "netflix.com", "spotify.com", "paypal.com", "stripe.com", "visa.com", "mastercard.com",
    "ebay.com", "alibaba.com", "aliexpress.com", "booking.com", "airbnb.com", "uber.com",
    # Swiss: federal administration, big providers, banks
    "admin.ch", "ch.ch", "parlament.ch", "bundesregierung.de", "bundestag.de", "swisscom.ch", "swisscom.com", "sunrise.ch", "salt.ch", "post.ch", "sbb.ch",
    "ubs.com", "ubs.ch", "credit-suisse.com", "postfinance.ch", "raiffeisen.ch", "zkb.ch", "snb.ch",
    "six-group.com", "switch.ch", "nic.ch",
    # international organisations
    "un.org", "who.int", "nato.int", "europa.eu", "icann.org", "iana.org", "ietf.org",
}
# Government / military top-level and second-level labels ("*.gov", "*.gov.uk", "*.mil.br", ...)
NEVER_CHECK_LABELS = {"gov", "mil", "gouv", "gob", "govt", "go", "gv", "bund", "admin", "army", "navy", "police"}
NEVER_CHECK_TLDS = {"gov", "mil", "int", "edu"}

# Countries whose websites are never checked: their country domains and any site whose
# server is located there (IP ranges from the regional internet registries).
BLOCKED_COUNTRIES = {
    "RU": ["ru", "su", "xn--p1ai"],                       # Russia (.рф)
    "BY": ["by", "xn--90ais"],                            # Belarus (.бел)
    "CN": ["cn", "xn--fiqs8s", "xn--fiqz9s"],             # China (.中国 / .中國)
    "HK": ["hk", "xn--j6w193g"],                          # Hong Kong
    "MO": ["mo"],                                         # Macau
    "IR": ["ir", "xn--mgba3a4f16a"],                      # Iran (.ایران)
    "KP": ["kp"],                                         # North Korea
    "SY": ["sy", "xn--ogbpf8fl"],                         # Syria
    "CU": ["cu"],                                         # Cuba
    "AF": ["af"],                                         # Afghanistan
    "MM": ["mm"],                                         # Myanmar
    "VE": ["ve"],                                         # Venezuela
}
GEO_URL = "https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/{cc}/{fam}-aggregated.txt"
GEO_REFRESH = 24 * 3600

# PHP2Shell (CVE-2026-109618 / -109619): first fixed upstream release per branch
PHP_FIXED = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
# versions distributions keep while backporting fixes (patch state invisible remotely)
DISTRO_VERSIONS = {"8.3.6", "8.1.2", "8.5.4", "8.0.30", "7.4.33", "8.2.7", "7.4.3", "7.2.24"}

HOSTNAME_RX = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# IP range sets with fast lookup
# ---------------------------------------------------------------------------
class RangeSet:
    """Merged integer intervals per IP version, looked up with bisect."""

    def __init__(self, cidrs=()):
        iv = {4: [], 6: []}
        for c in cidrs:
            try:
                n = ipaddress.ip_network(c.strip(), strict=False)
            except ValueError:
                continue
            iv[n.version].append((int(n.network_address), int(n.broadcast_address)))
        self.starts, self.ends = {}, {}
        for v, items in iv.items():
            items.sort()
            merged = []
            for s, e in items:
                if merged and s <= merged[-1][1] + 1:
                    merged[-1][1] = max(merged[-1][1], e)
                else:
                    merged.append([s, e])
            self.starts[v] = [m[0] for m in merged]
            self.ends[v] = [m[1] for m in merged]
        self.size = sum(len(x) for x in self.starts.values())

    def __contains__(self, ip):
        a = ipaddress.ip_address(ip)
        s, e = self.starts.get(a.version, []), self.ends.get(a.version, [])
        i = bisect.bisect_right(s, int(a)) - 1
        return i >= 0 and int(a) <= e[i]


class Blocklists:
    """Downloads VPN / datacenter / Tor lists, caches them on disk, refreshes them."""

    def __init__(self, state_dir, enabled, fail_closed):
        self.dir = os.path.join(state_dir, "blocklists")
        self.enabled = enabled
        self.fail_closed = fail_closed
        self.sets = {}
        self.loaded_at = 0
        self.lock = threading.Lock()

    def _download(self, name):
        for url in BLOCKLISTS[name]:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "cmsweb blocklist updater"})
                with urllib.request.urlopen(req, timeout=30) as r:
                    lines = r.read().decode("utf-8", "replace").splitlines()
                lines = [l.split("#")[0].strip() for l in lines]
                lines = [l for l in lines if l]
                if len(lines) < 50:                 # suspiciously small: keep the old one
                    raise ValueError(f"only {len(lines)} entries")
                os.makedirs(self.dir, exist_ok=True)
                tmp = os.path.join(self.dir, f"{name}.txt.tmp")
                with open(tmp, "w") as f:
                    f.write("\n".join(lines))
                os.replace(tmp, os.path.join(self.dir, f"{name}.txt"))
                return lines
            except Exception as e:  # noqa: BLE001
                log(f"blocklist {name}: {url} failed: {e}")
        return None

    def refresh(self):
        new = {}
        for name in BLOCKLISTS:
            lines = self._download(name)
            if lines is None:                       # fall back to the cached copy
                path = os.path.join(self.dir, f"{name}.txt")
                if os.path.exists(path):
                    with open(path) as f:
                        lines = f.read().splitlines()
            if lines:
                new[name] = RangeSet(lines)
        with self.lock:
            if new:
                self.sets.update(new)
                self.loaded_at = time.time()
        log("blocklists: " + ", ".join(f"{k} {v.size} ranges" for k, v in self.sets.items()))

    def start(self):
        if not self.enabled:
            return
        self.refresh()

        def loop():
            while True:
                time.sleep(BLOCKLIST_REFRESH)
                self.refresh()
        threading.Thread(target=loop, daemon=True).start()

    def check(self, ip):
        """Return the list name that contains ip, '' if clean, 'unavailable' if fail-closed."""
        if not self.enabled:
            return ""
        with self.lock:
            sets = dict(self.sets)
        if not sets and self.fail_closed:
            return "unavailable"
        for name, rs in sets.items():
            if ip in rs:
                return name
        return ""


class TargetGeo:
    """IP ranges of BLOCKED_COUNTRIES (for targets). Always on, fail-closed: while no
    list is available, no website can be checked."""

    def __init__(self, state_dir):
        self.path = os.path.join(state_dir, "blocklists", "target-countries.txt")
        self.ranges = None
        self.lock = threading.Lock()

    def _download(self):
        lines = []
        for cc in BLOCKED_COUNTRIES:
            for fam in ("ipv4", "ipv6"):
                url = GEO_URL.format(cc=cc.lower(), fam=fam)
                req = urllib.request.Request(url, headers={"User-Agent": "cmsweb blocklist updater"})
                try:
                    with urllib.request.urlopen(req, timeout=30) as r:
                        got = [l.split("#")[0].strip() for l in r.read().decode("utf-8", "replace").splitlines()]
                except urllib.error.HTTPError as e:
                    if e.code == 404:            # e.g. a country without IPv6 allocations
                        continue
                    raise
                lines += [l for l in got if l]
        if len(lines) < 1000:                    # partial / broken download: keep the old one
            raise ValueError(f"only {len(lines)} ranges")
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path + ".tmp", "w") as f:
            f.write("\n".join(lines))
        os.replace(self.path + ".tmp", self.path)
        return lines

    def refresh(self):
        try:
            lines = self._download()
        except Exception as e:  # noqa: BLE001
            log(f"target country list: download failed: {e}")
            lines = None
            if os.path.exists(self.path):
                with open(self.path) as f:
                    lines = f.read().splitlines()
        if lines:
            rs = RangeSet(lines)
            with self.lock:
                self.ranges = rs
            log(f"target country list: {rs.size} ranges ({', '.join(BLOCKED_COUNTRIES)})")
        elif self.ranges is None:
            log("target country list: NOT AVAILABLE - checks are refused until it can be loaded")

    def start(self):
        self.refresh()

        def loop():
            while True:
                time.sleep(GEO_REFRESH if self.ranges is not None else 300)
                self.refresh()
        threading.Thread(target=loop, daemon=True).start()

    def blocked(self, ip):
        """True if ip is in a blocked country, None if the list isn't available yet."""
        with self.lock:
            rs = self.ranges
        if rs is None:
            return None
        return ip in rs


# ---------------------------------------------------------------------------
# sliding-window rate limiter
# ---------------------------------------------------------------------------
class Limiter:
    def __init__(self):
        self.events = collections.defaultdict(collections.deque)
        self.lock = threading.Lock()
        self.last_gc = time.time()

    def check(self, key, limits, record=True):
        """(allowed, retry_after_seconds). Records the event only if allowed."""
        now = time.time()
        longest = max(w for _, w in limits)
        with self.lock:
            dq = self.events[key]
            while dq and dq[0] <= now - longest:
                dq.popleft()
            for count, window in limits:
                recent = [t for t in dq if t > now - window]
                if len(recent) >= count:
                    return False, int(recent[0] + window - now) + 1
            if record:
                dq.append(now)
            if now - self.last_gc > 600:            # drop idle keys
                for k in [k for k, d in self.events.items() if not d or d[-1] < now - 2 * 86400]:
                    del self.events[k]
                self.last_gc = now
        return True, 0


# ---------------------------------------------------------------------------
# target validation (SSRF protection)
# ---------------------------------------------------------------------------
class TargetError(Exception):
    pass


def normalize_host(raw):
    """Accept 'example.ch', 'https://example.ch/path' -> 'example.ch'. Hostnames only."""
    s = (raw or "").strip().lower()
    if len(s) > 300:
        raise TargetError("Input too long.")
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)            # drop scheme
    s = re.split(r"[/?#]", s, maxsplit=1)[0]                # drop path/query
    if "@" in s:
        raise TargetError("Please enter a plain hostname.")
    if ":" in s or s.startswith("["):
        raise TargetError("Ports and IP addresses are not supported - please enter a hostname.")
    s = s.rstrip(".")
    try:
        s = s.encode("idna").decode("ascii")                # internationalized domains
    except UnicodeError:
        raise TargetError("Invalid hostname.")
    if cmsscan.is_ip(s) or re.fullmatch(r"[0-9.]+", s):
        raise TargetError("IP addresses are not supported - please enter a hostname.")
    if not HOSTNAME_RX.match(s):
        raise TargetError("Invalid hostname.")
    return s


def is_public(ip):
    a = ipaddress.ip_address(ip)
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_global and not (a.is_multicast or a.is_reserved or a.is_loopback
                                or a.is_link_local or a.is_private)


NOT_ALLOWED = "This website can't be checked with this service."
BLOCKED_TLDS = {t for tlds in BLOCKED_COUNTRIES.values() for t in tlds}


def never_check(host):
    """Hard-coded exclusions by name. Returns a short reason for the audit log, or ''."""
    labels = host.split(".")
    if labels[-1] in BLOCKED_TLDS:
        return "country-tld"
    if labels[-1] in NEVER_CHECK_TLDS:
        return "gov-tld"
    # second-level government / military zones of country domains: gov.uk, gouv.fr, gv.at, go.jp ...
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in NEVER_CHECK_LABELS:
        return "gov-sld"
    for i in range(len(labels) - 1):                         # domain and all its subdomains
        if ".".join(labels[i:]) in NEVER_CHECK_DOMAINS:
            return "well-known"
    return ""


def resolve_target(host, allow_private, deny_ips, deny_hosts, geo):
    """Returns (ip, '') or raises TargetError(user message) with .reason for the audit log."""
    def refuse(reason, msg=NOT_ALLOWED):
        e = TargetError(msg)
        e.reason = reason
        raise e

    why = never_check(host)
    if why:
        refuse(why)
    if any(host == d or host.endswith("." + d) for d in deny_hosts):
        refuse("deny-host")
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        refuse("no-dns", "The hostname does not resolve.")
    ips = sorted({i[4][0] for i in infos}, key=lambda x: (":" in x, x))   # IPv4 first
    if not ips:
        refuse("no-dns", "The hostname does not resolve.")
    for ip in ips:                                          # ALL addresses are checked
        if not allow_private and not is_public(ip):
            refuse("non-public", "This hostname points to a non-public address and cannot be checked.")
        if ip in deny_ips:
            refuse("deny-ip")
        in_country = geo.blocked(ip)
        if in_country is None:
            refuse("geo-unavailable", "The service is temporarily unavailable. Please try again later.")
        if in_country:
            refuse("country-ip")
    return ips[0]


# ---------------------------------------------------------------------------
# scan + presentation
# ---------------------------------------------------------------------------
WHERE = {"header": "HTTP header", "cookie": "cookie", "body": "page content",
         "db-header": "HTTP header", "db-cookie": "cookie", "db-meta": "meta tag",
         "db-html": "page content", "db-script": "script path", "db-url": "URL",
         ".php-link": "link to a .php file"}


def friendly_evidence(evidence):
    out = []
    for e in [x.strip() for x in evidence.split(", ") if x.strip()]:
        if e.startswith("redirects to other server:"):
            out.append("Redirects to another server - that server was not checked: "
                       + e.split(":", 1)[1].strip())
            continue
        tech, _, where = e.partition(":")
        text = f"{tech}: {WHERE.get(where, where)}"
        if text not in out:
            out.append(text)
    return out


def version_ge(a, b):
    """'8.3.36' >= '8.3.36' -> True (numeric, part by part)."""
    pa = [int(x) for x in re.findall(r"\d+", a)]
    pb = [int(x) for x in re.findall(r"\d+", b)]
    return pa >= pb


def php_assessment(version):
    """PHP2Shell (CVE-2026-109618 / CVE-2026-109619) status, as far as visible."""
    if not version:
        return {"status": "unknown",
                "text": "The PHP version is not exposed, so the patch status cannot be checked "
                        "from outside. Check it on the server (package changelog or php -v)."}
    if version in DISTRO_VERSIONS:
        return {"status": "unknown",
                "text": f"PHP {version} is a Linux distribution build. Distributions backport "
                        "security fixes without changing this number, so whether PHP2Shell "
                        "(CVE-2026-109618/-109619) is patched is not visible from outside - "
                        "check the package changelog on the server."}
    branch = ".".join(version.split(".")[:2])
    fixed = PHP_FIXED.get(branch)
    if not fixed:
        return {"status": "bad",
                "text": f"PHP {branch} is end-of-life upstream and gets no official security "
                        "fixes. Unless your provider backports them, it is likely affected by "
                        "PHP2Shell (CVE-2026-109618/-109619). Plan an upgrade to PHP 8.4 or 8.5."}
    if version_ge(version, fixed):
        return {"status": "good",
                "text": f"PHP {version} includes the fix for PHP2Shell "
                        f"(CVE-2026-109618/-109619, fixed in {fixed})."}
    return {"status": "bad",
            "text": f"PHP {version} is older than {fixed} and likely vulnerable to PHP2Shell "
                    "(CVE-2026-109618/-109619, critical remote code execution). Update PHP."}


def scan(host, ip):
    vt = f"{host}@{ip}" if ":" not in ip else f"{host}@[{ip}]"
    try:
        row = cmsscan.check(vt, HTTP_TIMEOUT)
    finally:
        cmsscan.RESULT_META.pop(vt, None)                   # long-running: don't grow memory
        cmsscan.SNI_ONLY.discard(vt)
    _, final, status, verdict, version, apps, server, evidence = row
    result = {
        "host": host, "ip": ip, "final_url": final, "http_status": status,
        "reachable": verdict != "ERROR",
        "php": verdict.startswith("PHP"),
        "php_version": version,
        "apps": [a for a in apps.split(", ") if a],
        "server": server,
        "evidence": friendly_evidence(evidence) if verdict != "ERROR" else [],
        "error": evidence if verdict == "ERROR" else "",
        "recommendations": [],
    }
    if verdict == "SNI ONLY":
        result["reachable"] = False
        result["error"] = "The server refused the HTTPS connection for this hostname."
    if result["php"]:
        result["php_check"] = php_assessment(version)
    if version:
        result["recommendations"].append(
            "The site reveals its exact PHP version (X-Powered-By header). Set "
            "expose_php = Off in php.ini to stop advertising it.")
    if result["php"] and not version:
        result["recommendations"].append(
            "Keep PHP and all applications/plugins up to date; the version is hidden, "
            "which is good practice.")
    return result


# ---------------------------------------------------------------------------
# web server
# ---------------------------------------------------------------------------
class App:
    def __init__(self, a):
        self.a = a
        self.blocklists = Blocklists(a.state_dir, not a.no_blocklists, a.fail_closed)
        self.geo = TargetGeo(a.state_dir)
        # never check the server this runs on: the origin's domain (+ subdomains) and
        # every address it resolves to (which also covers all other sites on that server)
        self.own_host = (re.sub(r"^[a-z]+://", "", a.origin.lower()).split("/")[0].split(":")[0]
                         if a.origin else "")
        self.own_domains = {d for d in {self.own_host, cmsscan.base_domain(self.own_host)} if d} \
            if self.own_host and not cmsscan.is_ip(self.own_host) else set()
        self.limiter = Limiter()
        self.sem = threading.BoundedSemaphore(MAX_CONCURRENT)
        self.cache, self.cache_lock = {}, threading.Lock()
        self.pool = cf.ThreadPoolExecutor(max_workers=MAX_CONCURRENT + 2)
        self.audit_lock = threading.Lock()
        self.deny_ips = set(a.deny_ip)
        self.trusted = [ipaddress.ip_network(t, strict=False) for t in a.trusted_proxy]
        self.deny_hosts = {h.lower().strip(".") for h in a.deny_host}
        self.static = {}
        for name, ctype in (("index.html", "text/html; charset=utf-8"),
                            ("app.js", "text/javascript; charset=utf-8"),
                            ("style.css", "text/css; charset=utf-8")):
            with open(os.path.join(HERE, "static", name), "rb") as f:
                self.static["/" + name] = (f.read(), ctype)
        page, ctype = self.static["/index.html"]
        page = page.replace(b"<!--OPERATOR-->", self.operator_html().encode("utf-8"))
        # cache busting: reference CSS/JS with a hash of their content, so a new version
        # always gets a new URL and browsers never mix old and new files
        for name in ("style.css", "app.js"):
            ver = hashlib.sha256(self.static["/" + name][0]).hexdigest()[:10]
            page = page.replace(f'"/{name}"'.encode(), f'"/{name}?v={ver}"'.encode())
        self.static["/index.html"] = self.static["/"] = (page, ctype)

    def operator_html(self):
        """'Contact' section from CMSWEB_OPERATOR / CMSWEB_CONTACT / CMSWEB_IMPRINT_URL."""
        esc = lambda s: (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                         .replace('"', "&quot;"))
        name, mail, url = self.a.operator.strip(), self.a.contact.strip(), self.a.imprint_url.strip()
        if not (name or mail or url):          # optional: nothing set -> no section
            return ""
        parts = []
        if name:
            parts.append(f"This service is run by {esc(name)}.")
        if mail:
            parts.append(f'Questions, removal requests or abuse reports: '
                         f'<a href="mailto:{esc(mail)}">{esc(mail)}</a>.')
        html = "    <h2>Contact</h2>\n    <p>" + " ".join(parts) + "</p>\n"
        if url.startswith(("https://", "http://")):
            html += f'    <p><a href="{esc(url)}">Imprint</a></p>\n'
        return html

    def own_ips(self):
        """Current public addresses of this service's own hostname (re-resolved, so a
        changed server IP is picked up). Includes any address given in the origin."""
        if not self.own_host:
            return set()
        if cmsscan.is_ip(self.own_host):
            return {self.own_host.strip("[]")}
        try:
            return {i[4][0] for i in socket.getaddrinfo(self.own_host, 443, proto=socket.IPPROTO_TCP)}
        except OSError:
            return set()

    def audit(self, **entry):
        """One JSON line per check. With --audit-dir: one file per day, files older than
        --retention-days are deleted (the privacy notice promises this)."""
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **entry}
        line = json.dumps(entry, ensure_ascii=False)
        with self.audit_lock:
            if not self.a.audit_dir:
                print("AUDIT " + line, file=sys.stderr, flush=True)
                return
            os.makedirs(self.a.audit_dir, exist_ok=True)
            day = time.strftime("%Y-%m-%d")
            with open(os.path.join(self.a.audit_dir, f"audit-{day}.jsonl"), "a", encoding="utf-8") as f:
                f.write(line + "\n")
            if day != getattr(self, "_purged_day", None):          # purge once per day
                self._purged_day = day
                cutoff = time.time() - self.a.retention_days * 86400
                for name in os.listdir(self.a.audit_dir):
                    path = os.path.join(self.a.audit_dir, name)
                    if name.startswith("audit-") and os.path.getmtime(path) < cutoff:
                        os.remove(path)

    def client_key(self, ip):
        a = ipaddress.ip_address(ip)
        if a.version == 6:
            if a.ipv4_mapped:
                return str(a.ipv4_mapped)
            return str(ipaddress.ip_network(f"{ip}/64", strict=False))   # one /64 = one client
        return str(a)

    def handle_scan(self, client_ip, body, ua):
        """Returns (http_status, payload dict, extra headers)."""
        try:
            data = json.loads(body or b"{}")
        except ValueError:
            return 400, {"error": "Invalid request."}, {}
        if not isinstance(data, dict):
            return 400, {"error": "Invalid request."}, {}
        if data.get("consent") is not True:
            return 400, {"error": "Please confirm that you are authorized to have this website checked."}, {}

        listed = self.blocklists.check(client_ip)
        if listed:
            self.audit(client=client_ip, target=str(data.get("host", ""))[:100], outcome=f"blocked:{listed}")
            msg = ("This service is temporarily unavailable." if listed == "unavailable" else
                   "Requests via VPNs, proxies, Tor or hosting/datacenter networks are not accepted. "
                   "Please use your regular internet connection.")
            return 403, {"error": msg}, {}

        ok, retry = self.limiter.check("c:" + self.client_key(client_ip), CLIENT_LIMITS)
        if not ok:
            return 429, {"error": f"Too many checks. Please try again in {fmt_wait(retry)}."}, \
                {"Retry-After": str(retry)}

        try:
            host = normalize_host(data.get("host"))
        except TargetError as e:
            return 400, {"error": str(e)}, {}

        with self.cache_lock:
            hit = self.cache.get(host)
        if hit and time.time() - hit[0] < CACHE_TTL:
            self.audit(client=client_ip, target=host, consent=CONSENT_VERSION, ua=ua[:200], outcome="cached")
            return 200, {**hit[1], "cached": True, "checked_at": hit[2]}, {}

        try:
            ip = resolve_target(host, self.a.allow_private_targets,
                                self.deny_ips | self.own_ips(), self.deny_hosts | self.own_domains,
                                self.geo)
        except TargetError as e:
            self.audit(client=client_ip, target=host, consent=CONSENT_VERSION,
                       outcome=f"rejected:{getattr(e, 'reason', e)}")
            return 400, {"error": str(e)}, {}

        if not self.sem.acquire(blocking=False):
            return 503, {"error": "The service is busy right now. Please try again in a minute."}, \
                {"Retry-After": "60"}
        try:
            fut = self.pool.submit(scan, host, ip)
            try:
                result = fut.result(timeout=SCAN_TIMEOUT)
            except cf.TimeoutError:
                result = {"host": host, "ip": ip, "reachable": False,
                          "error": "The website took too long to respond.", "php": False,
                          "apps": [], "evidence": [], "recommendations": []}
        finally:
            self.sem.release()
        checked_at = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
        with self.cache_lock:
            self.cache[host] = (time.time(), result, checked_at)
            for k in [k for k, v in self.cache.items() if time.time() - v[0] > CACHE_TTL]:
                del self.cache[k]
        self.audit(client=client_ip, target=host, ip=ip, consent=CONSENT_VERSION, ua=ua[:200],
                   outcome="php" if result.get("php") else ("no-php" if result.get("reachable") else "unreachable"),
                   apps=result.get("apps"), php_version=result.get("php_version"))
        return 200, {**result, "cached": False, "checked_at": checked_at}, {}


def fmt_wait(s):
    if s < 90:
        return f"{s} seconds"
    if s < 5400:
        return f"{round(s / 60)} minutes"
    return f"{round(s / 3600)} hours"


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; "
                               "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
                               "form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "cmsweb"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            if app.a.access_log:
                log(f"{self.client_ip()} {fmt % args}")

        def client_ip(self):
            peer = self.client_address[0]
            if any(ipaddress.ip_address(peer) in net for net in app.trusted):
                real = (self.headers.get("X-Real-IP") or "").strip()
                if real and cmsscan.is_ip(real):
                    return real
            return peer

        def send(self, status, body, ctype, extra=None, cache="no-store"):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            for k, v in {**SECURITY_HEADERS, **(extra or {})}.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def send_json(self, status, obj, extra=None):
            self.send(status, json.dumps(obj).encode(), "application/json", extra)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                return self.send(200, b"ok\n", "text/plain")
            if path in app.static:
                body, ctype = app.static[path]
                if path in ("/", "/index.html"):
                    cache = "no-cache"                                 # always revalidate the page
                elif "v=" in self.path:
                    cache = "public, max-age=31536000, immutable"      # versioned asset URL
                else:
                    cache = "public, max-age=300"
                return self.send(200, body, ctype, cache=cache)
            self.send(404, b"Not found\n", "text/plain")

        do_HEAD = do_GET

        def do_POST(self):
            if self.path.split("?", 1)[0] != "/api/scan":
                return self.send_json(404, {"error": "Not found."})
            if app.a.origin and self.headers.get("Origin", "") != app.a.origin:
                return self.send_json(403, {"error": "Requests are only accepted from the website."})
            if not (self.headers.get("Content-Type", "").startswith("application/json")):
                return self.send_json(415, {"error": "Invalid request."})
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 < length <= 2048:
                return self.send_json(413, {"error": "Invalid request."})
            body = self.rfile.read(length)
            try:
                status, payload, extra = app.handle_scan(self.client_ip(), body,
                                                         self.headers.get("User-Agent", ""))
            except Exception as e:  # noqa: BLE001
                log(f"internal error: {e!r}")
                status, payload, extra = 500, {"error": "Internal error. Please try again later."}, {}
            self.send_json(status, payload, extra)

    return Handler


def main():
    ap = argparse.ArgumentParser(description="Public 'check my website' frontend for cmsscan")
    env = os.environ.get
    ap.add_argument("--bind", default=env("CMSWEB_BIND", "127.0.0.1"),
                    help="listen address (default 127.0.0.1, behind nginx; 0.0.0.0 in Docker)")
    ap.add_argument("--port", type=int, default=int(env("CMSWEB_PORT", "8088")))
    ap.add_argument("--origin", default=env("CMSWEB_ORIGIN", ""),
                    help="public origin, e.g. https://scan.example.ch - API requests from other "
                         "origins are refused (strongly recommended)")
    ap.add_argument("--trusted-proxy", action="append",
                    default=[x for x in env("CMSWEB_TRUSTED_PROXY", "127.0.0.1,::1").split(",") if x],
                    help="proxy address or network (CIDR) whose X-Real-IP header is trusted "
                         "(default: localhost)")
    ap.add_argument("--state-dir", default=os.environ.get("STATE_DIRECTORY", os.path.join(HERE, "state")),
                    help="where blocklists are cached")
    ap.add_argument("--audit-dir", default=env("CMSWEB_AUDIT_DIR", ""),
                    help="directory for the daily JSON-lines audit log of every check "
                         "(default: stderr / journal)")
    ap.add_argument("--operator", default=env("CMSWEB_OPERATOR", ""),
                    help="name of the person/company running the service (shown on the page)")
    ap.add_argument("--contact", default=env("CMSWEB_CONTACT", ""),
                    help="contact e-mail shown on the page (questions, abuse reports)")
    ap.add_argument("--imprint-url", default=env("CMSWEB_IMPRINT_URL", ""),
                    help="optional link to an existing imprint page")
    ap.add_argument("--retention-days", type=int, default=int(env("CMSWEB_RETENTION_DAYS", "30")),
                    help="delete audit log files older than this (default 30, matches the privacy notice)")
    ap.add_argument("--access-log", action="store_true", help="also log every HTTP request")
    ap.add_argument("--no-blocklists", action="store_true", help="don't block VPN/Tor/datacenter clients")
    ap.add_argument("--fail-closed", action="store_true",
                    help="refuse all checks while no blocklist could be loaded")
    ap.add_argument("--deny-host", action="append",
                    default=[x for x in env("CMSWEB_DENY_HOSTS", "").split(",") if x], metavar="DOMAIN",
                    help="domain (and its subdomains) that may never be checked; repeatable")
    ap.add_argument("--deny-ip", action="append",
                    default=[x for x in env("CMSWEB_DENY_IPS", "").split(",") if x], metavar="IP",
                    help="target IP that may never be checked (e.g. this server); repeatable")
    ap.add_argument("--allow-private-targets", action="store_true", help=argparse.SUPPRESS)  # tests only
    a = ap.parse_args()

    try:
        n, src = cmsscan.load_rules()
        log(f"fingerprints: {cmsscan.BUILTIN_APPS} built-in + {n} from {src}")
    except Exception as e:  # noqa: BLE001
        log(f"fingerprint database not loaded: {e}")
    if not a.origin:
        log("WARNING: --origin not set; the API accepts requests from any website")
    if a.allow_private_targets:
        log("WARNING: --allow-private-targets is set - for local testing only!")

    app = App(a)
    app.blocklists.start()
    app.geo.start()
    if app.own_host:
        log(f"never checked (own server): {', '.join(sorted(app.own_domains)) or '-'} "
            f"+ addresses {', '.join(sorted(app.own_ips())) or '(not resolvable yet)'}")
    server = ThreadingHTTPServer((a.bind, a.port), make_handler(app))
    server.daemon_threads = True
    log(f"cmsweb listening on http://{a.bind}:{a.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
