#!/usr/bin/env python3
"""
web.py - public "check my website" page for a panic-core scanner.
Generated from panic-core (https://github.com/akaihigurashi/panic-core), don't edit here.

A visitor enters ONE hostname and confirms they are authorized to have it checked.
The server then makes the same few requests a browser would (HTTPS, falling back
to HTTP, following redirects only on the same server) and shows what the scanner
found. No port scan, no IP ranges, no vhost probing.

Abuse protection:
  * authorization checkbox (logged with time, client IP, consent version)
  * client IPs from VPNs, Tor, proxies and datacenters are refused
    (public lists, refreshed automatically)
  * rate limit per client plus a concurrency cap
  * results per hostname are cached, so a target can't be hammered through us
  * targets: hostnames only, must resolve to PUBLIC IPs only (no internal /
    private / loopback addresses), connection pinned to the checked IP
    (no DNS rebinding), redirects only within the same server
  * hard-coded list of websites that are never checked, and never this server
  * same-origin check on the API (no driving scans from other websites); origins listed in
    PANIC_EXTRA_ORIGINS (the landing page's "Check all") may call it too, via CORS

Access keys (optional, PANIC_ACCESS_KEYS + PANIC_TRUST_SECRET): people with a key unlock
once at /unlock (or with a magic link /unlock#k=KEY - the part after # never reaches a
server) and get a signed HttpOnly cookie for 30 days. For them the rate limit, the result
cache, the VPN/datacenter/country checks on their own address and the never-check lists
(well-known sites, top sites, government, sanctioned countries) are lifted, and they can
check a single public IP address instead of a hostname. Internal /
private addresses, PANIC_DENY_HOSTS / PANIC_DENY_IPS and this server stay blocked, and
every check is logged with their name. Only the SHA-256 hash of a key is configured.
    python3 web.py --make-key akai      # new key + the line for .env

Standard library only. Runs behind a reverse proxy, e.g.:
    python3 web.py --origin https://scan.example.ch
"""
import argparse
import bisect
import importlib
import collections
import concurrent.futures as cf
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
SCANNER = os.environ.get("PANIC_SCANNER", "php2scan")   # the single-file scanner next to this file
engine = importlib.import_module(SCANNER)  # detection engine, used unchanged
engine.KEEP_INFO = True                    # web results need the full details

CONSENT_VERSION = engine.CONSENT_VERSION   # bump in the check whenever the consent text changes

# --- limits ---------------------------------------------------------------
CLIENT_LIMITS = [(5, 3600)]                         # per visitor: 5 checks per hour
MAX_CONCURRENT = 3                                  # scans running at the same time
CACHE_TTL = 3600                                    # same hostname -> cached result for an hour
SCAN_TIMEOUT = 45                                   # hard cap per scan (seconds)
HTTP_TIMEOUT = 6                                    # per request inside a scan

# --- access keys ----------------------------------------------------------------
TRUST_COOKIE = "panic_trust"
TRUST_DAYS = 30                                     # an unlock lasts this long per browser
UNLOCK_LIMITS = [(5, 900), (20, 86400)]             # unlock attempts per visitor
KEY_NAME_RX = re.compile(r"^[a-z0-9_-]{1,32}$")

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

# Countries whose websites are never checked (their country domains and any site whose
# server is located there, IP ranges from the regional internet registries), and whose
# visitors can't use the service.
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

# The most visited websites (Tranco research ranking, https://tranco-list.eu) are never
# checked either: the top TOP_SITES domains and all their subdomains.
TOP_SITES = 100
TOP_SITES_URL = "https://tranco-list.eu/top-1m.csv.zip"
TOP_SITES_REFRESH = 7 * 24 * 3600

HOSTNAME_RX = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")


def env(name, default=""):
    """PANIC_<name>, or the older CMSWEB_<name>."""
    return os.environ.get("PANIC_" + name, os.environ.get("CMSWEB_" + name, default))


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
                req = urllib.request.Request(url, headers={"User-Agent": f"{engine.NAME} blocklist updater"})
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
                req = urllib.request.Request(url, headers={"User-Agent": f"{engine.NAME} blocklist updater"})
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


class TopSites:
    """Top TOP_SITES domains of the Tranco list, cached on disk and refreshed weekly.
    Comes on top of the hard-coded NEVER_CHECK_DOMAINS, so if the list can't be
    loaded the service keeps working with the hard-coded list only."""

    def __init__(self, state_dir):
        self.path = os.path.join(state_dir, "blocklists", "top-sites.txt")
        self.domains = frozenset()
        self.lock = threading.Lock()

    def _download(self):
        import io
        import zipfile
        req = urllib.request.Request(TOP_SITES_URL, headers={"User-Agent": f"{engine.NAME} blocklist updater"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read()
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            with z.open(z.namelist()[0]) as f:
                domains = []
                for line in io.TextIOWrapper(f, encoding="utf-8", errors="replace"):
                    domain = line.strip().split(",")[-1].lower().rstrip(".")
                    if domain:
                        domains.append(domain)
                    if len(domains) >= TOP_SITES:
                        break
        if len(domains) < TOP_SITES // 2:
            raise ValueError(f"only {len(domains)} domains")
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path + ".tmp", "w") as f:
            f.write("\n".join(domains))
        os.replace(self.path + ".tmp", self.path)
        return domains

    def refresh(self):
        try:
            domains = self._download()
        except Exception as e:  # noqa: BLE001
            log(f"top sites list: download failed: {e}")
            domains = None
            if os.path.exists(self.path):
                with open(self.path) as f:
                    domains = f.read().split()
        if domains:
            with self.lock:
                self.domains = frozenset(domains)
            log(f"top sites list: {len(domains)} domains are never checked")

    def start(self):
        self.refresh()

        def loop():
            while True:
                time.sleep(TOP_SITES_REFRESH if self.domains else 3600)
                self.refresh()
        threading.Thread(target=loop, daemon=True).start()

    def contains(self, host):
        with self.lock:
            domains = self.domains
        labels = host.split(".")
        return any(".".join(labels[i:]) in domains for i in range(len(labels) - 1))


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


class Trust:
    """Access keys: name -> SHA-256 of the key (the key itself is never stored), and the
    signed cookie that marks an unlocked browser. The signature covers the key's hash, so
    removing or replacing a key in ACCESS_KEYS revokes every cookie made with it."""

    def __init__(self, keys_spec, secret, domain):
        self.keys = {}
        for item in (keys_spec or "").split(","):
            name, _, digest = item.strip().partition(":")
            name, digest = name.strip().lower(), digest.strip().lower()
            if not name and not digest:
                continue
            if not KEY_NAME_RX.match(name) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                log(f"ignoring invalid ACCESS_KEYS entry {name[:32]!r} (expected name:sha256-hex)")
                continue
            self.keys[name] = digest
        self.secret = (secret or "").encode()
        self.domain = (domain or "").strip().lstrip(".")
        self.enabled = bool(self.keys) and len(self.secret) >= 32
        if self.keys and not self.enabled:
            log("WARNING: ACCESS_KEYS is set but TRUST_SECRET is missing or shorter than 32 "
                "characters - access keys are disabled")

    def match(self, key):
        """Name of the key, or None. Compares hashes in constant time."""
        if not self.enabled or not isinstance(key, str) or not 16 <= len(key.strip()) <= 200:
            return None
        digest = hashlib.sha256(key.strip().encode()).hexdigest()
        found = None
        for name, kd in self.keys.items():
            if hmac.compare_digest(digest, kd):
                found = name
        return found

    def _sig(self, name, exp):
        msg = f"{name}|{exp}|{self.keys[name]}".encode()
        return hmac.new(self.secret, msg, hashlib.sha256).hexdigest()[:40]

    def _header(self, value, max_age):
        parts = [f"{TRUST_COOKIE}={value}", "Path=/", f"Max-Age={max_age}", "Secure", "HttpOnly",
                 "SameSite=Lax"]
        if self.domain:
            parts.insert(1, f"Domain={self.domain}")
        return "; ".join(parts)

    def issue(self, name):
        exp = int(time.time()) + TRUST_DAYS * 86400
        return self._header(f"{name}.{exp}.{self._sig(name, exp)}", TRUST_DAYS * 86400), exp

    def clear(self):
        return self._header("", 0)

    def who(self, cookie_header):
        """(name, expiry) for a valid cookie, else (None, 0)."""
        if not self.enabled or not cookie_header:
            return None, 0
        for part in cookie_header.split(";"):
            k, _, v = part.strip().partition("=")
            if k != TRUST_COOKIE:
                continue
            bits = v.strip().strip('"').split(".")
            if len(bits) != 3 or bits[0] not in self.keys or not bits[1].isdigit():
                continue
            name, exp, sig = bits[0], int(bits[1]), bits[2]
            if exp > time.time() and hmac.compare_digest(sig, self._sig(name, exp)):
                return name, exp
        return None, 0


# ---------------------------------------------------------------------------
# target validation (SSRF protection)
# ---------------------------------------------------------------------------
class TargetError(Exception):
    pass


def normalize_host(raw, allow_ip=False):
    """Accept 'example.ch', 'https://example.ch/path' -> 'example.ch'. Hostnames only;
    allow_ip (access key): a single public IP address too, e.g. 203.0.113.10 or [2001:db8::1]."""
    s = (raw or "").strip().lower()
    if len(s) > 300:
        raise TargetError("Input too long.")
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)            # drop scheme
    s = re.split(r"[/?#]", s, maxsplit=1)[0]                # drop path/query
    if allow_ip:
        bare = s[1:-1] if s.startswith("[") and s.endswith("]") else s
        try:
            return str(ipaddress.ip_address(bare))
        except ValueError:
            pass
    if "@" in s:
        raise TargetError("Please enter a plain hostname.")
    if ":" in s or s.startswith("["):
        raise TargetError("Ports and IP addresses are not supported - please enter a hostname.")
    s = s.rstrip(".")
    try:
        s = s.encode("idna").decode("ascii")                # internationalized domains
    except UnicodeError:
        raise TargetError("Invalid hostname.")
    if engine.is_ip(s) or re.fullmatch(r"[0-9.]+", s):
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
COUNTRY_BLOCKED = "This service is not available in your country."
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


def resolve_target(host, allow_private, deny_ips, deny_hosts, geo, top=None, trusted=False):
    """Returns (ip, '') or raises TargetError(user message) with .reason for the audit log.
    trusted (access key): the never-check lists and the country check are skipped; private
    addresses and the operator's own deny lists are always enforced."""
    def refuse(reason, msg=NOT_ALLOWED):
        e = TargetError(msg)
        e.reason = reason
        raise e

    why = "" if trusted else never_check(host)
    if why:
        refuse(why)
    if not trusted and top is not None and top.contains(host):
        refuse("top-site")
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
            refuse("non-public", "This is a non-public address and cannot be checked." if engine.is_ip(host)
                   else "This hostname points to a non-public address and cannot be checked.")
        if ip in deny_ips:
            refuse("deny-ip")
        if trusted:
            continue
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
         "version-url": "version information page"}
WHERE.update(getattr(engine, "WHERE", {}))


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


def scan_one(host, ip, port, options):
    addr = ip if ":" not in ip else f"[{ip}]"
    vt = (addr if engine.is_ip(host) else f"{host}@{addr}") + (f":{port}" if port else "")
    try:
        row = engine.check(vt, HTTP_TIMEOUT, options)
        info = engine.INFO.get(vt)
    finally:
        engine.RESULT_META.pop(vt, None)                    # long-running: don't grow memory
        engine.SNI_ONLY.discard(vt)
        engine.INFO.pop(vt, None)
    return row, info


def scan(host, ip, options):
    """The website itself (443, then 80), plus the product's own port if the check names one
    (WEB_EXTRA_PORTS, e.g. Plex 32400) and it is open. The most serious answer wins."""
    best = None
    for port in [None] + list(getattr(engine, "WEB_EXTRA_PORTS", [])):
        if port and not engine.port_open(ip, port, 3):
            continue
        row, info = scan_one(host, ip, port, options)
        style = engine.verdict_style(row) if hasattr(engine, "verdict_style") else None
        rank = style[0] if style else 999
        if best is None or rank < best[0]:
            res = engine.web_result(host, ip, row, info, friendly_evidence)
            res["port"] = port or ""
            best = (rank, res)
    return best[1]


# ---------------------------------------------------------------------------
# web server
# ---------------------------------------------------------------------------
class App:
    def __init__(self, a):
        self.a = a
        self.blocklists = Blocklists(a.state_dir, not a.no_blocklists, a.fail_closed)
        self.geo = TargetGeo(a.state_dir)
        self.top = TopSites(a.state_dir)
        # never check the server this runs on: the origin's domain (+ subdomains) and
        # every address it resolves to (which also covers all other sites on that server)
        self.own_host = (re.sub(r"^[a-z]+://", "", a.origin.lower()).split("/")[0].split(":")[0]
                         if a.origin else "")
        self.own_domains = {d for d in {self.own_host, engine.base_domain(self.own_host)} if d} \
            if self.own_host and not engine.is_ip(self.own_host) else set()
        self.limiter = Limiter()
        self.sem = threading.BoundedSemaphore(MAX_CONCURRENT)
        self.cache, self.cache_lock = {}, threading.Lock()
        self.pool = cf.ThreadPoolExecutor(max_workers=MAX_CONCURRENT + 2)
        self.audit_lock = threading.Lock()
        self.deny_ips = set(a.deny_ip)
        self.trusted = [ipaddress.ip_network(t, strict=False) for t in a.trusted_proxy]
        self.deny_hosts = {h.lower().strip(".") for h in a.deny_host}
        self.origins = {o.rstrip("/") for o in [a.origin] + a.extra_origin if o}
        self.trust = Trust(a.access_keys, a.trust_secret, a.cookie_domain)
        self.static = {}
        root = os.path.join(HERE, "static")
        for dirpath, _, files in os.walk(root):
            for name in files:
                ctype = STATIC_TYPES.get(os.path.splitext(name)[1].lower())
                if not ctype:
                    continue
                path = os.path.join(dirpath, name)
                with open(path, "rb") as f:
                    self.static["/" + os.path.relpath(path, root).replace(os.sep, "/")] = (f.read(), ctype)
        page, ctype = self.static["/index.html"]
        page = page.replace(b"<!--OPERATOR-->", self.operator_html().encode("utf-8"))
        # cache busting: reference CSS/JS with a hash of their content, so a new version
        # always gets a new URL and browsers never mix old and new files
        for name in [p[1:] for p in self.static if p.endswith((".css", ".js"))]:
            ver = hashlib.sha256(self.static["/" + name][0]).hexdigest()[:10]
            page = page.replace(f'"/{name}"'.encode(), f'"/{name}?v={ver}"'.encode())
        self.static["/index.html"] = self.static["/"] = (page, ctype)
        for path, (text, ctype) in TRUST_STATIC.items():     # /unlock page + badge, same for all
            self.static[path] = (text.encode("utf-8"), ctype)

    def operator_html(self):
        """'Contact' section from PANIC_OPERATOR / PANIC_CONTACT / PANIC_IMPRINT_URL."""
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
        if engine.is_ip(self.own_host):
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

    def handle_unlock(self, client_ip, body, ua):
        if not self.trust.enabled:
            return 404, {"error": "Access keys are not set up on this server."}, {}
        ok, retry = self.limiter.check("u:" + self.client_key(client_ip), UNLOCK_LIMITS)
        if not ok:
            self.audit(client=client_ip, ua=ua[:200], outcome="unlock:rate-limited")
            return 429, {"error": f"Too many attempts. Please try again in {fmt_wait(retry)}."}, \
                {"Retry-After": str(retry)}
        try:
            data = json.loads(body or b"{}")
        except ValueError:
            data = {}
        name = self.trust.match(data.get("key") if isinstance(data, dict) else None)
        if not name:
            self.audit(client=client_ip, ua=ua[:200], outcome="unlock:failed")   # never the key
            time.sleep(1)
            return 403, {"error": "This key is not valid."}, {}
        cookie, exp = self.trust.issue(name)
        self.audit(client=client_ip, ua=ua[:200], outcome="unlock:ok", trusted=name)
        return 200, {"enabled": True, "trusted": name,
                     "until": time.strftime("%Y-%m-%d", time.gmtime(exp))}, {"Set-Cookie": cookie}

    @staticmethod
    def cache_key(host, options, trusted):
        key = host + ("|" + json.dumps(options, sort_keys=True) if options else "")
        return f"t:{trusted}:{key}" if trusted else key

    def cached_view(self, client_ip, data, trusted):
        """A result that was checked within the last hour, without checking again: no request
        to the website, so no consent, no rate limit. 404 if there is none."""
        try:
            host = normalize_host(data.get("host"), allow_ip=bool(trusted))
        except TargetError as e:
            return 400, {"error": str(e)}, {}
        key = self.cache_key(host, engine.web_options(data), trusted)
        with self.cache_lock:
            hit = self.cache.get(key)
        if not hit or time.time() - hit[0] >= CACHE_TTL:
            return 404, {"error": "No recent result for this address."}, {}
        return 200, {**hit[1], "cached": True, "checked_at": hit[2]}, {}

    def handle_scan(self, client_ip, body, ua, trusted=None):
        """Returns (http_status, payload dict, extra headers). trusted: name of a valid
        access key cookie - no rate limit, cache or client checks, wider target rules."""
        try:
            data = json.loads(body or b"{}")
        except ValueError:
            return 400, {"error": "Invalid request."}, {}
        if not isinstance(data, dict):
            return 400, {"error": "Invalid request."}, {}
        if data.get("cached_only") is True:          # "Details" from Check all: show, never scan
            return self.cached_view(client_ip, data, trusted)
        if data.get("consent") is not True:
            return 400, {"error": "Please confirm that you are authorized to have this website checked."}, {}

        tr = {"trusted": trusted} if trusted else {}         # logged with every entry
        if not trusted and self.geo.blocked(client_ip):          # visitors from BLOCKED_COUNTRIES
            self.audit(client=client_ip, target=str(data.get("host", ""))[:100], outcome="blocked:country")
            return 403, {"error": COUNTRY_BLOCKED}, {}

        listed = None if trusted else self.blocklists.check(client_ip)
        if listed:
            self.audit(client=client_ip, target=str(data.get("host", ""))[:100], outcome=f"blocked:{listed}")
            msg = ("This service is temporarily unavailable." if listed == "unavailable" else
                   "Requests via VPNs, proxies, Tor or hosting/datacenter networks are not accepted. "
                   "Please use your regular internet connection.")
            return 403, {"error": msg}, {}

        try:
            host = normalize_host(data.get("host"), allow_ip=bool(trusted))
        except TargetError as e:
            return 400, {"error": str(e)}, {}
        options = engine.web_options(data)                  # e.g. {"probe": True}, validated
        opt = {"options": options} if options else {}       # only logged when used
        key = self.cache_key(host, options, trusted)

        with self.cache_lock:
            hit = None if trusted else self.cache.get(key)  # key holders always get a fresh check
        if hit and time.time() - hit[0] < CACHE_TTL:
            self.audit(client=client_ip, target=host, consent=CONSENT_VERSION, ua=ua[:200], outcome="cached",
                       **opt)
            return 200, {**hit[1], "cached": True, "checked_at": hit[2]}, {}

        try:
            ip = resolve_target(host, self.a.allow_private_targets,
                                self.deny_ips | self.own_ips(), self.deny_hosts | self.own_domains,
                                self.geo, self.top, trusted=bool(trusted))
        except TargetError as e:
            self.audit(client=client_ip, target=host, consent=CONSENT_VERSION,
                       outcome=f"rejected:{getattr(e, 'reason', e)}", **opt, **tr)
            return 400, {"error": str(e)}, {}

        if not self.sem.acquire(blocking=False):
            return 503, {"error": "The service is busy right now. Please try again in a minute."}, \
                {"Retry-After": "60"}
        # Rule: no request to the website, no rate used. Cached answers, refused or invalid
        # targets and "busy" cost nothing; only a check that really runs is counted.
        ok, retry = (True, 0) if trusted else \
            self.limiter.check("c:" + self.client_key(client_ip), CLIENT_LIMITS)
        if not ok:
            self.sem.release()
            return 429, {"error": f"Too many checks. Please try again in {fmt_wait(retry)}."}, \
                {"Retry-After": str(retry)}
        try:
            fut = self.pool.submit(scan, host, ip, options)
            try:
                result = fut.result(timeout=SCAN_TIMEOUT)
            except cf.TimeoutError:
                result = engine.web_timeout_result(host, ip)
        finally:
            self.sem.release()
        checked_at = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
        # key holders' results go to their own cache entry (they may check sites the public
        # can't), only used to show them the result again via cached_only
        with self.cache_lock:
            self.cache[key] = (time.time(), result, checked_at)
            for k in [k for k, v in self.cache.items() if time.time() - v[0] > CACHE_TTL]:
                del self.cache[k]
        self.audit(client=client_ip, target=host, ip=ip, consent=CONSENT_VERSION, ua=ua[:200],
                   **engine.audit_fields(result), **opt, **tr)
        return 200, {**result, "cached": False, "checked_at": checked_at}, {}


def fmt_wait(s):
    if s < 90:
        return f"{s} seconds"
    if s < 5400:
        return f"{round(s / 60)} minutes"
    return f"{round(s / 3600)} hours"


STATIC_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png",
                ".ico": "image/x-icon", ".woff2": "font/woff2", ".txt": "text/plain; charset=utf-8"}

# /unlock page and the "Unlocked" badge: the same on every scanner (served by this file)
UNLOCK_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Unlock - shouldipanic.ch</title>
<link rel="stylesheet" href="/unlock.css">
<script src="/unlock.js" defer></script>
</head>
<body>
<main>
  <p class="brand"><a href="https://shouldipanic.ch">shouldipanic<span class="q">?</span></a></p>
  <h1>Unlock</h1>
  <p class="lede">For people with an access key. Unlocked, there's no rate limit and no saved
    results, well-known or foreign websites can be checked too, and so can public IP addresses. Internal addresses stay
    blocked, and every check is logged under your name.</p>

  <form id="unlock" novalidate>
    <input type="text" name="username" value="shouldipanic.ch" autocomplete="username" class="sr-only" tabindex="-1" aria-hidden="true">
    <label for="key">Access key</label>
    <div class="row">
      <input id="key" name="password" type="password" autocomplete="current-password"
             autocapitalize="off" spellcheck="false" required>
      <button type="submit" id="go">Unlock</button>
    </div>
    <p id="msg" class="msg" role="status" aria-live="polite"></p>
  </form>

  <section id="done" class="done" hidden aria-live="polite">
    <p class="ok"><svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Z M7.5 12.5l3 3 6-6.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
      <span>Unlocked as <strong id="who"></strong> until <span id="until"></span>, on every
      shouldipanic.ch scanner in this browser.</span></p>
    <div class="row">
      <a class="btn" href="/">Continue</a>
      <button type="button" id="lock" class="btn-ghost">Lock again</button>
    </div>
  </section>
</main>
</body>
</html>
"""

UNLOCK_CSS = r""":root { --bg: #f1ece2; --card: #fbf7f0; --ink: #1d1712; --soft: #5b4c3f; --line: #dccfba;
  --accent: #d2502a; --accent-hi: #b23f1c; --on: #fff8f0; --ok-bg: #dcebd3; --ok: #23461a; --bad: #9a2a12;
  color-scheme: light dark; }
@media (prefers-color-scheme: dark) { :root { --bg: #18130f; --card: #231c16; --ink: #f3e9da; --soft: #bba48c;
  --line: #3d3025; --accent: #e0683f; --accent-hi: #f07a52; --on: #1d1712; --ok-bg: #1f3319; --ok: #c8e4b9; --bad: #f08a6e; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 17px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 560px; margin: 0 auto; padding: 48px 20px; }
a { color: var(--accent); }
:focus-visible { outline: 3px solid var(--accent); outline-offset: 2px; }
.brand { margin: 0; }
.brand a { color: var(--ink); text-decoration: none; font: 700 22px ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: -0.04em; }
.brand .q { display: inline-block; margin-left: 2px; padding: 0 6px 1px; border-radius: 4px; background: var(--accent); color: var(--on); transform: rotate(-8deg); }
h1 { margin: 40px 0 0; font-size: 40px; line-height: 1.05; letter-spacing: -0.03em; }
.lede { color: var(--soft); margin: 12px 0 0; }
form, .done { margin-top: 32px; padding: 24px; border-radius: 14px; background: var(--card); border: 1.5px solid var(--line); }
label { display: block; font-weight: 600; margin-bottom: 8px; }
.row { display: flex; flex-wrap: wrap; gap: 10px; }
#key { flex: 1 1 240px; min-width: 0; min-height: 50px; padding: 0 14px; border: 2px solid var(--line); border-radius: 8px;
  background: var(--bg); color: var(--ink); font: 500 17px ui-monospace, SFMono-Regular, Menlo, monospace; }
#key:focus { border-color: var(--accent); outline: none; }
button, .btn { display: inline-flex; align-items: center; justify-content: center; min-height: 50px; padding: 0 22px; border: 0;
  border-radius: 8px; background: var(--accent); color: var(--on); font: 600 16px system-ui, sans-serif; text-decoration: none; cursor: pointer; }
button:hover, .btn:hover { background: var(--accent-hi); color: var(--on); }
.btn-ghost { background: transparent; color: var(--ink); border: 1.5px solid var(--line); }
.btn-ghost:hover { background: transparent; color: var(--ink); border-color: var(--accent); }
.msg { margin: 12px 0 0; min-height: 1.5em; font-weight: 600; color: var(--bad); }
.msg.info { color: var(--soft); font-weight: 400; }
.ok { display: flex; gap: 12px; align-items: flex-start; margin: 0 0 18px; padding: 14px 16px; border-radius: 10px; background: var(--ok-bg); color: var(--ok); }
.ok svg { flex: none; margin-top: 2px; }
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
"""

UNLOCK_JS = r""""use strict";
// Unlock with an access key. A magic link carries the key after "#": browsers never send
// that part to any server, it only exists here. It is removed from the address bar at once.
(function () {
  const form = document.getElementById("unlock");
  const input = document.getElementById("key");
  const msg = document.getElementById("msg");
  const done = document.getElementById("done");

  function say(text, info) {
    msg.textContent = text;
    msg.className = info ? "msg info" : "msg";
  }
  function showDone(d) {
    document.getElementById("who").textContent = d.trusted;
    document.getElementById("until").textContent = d.until || "";
    form.hidden = true;
    done.hidden = false;
  }
  function showForm() {
    done.hidden = true;
    form.hidden = false;
  }
  async function unlock(key) {
    say("Checking…", true);
    try {
      const res = await fetch("/api/unlock", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key: key }),
      });
      let d = {};
      try { d = await res.json(); } catch (e) { /* not JSON */ }
      if (!res.ok) {
        say(d.error || "Unlock failed (error " + res.status + ").");
        showForm();
        input.focus();
        return;
      }
      input.value = "";
      say("");
      showDone(d);
    } catch (e) {
      say("The service could not be reached. Try again later.");
    }
  }

  function fromHash() {
    let hash = location.hash.slice(1);
    if (!hash) return false;
    history.replaceState(null, "", location.pathname);
    if (hash.startsWith("k=")) hash = hash.slice(2);
    try { hash = decodeURIComponent(hash); } catch (e) { /* keep as is */ }
    unlock(hash);
    return true;
  }
  window.addEventListener("hashchange", fromHash);   // magic link opened on this page

  if (!fromHash()) {
    fetch("/api/whoami", { credentials: "same-origin", cache: "no-store" })
      .then((r) => r.json())
      .then((d) => {
        if (d.trusted) showDone(d);
        else if (d.enabled === false) say("Access keys are not set up on this server.", true);
      })
      .catch(() => {});
  }

  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const key = input.value.trim();
    if (!key) { say("Enter your access key."); input.focus(); return; }
    unlock(key);
  });

  document.getElementById("lock").addEventListener("click", async () => {
    try {
      await fetch("/api/lock", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json" }, body: "{}",
      });
    } catch (e) { /* cookie stays until it expires */ }
    showForm();
    say("Locked. This browser is back to the normal limits.", true);
  });
})();
"""

TRUST_JS = r""""use strict";
// Shows "Unlocked: name" in the top bar when this browser has a valid access-key cookie.
(function () {
  fetch("/api/whoami", { credentials: "same-origin", cache: "no-store" })
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => {
      if (!d || !d.trusted) return;
      const bar = document.querySelector(".nav-links") || document.querySelector("nav");
      if (!bar) return;
      const a = document.createElement("a");
      a.href = "/unlock";
      a.className = "trust-badge";
      a.title = "Access key active until " + d.until + ". Click to lock.";
      a.textContent = "Unlocked: " + d.trusted;
      const s = a.style;
      s.display = "inline-flex"; s.alignItems = "center"; s.minHeight = "34px"; s.padding = "0 12px";
      s.borderRadius = "999px"; s.border = "1.5px solid currentColor"; s.fontSize = "14px";
      s.fontWeight = "600"; s.textDecoration = "none"; s.whiteSpace = "nowrap";
      if (!bar.classList.contains("nav-links")) { s.marginLeft = "auto"; s.marginRight = "12px"; }
      bar.insertBefore(a, bar.lastElementChild);
    })
    .catch(() => {});
})();
"""

TRUST_STATIC = {
    "/unlock": (UNLOCK_HTML, "text/html; charset=utf-8"),
    "/unlock.css": (UNLOCK_CSS, "text/css; charset=utf-8"),
    "/unlock.js": (UNLOCK_JS, "text/javascript; charset=utf-8"),
    "/trust.js": (TRUST_JS, "text/javascript; charset=utf-8"),
}

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; "
                               "img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; "
                               "form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = engine.NAME
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            if app.a.access_log:
                log(f"{self.client_ip()} {fmt % args}")

        def client_ip(self):
            peer = self.client_address[0]
            if any(ipaddress.ip_address(peer) in net for net in app.trusted):
                real = (self.headers.get("X-Real-IP") or "").strip()
                if real and engine.is_ip(real):
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
            trusted, exp = app.trust.who(self.headers.get("Cookie", ""))
            if path == "/api/whoami":
                return self.send_json(200, {"enabled": app.trust.enabled, "trusted": trusted,
                                            "until": time.strftime("%Y-%m-%d", time.gmtime(exp))
                                            if trusted else None})
            if not trusted and app.geo.blocked(self.client_ip()):   # visitors from BLOCKED_COUNTRIES
                return self.send(403, (COUNTRY_BLOCKED + "\n").encode(), "text/plain; charset=utf-8")
            if path in app.static:
                body, ctype = app.static[path]
                if path in ("/", "/index.html", "/unlock"):
                    cache = "no-cache"                                 # always revalidate the page
                elif "v=" in self.path or path.endswith(".woff2"):
                    cache = "public, max-age=31536000, immutable"      # versioned asset URL
                else:
                    cache = "public, max-age=300"
                return self.send(200, body, ctype, cache=cache)
            self.send(404, b"Not found\n", "text/plain")

        do_HEAD = do_GET

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            if path not in ("/api/scan", "/api/unlock", "/api/lock"):
                return self.send_json(404, {"error": "Not found."})
            origin = self.headers.get("Origin", "")
            if app.origins and origin not in app.origins:
                return self.send_json(403, {"error": "Requests are only accepted from the website."})
            cors = self.cors_headers(origin)
            # text/plain too: a "simple" cross-origin request needs no preflight (Check all on
            # the landing page). The Origin check above is what keeps other websites out.
            ctype = self.headers.get("Content-Type", "")
            if not ctype.startswith(("application/json", "text/plain")):
                return self.send_json(415, {"error": "Invalid request."}, cors)
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 < length <= 2048:
                return self.send_json(413, {"error": "Invalid request."}, cors)
            body = self.rfile.read(length)
            ua = self.headers.get("User-Agent", "")
            if path == "/api/lock":
                return self.send_json(200, {"enabled": app.trust.enabled, "trusted": None},
                                      {"Set-Cookie": app.trust.clear(), **cors})
            try:
                if path == "/api/unlock":
                    status, payload, extra = app.handle_unlock(self.client_ip(), body, ua)
                else:
                    trusted, _ = app.trust.who(self.headers.get("Cookie", ""))
                    status, payload, extra = app.handle_scan(self.client_ip(), body, ua, trusted)
            except Exception as e:  # noqa: BLE001
                log(f"internal error: {e!r}")
                status, payload, extra = 500, {"error": "Internal error. Please try again later."}, {}
            self.send_json(status, payload, {**extra, **cors})

        def cors_headers(self, origin):
            """Let the other allowed origins (PANIC_EXTRA_ORIGINS, e.g. the landing page) read
            the answer, with the unlock cookie. Never '*'."""
            if not origin or origin == app.a.origin.rstrip("/") or origin not in app.origins:
                return {}
            return {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true",
                    "Vary": "Origin"}

        def do_OPTIONS(self):
            origin = self.headers.get("Origin", "")
            cors = self.cors_headers(origin)
            if not cors or self.path.split("?", 1)[0] != "/api/scan":
                return self.send(403, b"", "text/plain")
            self.send(204, b"", "text/plain", {**cors, "Access-Control-Allow-Methods": "POST",
                                               "Access-Control-Allow-Headers": "Content-Type",
                                               "Access-Control-Max-Age": "86400"})

    return Handler


def make_key(a):
    name = a.make_key.strip().lower()
    if not KEY_NAME_RX.match(name):
        sys.exit("name: lowercase letters, digits, - and _ (max 32)")
    key = secrets.token_urlsafe(24)
    digest = hashlib.sha256(key.encode()).hexdigest()
    sites = [o.rstrip("/") for o in a.extra_origin + [a.origin] if o] or ["https://<your site>"]
    print(f"\nAccess key for {name} (shown only once - save it in your password manager):\n\n    {key}\n")
    print("Magic link (keep it in your password manager too, not as a bookmark):\n")
    for site in dict.fromkeys(sites):
        print(f"    {site}/unlock#k={key}")
    print("\nAdd to .env (several keys: separate with commas), then restart the containers:\n")
    print(f"    ACCESS_KEYS={name}:{digest}")
    if len(a.trust_secret) < 32:
        print(f"    TRUST_SECRET={secrets.token_hex(32)}")
    print("\nOnly the hash goes into .env. The key itself is not stored anywhere.\n")


def main():
    ap = argparse.ArgumentParser(description=f"Public 'check my website' page for {engine.NAME}")
    ap.add_argument("--bind", default=env("BIND", "127.0.0.1"),
                    help="listen address (default 127.0.0.1, behind nginx; 0.0.0.0 in Docker)")
    ap.add_argument("--port", type=int, default=int(env("PORT", "8088")))
    ap.add_argument("--origin", default=env("ORIGIN", ""),
                    help="public origin, e.g. https://scan.example.ch - API requests from other "
                         "origins are refused (strongly recommended)")
    ap.add_argument("--trusted-proxy", action="append",
                    default=[x for x in env("TRUSTED_PROXY", "127.0.0.1,::1").split(",") if x],
                    help="proxy address or network (CIDR) whose X-Real-IP header is trusted "
                         "(default: localhost)")
    ap.add_argument("--state-dir", default=os.environ.get("STATE_DIRECTORY", os.path.join(HERE, "state")),
                    help="where blocklists are cached")
    ap.add_argument("--audit-dir", default=env("AUDIT_DIR", ""),
                    help="directory for the daily JSON-lines audit log of every check "
                         "(default: stderr / journal)")
    ap.add_argument("--operator", default=env("OPERATOR", ""),
                    help="name of the person/company running the service (shown on the page)")
    ap.add_argument("--contact", default=env("CONTACT", ""),
                    help="contact e-mail shown on the page (questions, abuse reports)")
    ap.add_argument("--imprint-url", default=env("IMPRINT_URL", ""),
                    help="optional link to an existing imprint page")
    ap.add_argument("--retention-days", type=int, default=int(env("RETENTION_DAYS", "30")),
                    help="delete audit log files older than this (default 30, matches the privacy notice)")
    ap.add_argument("--access-log", action="store_true", help="also log every HTTP request")
    ap.add_argument("--no-blocklists", action="store_true", help="don't block VPN/Tor/datacenter clients")
    ap.add_argument("--fail-closed", action="store_true",
                    help="refuse all checks while no blocklist could be loaded")
    ap.add_argument("--deny-host", action="append",
                    default=[x for x in env("DENY_HOSTS", "").split(",") if x], metavar="DOMAIN",
                    help="domain (and its subdomains) that may never be checked; repeatable")
    ap.add_argument("--deny-ip", action="append",
                    default=[x for x in env("DENY_IPS", "").split(",") if x], metavar="IP",
                    help="target IP that may never be checked (e.g. this server); repeatable")
    ap.add_argument("--extra-origin", action="append",
                    default=[x.strip() for x in env("EXTRA_ORIGINS", "").split(",") if x.strip()],
                    metavar="ORIGIN", help="another origin whose pages may call this API, e.g. "
                                           "https://shouldipanic.ch for its /unlock page; repeatable")
    ap.add_argument("--access-keys", default=env("ACCESS_KEYS", ""), metavar="NAME:SHA256,...",
                    help="access keys as name:sha256-of-key (make one with --make-key). "
                         "Better via env PANIC_ACCESS_KEYS")
    ap.add_argument("--trust-secret", default=env("TRUST_SECRET", ""), metavar="SECRET",
                    help="secret that signs unlock cookies, 32+ characters, the same on every "
                         "scanner. Better via env PANIC_TRUST_SECRET")
    ap.add_argument("--cookie-domain", default=env("COOKIE_DOMAIN", ""), metavar="DOMAIN",
                    help="share the unlock between subdomains, e.g. shouldipanic.ch")
    ap.add_argument("--make-key", metavar="NAME",
                    help="create a new access key for NAME, print it and the ACCESS_KEYS line, exit")
    ap.add_argument("--allow-private-targets", action="store_true", help=argparse.SUPPRESS)  # tests only
    a = ap.parse_args()
    if a.make_key:
        make_key(a)
        return

    try:
        n, src = engine.load_rules()
        log(f"{engine.NAME} {engine.VERSION}: fingerprints {engine.builtin_count()} built-in + {n} from {src}")
    except Exception as e:  # noqa: BLE001
        log(f"fingerprint database not loaded: {e}")
    if not a.origin:
        log("WARNING: --origin not set; the API accepts requests from any website")
    if a.allow_private_targets:
        log("WARNING: --allow-private-targets is set - for local testing only!")

    app = App(a)
    if app.trust.enabled:
        log(f"access keys: {', '.join(sorted(app.trust.keys))}"
            + (f" (cookie for {app.trust.domain})" if app.trust.domain else ""))
    app.blocklists.start()
    app.geo.start()
    app.top.start()
    if app.own_host:
        log(f"never checked (own server): {', '.join(sorted(app.own_domains)) or '-'} "
            f"+ addresses {', '.join(sorted(app.own_ips())) or '(not resolvable yet)'}")
    server = ThreadingHTTPServer((a.bind, a.port), make_handler(app))
    server.daemon_threads = True
    log(f"{engine.NAME} web listening on http://{a.bind}:{a.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
