"""
php2scan.py - PHP / PHP-CMS detection with an integrated TCP port scan.
Part of shouldipanic.ch: is your website affected by PHP2Shell
(CVE-2026-109618 / CVE-2026-109619)?

For each IP/host it first runs a TCP connect scan of 20 common web ports
(-p all for all 65535). It then discovers the vhosts on each IP (TLS
certificates, redirects, reverse DNS, passive DNS, certificate transparency,
optionally your own name list) and checks every vhost on that IP.
On every open port it sends ONE normal GET request to "/" (following up to 5
redirects) and looks at response headers, cookies and HTML.
It does not probe extra paths and sends no payloads.
Only scan systems you are authorized to check.

Fingerprints: ~120 hand-written PHP application rules, plus 315 PHP
technologies embedded from the open Wappalyzer fingerprint database
(webappanalyzer). Works fully offline. -U downloads a fresher copy of the
database into ~/.cache/php2scan, which then takes precedence.

Usage (results are printed to the terminal):
    python3 php2scan.py 203.0.113.10               # 20 web ports + vhost discovery (default)
    python3 php2scan.py 203.0.113.10 203.0.113.11 example.ch
    python3 php2scan.py 198.51.100.0/24            # whole IP range
    python3 php2scan.py 203.0.113.10 -p all        # all 65535 TCP ports
    python3 php2scan.py 203.0.113.10 -p 80,443,8000-8100   # custom port list
    python3 php2scan.py shop.example.ch@203.0.113.10       # one known vhost on a specific IP
    python3 php2scan.py 203.0.113.10 --no-vhosts   # only the IP's default sites
    python3 php2scan.py 203.0.113.10 --no-ct       # vhosts without crt.sh lookup
    python3 php2scan.py 203.0.113.0/24 --names domains.txt  # + your own hostnames (most complete)

Complete vhost lists from the servers themselves (best source for --names):
    apache2ctl -S 2>/dev/null | awk '/namevhost/{print $4} /alias/{print $2}' | sort -u
    nginx -T 2>/dev/null | awk '$1=="server_name"{for(i=2;i<=NF;i++){gsub(";","",$i);print $i}}' | sort -u

Passive DNS: OTX and HackerTarget are used by default (no keys). More sources:
    python3 php2scan.py 203.0.113.10 --shodan-key KEY --vt-key KEY --securitytrails-key KEY
    python3 php2scan.py 203.0.113.10 -n            # no port scan, only 443/80
    python3 php2scan.py ips.txt -o out.csv         # file input / additional CSV output
    python3 php2scan.py 203.0.113.10 -a            # also show hidden rows (errors, duplicates)
    python3 php2scan.py 203.0.113.10 -d            # debug: scan, discovery, requests, matches
    python3 php2scan.py -U                         # refresh the fingerprint database

Targets can be IPs, CIDR ranges, hostnames, URLs, or a file with one per line.

Verdict column:
    PHP (version)  X-Powered-By reveals the exact PHP version
    PHP            PHP is certain (PHP CMS, PHP session cookie or .php links)
    NO SIGN        nothing PHP-specific visible (version may just be hidden)
    SNI ONLY       HTTPS server that only answers for its hostnames (e.g. nginx
                   ssl_reject_handshake); its vhosts are listed in the vhost results
    NOT HTTP       open port, but not a web server (shown with -a)
    ERROR          host not reachable / no open port (shown with -a)
"""
# check module for panic-core: everything specific to php2scan.
# panic-core/bundle.py turns this file plus the engine into php2scan.py.
from engine import *  # noqa: F401,F403  # bundle: strip

NAME = "php2scan"
VERSION = "2.1.1"
DESCRIPTION = "PHP/CMS detection with integrated TCP port scan (PHP2Shell, CVE-2026-109618/-109619)."
TARGETS = {"PHP"}                # database: PHP and every technology that runs on PHP
BUILTIN_LABEL = "PHP apps"
COLUMNS = ["target", "final_url", "http_status", "verdict", "php_version", "php_apps", "server", "evidence"]
IMPLIES = {}                     # extra "X always runs on Y" rules (besides the database)

BANNER = r"""
    ____  __  ______ ___  _____ _________    _   __
   / __ \/ / / / __ \__ \/ ___// ____/   |  / | / /
  / /_/ / /_/ / /_/ /_/ /\__ \/ /   / /| | /  |/ /
 / ____/ __  / ____/ __/___/ / /___/ ___ |/ /|  /
/_/   /_/ /_/_/   /____/____/\____/_/  |_/_/ |_/
"""
BANNER_COLOR = "32"
BANNER_TAGS = ["PHP & CMS detection  ::  port scan  ::  fingerprinting"]

# (technology, where, regex). Everything except "PHP" is a PHP application,
# so any match means the site definitely runs PHP.
FINGERPRINTS = [
    # PHP itself
    ("PHP", "header", r"x-powered-by:[^\n]*\bphp/?(\d+\.\d+\.\d+)?"),
    ("PHP", "cookie", r"\bPHPSESSID="),
    # WordPress
    ("WordPress", "body", r"/wp-(?:content|includes)/"),
        ("WordPress", "header", r"^link:[^\n]*api\.w\.org"),
    ("WordPress", "cookie", r"\b(?:wordpress_|wp-settings-)"),
    # Joomla
        ("Joomla", "body", r"/media/(?:jui|system)/js/|joomla-script-options"),
    # Drupal
    ("Drupal", "header", r"^x-generator:\s*drupal|^x-drupal-"),
    ("Drupal", "body", r"drupalSettings|/sites/default/files/"),
    ("Drupal", "cookie", r"\bS?SESS[0-9a-f]{32}="),
    # TYPO3
    ("TYPO3", "body", r"/typo3(?:conf|temp)/"),
    ("TYPO3", "cookie", r"\bfe_typo_user="),
    # Contao
    ("Contao", "body", r"/assets/contao/"),
    # Magento
    ("Magento", "header", r"^x-magento-"),
    ("Magento", "body", r"data-mage-init|/static/version\d+/frontend/|Mage\.Cookies"),
    ("Magento", "cookie", r"\bmage-(?:cache|messages)"),
    # Shopware
    ("Shopware", "body", r"/bundles/storefront/"),
    ("Shopware", "cookie", r"\bsw-(?:states|context-token)"),
    # PrestaShop
    ("PrestaShop", "body", r"\bvar prestashop\s*="),
    ("PrestaShop", "cookie", r"\bPrestaShop-"),
    # OpenCart
    ("OpenCart", "cookie", r"\bOCSESSID="),
    ("OpenCart", "body", r"catalog/view/(?:theme|javascript)/"),
    # Nextcloud / ownCloud
    ("Nextcloud", "cookie", r"nc_sameSiteCookie|\boc[a-z0-9]{10,}=|\boc_sessionPassphrase="),
    ("Nextcloud", "body", r"data-requesttoken=|oc_requesttoken|id=\"body-(?:login|user|public)\""),
    # Nextcloud iOS app id in <meta name="apple-itunes-app"> (on every Nextcloud page)
    ("Nextcloud", "body", r"app-id=1125420102"),
    # Nextcloud's maintenance / "untrusted domain" / error pages
    ("Nextcloud", "body", r"/core/(?:img|css|js)/|class=\"guest-box|nextcloud.{0,40}maintenance"),
    # Redirect to the login page with Nextcloud's redirect_url parameter
    ("Nextcloud", "header", r"^location:[^\n]*/(?:index\.php/)?login\?redirect_url="),
    # Webmail / admin tools
    ("Roundcube", "cookie", r"\broundcube_sessid="),
    ("Roundcube", "body", r"rcmail\.|roundcube_"),
    ("phpMyAdmin", "cookie", r"\b(?:phpMyAdmin|pma_lang)="),
    ("phpMyAdmin", "body", r"<title>[^<]*phpmyadmin"),
    # Frameworks
    ("Laravel", "cookie", r"\blaravel_session="),
    ("CodeIgniter", "cookie", r"\bci_session="),
    ("Craft CMS", "cookie", r"\bCraftSessionId"),
    ("Craft CMS", "header", r"^x-powered-by:[^\n]*craft cms"),
    ("ProcessWire", "cookie", r"\bwire="),
    ("Moodle", "cookie", r"\bMoodleSession"),
    ("Moodle", "body", r"/theme/yui_combo\.php|M\.cfg\s*=\s*\{[^}]*wwwroot"),
]

# PHP applications that announce themselves in <meta name="generator">.
# (name, regex fragment matched inside the generator tag)
GENERATORS = [
    ("WordPress", r"wordpress"), ("Joomla", r"joomla"), ("Drupal", r"drupal"),
    ("Backdrop CMS", r"backdrop"), ("TYPO3", r"typo3"), ("Contao", r"contao"),
    ("Concrete CMS", r"concrete"), ("SilverStripe", r"silverstripe"), ("Neos", r"\bneos\b"),
    ("MODX", r"modx"), ("ProcessWire", r"processwire"), ("Kirby", r"kirby"),
    ("Grav", r"\bgrav"), ("Bolt CMS", r"\bbolt\b"), ("CMS Made Simple", r"cms made simple"),
    ("Textpattern", r"textpattern"), ("b2evolution", r"b2evolution"), ("Serendipity", r"serendipity"),
    ("Dotclear", r"dotclear"), ("PivotX", r"pivotx"), ("Nucleus CMS", r"nucleus"),
    ("e107", r"\be107\b"), ("PHP-Fusion", r"php-?fusion"), ("XOOPS", r"xoops"),
    ("PHP-Nuke", r"php-?nuke"), ("Mambo", r"\bmambo\b"), ("Zikula", r"zikula"),
    ("Elxis", r"elxis"), ("WebsiteBaker", r"website ?baker"), ("LEPTON CMS", r"\blepton\b"),
    ("ImpressPages", r"impresspages"), ("GetSimple", r"getsimple"), ("Pico", r"\bpico\b"),
    ("HTMLy", r"htmly"), ("WonderCMS", r"wondercms"), ("Typesetter", r"typesetter|gpeasy"),
    ("Automad", r"automad"), ("Bludit", r"bludit"), ("Koken", r"\bkoken\b"),
    ("MediaWiki", r"mediawiki"), ("DokuWiki", r"dokuwiki"), ("Tiki Wiki", r"\btiki\b"),
    ("PmWiki", r"pmwiki"), ("Chamilo", r"chamilo"), ("Piwigo", r"piwigo"),
    ("Zenphoto", r"zenphoto"), ("vBulletin", r"vbulletin"), ("Discuz!", r"discuz"),
    ("phpwind", r"phpwind"), ("Magento", r"magento"), ("Shopware", r"shopware"),
    ("PrestaShop", r"prestashop"), ("OpenCart", r"opencart"), ("JTL-Shop", r"jtl-?shop"),
    ("Gambio", r"gambio"), ("xt:Commerce", r"xt:?commerce"), ("osCommerce", r"oscommerce"),
    ("Zen Cart", r"zen ?cart"), ("CubeCart", r"cubecart"), ("CS-Cart", r"cs-?cart"),
    ("Thelia", r"thelia"), ("OXID eShop", r"oxid"), ("Sylius", r"sylius"),
    ("Craft CMS", r"craft cms"), ("ExpressionEngine", r"expressionengine"), ("October CMS", r"octobercms|october cms"),
    ("Statamic", r"statamic"), ("Pimcore", r"pimcore"), ("Sulu", r"\bsulu\b"),
    ("Mautic", r"mautic"), ("Elgg", r"\belgg\b"), ("Moodle", r"moodle"),
]
GEN_TAG = (r"<meta(?=[^>]*\bname\s*=\s*[\"']?generator\b)[^>]*\bcontent\s*=\s*[\"'][^\"']*{}")
FINGERPRINTS += [(n, "body", GEN_TAG.format(g)) for n, g in GENERATORS]

# Session / app cookies that only PHP applications set.
COOKIES = [
    ("phpBB", r"phpbb3?_\w+_(?:sid|u|k)="), ("vBulletin", r"\bbb_(?:sessionhash|lastvisit|lastactivity)="),
    ("MyBB", r"\bmybb\[|\bmybbuser="), ("Simple Machines Forum", r"\bSMFCookie\d*="),
    ("XenForo", r"\bxf_(?:session|csrf)="), ("Invision Community", r"\bips4_\w+="),
    ("Flarum", r"\bflarum_session="), ("Dolibarr", r"\bDOLSESSID_"), ("SugarCRM/SuiteCRM", r"\bsugar_user_theme="),
    ("GLPI", r"\bglpi_[0-9a-f]+="), ("MantisBT", r"\bMANTIS_\w+="), ("ILIAS", r"\bilClientId="),
    ("Matomo", r"\b(?:MATOMO|PIWIK)_SESSID="), ("osCommerce", r"\bosCsid="), ("Zen Cart", r"\bzenid="),
    ("JTL-Shop", r"\bJTLSHOP="), ("xt:Commerce", r"\bXTCsid="), ("CS-Cart", r"\bsid_customer_\w+="),
    ("WHMCS", r"\bWHMCS[a-zA-Z0-9]+="), ("SquirrelMail", r"\bSQMSESSID="), ("Horde", r"\bHorde\w*="),
    ("ISPConfig", r"\bISPCONFIGSESS="), ("DokuWiki", r"\bDokuWiki=|\bDW[0-9a-f]{32}="),
    ("Kanboard", r"\bKB_SID="), ("Tiny Tiny RSS", r"\bttrss_sid="), ("Shaarli", r"\bshaarli="),
    ("osTicket", r"\bOSTSESSID="), ("Phabricator", r"\bphsid="), ("Snipe-IT", r"\bsnipeit_session="),
    ("October CMS", r"\boctober_session="), ("ExpressionEngine", r"\bexp_(?:last_visit|csrf_token|tracker)="),
    ("CakePHP", r"\bCAKEPHP="), ("Yii", r"\bYII_CSRF_TOKEN="), ("Mautic", r"\bmautic_\w+="),
    ("BookStack", r"\bbookstack_session="), ("Zikula", r"\bZIKULASID\d*="), ("Elgg", r"\bElgg="),
    ("Coppermine", r"\bcpg\d+\w*_data="), ("Gallery", r"\bGALLERYSID="), ("Kayako", r"\bSWIFT_\w+="),
    ("Joomla", r"\bjoomla_user_state="), ("Statamic", r"\bstatamic_session="),
    ("Akaunting", r"\bakaunting_session="), ("Invoice Ninja", r"\bninja_session="),
    ("Firefly III", r"\bfirefly_iii_session="), ("Leantime", r"\bleantime_session="),
    ("Pterodactyl", r"\bpterodactyl_session="), ("FreeScout", r"\bfreescout_session="),
    ("Lychee", r"\blychee_session="), ("Monica", r"\bmonica_session="), ("Grav", r"\bgrav-site-\w+="),
    ("Concrete CMS", r"\bCONCRETE5?="), ("Pimcore", r"\bpimcore_admin_sid="), ("Sylius", r"\bsylius_\w+="),
    ("Laminas/Zend", r"\bZDEDebuggerPresent="), ("Symfony", r"\bsf_redirect="),
]
FINGERPRINTS += [(n, "cookie", c) for n, c in COOKIES]

# Response headers that only PHP applications send.
HEADERS = [
    ("WordPress", r"^x-pingback:[^\n]*xmlrpc\.php"), ("Joomla", r"^x-content-encoded-by:\s*joomla"),
    ("Pimcore", r"^x-powered-by:[^\n]*pimcore"), ("ExpressionEngine", r"^x-powered-by:[^\n]*expressionengine"),
    ("Kirby", r"^x-powered-by:[^\n]*kirby"), ("Sulu", r"^x-generator:\s*sulu"),
    ("Shopware", r"^sw-(?:context-token|version-id|language-id):"), ("Contao", r"^contao-cache:"),
    ("TYPO3", r"^x-typo3-"), ("PrestaShop", r"^powered-by:\s*prestashop"),
    ("Symfony", r"^x-debug-token:"), ("Nextcloud", r"^x-nextcloud-"),
    ("phpBB", r"^x-powered-by:[^\n]*phpbb"), ("Statamic", r"^x-powered-by:[^\n]*statamic"),
]
FINGERPRINTS += [(n, "header", h) for n, h in HEADERS]

# Distinctive HTML/paths of the page itself. Only structural traces (paths,
# JS variables, page titles), never bare product names: a page that merely
# mentions or links to "Nextcloud" must not count. URLs to other servers are
# neutralized before these run (see local_view), so foreign assets never match.
BODY = [
    ("phpBB", r"/styles/prosilver/|/styles/\w+/theme/stylesheet\.css|phpbb_\w+\s*="),
    ("MyBB", r"/jscripts/general\.js|var my_post_key"),
    ("Simple Machines Forum", r"var smf_|smf_scripturl"), ("XenForo", r"data-xf-init|/js/xf/"),
    ("Invision Community", r"ipsSettings|/uploads/set_resources_"), ("Flarum", r"flarum-loading|flarum\.core"),
    ("vBulletin", r"vbulletin_|/clientscript/vbulletin"), ("Discuz!", r"discuz_uid"),
    ("Adminer", r"<title>[^<]*adminer"), ("phpPgAdmin", r"<title>[^<]*phppgadmin"),
    ("SquirrelMail", r"<title>[^<]*squirrelmail|/squirrelmail/(?:src|images)/"),
    ("RainLoop/SnappyMail", r"<title>[^<]*(?:rainloop|snappymail)|/(?:rainloop|snappymail)/v/"),
    ("Horde", r"<title>[^<]*horde|/horde/themes/"), ("LimeSurvey", r"<title>[^<]*limesurvey|/assets/packages/limesurvey|LSvar"),
    ("osTicket", r"<title>[^<]*osticket|/js/osticket\.js"), ("Matomo", r"<title>[^<]*(?:matomo|piwik)"),
    ("EspoCRM", r"<title>[^<]*espocrm"), ("Froxlor", r"<title>[^<]*froxlor"),
    ("ISPConfig", r"<title>[^<]*ispconfig"), ("Dolibarr", r"<title>[^<]*dolibarr|/theme/eldy/"),
    ("GLPI", r"<title>[^<]*\bglpi\b"), ("MantisBT", r"<title>[^<]*mantisbt|/js/mantis\.js"),
    ("Phabricator", r"<title>[^<]*phabricator|/res/phabricator/"), ("Kanboard", r"<title>[^<]*kanboard"),
    ("FreshRSS", r"<title>[^<]*freshrss"), ("Bludit", r"/bl-(?:themes|kernel|plugins)/"),
    ("WHMCS", r"whmcsBaseUrl|/templates/(?:six|twenty-one|lagom2?)/(?:css|js)/"),
    ("Mautic", r"/media/js/mautic|<title>[^<]*mautic"),
    ("Pimcore", r"/bundles/pimcore"), ("Craft CMS", r"/cpresources/"), ("Statamic", r"/vendor/statamic/"),
    ("October CMS", r"/modules/system/assets/"), ("Concrete CMS", r"/concrete/(?:js|css|images)/|CCM_DISPATCHER"),
    ("Joomla", r"/components/com_\w+/"), ("ExpressionEngine", r"/themes/ee/"),
    ("Textpattern", r"/textpattern/(?:textpattern\.js|css\.php)"), ("DokuWiki", r"/lib/exe/(?:css|js)\.php|class=\"dokuwiki"),
    ("MediaWiki", r"/load\.php\?[^\"']*modules=|mw\.config\.set"), ("Tiki Wiki", r"tiki-index\.php"),
    ("ILIAS", r"ilias\.php|/Customizing/global/"), ("Nextcloud", r"/core/js/oc\.js|/apps/theming/|/dist/core-(?:common|main)\.js"),
    ("ownCloud", r"/apps/theme-\w+/|/core/js/oc\.js"), ("Sylius", r"/bundles/syliusshop/"),
    ("OXID eShop", r"/out/(?:flow|wave|azure)/(?:src|img)/"), ("Gambio", r"/templates/Honeygrid/|/GXModules/"),
    ("JTL-Shop", r"/templates/NOVA/"), ("CubeCart", r"index\.php\?_a=|/skins/foundation/"),
    ("Thelia", r"/templates/frontOffice/"), ("Zen Cart", r"index\.php\?main_page="),
    ("osCommerce", r"product_info\.php\?products_id="), ("Snipe-IT", r"<title>[^<]*snipe-?it"),
    ("BookStack", r"<title>[^<]*bookstack"), ("Grav", r"/user/themes/"),
    ("Kirby", r"/media/plugins/[\w-]+/[\w-]+/|/assets/kirby"),
    ("ProcessWire", r"/site/assets/files/\d+/|/site/templates/(?:styles|scripts)/"),
    ("Laravel", r"/vendor/livewire/|/livewire/livewire(?:\.min)?\.js|wire:id="), ("Symfony", r"/_wdt/|sf-toolbar"),
    ("Chamilo", r"/main/inc/lib/javascript/"), ("Piwigo", r"/themes/default/js/|piwigo_"),
]
FINGERPRINTS += [(n, "body", b) for n, b in BODY]


PHP_LINK = r"""(?:href|src|action)\s*=\s*["']([^"'#?]*\.php)(?:[?#"'])"""


def post_fingerprint(info):
    """.php links on the same server (external ones were neutralized before)."""
    for link in re.findall(PHP_LINK, info["body"], re.I):
        if "external.invalid" in link:
            continue
        if "PHP" not in info["techs"]:
            info["techs"].insert(0, "PHP")
        info["evidence"].append("PHP:.php-link")
        info["log"](f"  match {'PHP':<20} in link  : {link!r}")
        break


def verdict(info):
    """(verdict, version, apps) for the result row."""
    techs, versions = info["techs"], info["versions"]
    version = versions.get("PHP", "")
    if version:
        v = f"PHP ({version})"
    elif techs:
        v = "PHP"
    else:
        v = "NO SIGN"
    apps = [f"{t} {versions[t]}" if t in versions else t for t in techs if t != "PHP"]
    return v, version, apps


def count_key(v):
    return "PHP" if v.startswith("PHP") else v


def verdict_style(row):
    """(rank, colour, status, reason) for the result list: what the verdict means for PHP2Shell."""
    v, version = row[3], row[4]
    if not v.startswith("PHP"):
        return 50, "plain", "NO PHP FOUND", ""
    if not version:
        return 20, "yellow", "UNKNOWN", "PHP, but the version is hidden"
    if version in DISTRO_VERSIONS:
        return 20, "yellow", "UNKNOWN", f"PHP {version} distro build: check the package"
    branch = ".".join(version.split(".")[:2])
    fixed = PHP_FIXED.get(branch)
    if not fixed:
        return 10, "red", "VULNERABLE", f"PHP {branch} is end of life"
    if version_ge(version, fixed):
        return 40, "green", "PATCHED", f"PHP {version} (fixed in {fixed})"
    return 10, "red", "VULNERABLE", f"PHP {version} < {fixed}"


EXAMPLES = """examples:
  php2scan.py 203.0.113.10                       20 web ports + every vhost on the IP
  php2scan.py 198.51.100.0/24                    a whole IP range
  php2scan.py shop.example.ch@203.0.113.10       one known vhost on a specific IP
  php2scan.py 203.0.113.0/24 --names domains.txt + hostnames from your own data
  php2scan.py 203.0.113.10 -p all -o out.csv     all 65535 ports, results also as CSV

status: VULNERABLE (PHP version without the fix) - PATCHED - UNKNOWN (PHP, but the
version is hidden or a distro build: check on the server) - NO PHP FOUND
"""


# ---------------------------------------------------------------------------
# web page (web.py): assessment shown to visitors
# ---------------------------------------------------------------------------
CONSENT_VERSION = "2026-10-26.4"   # bump whenever the consent / rules text on the page changes

# PHP2Shell (CVE-2026-109618 / -109619): first fixed upstream release per branch
PHP_FIXED = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
# versions distributions keep while backporting fixes (patch state invisible remotely)
DISTRO_VERSIONS = {"8.3.6", "8.1.2", "8.5.4", "8.0.30", "7.4.33", "8.2.7", "7.4.3", "7.2.24"}

WHERE = {".php-link": "link to a .php file"}


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


def web_options(data):
    return {}                                     # no options on the page


def web_result(host, ip, row, info, friendly_evidence):
    _, final, status, verdict_, version, apps, server, evidence = row
    result = {
        "host": host, "ip": ip, "final_url": final, "http_status": status,
        "reachable": verdict_ != "ERROR",
        "php": verdict_.startswith("PHP"),
        "php_version": version,
        "apps": [a for a in apps.split(", ") if a],
        "server": server,
        "evidence": friendly_evidence(evidence) if verdict_ != "ERROR" else [],
        "error": evidence if verdict_ == "ERROR" else "",
        "recommendations": [],
    }
    if verdict_ == "SNI ONLY":
        result["reachable"] = False
        result["error"] = "The server refused the HTTPS connection for this hostname."
    if result["php"]:
        result["php_check"] = php_assessment(version)
        branch = ".".join(version.split(".")[:2]) if version else ""
        result["fixed"] = [{"software": f"PHP {b}", "versions": v, "note": "", "found": b == branch}
                           for b, v in PHP_FIXED.items()]
        result["fixed"].append({"software": f"Older than PHP {min(PHP_FIXED)}", "versions": "",
                                "note": "end of life: no official fix, upgrade",
                                "found": bool(branch) and branch not in PHP_FIXED})
    if version:
        result["recommendations"].append(
            "The site reveals its exact PHP version (X-Powered-By header). Set "
            "expose_php = Off in php.ini to stop advertising it.")
    if result["php"] and not version:
        result["recommendations"].append(
            "Keep PHP and all applications/plugins up to date; the version is hidden, "
            "which is good practice.")
    return result


def web_timeout_result(host, ip):
    return {"host": host, "ip": ip, "reachable": False,
            "error": "The website took too long to respond.", "php": False,
            "apps": [], "evidence": [], "recommendations": []}


def audit_fields(result):
    """Fields of the audit log line (unchanged from cmsweb)."""
    return {"outcome": "php" if result.get("php") else ("no-php" if result.get("reachable") else "unreachable"),
            "apps": result.get("apps"), "php_version": result.get("php_version")}
