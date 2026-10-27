#!/usr/bin/env python3
"""
cmsscan.py - PHP / PHP-CMS detection with an integrated TCP port scan.

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
database into ~/.cache/cmsscan, which then takes precedence.

Usage (results are printed to the terminal):
    python3 cmsscan.py 203.0.113.10               # 20 web ports + vhost discovery (default)
    python3 cmsscan.py 203.0.113.10 203.0.113.11 example.ch
    python3 cmsscan.py 198.51.100.0/24            # whole IP range
    python3 cmsscan.py 203.0.113.10 -p all        # all 65535 TCP ports
    python3 cmsscan.py 203.0.113.10 -p 80,443,8000-8100   # custom port list
    python3 cmsscan.py shop.example.ch@203.0.113.10       # one known vhost on a specific IP
    python3 cmsscan.py 203.0.113.10 --no-vhosts   # only the IP's default sites
    python3 cmsscan.py 203.0.113.10 --no-ct       # vhosts without crt.sh lookup
    python3 cmsscan.py 203.0.113.0/24 --names domains.txt  # + your own hostnames (most complete)

Complete vhost lists from the servers themselves (best source for --names):
    apache2ctl -S 2>/dev/null | awk '/namevhost/{print $4} /alias/{print $2}' | sort -u
    nginx -T 2>/dev/null | awk '$1=="server_name"{for(i=2;i<=NF;i++){gsub(";","",$i);print $i}}' | sort -u

Passive DNS: OTX and HackerTarget are used by default (no keys). More sources via API keys,
read from the environment so they don't show up in `ps` or shell history:
    CMSSCAN_SHODAN_KEY  CMSSCAN_VT_KEY  CMSSCAN_SECURITYTRAILS_KEY
    ( set -a; . ./.env; set +a; python3 cmsscan.py 203.0.113.10 )
    (--shodan-key / --vt-key / --securitytrails-key also work, but expose the key in argv)
    python3 cmsscan.py 203.0.113.10 -n            # no port scan, only 443/80
    python3 cmsscan.py ips.txt -o out.csv         # file input / additional CSV output
    python3 cmsscan.py 203.0.113.10 -a            # also show hidden rows (errors, duplicates)
    python3 cmsscan.py 203.0.113.10 -d            # debug: scan, discovery, requests, matches
    python3 cmsscan.py -U                         # refresh the fingerprint database

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
import argparse
import concurrent.futures as cf
import csv
import fnmatch
import functools
import glob
import hashlib
import http.client
import ipaddress
import itertools
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

UA = "Mozilla/5.0 (compatible; cmsscan/1.0; hosting security check)"
MAX_BODY = 1_500_000

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

COMPILED = [(t, w, re.compile(p, re.I | re.M)) for t, w, p in FINGERPRINTS]
BUILTIN_APPS = len({t for t, _, _ in FINGERPRINTS if t != "PHP"})

# --- optional external database: open Wappalyzer fork "webappanalyzer" (GPL-3.0) ---
# Embedded below (GPL-3.0); --update-rules downloads a fresher copy.
RULES_URL = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/{}.json"
RULES_FILES = ["_"] + [chr(c) for c in range(ord("a"), ord("z") + 1)]
RULES_DIR = os.path.join(os.path.expanduser("~"), ".cache", "cmsscan", "technologies")
DB_RULES = []   # (tech, kind, key, regex, version_template)


# --- embedded fingerprint database ------------------------------------------
# 315 PHP technologies extracted from webappanalyzer (open Wappalyzer fork),
# https://github.com/enthec/webappanalyzer, commit d91f7e5 (2026-10-19), GPL-3.0.
# Fields kept: headers, cookies, meta, html, scriptSrc, url, implies.
# Refresh with: python3 cmsscan.py -U   (a downloaded copy takes precedence)
EMBEDDED_RULES_DATE = "2026-10-19"
EMBEDDED_RULES = r'''{
"1C-Bitrix":{"cookies":{"BITRIX_SM_GUEST_ID":"","BITRIX_SM_LAST_IP":"","BITRIX_SM_SALE_UID":""},"headers":{"Set-Cookie":"BITRIX_","X-Powered-CMS":"Bitrix Site Manager"},"implies":["PHP"],"scriptSrc":["bitrix(?:\\.info/|/js/main/core)"]},
"4Partners CMS":{"implies":["PHP","4Partners","Nginx"],"meta":{"author":"^4CMS$"}},
"AbhiCMS":{"implies":["PHP","MySQL"],"meta":{"generator":"AbhiCMS\\s([\\d\\.]+)\\;version:\\1"}},
"Adminer":{"cookies":{"adminer_key":"","adminer_sid":""},"headers":{"composed-by":"adminer\\((\\d\\.)+\\)\\;version:\\1"},"html":["Adminer</a> <span class=\"version\">([\\d.]+)</span>\\;version:\\1","onclick=\"bodyClick\\(event\\);\" onload=\"verifyVersion\\('([\\d.]+)'\\);\">\\;version:\\1"],"implies":["PHP"]},
"Aegea":{"headers":{"X-Powered-By":"^(?:E2\\s)?Aegea\\s(?:v)?([\\d\\.]+)\\;version:\\1"},"implies":["PHP","jQuery"]},
"Akaunting":{"headers":{"X-Akaunting":"^Free Accounting Software$"},"html":["<link[^>]+akaunting-green\\.css","Powered By Akaunting: <a [^>]*href=\"https?://(?:www\\.)?akaunting\\.com[^>]+>"],"implies":["Laravel"]},
"Aksara CMS":{"implies":["PHP","MySQL","CodeIgniter","Bootstrap","jQuery","OpenLayers"]},
"All in One SEO":{"html":["<!-- all in one seo ([\\d.]+) \\;version:\\1","<!-- all in one seo pack ([\\d.]+) \\;version:\\1","<!-- all in one seo pro ([\\d.]+) \\;version:pro \\1"],"implies":["WordPress"],"meta":{"generator":"^all in one seo \\(aioseo\\) ([\\d\\.]+)\\;version:\\1"}},
"AlvandCMS":{"implies":["PHP","MySQL"],"meta":{"generator":"AlvandCMS\\s([\\d\\.]+)\\;version:\\1"}},
"Amiro.CMS":{"implies":["PHP","MySQL"],"meta":{"generator":"Amiro"}},
"Apereo CAS":{"implies":["Java","PHP"]},
"Arastta":{"headers":{"Arastta":"^(.+)$\\;version:\\1","X-Arastta":"","x-arastta":""},"implies":["PHP"],"scriptSrc":["arastta\\.js"]},
"Argento":{"implies":["Magento"]},
"BIGACE":{"implies":["PHP"],"meta":{"generator":"BIGACE ([\\d.]+)\\;version:\\1"}},
"BOOM":{"headers":{"X-Supplied-By":"MANA"},"implies":["WordPress"],"meta":{"generator":"^boom site builder$"}},
"Backdrop":{"headers":{"X-Backdrop-Cache":"","X-Generator":"^Backdrop CMS(?:\\s([\\d.]+))?\\;version:\\1"},"implies":["PHP"],"meta":{"generator":"^Backdrop CMS(?:\\s([\\d.]+))?\\;version:\\1"}},
"Banshee":{"headers":{"X-Powered-By":"Banshee PHP framework v([\\d\\.]+)\\;version:\\1"},"implies":["PHP"],"meta":{"generator":"Banshee PHP"}},
"Batflat":{"implies":["PHP","SQLite"],"meta":{"generator":"^Batflat$"}},
"BigTree CMS":{"implies":["PHP","MySQL"]},
"Bigware":{"cookies":{"bigWAdminID":"","bigwareCsid":""},"html":["(?:Diese <a href=[^>]+bigware\\.de|<a href=[^>]+/main_bigware_\\d+\\.php)"],"implies":["PHP"],"url":["(?:\\?|&)bigWAdminID="]},
"Blessing Skin":{"implies":["Laravel"]},
"Blitz":{"headers":{"X-Powered-By":"^Blitz$"},"html":["<!-- Cached by Blitz on"],"implies":["Craft CMS"]},
"BoidCMS":{"headers":{"X-Powered-By":"BoidCMS"},"implies":["PHP"]},
"Bold Themes":{"implies":["WordPress"]},
"Bolt CMS":{"implies":["PHP"],"meta":{"generator":"Bolt"}},
"Bonfire":{"cookies":{"bf_session":""},"html":["Powered by <a[^>]+href=\"https?://(?:www\\.)?cibonfire\\.com[^>]*>Bonfire v([^<]+)\\;version:\\1"],"implies":["CodeIgniter"]},
"BookStack":{"cookies":{"bookstack_session":""},"implies":["PHP","MySQL","Laravel"]},
"Botble CMS":{"cookies":{"botble_session":""},"headers":{"CMS-Version":"^(.+)$\\;version:\\1\\;confidence:0"},"implies":["Laravel"]},
"Brownie":{"headers":{"X-Powered-By":"Brownie"},"implies":["PHP","MySQL","Amazon Web Services","Bootstrap","jQuery"],"scriptSrc":["assets\\.youthsrl\\.com/brownie"]},
"CMS Made Simple":{"cookies":{"CMSSESSID":""},"implies":["PHP"],"meta":{"generator":"CMS Made Simple"}},
"CMSimple":{"implies":["PHP"],"meta":{"generator":"CMSimple( [\\d.]+)?\\;version:\\1"}},
"CPG Dragonfly":{"headers":{"X-Powered-By":"^Dragonfly CMS"},"implies":["PHP"],"meta":{"generator":"CPG Dragonfly"}},
"CS Cart":{"implies":["PHP"],"scriptSrc":["var/cache/misc/assets/js/tygh/scripts-(?:[\\d\\w]+)\\.js"]},
"Cachet":{"implies":["PHP"]},
"CakePHP":{"cookies":{"cakephp":""},"implies":["PHP"],"meta":{"application-name":"CakePHP"}},
"Cargo":{"implies":["PHP"],"meta":{"cargo_title":""},"scriptSrc":["(?<!elo\\.io)/cargo\\."]},
"Centminmod":{"headers":{"X-Powered-By":"centminmod"},"implies":["CentOS","Nginx","PHP"]},
"Chamilo":{"headers":{"X-Powered-By":"Chamilo ([\\d.]+)\\;version:\\1"},"implies":["PHP"],"meta":{"generator":"Chamilo ([\\d.]+)\\;version:\\1"}},
"Chevereto":{"implies":["PHP"],"meta":{"generator":"Chevereto\\s(?:[\\d\\.]+)"},"scriptSrc":["/chevereto\\.js"]},
"Classeh":{"implies":["PHP","React","Python"],"meta":{"author":"^fanavar\\.org$"}},
"ClickHeat":{"implies":["PHP"],"scriptSrc":["clickheat.*\\.js"]},
"Clockwork":{"headers":{"x-clockwork-version":"^([\\d\\.]+)$\\;version:\\1"},"implies":["PHP"]},
"Cloudify.store":{"cookies":{"cloudify_session":""},"implies":["PHP","MySQL","React"]},
"Cloudrexx":{"implies":["PHP","MySQL"],"meta":{"generator":"^cloudrexx$"}},
"Coaster CMS":{"implies":["Laravel"],"meta":{"generator":"^Coaster CMS v([\\d.]+)$\\;version:\\1"}},
"CodeIgniter":{"cookies":{"ci_csrf_token":"^(.+)$\\;version:\\1?2+:","ci_session":"","exp_last_activity":"","exp_tracker":""},"html":["<input[^>]+name=\"ci_csrf_token\""],"implies":["PHP"]},
"Concrete CMS":{"cookies":{"CONCRETE5":""},"implies":["PHP"],"meta":{"generator":"^concrete5(?: - ([\\d.]+)$)?\\;version:\\1"},"scriptSrc":["/concrete/js/"]},
"Contao":{"implies":["PHP"],"meta":{"generator":"^Contao Open Source CMS$"}},
"Contenido":{"implies":["PHP"],"meta":{"generator":"Contenido ([\\d.]+)\\;version:\\1"}},
"Convertr":{"implies":["PHP","MySQL","Vue.js","Nuxt.js","Amazon Web Services"],"meta":{"author":"^Convertr Commerce$"}},
"Coppermine":{"html":["<!--Coppermine Photo Gallery ([\\d.]+)\\;version:\\1"],"implies":["PHP"]},
"Cotonti":{"implies":["PHP"],"meta":{"generator":"Cotonti"}},
"Craft CMS":{"cookies":{"CRAFT_CSRF_TOKEN":"","CraftSessionId":""},"headers":{"X-Powered-By":"\\bCraft CMS\\b"},"implies":["Yii"]},
"Craft Commerce":{"headers":{"X-Powered-By":"\\bCraft Commerce\\b"},"implies":["Craft CMS"]},
"Crealive":{"implies":["PHP","MySQL","Laravel"]},
"CubeCart":{"implies":["PHP"],"meta":{"generator":"cubecart"}},
"Danneo CMS":{"headers":{"X-Powered-By":"CMS Danneo ([\\d.]+)\\;version:\\1"},"implies":["Apache HTTP Server","PHP","MySQL"],"meta":{"generator":"Danneo CMS ([\\d.]+)\\;version:\\1"}},
"DataLife Engine":{"implies":["PHP","Apache HTTP Server"],"meta":{"generator":"DataLife Engine"}},
"DedeCMS":{"implies":["PHP"],"scriptSrc":["dedeajax"]},
"DirectAdmin":{"headers":{"Server":"DirectAdmin Daemon v([\\d.]+)\\;version:\\1"},"html":["<a[^>]+>DirectAdmin</a> Web Control Panel"],"implies":["PHP","Apache HTTP Server"]},
"Discuz! X":{"implies":["PHP"],"meta":{"generator":"Discuz! X([\\d\\.]+)?\\;version:\\1"}},
"Dokeos":{"headers":{"X-Powered-By":"Dokeos"},"html":["(?:Portal <a[^>]+>Dokeos|@import \"[^\"]+dokeos_blue)"],"implies":["PHP","Xajax","jQuery"],"meta":{"generator":"Dokeos"}},
"DokuWiki":{"cookies":{"DokuWiki":""},"implies":["PHP"],"meta":{"generator":"^DokuWiki( Release [\\d-]+)?\\;version:\\1"}},
"Dotclear":{"headers":{"X-Dotclear-Static-Cache":""},"implies":["PHP"]},
"Dotser":{"implies":["PHP","MySQL"],"meta":{"generator":"^Dotser\\sCommerce\\s((?:\\d+\\.)+\\d+)/\\;version:\\1"}},
"Drupal":{"cookies":{"SESS[a-f0-9]{32}":""},"headers":{"Expires":"19 Nov 1978","X-Drupal-Cache":"","X-Generator":"^Drupal(?:\\s([\\d.]+))?\\;version:\\1"},"html":["<(?:link|style)[^>]+\"/sites/(?:default|all)/(?:themes|modules)/"],"implies":["PHP"],"meta":{"generator":"^Drupal(?:\\s([\\d.]+))?\\;version:\\1"},"scriptSrc":["drupal\\.js"]},
"Drupal Commerce":{"html":["<[^>]+(?:id=\"block[_-]commerce[_-]cart[_-]cart|class=\"commerce[_-]product[_-]field)"],"implies":["Drupal"],"scriptSrc":["/modules/(?:contrib/)?commerce/js/conditions\\.js\\;confidence:50","/profiles/commerce_kickstart/modules/contrib/commerce/modules/checkout/commerce_checkout\\.js\\;confidence:50","/sites/(?:all|default)/modules/(?:contrib/)?commerce/modules/checkout/commerce_checkout\\.js\\;confidence:50"]},
"E-monsite":{"implies":["Symfony","MySQL"],"meta":{"generator":"^e-monsite\\s\\(e-monsite\\.com\\)$"}},
"EC-CUBE":{"implies":["PHP"],"scriptSrc":["eccube\\.js","win_op\\.js"]},
"Ebasnet":{"implies":["PHP","MySQL","Varnish","Symfony"],"meta":{"author":"^Ebasnet Web Solutions$"},"scriptSrc":["cdnebasnet\\.com/"]},
"ElasticSuite":{"cookies":{"STUID":"\\;confidence:50","STVID":"\\;confidence:50"},"implies":["PHP","Elasticsearch"],"scriptSrc":["/Smile_ElasticsuiteTracker/"]},
"Elcodi":{"headers":{"X-Elcodi":""},"implies":["PHP","Symfony"]},
"Eleanor CMS":{"implies":["PHP"],"meta":{"generator":"Eleanor"}},
"Elementor Cloud":{"headers":{"x-powered-by":"Elementor Cloud"},"implies":["WordPress","Elementor"]},
"Eticex":{"implies":["MySQL","React","PHP"],"scriptSrc":["\\.eticex\\.com/"]},
"Eveve":{"html":["<iframe[^>]*[\\w]+\\.eveve\\.com"],"implies":["PHP"]},
"ExpressionEngine":{"cookies":{"exp_csrf_token":"","exp_last_activity":"","exp_tracker":""},"implies":["PHP"]},
"FUDforum":{"implies":["Perl","PHP"]},
"Fat-Free Framework":{"headers":{"X-Powered-By":"^Fat-Free Framework$"},"implies":["PHP"]},
"Flarum":{"html":["<div id=\"flarum-loading\""],"implies":["PHP","MySQL"]},
"FluxBB":{"html":["<p id=\"poweredby\">[^<]+<a href=\"https?://fluxbb\\.org/\">"],"implies":["PHP"]},
"Flyspray":{"cookies":{"flyspray_project":""},"html":["(?:<a[^>]+>Powered by Flyspray|<map id=\"projectsearchform)"],"implies":["PHP"]},
"Flywheel":{"headers":{"x-fw-hash":"","x-fw-serve":"","x-fw-server":"^Flywheel(?:/([\\d.]+))?\\;version:\\1","x-fw-static":"","x-fw-type":""},"implies":["WordPress"]},
"Fork CMS":{"implies":["Symfony"],"meta":{"generator":"^Fork CMS$"}},
"Frontity":{"implies":["React","Webpack","WordPress"],"meta":{"generator":"^Frontity"}},
"GLPI":{"implies":["PHP"],"meta":{"glpi:csrf_token":""},"scriptSrc":["//.*glpi.+common\\.min\\.js\\?v=(\\d+\\.\\d+\\.\\d+)\\;version:\\1"]},
"Gambio":{"html":["(?:<link[^>]* href=\"templates/gambio/|<a[^>]content\\.php\\?coID=\\d|<!-- gambio eof -->|<!--[\\s=]+Shopsoftware by Gambio GmbH \\(c\\))"],"implies":["PHP"],"scriptSrc":["gm_javascript\\.js\\.php"]},
"GetSimple CMS":{"implies":["PHP"],"meta":{"generator":"GetSimple"}},
"Gnuboard":{"implies":["PHP","MySQL"]},
"GoMage":{"implies":["PWA","Magento\\;version:2"]},
"Grav":{"implies":["PHP"],"meta":{"generator":"GravCMS(?:\\s([\\d.]+))?\\;version:\\1"}},
"HHVM":{"headers":{"X-Powered-By":"HHVM/?([\\d.]+)?\\;version:\\1"},"implies":["PHP\\;confidence:75"]},
"Hamechio":{"implies":["PHP"],"meta":{"generator":"hamech\\.io/"}},
"HeliumWeb":{"headers":{"X-Powered-By":"Adrikikicp Development"},"implies":["PHP"],"scriptSrc":["helium/src/helium.js/helium_web.js","http://maven.enriquitomcfh.ml/helium.js/helium_web.js","http://maven.enriquitomcfh.ml/helium.js/helium_web.min.js"]},
"Helix Ultimate":{"implies":["Joomla"]},
"Higher Logic Vanilla":{"headers":{" x-vanilla-version":"([\\d\\.]+)\\;version:\\1","X-Powered-By":"Vanilla"},"implies":["PHP"]},
"Hinza Advanced CMS":{"implies":["Laravel"],"meta":{"generator":"hinzacms"}},
"Hosttech Website Creator":{"implies":["PHP","MySQL","Vue.js"],"meta":{"generator":"Website Creator by hosttech","wsc_rendermode":""}},
"Hotaru CMS":{"cookies":{"hotaru_mobile":""},"implies":["PHP"],"meta":{"generator":"Hotaru CMS"}},
"Huberway":{"cookies":{"huberway_session":""},"implies":["PHP","MySQL"]},
"Hyva Themes":{"headers":{"X-Built-With":"^Hyva Themes$"},"implies":["Magento\\;version:2","Tailwind CSS","Alpine.js"]},
"IPB":{"cookies":{"ipbWWLmodpids":"","ipbWWLsession_id":""},"html":["<link[^>]+ipb_[^>]+\\.css"],"implies":["PHP","MySQL"],"scriptSrc":["jscripts/ips_"]},
"Ibexa DXP":{"headers":{"x-powered-by":"^Ibexa\\sExperience\\sv([\\d\\.]+)$\\;version:\\1"},"implies":["PHP","Symfony"],"meta":{"generator":"^eZ Platform"}},
"ImpressCMS":{"cookies":{"ICMSSession":"","ImpressCMS":""},"implies":["PHP"],"meta":{"generator":"ImpressCMS"},"scriptSrc":["include/linkexternal\\.js"]},
"ImpressPages":{"implies":["PHP"],"meta":{"generator":"ImpressPages(?: CMS)?( [\\d.]*)?\\;version:\\1"}},
"Indexhibit":{"html":["<(?:link|a href) [^>]+ndxz-studio"],"implies":["PHP","Apache HTTP Server","Exhibit"],"meta":{"generator":"Indexhibit"}},
"InstantCMS":{"cookies":{"InstantCMS[logdate]":""},"implies":["PHP"],"meta":{"generator":"InstantCMS"}},
"Invision Power Board":{"cookies":{"ipbWWLmodpids":"","ipbWWLsession_id":""},"html":["<link[^>]+ipb_[^>]+\\.css"],"implies":["PHP","MySQL"],"scriptSrc":["jscripts/ips_"]},
"J2Store":{"implies":["Joomla"]},
"JobberBase":{"implies":["PHP"],"meta":{"generator":"Jobberbase"}},
"JoomShopping":{"implies":["Joomla"],"scriptSrc":["/components/com_jshopping/"]},
"Joomla":{"cookies":{"joomla_[a-z0-9]+":""},"headers":{"X-Content-Encoded-By":"Joomla! ([\\d.]+)\\;version:\\1"},"html":["(?:<div[^>]+id=\"wrapper_r\"|<(?:link|script)[^>]+(?:feed|components)/com_|<table[^>]+class=\"pill)\\;confidence:50"],"implies":["PHP"],"meta":{"generator":"Joomla!(?: ([\\d.]+))?\\;version:\\1"},"scriptSrc":["(?:^|/)(feed/com_|components/com_)"],"url":["option=com_"]},
"K2":{"html":["<!--(?: JoomlaWorks \"K2\"| Start K2)"],"implies":["Joomla"]},
"KPHP":{"headers":{"x-powered-by":"^KPHP/([\\d\\.]+)$\\;version:\\1"},"implies":["PHP"]},
"Keyvos":{"implies":["Laravel","MySQL","Elasticsearch"],"meta":{"generator":"Keyvos CMS"}},
"Kinsta":{"headers":{"x-kinsta-cache":""},"implies":["WordPress"]},
"Kirby":{"cookies":{"kirby_session":""},"implies":["PHP","Vue.js"]},
"Kitcart":{"cookies":{"kitcart_session":""},"implies":["Laravel","PHP"]},
"Koala Framework":{"html":["<!--[^>]+This website is powered by Koala Web Framework CMS"],"implies":["PHP"],"meta":{"generator":"^Koala Web Framework CMS"}},
"Kohana":{"cookies":{"kohanasession":""},"headers":{"X-Powered-By":"Kohana Framework ([\\d.]+)\\;version:\\1"},"implies":["PHP"]},
"Koken":{"cookies":{"koken_referrer":""},"html":["<!--\\s+KOKEN DEBUGGING"],"implies":["PHP","MySQL"],"meta":{"generator":"Koken ([\\d.]+)\\;version:\\1"},"scriptSrc":["koken(?:\\.js\\?([\\d.]+)|/storage)\\;version:\\1"]},
"Komodo CMS":{"implies":["PHP"],"meta":{"generator":"^Komodo CMS"}},
"Kooomo":{"implies":["PHP","MySQL"],"meta":{"generator":"Kooomo(?: v([\\d.]+))?\\;version:\\1"}},
"LEPTON":{"implies":["PHP"],"meta":{"generator":"LEPTON"}},
"Laravel":{"cookies":{"laravel_session":""},"implies":["PHP"]},
"Laravel Echo":{"implies":["Laravel"]},
"Lede":{"html":["<a [^>]*href=\"[^\"]+joinlede.com"],"implies":["WordPress","WordPress VIP"],"meta":{"og:image":"https?\\:\\/\\/lede-admin"}},
"LightMon Engine":{"cookies":{"lm_online":""},"html":["<!-- Lightmon Engine Copyright Lightmon"],"implies":["PHP"],"meta":{"generator":"LightMon Engine"}},
"Lithium":{"cookies":{"LithiumVisitor":""},"html":[" <a [^>]+Powered by Lithium"],"implies":["PHP"]},
"LiveStreet CMS":{"headers":{"X-Powered-By":"LiveStreet CMS"},"implies":["PHP"]},
"Livewire":{"html":["<[^>]{1,512}\\bwire:"],"implies":["Laravel"],"scriptSrc":["livewire(?:\\.min)?\\.js"]},
"MODX":{"headers":{"X-Powered-By":"^MODX"},"html":["<a[^>]+>Powered by MODX</a>","<!-- Modx process time debug info -->","<(?:link|script)[^>]+assets/snippets/\\;confidence:20","<form[^>]+id=\"ajaxSearch_form\\;confidence:20","<input[^>]+id=\"ajaxSearch_input\\;confidence:20"],"implies":["PHP"],"meta":{"generator":"MODX[^\\d.]*([\\d.]+)?\\;version:\\1"},"scriptSrc":["/assets/components/templates/\\;confidence:50"]},
"MVD Studio":{"headers":{"X-Built-By":"MVD Studio","X-Generator":"MVD Studio","X-Powered-By":"MVD Studio"},"implies":["Laravel","PHP"],"meta":{"generator":"MVD Studio"}},
"Magento":{"cookies":{"X-Magento-Vary":"","frontend":"\\;confidence:50","mage-cache-storage":"","mage-cache-storage-section-invalidation":"","mage-translation-file-version":"","mage-translation-storage":""},"implies":["PHP","MySQL"],"scriptSrc":["js/mage","skin/frontend/(?:default|(enterprise))\\;version:\\1?1 (Enterprise):1 (Community)","skin/frontend/\\;confidence:50\\;version:\\1","static/_requirejs\\;confidence:50\\;version:2"]},
"Magewire":{"implies":["Laravel","Livewire"]},
"Maho":{"cookies":{"maho_session":""},"implies":["MySQL","PHP"],"scriptSrc":["js/maho-autocomplete\\.js","js/maho-captcha\\.js","js/maho-dialog\\.js","js/maho-load-on-intent\\.js","js/maho-passkey-tools\\.js","js/maho-tree\\.js"]},
"MaxSite CMS":{"implies":["PHP"],"meta":{"generator":"MaxSite CMS"}},
"MaxenceDEVCMS":{"implies":["PHP","MySQL"],"meta":{"author":"^MaxenceDEV$"}},
"MediaWiki":{"cookies":{"wiki\\d+_session":""},"html":["<body[^>]+class=\"mediawiki\"","<(?:a|img)[^>]+>Powered by MediaWiki</a>","<a[^>]+/Special:WhatLinksHere/"],"implies":["PHP"],"meta":{"generator":"^MediaWiki ?(.+)$\\;version:\\1"}},
"Melis Platform":{"html":["<!-- Rendered with Melis CMS V2","<!-- Rendered with Melis Platform"],"implies":["Apache HTTP Server","PHP","MySQL","Symfony","Laravel","Zend"],"meta":{"generator":"^Melis Platform\\.","powered-by":"^Melis CMS\\."}},
"Modified eCommerce":{"implies":["PHP","MySQL"],"meta":{"generator":"by modified eCommerce Shopsoftware"}},
"Moguta.CMS":{"html":["<link[^>]+href=[\"'][^\"]+mg-(?:core|plugins|templates)/"],"implies":["PHP"],"scriptSrc":["mg-(?:core|plugins|templates)/"]},
"Moodle":{"cookies":{"MOODLEID_":"","MoodleSession":""},"html":["<img[^>]+moodlelogo"],"implies":["PHP"],"meta":{"keywords":"^moodle"}},
"MotoCMS":{"html":["<link [^>]*href=\"[^>]*\\/mt-content\\/[^>]*\\.css"],"implies":["PHP","AngularJS","jQuery"],"scriptSrc":["/mt-includes/js/website(?:assets)?\\.(?:min)?\\.js"]},
"MyBB":{"cookies":{"mybb[lastactive]":"","mybb[lastvisit]":""},"implies":["PHP"]},
"NamelessMC":{"implies":["PHP","Laravel","MySQL"]},
"Neos CMS":{"headers":{"X-Flow-Powered":"Neos/?(.+)?$\\;version:\\1"},"implies":["Neos Flow"],"scriptSrc":["/Neos\\.Neos/"],"url":["/neos/"]},
"Neos Flow":{"headers":{"X-Flow-Powered":"Flow/?(.+)?$\\;version:\\1"},"implies":["PHP"]},
"Nette Framework":{"cookies":{"nette-browser":""},"headers":{"X-Powered-By":"^Nette Framework"},"html":["<input[^>]+data-nette-rules","<div[^>]+id=\"snippet-","<input[^>]+id=\"frm-"],"implies":["PHP"]},
"Nextcloud":{"cookies":{" __Host-nc_sameSiteCookielax":"","__Host-nc_sameSiteCookiestrict":""},"implies":["PHP"]},
"NexusPHP":{"implies":["PHP","MySQL","Redis"],"meta":{"generator":"^NexusPHP$"}},
"OXID eShop":{"cookies":{"sid_key":"oxid"},"implies":["PHP"]},
"OXID eShop Community Edition":{"html":["<!--[^-]*OXID eShop Community Edition, Version (\\d+)\\;version:\\1"],"implies":["PHP"]},
"OXID eShop Enterprise Edition":{"html":["<!--[^-]*OXID eShop Enterprise Edition, Version (\\d+)\\;version:\\1"],"implies":["PHP"]},
"OXID eShop Professional Edition":{"html":["<!--[^-]*OXID eShop Professional Edition, Version (\\d+)\\;version:\\1"],"implies":["PHP"]},
"October CMS":{"cookies":{"october_session":""},"implies":["Laravel"],"meta":{"generator":"OctoberCMS"}},
"Omurga Sistemi":{"implies":["MySQL","PHP"],"meta":{"generator":"^OS-Omurga Sistemi"}},
"OnShop":{"implies":["PHP"],"meta":{"generator":"Onshop Ecommerce"}},
"Open Journal Systems":{"cookies":{"OJSSID":""},"implies":["PHP"],"meta":{"generator":"Open Journal Systems(?: ([\\d.]+))?\\;version:\\1"}},
"Open eShop":{"implies":["PHP"],"meta":{"author":"open-eshop\\.com","copyright":"Open eShop ?([0-9.]+)?\\;version:\\1"}},
"OpenCart":{"cookies":{"OCSESSID":""},"implies":["PHP","MySQL"]},
"OpenElement":{"implies":["PHP"],"meta":{"generator":"openElement\\s\\(([\\d\\.]+)\\)\\;version:\\1"}},
"OpenSwoole":{"headers":{"Server":"OpenSwoole(?:/([\\d.]+))?\\;version:\\1"},"implies":["PHP"]},
"OroCommerce":{"cookies":{"orosfid":""},"html":["<script [^>]+data-requiremodule=\"oro/","<script [^>]+data-requiremodule=\"oroui/"],"implies":["PHP","Symfony"],"scriptSrc":["oro\\.min\\.js\\?version=([\\d.]+)\\;version:\\1"]},
"PHP":{"cookies":{"PHPSESSID":""},"headers":{"Server":"php/?([\\d.]+)?\\;version:\\1","X-Powered-By":"^php/?([\\d.]+)?\\;version:\\1"},"url":["\\.php(?:$|\\?)"]},
"PHP-Nuke":{"html":["<[^>]+Powered by PHP-Nuke"],"implies":["PHP","MySQL"],"meta":{"generator":"PHP-Nuke"}},
"PHPBoost":{"implies":["PHP"],"meta":{"generator":"^PHPBoost$"}},
"PHPFusion":{"headers":{"X-PHPFusion":"(.+)$\\;version:\\1","X-Powered-By":"PHP(?:-)?Fusion (.+)$\\;version:\\1"},"html":["Powered by <a href=\"[^>]+phpfusion","Powered by <a href=\"[^>]+php-fusion"],"implies":["PHP","MySQL"]},
"Pagely":{"headers":{"Server":"^Pagely"},"implies":["WordPress","Amazon Web Services"]},
"Pantheon":{"headers":{"Server":"^Pantheon","x-pantheon-styx-hostname":"","x-styx-req-id":""},"implies":["PHP","Nginx","MariaDB","Fastly"]},
"Paymenter":{"cookies":{"paymenter_session":""},"implies":["PHP","MySQL","Tailwind CSS"]},
"Phabricator":{"cookies":{"phsid":""},"html":["<[^>]+(?:class|id)=\"phabricator-"],"implies":["PHP"],"scriptSrc":["/phabricator/[a-f0-9]{8}/rsrc/js/phui/[a-z-]+\\.js$"]},
"PhotoShelter":{"implies":["PHP","MySQL","jQuery"],"scriptSrc":["\\.psecn\\.photoshelter\\.com/"],"url":["photoshelter\\.com"]},
"Pimcore":{"headers":{"X-Powered-By":"^pimcore$"},"implies":["PHP"],"scriptSrc":["/pimcorecore/js/targeting\\.js"]},
"Pingoteam":{"implies":["PHP"],"meta":{"designer":"Pingoteam"}},
"PixelFed":{"implies":["Laravel"]},
"Plug&Pay":{"cookies":{"plug_pay_session":"","plugpay_session":""},"implies":["Laravel"],"scriptSrc":["\\.plugandpay\\.nl"]},
"Pressable":{"headers":{"host-header":"^Pressable"},"implies":["WordPress"]},
"PrestaShop":{"cookies":{"PrestaShop":""},"headers":{"Powered-By":"^Prestashop$"},"html":["Powered by <a\\s+[^>]+>PrestaShop","<!-- /Block [a-z ]+ module (?:HEADER|TOP)?\\s?-->","<!-- /Module Block [a-z ]+ -->"],"implies":["PHP","MySQL"],"meta":{"generator":"PrestaShop"},"scriptSrc":["/modules/ps_[a-z]+/"]},
"ProcessWire":{"headers":{"X-Powered-By":"ProcessWire CMS"},"implies":["PHP"]},
"Proximis Unified Commerce":{"html":["<html[^>]+data-ng-app=\"RbsChangeApp\""],"implies":["PHP","AngularJS"],"meta":{"generator":"Proximis Unified Commerce"}},
"Pterodactyl Panel":{"cookies":{"pterodactyl_session":""},"implies":["Go","PHP","React","Laravel"]},
"Pulse CMS":{"implies":["PHP"],"scriptSrc":["/PulseCMS/.*?/tracker\\.php"]},
"PyroCMS":{"cookies":{"pyrocms":""},"headers":{"X-Streams-Distribution":"PyroCMS"},"implies":["Laravel"]},
"Question2Answer":{"html":["<!-- Powered by Question2Answer"],"implies":["PHP"],"scriptSrc":["\\./qa-content/qa-page\\.js\\?([0-9.]+)\\;version:\\1"]},
"RBS Change":{"html":["<html[^>]+xmlns:change="],"implies":["PHP"],"meta":{"generator":"RBS Change"}},
"REDAXO":{"implies":["PHP"],"url":["^https?://(?:www\\.)?[\\d\\w\\-]+\\.[\\w]+/redaxo/\\;confidence:50"]},
"RainLoop":{"headers":{"Server":"^RainLoop"},"html":["<link[^>]href=\"rainloop/v/([0-9.]+)/static/apple-touch-icon\\.png/>\\;version:\\1"],"implies":["PHP"],"meta":{"rlAppVersion":"^([0-9.]+)$\\;version:\\1"},"scriptSrc":["^rainloop/v/([0-9.]+)/\\;version:\\1"]},
"Redis Object Cache":{"html":["<!--\\s+Performance optimized by Redis Object Cache"],"implies":["Redis","WordPress"]},
"Ripple":{"headers":{"x-sdp-app-type":"ripple"},"implies":["Nuxt.js","Vue.js","Drupal"]},
"RiteCMS":{"implies":["PHP","SQLite\\;confidence:80"],"meta":{"generator":"^RiteCMS(?: (.+))?\\;version:\\1"}},
"RoadRunner":{"headers":{"Server":"RoadRunner"},"implies":["PHP"]},
"Roadiz CMS":{"headers":{"X-Powered-By":"Roadiz CMS"},"implies":["PHP","Symfony"],"meta":{"generator":"^Roadiz ?(?:master|develop)? v?([0-9\\.]+)\\;version:\\1"}},
"RoundCube":{"html":["<title>RoundCube"],"implies":["PHP"]},
"Rubedo":{"implies":["MongoDB","Elasticsearch","PHP"]},
"S-COREpion":{"headers":{"x-powered-by":"^S-COREpion CMS$"},"implies":["PHP","MySQL"]},
"SEOmatic":{"implies":["Craft CMS"],"meta":{"generator":"^SEOmatic$"}},
"SOBI 2":{"html":["(?:<!-- start of Sigsiu Online Business Index|<div[^>]* class=\"sobi2)"],"implies":["Joomla"]},
"SPIP":{"headers":{"Composed-By":"SPIP ([\\d.]+) @\\;version:\\1","X-Spip-Cache":""},"implies":["PHP"],"meta":{"generator":"(?:^|\\s)SPIP(?:\\s([\\d.]+(?:\\s\\[\\d+\\])?))?\\;version:\\1"}},
"SQL Buddy":{"html":["(?:<title>SQL Buddy</title>|<[^>]+onclick=\"sideMainClick\\(\"home\\.php)"],"implies":["PHP"]},
"Saly":{"implies":["PHP","Svelte"],"meta":{"application-name":"^Saly\\sB2B\\sPlatform$"}},
"Sapren":{"implies":["Laravel","PHP","MySQL"],"meta":{"generator":"^Saprenco.com Website Builder$"}},
"Sarka-SPIP":{"implies":["SPIP"],"meta":{"generator":"Sarka-SPIP(?:\\s([\\d.]+))?\\;version:\\1"}},
"ScandiPWA":{"implies":["Magento\\;version:2","React","PWA"]},
"Seko OmniReturns":{"implies":["MySQL","PHP"],"scriptSrc":["//cdn\\.omniparcelreturns\\.com/"]},
"Sellacious":{"implies":["Joomla"]},
"Selldone":{"implies":["PHP","Vue.js"],"meta":{"selldone-capi":"","selldone-cdn-id":"","selldone-cdn-images":"","selldone-iframe":""}},
"Seravo":{"headers":{"x-powered-by":"^Seravo"},"implies":["WordPress"]},
"Serendipity":{"implies":["PHP"],"meta":{"Powered-By":"Serendipity v\\.([\\d.]+)\\;version:\\1","generator":"Serendipity(?: v\\.([\\d.]+))?\\;version:\\1"}},
"Shopery":{"headers":{"X-Shopery":""},"implies":["PHP","Symfony","Elcodi"]},
"Shoptet":{"html":["<link [^>]*href=\"https?://cdn\\.myshoptet\\.com/"],"implies":["PHP"],"meta":{"web_author":"^Shoptet"},"scriptSrc":["^https?://cdn\\.myshoptet\\.com/"]},
"Shopware":{"headers":{"sw-context-token":"^[\\w]{32}$\\;version:6","sw-invalidation-states":"\\;version:6","sw-language-id":"^[a-fA-F0-9]{32}$\\;version:6","sw-version-id":"\\;version:6"},"html":["<title>Shopware ([\\d\\.]+) [^<]+\\;version:\\1"],"implies":["PHP","MySQL","jQuery","Symfony"],"meta":{"application-name":"Shopware"},"scriptSrc":["(?:(shopware)|/web/cache/[0-9]{10}_.+)\\.js\\;version:\\1?4:5","/jquery\\.shopware\\.min\\.js","/engine/Shopware/"]},
"Shuttle":{"implies":["Laravel","PHP","Amazon Web Services"],"scriptSrc":["shuttle(?:-assets-new|-storage)\\.s3\\.amazonaws\\.com"]},
"Silverstripe":{"html":["Powered by <a href=\"[^>]+Silverstripe"],"implies":["PHP"],"meta":{"generator":"^SilverStripe"}},
"Simple Machines Forum":{"implies":["PHP"]},
"SimpleSAMLphp":{"cookies":{"SimpleSAML":"","SimpleSAMLSessionID":""},"implies":["PHP"]},
"SitePad":{"implies":["PHP"],"meta":{"generator":"^SitePad(?:\\s([\\d\\.]+))?$\\;version:\\1"}},
"Skilldo":{"headers":{"cms-name":"^Skilldo$","cms-version":"([\\d\\.]+)\\;version:\\1\\;confidence:0"},"implies":["PHP","MySQL"]},
"Sky-Shop":{"implies":["PHP","Bootstrap","jQuery"],"meta":{"generator":"Sky-Shop"}},
"SlickStack":{"headers":{"x-powered-by":"SlickStack"},"implies":["WordPress"]},
"SobiPro":{"implies":["Joomla"]},
"Solodev":{"headers":{"solodev_session":""},"html":["<div class=[\"']dynamicDiv[\"'] id=[\"']dd\\.\\d\\.\\d(?:\\.\\d)?[\"']>"],"implies":["PHP"],"scriptSrc":["www\\.solodev\\.com/"]},
"SoteShop":{"cookies":{"soteshop":"^\\w+$"},"implies":["PHP"]},
"Spatie Laravel Cookie Consent":{"implies":["Laravel"]},
"Spatie Media Library Pro":{"implies":["Laravel"]},
"Spatie Support Bubble":{"implies":["Laravel","Tailwind CSS"]},
"SpiritShop":{"cookies":{"SPIRITSHOP_ID":""},"implies":["PHP","MySQL"]},
"Square Online":{"implies":["Weebly"]},
"SquirrelMail":{"html":["<small>SquirrelMail version ([.\\d]+)[^<]*<br \\;version:\\1"],"implies":["PHP"],"url":["/src/webmail\\.php(?:$|\\?)"]},
"Squiz Matrix":{"headers":{"X-Powered-By":"Squiz Matrix"},"html":["<!--\\s+Running (?:MySource|Squiz) Matrix"],"implies":["PHP"],"meta":{"generator":"Squiz Matrix"},"scriptSrc":["/__data/assets/(js_file_folder|git_bridge|js_file)/"]},
"Statamic":{"headers":{"x-powered-by":"^Statamic$"},"implies":["PHP","Laravel"]},
"Strattic":{"headers":{"x-powered-by":"Strattic"},"implies":["WordPress"]},
"Subrion":{"headers":{"X-Powered-CMS":"Subrion CMS"},"implies":["PHP"],"meta":{"generator":"^Subrion "}},
"Sulu":{"headers":{"X-Generator":"Sulu/?(.+)?$\\;version:\\1"},"implies":["Symfony"]},
"SummerCart":{"implies":["PHP"]},
"SuperPWA":{"implies":["WordPress","PWA"]},
"Sylius":{"implies":["Symfony"],"scriptSrc":["syliusshop/script\\.js","syliusgtmenhancedecommerceplugin"]},
"Symfony":{"cookies":{"sf_redirect":""},"implies":["PHP"]},
"TYPO3 CMS":{"implies":["PHP"],"meta":{"generator":"TYPO3\\s+(?:CMS\\s+)?(?:[\\d.]+)?(?:\\s+CMS)?"},"scriptSrc":["^/?typo3(?:conf|temp)/"],"url":["/typo3/"]},
"Tebex":{"headers":{"tb-cache-country":"^\\w+$\\;confidence:50","tb-cache-group":"^webstore$\\;confidence:50"},"implies":["MySQL","Sass","PHP"],"scriptSrc":["js\\.tebex\\.io/"]},
"Textpattern CMS":{"implies":["PHP","MySQL"],"meta":{"generator":"Textpattern"}},
"Thelia":{"html":["<(?:link|style|script)[^>]+/assets/frontOffice/"],"implies":["PHP","Symfony"]},
"ThinkPHP":{"cookies":{"thinkphp_show_page_trace":""},"headers":{"X-Powered-By":"ThinkPHP"},"implies":["PHP"]},
"TwistPHP":{"headers":{"X-Powered-By":"TwistPHP"},"implies":["PHP"]},
"Typecho":{"implies":["PHP"],"meta":{"generator":"Typecho( [\\d.]+)?\\;version:\\1"},"url":["/admin/login\\.php?referer=http%3A%2F%2F"]},
"UMI.CMS":{"headers":{"X-Generated-By":"UMI\\.CMS"},"implies":["PHP"]},
"Ubercart":{"implies":["Drupal"],"scriptSrc":["uc_cart/uc_cart_block\\.js"]},
"Ultimate Bulletin Board":{"implies":["PHP"],"meta":{"generator":"^UBB\\.threads\\s([\\d\\.]+)$\\;version:\\1"}},
"Upvoty":{"implies":["PHP"]},
"Ushahidi":{"cookies":{"ushahidi":""},"implies":["PHP","MySQL","OpenLayers"],"scriptSrc":["/js/ushahidi\\.js$"]},
"Uvodo":{"implies":["MySQL","PHP","React"],"scriptSrc":["cdn\\.uvo\\.do/"]},
"Vanilla":{"headers":{"X-Powered-By":"Vanilla"},"html":["<body id=\"(?:DiscussionsPage|vanilla)"],"implies":["PHP"]},
"Varbase":{"implies":["Drupal"]},
"VirtueMart":{"html":["<div id=\"vmMainPage"],"implies":["Joomla"]},
"Visual Composer":{"implies":["WordPress","PHP"],"meta":{"generator":"Powered by Visual Composer Website Builder"}},
"WP Engine":{"headers":{"X-Pass-Why":"","X-Powered-By":"WP Engine","X-WPE-Loopback-Upstream-Addr":"","wpe-backend":""},"implies":["WordPress"]},
"Webasyst Shop-Script":{"implies":["PHP","MySQL"]},
"Weblication":{"implies":["PHP","XSLT"],"meta":{"generator":"^Weblication\u00ae CMS$"}},
"Website Creator":{"implies":["PHP","MySQL","Vue.js"],"meta":{"generator":"Website Creator by hosttech","wsc_rendermode":""}},
"WebsiteBaker":{"implies":["PHP","MySQL"],"meta":{"generator":"WebsiteBaker"}},
"Weebly":{"implies":["PHP","MySQL"],"scriptSrc":["cdn\\d+\\.editmysite\\.com"]},
"WeltPixel Pearl Theme":{"implies":["Magento\\;version:2"]},
"Winter CMS":{"implies":["Laravel"],"meta":{"author":"^Winter CMS$","generator":"^Winter CMS$"}},
"Wolf CMS":{"html":["(?:<a href=\"[^>]+wolfcms\\.org[^>]+>Wolf CMS(?:</a>)? inside|Thank you for using <a[^>]+>Wolf CMS)"],"implies":["PHP"]},
"Woltlab Community Framework":{"implies":["PHP"],"scriptSrc":["WCF\\..*\\.js"]},
"WordPress":{"headers":{"X-Pingback":"/xmlrpc\\.php$","link":"rel=\"https://api\\.w\\.org/\""},"html":["<link rel=[\"']stylesheet[\"'] [^>]+/wp-(?:content|includes)/","<link[^>]+s\\d+\\.wp\\.com"],"implies":["PHP","MySQL"],"meta":{"generator":"^WordPress(?: ([\\d.]+))?\\;version:\\1","shareaholic:wp_version":""},"scriptSrc":["/wp-(?:content|includes)/","wp-embed\\.min\\.js","wp-static\\.assets\\.sh/"]},
"WordPress VIP":{"headers":{"x-powered-by":"^WordPress VIP|wpvip\\.com"},"implies":["WordPress"]},
"WordPress.com":{"headers":{"host-header":"WordPress\\.com"},"implies":["WordPress"]},
"X-Cart":{"implies":["PHP"],"meta":{"generator":"X-Cart(?: (\\d+))?\\;version:\\1"}},
"XAMPP":{"html":["<title>XAMPP(?: Version ([\\d\\.]+))?</title>\\;version:\\1"],"implies":["Apache HTTP Server","MySQL","PHP","Perl"],"meta":{"author":"Kai Oswald Seidler\\;confidence:10"}},
"XOOPS":{"implies":["PHP"],"meta":{"generator":"XOOPS"}},
"XenForo":{"cookies":{"xf_csrf":"","xf_session":""},"html":["(?:jQuery\\.extend\\(true, XenForo|<a[^>]+>Forum software by XenForo\u2122|<!--XF:branding|<html[^>]+id=\"XenForo\")","<html id=\"XF\" "],"implies":["PHP","MySQL"]},
"Xiuno BBS":{"implies":["PHP"],"meta":{"author":"XiunoBBS\\s([\\d\\.]+)\\;version:\\1"}},
"YesWiki":{"implies":["PHP"],"scriptSrc":["javascripts/yeswiki-base\\.js"]},
"Yii":{"cookies":{"YII_CSRF_TOKEN":""},"html":["Powered by <a href=\"http://www\\.yiiframework\\.com/\" rel=\"external\">Yii Framework</a>","<input type=\"hidden\" value=\"[a-zA-Z0-9]{40}\" name=\"YII_CSRF_TOKEN\" \\/>","<!\\[CDATA\\[YII-BLOCK-(?:HEAD|BODY-BEGIN|BODY-END)\\]"],"implies":["PHP"],"scriptSrc":["/assets/[a-zA-Z0-9]{8}\\/yii\\.js$","yii(?:\\.|)?(?:validation|activeform)\\.js"]},
"Yoast SEO":{"html":["<!-- This site is optimized with the Yoast (?:WordPress )?SEO plugin v([^\\s]+) -\\;version:\\1","<!-- This site is optimized with the Yoast SEO Premium plugin v(?:[^\\s]+) \\(Yoast SEO v([^\\s]+)\\) -\\;version:\\1"],"implies":["WordPress"]},
"Yoori":{"implies":["Laravel","PHP","Vue.js","PWA","MySQL","cPanel"]},
"YouCan":{"headers":{"x-powered-by":"Youcan\\.Private\\.DC/"},"implies":["PHP","MySQL","Redis","Laravel","YouCan Pay"]},
"Zabbix":{"html":["<body[^>]+zbxCallPostScripts"],"implies":["PHP"],"meta":{"Author":"ZABBIX SIA\\;confidence:70"},"url":["\\/zabbix\\/\\;confidence:30"]},
"Ziggy":{"implies":["Laravel","Inertia.js"]},
"Zoey":{"implies":["PHP","MySQL"],"scriptSrc":["cdna4\\.zoeysite\\.com"]},
"Zozo":{"implies":["PHP","MySQL"],"meta":{"generator":"Zozo Ecommerce"},"scriptSrc":["zozo-main\\.min\\.js"]},
"a-blog cms":{"implies":["PHP"],"meta":{"generator":"a-blog cms"}},
"e107":{"cookies":{"e107_tz":""},"headers":{"X-Powered-By":"e107"},"implies":["PHP"],"scriptSrc":["[^a-z\\d]e107\\.js"]},
"eSyndiCat":{"headers":{"X-Drectory-Script":"^eSyndiCat"},"implies":["PHP"],"meta":{"generator":"^eSyndiCat "}},
"eZ Publish":{"cookies":{"eZSESSID":""},"headers":{"X-Powered-By":"^eZ Publish"},"implies":["PHP"],"meta":{"generator":"eZ Publish"}},
"experiencedCMS":{"implies":["PHP"],"meta":{"generator":"^experiencedCMS$"}},
"gitlist":{"html":["<p>Powered by <a[^>]+>GitList ([\\d.]+)\\;version:\\1"],"implies":["PHP","git"]},
"govCMS":{"implies":["Drupal"],"meta":{"generator":"Drupal ([\\d]+) \\(http:\\/\\/drupal\\.org\\) \\+ govCMS\\;version:\\1"}},
"h5ai":{"implies":["PHP"],"scriptSrc":["/_h5ai/(?:public|client)/js/scripts\\.js"]},
"iEXExchanger":{"cookies":{"iexexchanger_session":""},"implies":["PHP","Apache HTTP Server","Angular"],"meta":{"generator":"iEXExchanger"}},
"iPresta":{"implies":["PHP","PrestaShop"],"meta":{"designer":"iPresta"}},
"iScripts":{"implies":["PHP"],"meta":{"copyright":"^Copyright \\(C\\) www\\.iScripts\\.com,? \\d{4}\\. All rights reserved\\.$"}},
"ocStore":{"html":["<!--[^>]+ocStore(?:\\s([\\d\\.a-z]+))?\\;version:\\1"],"implies":["OpenCart"]},
"osCommerce":{"cookies":{"osCsid":""},"html":["<br />Powered by <a href=\"https?://www\\.oscommerce\\.com","<(?:input|a)[^>]+name=\"osCsid\"","<(?:tr|td|table)class=\"[^\"]*infoBoxHeading"],"implies":["PHP","MySQL"]},
"osTicket":{"cookies":{"OSTSESSID":""},"implies":["PHP","MySQL"]},
"ownCloud":{"html":["<a href=\"https://owncloud\\.com\" target=\"_blank\">ownCloud Inc\\.</a><br/>Your Cloud, Your Data, Your Way!"],"implies":["PHP"],"meta":{"apple-itunes-app":"app-id=543672169"}},
"papaya CMS":{"html":["<link[^>]*/papaya-themes/"],"implies":["PHP"]},
"phpAlbum":{"html":["<!--phpalbum ([.\\d\\s]+)-->\\;version:\\1"],"implies":["PHP"]},
"phpBB":{"cookies":{"phpbb":""},"html":["Powered by <a[^>]+phpBB","<div class=phpbb_copyright>","<[^>]+styles/(?:sub|pro)silver/theme","<img[^>]+i_icon_mini","<table class=\"[^\"]*forumline"],"implies":["PHP"],"meta":{"copyright":"phpBB Group"}},
"phpCMS":{"implies":["PHP"]},
"phpDocumentor":{"html":["<!-- Generated by phpDocumentor"],"implies":["PHP"]},
"phpMyAdmin":{"headers":{"Set-Cookie":"phpMyAdmin_https"},"html":["!\\[CDATA\\[[^<]*PMA_VERSION:\\\"([\\d.]+)\\;version:\\1","(?: \\| phpMyAdmin ([\\d.]+)<\\/title>|PMA_sendHeaderLocation\\(|<link [^>]*href=\"[^\"]*phpmyadmin\\.css\\.php)\\;version:\\1"],"implies":["PHP","MySQL"]},
"phpPgAdmin":{"html":["(?:<title>phpPgAdmin</title>|<span class=\"appname\">phpPgAdmin)"],"implies":["PHP"]},
"phpRS":{"implies":["PHP"],"meta":{"generator":"^phpRS$"}},
"phpSQLiteCMS":{"implies":["PHP","SQLite"],"meta":{"generator":"^phpSQLiteCMS(?: (.+))?$\\;version:\\1"}},
"phpwind":{"html":["(?:Powered|Code) by <a href=\"[^\"]+phpwind\\.net"],"implies":["PHP"],"meta":{"generator":"^phpwind(?: v([0-9-]+))?\\;version:\\1"}},
"pinoox":{"cookies":{"pinoox_session":""},"implies":["PHP"]},
"punBB":{"html":["Powered by <a href=\"[^>]+punbb"],"implies":["PHP"]},
"uKnowva":{"headers":{"X-Content-Encoded-By":"uKnowva ([\\d.]+)\\;version:\\1"},"html":["<a[^>]+>Powered by uKnowva</a>"],"implies":["PHP"],"meta":{"generator":"uKnowva (?: ([\\d.]+))?\\;version:\\1"},"scriptSrc":["/media/conv/js/jquery\\.js"]},
"vBulletin":{"cookies":{"bblastactivity":"","bblastvisit":"","bbsessionhash":""},"html":["<div id=\"copyright\">Powered by vBulletin"],"implies":["PHP"],"meta":{"generator":"vBulletin ?([\\d.]+)?\\;version:\\1"}},
"vibecommerce":{"implies":["PHP"],"meta":{"designer":"vibecommerce","generator":"vibecommerce"}},
"wp.cloud":{"headers":{"host-header":"wpcloud"},"implies":["WordPress"]},
"wpBakery":{"implies":["PHP"],"meta":{"generator":"WPBakery"}},
"wpCache":{"headers":{"X-Powered-By":"wpCache(?:/([\\d.]+))?\\;version:\\1"},"html":["<!--[^>]+wpCache"],"implies":["PHP"],"meta":{"generator":"wpCache","keywords":"wpCache"},"url":["^https?://[^/]+\\.wpcache\\.co"]}
}'''


def update_rules(dest=RULES_DIR):
    os.makedirs(dest, exist_ok=True)
    ok = 0
    for name in RULES_FILES:
        url = RULES_URL.format(name)
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                data = r.read()
            json.loads(data)                       # validate before saving
            with open(os.path.join(dest, f"{name}.json"), "wb") as f:
                f.write(data)
            ok += 1
        except Exception as e:  # noqa: BLE001
            print(f"  failed {url}: {e}", file=sys.stderr)
    print(f"Downloaded {ok}/{len(RULES_FILES)} rule files to {dest}", file=sys.stderr)
    return ok == len(RULES_FILES)


def load_rules(path=RULES_DIR):
    """Load every technology that runs on PHP (directly or via 'implies').
    Uses a downloaded database (-U / --rules) if present, else the embedded one.
    Returns (number of PHP technologies, source description)."""
    files = [path] if os.path.isfile(path) else sorted(glob.glob(os.path.join(path, "*.json")))
    techs = {}
    for f in files:
        with open(f, encoding="utf-8") as fh:
            techs.update(json.load(fh))
    if techs:
        newest = max(os.path.getmtime(f) for f in files)
        source = f"downloaded database ({time.strftime('%Y-%m-%d', time.localtime(newest))})"
    else:
        techs = json.loads(EMBEDDED_RULES)
        source = f"embedded database ({EMBEDDED_RULES_DATE})"
    return _load_techs(techs), source


def _load_techs(techs):

    def implies(t):
        v = techs.get(t, {}).get("implies", [])
        return [x.split("\\;")[0] for x in ([v] if isinstance(v, str) else v)]

    php = {"PHP"}
    changed = True
    while changed:                       # transitive: e.g. Plugin -> WordPress -> PHP
        changed = False
        for t in techs:
            if t not in php and any(i in php for i in implies(t)):
                php.add(t)
                changed = True

    def as_list(v):
        return [v] if isinstance(v, str) else (v or [])

    def add(tech, kind, key, pattern):
        pat, _, rest = pattern.partition("\\;")
        ver = ""
        for part in rest.split("\\;"):
            if part.startswith("version:"):
                ver = part[8:]
        try:
            rx = re.compile(pat, re.I) if pat else None
        except re.error:
            return                       # JS-only regex syntax: skip
        DB_RULES.append((tech, kind, key, rx, ver))

    for t in php:
        d = techs.get(t, {})
        for k, v in (d.get("headers") or {}).items():
            add(t, "header", k.lower(), v)
        for k, v in (d.get("cookies") or {}).items():
            add(t, "cookie", k, v)
        for k, v in (d.get("meta") or {}).items():
            for p in as_list(v):
                add(t, "meta", k.lower(), p)
        for p in as_list(d.get("html")):
            add(t, "html", "", p)
        for p in as_list(d.get("scriptSrc")):
            add(t, "script", "", p)
        for p in as_list(d.get("url")):
            add(t, "url", "", p)
    return len(php) - 1


def parse_response(final, hdr, cookie, body):
    """Structured view of a response for the database rules."""
    headers = {}
    for line in hdr.splitlines():
        k, _, v = line.partition(": ")
        headers.setdefault(k.lower(), []).append(v)
    cookies = {}
    for line in cookie.splitlines():
        name, _, val = line.split(";", 1)[0].partition("=")
        cookies[name.strip()] = val.strip()
    metas = {}
    for tag in re.findall(r"<meta\s[^>]*>", body, re.I):
        name = re.search(r"""(?:name|property|http-equiv)\s*=\s*["']([^"']+)""", tag, re.I)
        content = re.search(r"""content\s*=\s*["']([^"']*)""", tag, re.I)
        if name:
            metas.setdefault(name.group(1).lower(), []).append(content.group(1) if content else "")
    scripts = re.findall(r"""<script[^>]+src\s*=\s*["']([^"']+)""", body, re.I)
    return headers, cookies, metas, scripts


def match_db(final, hdr, cookie, body):
    """Yield (tech, where, matched_text, version) for database rules."""
    if not DB_RULES:
        return
    headers, cookies, metas, scripts = parse_response(final, hdr, cookie, body)
    for tech, kind, key, rx, ver in DB_RULES:
        if kind == "header":
            values = headers.get(key, [])
        elif kind == "cookie":
            values = [v for n, v in cookies.items() if fnmatch.fnmatch(n, key)]
        elif kind == "meta":
            values = metas.get(key, [])
        elif kind == "html":
            values = [body]
        elif kind == "script":
            values = scripts
        else:
            values = [final]
        for v in values:
            m = rx.search(v) if rx else True
            if not m:
                continue
            version = ""
            if rx and ver and "\\1" in ver and m.lastindex:
                version = m.group(1) or ""
            text = (m.group(0) if rx else f"{key} present")[:90]
            yield tech, f"db-{kind}", text, version
            break
PHP_LINK = r"""(?:href|src|action)\s*=\s*["']([^"'#?]*\.php)(?:[?#"'])"""


def make_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False          # fingerprinting only: don't skip
    ctx.verify_mode = ssl.CERT_NONE     # customers with broken certificates
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")   # also talk to old servers
    except ssl.SSLError:
        pass
    return ctx


TLS_CTX = make_ctx()


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to a fixed IP while sending another name via SNI (vhost scanning)."""

    def __init__(self, ip, port, sni, timeout):
        super().__init__(ip, port, timeout=timeout, context=TLS_CTX)
        self._sni = sni

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = TLS_CTX.wrap_socket(sock, server_hostname=self._sni or None)


def http_get(url, timeout, pin=None):
    """One GET without redirects. pin: {hostname: ip} -> connect to that IP but
    send the hostname as Host header and SNI. Returns (status, header list)."""
    u = urlparse(url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    ip = (pin or {}).get(host.lower(), host)
    sni = host if not is_ip(host) else None
    if u.scheme == "https":
        conn = PinnedHTTPSConnection(ip, port, sni, timeout)
    else:
        conn = http.client.HTTPConnection(ip, port, timeout=timeout)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    host_hdr = host if ":" not in host else f"[{host}]"
    if u.port and u.port not in (80, 443):
        host_hdr += f":{u.port}"
    conn.request("GET", path, headers={"Host": host_hdr, "User-Agent": UA,
                                       "Accept": "text/html,*/*", "Connection": "close"})
    resp = conn.getresponse()
    return conn, resp


def is_ip(s):
    try:
        ipaddress.ip_address(s.strip("[]"))
        return True
    except ValueError:
        return False


RESULT_META = {}   # target -> (body hash, <title>) to spot vhosts that just show the default site

# absolute or protocol-relative URL: https://host, http://host, //host  (also JSON-escaped)
URL_HOST_RX = re.compile(r"(?:https?:)?//([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?|\[[0-9a-f:.]+\])(?::\d+)?"
                         r"(?:[/?#][^\s\"'<>()\\,]*)?", re.I)   # host + the whole rest of the URL


def local_view(body, host, server_ips):
    """Return the page with every URL to ANOTHER server replaced by //external.invalid.
    A URL counts as local if its host is the page's own host (with/without www.),
    or a hostname that resolves to the scanned server's IP."""
    host = host.lower()
    me = {host, host[4:] if host.startswith("www.") else "www." + host}
    verdict = {}
    dropped = set()

    def is_local(h):
        h = h.lower().strip("[]")
        if h in me or h in server_ips:
            return True
        if h not in verdict:
            if is_ip(h) or "." not in h:
                verdict[h] = False
            else:
                verdict[h] = bool(server_ips and set(resolve(h)) & server_ips)
        return verdict[h]

    def repl(m):
        if is_local(m.group(1)):
            return m.group(0)
        dropped.add(m.group(1).lower())
        return "//external.invalid/"              # host AND path removed

    text = body.replace("\\/", "/")               # JSON-escaped URLs: https:\/\/host\/...
    return URL_HOST_RX.sub(repl, text), dropped


DEBUG = 0
PRINT_LOCK = threading.Lock()

BANNER = r"""
   ______ __  ___ _____ _____  _____  ___     _   __
  / ____//  |/  // ___// ___/ / ___/ /   |   / | / /
 / /    / /|_/ / \__ \ \__ \ / /    / /| |  /  |/ /
/ /___ / /  / / ___/ /___/ // /___ / ___ | / /|  /
\____//_/  /_/ /____//____/ \____//_/  |_|/_/ |_/
"""


def print_banner():
    """Banner goes to stderr so piped/redirected results stay clean."""
    color = sys.stderr.isatty()
    g, d, r = ("\033[1;32m", "\033[2;32m", "\033[0m") if color else ("", "", "")
    print(f"{g}{BANNER}{r}", file=sys.stderr)
    print(f"{d}  [ PHP & CMS detection  ::  port scan  ::  fingerprinting ]{r}", file=sys.stderr)
    print(f"{d}  [ authorized targets only  ::  v1.0                     ]{r}\n", file=sys.stderr, flush=True)


def explain(e):
    """Turn a network exception into a short reason plus a hint."""
    reason = getattr(e, "reason", e)
    text = " ".join(f"{type(e).__name__}: {reason}".split())   # no stray newlines
    s = str(reason).lower()
    if isinstance(reason, socket.timeout) or "timed out" in s:
        hint = "timeout: host silent or port filtered by a firewall (try a larger -t)"
    elif "refused" in s:
        hint = "connection refused: nothing listening on that port"
    elif "name or service not known" in s or "nodename nor servname" in s or "getaddrinfo" in s:
        hint = "DNS: hostname does not resolve"
    elif "no route" in s or "unreachable" in s:
        hint = "network unreachable: routing or firewall"
    elif isinstance(reason, ssl.SSLError) or "ssl" in s or "tls" in s:
        hint = "TLS handshake failed: old protocol/cipher, or port is not HTTPS"
    elif "reset" in s:
        hint = "connection reset: WAF/firewall or server closed it"
    elif "remote end closed" in s or "badstatusline" in s:
        hint = "server closed connection without a valid HTTP reply"
    else:
        hint = ""
    return text, hint


META_REFRESH_RX = re.compile(
    r"""<meta(?=[^>]*http-equiv\s*=\s*["']?refresh)[^>]*content\s*=\s*["']?\s*\d*\s*;?\s*url\s*=\s*['"]?([^"'>\s]+)""",
    re.I)
JS_REDIRECT_RX = re.compile(
    r"""(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']"""
    r"""|location\.(?:replace|assign)\(\s*["']([^"']+)["']\s*\)""", re.I)


def body_redirect(body):
    """Target of a client-side redirect in a small placeholder page, else None.
    Only small pages count, so a big site with some location= in its JS isn't 'redirected'."""
    if len(body) > 4096:
        return None
    m = META_REFRESH_RX.search(body)
    if m:
        return m.group(1)
    m = JS_REDIRECT_RX.search(body)
    if m:
        return m.group(1) or m.group(2)
    return None


def fetch(url, timeout, log, pin=None):
    """GET url, follow up to 5 redirects manually so every Set-Cookie is kept.

    Redirects are only followed while they stay on the SAME SERVER (same IP):
    hosts in pin are reached on their pinned IP, other hostnames only if they
    resolve to the scanned IP. A redirect to another server is reported, not
    followed, so results always describe the scanned server.
    Returns (final_url, status, headers, cookies, body, server, locations, offsite_url)."""
    headers, cookies, locations = [], [], []
    pin = dict(pin or {})
    first = (urlparse(url).hostname or "").lower()
    if pin:
        server_ips = set(pin.values())
    elif is_ip(first):
        server_ips = {first.strip("[]")}
    else:
        server_ips = set(resolve(first))
        if server_ips:                       # keep talking to the IP we resolved first
            pin[first] = sorted(server_ips)[0]
    for hop in range(6):
        h = (urlparse(url).hostname or "").lower()
        via = f"  via {pin[h]}" if pin and h in pin else ""
        log(f"  -> GET {url}{via}" + (f"  (redirect {hop})" if hop else ""))
        t0 = time.monotonic()
        conn, resp = http_get(url, timeout, pin)
        try:
            hdrs = resp.getheaders()
            log(f"     HTTP {resp.status} in {time.monotonic() - t0:.2f}s")
            for k, v in hdrs:
                log(f"     < {k}: {v}")
            headers += [f"{k.lower()}: {v}" for k, v in hdrs]
            cookies += [v for k, v in hdrs if k.lower() == "set-cookie"]
            loc = resp.getheader("Location")
            body = ""
            if resp.status in (301, 302, 303, 307, 308) and loc:
                nxt = urljoin(url, loc)
            else:
                body = resp.read(MAX_BODY).decode("utf-8", "replace")
                log(f"     body: {len(body)} chars")
                # client-side redirect in a small placeholder page (meta refresh or
                # window.location), e.g. Nextcloud's static index.html -> index.php
                target = body_redirect(body) if hop < 5 else None
                if not target:
                    return (url, resp.status, "\n".join(headers), "\n".join(cookies), body,
                            resp.getheader("Server", ""), locations, "")
                nxt = urljoin(url, target)
                log(f"     client-side redirect in page -> {nxt}")
            locations.append(nxt)
            if urlparse(nxt).scheme not in ("http", "https"):
                log(f"     redirect to non-HTTP target ignored: {nxt}")
                return (url, resp.status, "\n".join(headers), "\n".join(cookies), body,
                        resp.getheader("Server", ""), locations, "")
            nh = (urlparse(nxt).hostname or "").lower().strip("[]")
            if nh not in pin and nh not in server_ips:
                target_ips = set(resolve(nh)) if not is_ip(nh) else {nh}
                if server_ips and target_ips & server_ips:
                    pin[nh] = pin.get(first) or sorted(server_ips)[0]   # same server: follow
                else:
                    log(f"     redirect to another server ({nh} -> "
                        f"{','.join(sorted(target_ips)) or 'no dns'}): not followed")
                    return (url, resp.status, "\n".join(headers), "\n".join(cookies), body,
                            resp.getheader("Server", ""), locations, nxt)
            if nxt == url:                      # page refreshing itself: done
                return (url, resp.status, "\n".join(headers), "\n".join(cookies), body,
                        resp.getheader("Server", ""), locations, "")
            url = nxt
            continue
        finally:
            conn.close()
    log("     too many redirects, stopped")
    return url, 0, "\n".join(headers), "\n".join(cookies), "", "", locations, ""


SNI_ONLY = set()   # "ip:port" endpoints whose TLS only works with a hostname


def is_sni_reject(e):
    """Handshake aborted by the server (no alert, or 'unrecognized name'/'handshake failure'),
    which is how nginx/Apache react to a missing or unknown SNI hostname."""
    # urllib wraps errors in URLError(.reason = exception); ssl.SSLError's own .reason is a
    # string like "TLSV1_UNRECOGNIZED_NAME" - so look at the exception objects, not .reason
    errs = [e] + ([e.reason] if isinstance(getattr(e, "reason", None), BaseException) else [])
    for x in errs:
        s = f"{type(x).__name__} {x} {getattr(x, 'reason', '')}".upper()
        if isinstance(x, (ssl.SSLError, ConnectionResetError)) and any(
                k in s for k in ("EOF", "UNRECOGNIZED_NAME", "HANDSHAKE_FAILURE",
                                 "INTERNAL_ERROR", "CONNECTIONRESET")):
            return True
    return False


def check(target, timeout):
    lines = []
    log = lines.append if DEBUG else (lambda _m: None)
    try:
        return _check(target, timeout, log)
    finally:
        if DEBUG:
            with PRINT_LOCK:
                print(f"\n[DEBUG] {target}", file=sys.stderr)
                print("\n".join(lines), file=sys.stderr, flush=True)


def _check(target, timeout, log):
    target = target.strip()
    pin = None
    if "://" in target:
        urls = [target]
    else:
        vhost, addr = (target.split("@", 1) + [None])[:2] if "@" in target else (None, target)
        ip, port = split_hostport(addr)
        if vhost:                          # vhost@ip:port -> Host/SNI = vhost, connect to ip
            pin = {vhost.lower(): ip}
            name = vhost if port is None else f"{vhost}:{port}"
        else:
            name = addr
        if port == 80:
            urls = [f"http://{name}/"]
        elif port == 443:
            urls = [f"https://{name}/"]
        else:   # unknown port: try TLS first, then plain HTTP
            urls = [f"https://{name}/", f"http://{name}/"]
    errors, sni_rejected = [], False
    for url in urls:
        try:
            final, status, hdr, cookie, body, server, locations, offsite = fetch(url, timeout, log, pin)
            break
        except Exception as e:  # noqa: BLE001 - report any network error
            text, hint = explain(e)
            scheme = urlparse(url).scheme
            # TLS server that hangs up / refuses when we connect WITHOUT a hostname:
            # nginx "ssl_reject_handshake on" or no default certificate. It is an HTTPS
            # server - it just only answers for its configured vhosts.
            if scheme == "https" and is_sni_reject(e) and is_ip(urlparse(url).hostname or ""):
                sni_rejected = True
                hint = "TLS refused without a hostname (SNI): server only answers for its vhosts"
            log(f"     ERROR {text}")
            if hint:
                log(f"     hint: {hint}")
            if DEBUG >= 2:
                log("     " + traceback.format_exc().strip().replace("\n", "\n     "))
            errors.append(f"{scheme}: {hint or text}")
    else:
        if sni_rejected:
            SNI_ONLY.add(target)
            return [target, "", "", "SNI ONLY", "", "", "",
                    "HTTPS needs a hostname (SNI) - see vhost results"]
        return [target, "", "", "ERROR", "", "", "", " | ".join(errors)]

    title = re.search(r"<title[^>]*>([^<]{0,200})", body, re.I)
    RESULT_META[target] = {
        "hash": hashlib.sha1(re.sub(r"\s+", "", body).encode()).hexdigest(),
        "title": (title.group(1).strip() if title else ""),
        "status": status,
        "hosts": {(urlparse(u).hostname or "").lower() for u in locations + [final]},
    }

    # Only this server's own content counts: neutralize every URL that points to
    # another server (images, scripts, CSS, iframes, links from e.g. a WordPress
    # elsewhere), so path rules like /wp-content/ can't match foreign resources.
    fhost = (urlparse(final).hostname or "").lower().strip("[]")
    if pin:
        server_ips = set(pin.values())
    elif is_ip(fhost):
        server_ips = {fhost}
    else:
        server_ips = set(resolve(fhost))
    local, dropped = local_view(body, fhost, server_ips)
    if dropped:
        log(f"  ignored {len(dropped)} external host(s): {', '.join(sorted(dropped)[:8])}"
            + (" ..." if len(dropped) > 8 else ""))

    techs, evidence, version = [], [], ""
    if offsite:
        evidence.append(f"redirects to other server: {offsite}")
    src = {"header": hdr, "cookie": cookie, "body": local}
    for tech, where, rx in COMPILED:
        m = rx.search(src[where])
        if not m:
            continue
        if tech == "PHP" and where == "header" and m.lastindex and m.group(1):
            version = m.group(1)
        if tech not in techs:
            techs.append(tech)
        evidence.append(f"{tech}:{where}")
        log(f"  match {tech:<20} in {where:<6}: {m.group(0)[:90]!r}")

    # external fingerprint database (if loaded)
    app_versions = {}
    known = {t.lower() for t in techs}
    for tech, where, text, ver in match_db(final, hdr, cookie, local):
        if tech == "PHP" and ver and not version:
            version = ver
        # same product, different spelling ("TYPO3" built-in vs "TYPO3 CMS" in the database)
        for t in techs:
            tl, dl = t.lower(), tech.lower()
            if t != tech and (dl.startswith(tl + " ") or tl.startswith(dl + " ")):
                tech = t
                break
        if ver and tech != "PHP":
            app_versions.setdefault(tech, ver)
        if tech.lower() not in known:
            techs.append(tech)
            known.add(tech.lower())
        evidence.append(f"{tech}:{where}")
        log(f"  match {tech:<20} in {where:<9}: {text!r}" + (f"  version {ver}" if ver else ""))

    # .php links on the same server (external ones were neutralized above)
    for link in re.findall(PHP_LINK, local, re.I):
        if "external.invalid" in link:
            continue
        if "PHP" not in techs:
            techs.insert(0, "PHP")
        evidence.append("PHP:.php-link")
        log(f"  match {'PHP':<20} in link  : {link!r}")
        break
    if not [e for e in evidence if not e.startswith("redirects to")]:
        log("  no PHP fingerprint matched")

    if version:
        verdict = f"PHP ({version})"
    elif techs:
        verdict = "PHP"
    else:
        verdict = "NO SIGN"
    apps = [f"{t} {app_versions[t]}" if t in app_versions else t for t in techs if t != "PHP"]
    return [target, final, status, verdict, version, ", ".join(apps), server,
            ", ".join(dict.fromkeys(evidence))]


def expand(arg):
    """An IP, IP range (CIDR), hostname, URL, or a file containing any of these."""
    import ipaddress, os
    if os.path.isfile(arg):
        out = []
        with open(arg, encoding="utf-8") as f:
            for l in f:
                l = l.strip()
                if l and not l.startswith("#"):
                    out += expand(l)
        return out
    if "/" in arg and "://" not in arg:
        try:
            net = ipaddress.ip_network(arg, strict=False)
            hosts = list(net.hosts()) or [net.network_address]
            return [f"[{h}]" if h.version == 6 else str(h) for h in hosts]
        except ValueError:
            pass
    return [arg]


# Common web ports: standard, alternate HTTP/HTTPS, and hosting panels
# (cPanel 2082/2083, WHM 2086/2087, DirectAdmin 2222, Plesk 8443/8880,
#  CyberPanel 8090, LiteSpeed WebAdmin 7080)
DEFAULT_PORTS = "80,443,81,2082,2083,2086,2087,2222,3000,4443,7080,8000,8008,8080,8081,8090,8443,8880,8888,9443"


def parse_ports(spec):
    spec = spec.strip().lower()
    if spec in ("all", "-", "1-65535"):
        return list(range(1, 65536))
    if spec == "web":
        spec = DEFAULT_PORTS
    ports = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            ports += range(lo, hi + 1)
        else:
            ports.append(int(part))
    return list(dict.fromkeys(p for p in ports if 0 < p < 65536))


def split_hostport(t):
    """'1.2.3.4' -> ('1.2.3.4', None); 'host:8080' -> ('host', 8080); '[::1]:443' -> ('::1', 443)."""
    if t.startswith("["):
        host, _, rest = t[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
    if t.count(":") == 1:
        host, port = t.split(":")
        return host, int(port) if port.isdigit() else None
    return t, None


def port_open(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def max_sockets():
    """How many parallel connections the OS allows us (open-file limit)."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = 4096
        if soft < want and (hard == resource.RLIM_INFINITY or hard > soft):
            new = want if hard == resource.RLIM_INFINITY else min(want, hard)
            resource.setrlimit(resource.RLIMIT_NOFILE, (new, hard))
            soft = new
        return max(50, soft - 100)
    except Exception:  # noqa: BLE001 - Windows has no resource module
        return 500


def scan(items, workers, timeout):
    """TCP connect scan. items: iterable of (target, host, port). Streams work so
    even a full 65535-port scan of many hosts stays small in memory."""
    total = len(items)
    open_ports, done, last_pct = {}, 0, -1
    t0 = time.monotonic()

    def probe(item):
        t, h, p = item
        return t, p, port_open(h, p, timeout)

    it = iter(items)
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        pending = {ex.submit(probe, x) for x in itertools.islice(it, workers * 2)}
        while pending:
            finished, pending = cf.wait(pending, return_when=cf.FIRST_COMPLETED)
            for f in finished:
                t, p, ok = f.result()
                done += 1
                if ok:
                    open_ports.setdefault(t, []).append(p)
                    if DEBUG:
                        print(f"\r[SCAN] open {t}:{p}" + " " * 20, file=sys.stderr, flush=True)
                nxt = next(it, None)
                if nxt is not None:
                    pending.add(ex.submit(probe, nxt))
            pct = done * 100 // total
            if pct != last_pct and sys.stderr.isatty():
                last_pct = pct
                el = time.monotonic() - t0
                eta = el / done * (total - done) if done else 0
                n_open = sum(len(v) for v in open_ports.values())
                print(f"\r  scan {pct:3d}%  {done}/{total} probes  {n_open} open  ETA {eta:5.0f}s ",
                      end="", file=sys.stderr, flush=True)
    if sys.stderr.isatty():
        print(file=sys.stderr)
    return open_ports


# --- vhost discovery -------------------------------------------------------

HOSTNAME_RX = re.compile(r"^(?:\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$", re.I)


def _der_len(b, i):
    n = b[i]
    i += 1
    if n < 0x80:
        return n, i
    k = n & 0x7F
    return int.from_bytes(b[i:i + k], "big"), i + k


def cert_names_from_der(der):
    """Hostnames from a DER certificate: subjectAltName dNSNames + CommonName."""
    names = set()
    k = der.find(b"\x06\x03\x55\x1d\x11")             # OID 2.5.29.17 subjectAltName
    if k >= 0:
        try:
            i = k + 5
            if der[i] == 0x01:                           # optional 'critical' BOOLEAN
                ln, i2 = _der_len(der, i + 1)
                i = i2 + ln
            if der[i] == 0x04:                           # OCTET STRING
                ln, i = _der_len(der, i + 1)
                seq = der[i:i + ln]
                if seq and seq[0] == 0x30:
                    sl, j = _der_len(seq, 1)
                    end = j + sl
                    while j < end:
                        tag = seq[j]
                        ln, j2 = _der_len(seq, j + 1)
                        if tag == 0x82:                  # dNSName
                            names.add(seq[j2:j2 + ln].decode("ascii", "ignore"))
                        j = j2 + ln
        except IndexError:
            pass
    for m in re.finditer(rb"\x06\x03\x55\x04\x03[\x0c\x13\x16](.)", der, re.S):   # CN
        ln = m.group(1)[0]
        names.add(der[m.end():m.end() + ln].decode("utf-8", "ignore"))
    return {n.strip().lower() for n in names if HOSTNAME_RX.match(n.strip())}


def cert_names(ip, port, sni, timeout):
    """Names in the certificate the server presents for sni. None = no TLS on this port."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            with TLS_CTX.wrap_socket(s, server_hostname=sni) as t:
                der = t.getpeercert(binary_form=True)
        return cert_names_from_der(der) if der else set()
    except (OSError, ValueError):
        return None


@functools.lru_cache(maxsize=20000)
def resolve(name):
    try:
        return frozenset(ai[4][0] for ai in socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP))
    except (OSError, UnicodeError):
        return frozenset()


def reverse_dns(ip):
    try:
        n, aliases, _ = socket.gethostbyaddr(ip)
        return {n, *aliases}
    except (OSError, UnicodeError):
        return set()


def base_domain(name):
    parts = name.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "net", "org", "ac", "gov", "edu"):
        return ".".join(parts[-3:])          # example.co.uk
    return ".".join(parts[-2:])


@functools.lru_cache(maxsize=5000)
def ct_names(domain, timeout):
    """Certificate Transparency: all names ever in a public certificate for *.domain (crt.sh)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read() or b"[]")
    return frozenset(n for e in data for n in e.get("name_value", "").split("\n"))


def _get(url, timeout, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def pdns_otx(ip, timeout):
    """AlienVault OTX passive DNS (free, no key)."""
    kind = "IPv6" if ":" in ip else "IPv4"
    data = json.loads(_get(f"https://otx.alienvault.com/api/v1/indicators/{kind}/{ip}/passive_dns", timeout))
    return {e.get("hostname", "") for e in data.get("passive_dns", [])}


def pdns_hackertarget(ip, timeout):
    """HackerTarget reverse IP (free, no key, few queries per day)."""
    txt = _get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout)
    low = txt.lower()
    if "error" in low or "api count" in low or "no dns a records" in low or "no records" in low:
        raise RuntimeError(txt.strip()[:80])
    return set(txt.split())


API_KEYS = {}   # filled from CMSSCAN_*_KEY env vars or --vt-key / --shodan-key / --securitytrails-key
KEY_ENV = {"virustotal": "CMSSCAN_VT_KEY", "shodan": "CMSSCAN_SHODAN_KEY",
           "securitytrails": "CMSSCAN_SECURITYTRAILS_KEY"}


def redact_keys(text):
    """Remove API key values from text (error messages, debug output)."""
    for key in API_KEYS.values():
        if key:
            text = text.replace(key, "***")
    return text


def pdns_virustotal(ip, timeout):
    """VirusTotal resolutions (free API key, 500 lookups/day)."""
    data = json.loads(_get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions?limit=40",
                           timeout, {"x-apikey": API_KEYS["virustotal"]}))
    return {d.get("attributes", {}).get("host_name", "") for d in data.get("data", [])}


def pdns_shodan(ip, timeout):
    """Shodan host info: hostnames and domains (API key)."""
    data = json.loads(_get(f"https://api.shodan.io/shodan/host/{ip}?key={API_KEYS['shodan']}"
                           "&minify=true", timeout))
    return set(data.get("hostnames", [])) | set(data.get("domains", []))


def pdns_securitytrails(ip, timeout):
    """SecurityTrails reverse A lookup (API key)."""
    req = urllib.request.Request(
        "https://api.securitytrails.com/v1/domains/list",
        data=json.dumps({"filter": {"ipv4": ip}}).encode(),
        headers={"User-Agent": UA, "APIKEY": API_KEYS["securitytrails"],
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read())
    return {d.get("hostname", "") for d in data.get("records", [])}


# (name, function, needs an API key?) - free sources always run, keyed ones only with a key
PDNS_SOURCES = [
    ("otx", pdns_otx, False),
    ("hackertarget", pdns_hackertarget, False),
    ("virustotal", pdns_virustotal, True),
    ("shodan", pdns_shodan, True),
    ("securitytrails", pdns_securitytrails, True),
]


def passive_dns(ip, timeout=12):
    """Ask every available passive DNS source (in parallel) which names resolved to ip."""
    names, log = {}, []
    sources = [(s, fn) for s, fn, needs_key in PDNS_SOURCES if not needs_key or API_KEYS.get(s)]

    def ask(item):
        src, fn = item
        try:
            return src, {n for n in fn(ip.strip("[]"), timeout) if n}, ""
        except Exception as e:  # noqa: BLE001
            return src, None, redact_keys(str(e))[:80]

    with cf.ThreadPoolExecutor(max_workers=max(1, len(sources))) as ex:
        for src, got, err in ex.map(ask, sources):
            if got is None:
                log.append(f"passive DNS {src}: failed ({err})")
            else:
                names[src] = got
                log.append(f"passive DNS {src}: {len(got)} name(s)")
    return names, log


CANDIDATE_NAMES = set()   # --names: hostnames from your own data (vhost configs, customer list)
SEED_NAMES = {}           # ip -> hostnames given as targets (starting points for discovery)


def discover_vhosts(ip, web_ports, a):
    """Find hostnames served on ip. Returns ({name: {sources}}, {name: resolved IPs}, log lines)."""
    found, log = {}, []

    def add(n, src):
        n = n.strip().lower().rstrip(".")
        if n.startswith("*."):                   # wildcard cert: try the bare domain and www.
            add(n[2:], src)
            add("www." + n[2:], src)
            return
        if HOSTNAME_RX.match(n) and not is_ip(n):
            found.setdefault(n, set()).add(src)

    seen_sni = set()
    ip_n = str(ipaddress.ip_address(ip.strip("[]")))
    tls_timeout = max(2.0, a.scan_timeout * 3)
    timing = {}
    t_start = time.monotonic()

    def hosted_here(names_):
        """Names configured on this server (own certs/redirects) or resolving to it.
        Resolved in parallel; only these are worth TLS handshakes and CT lookups."""
        names_ = list(names_)
        with cf.ThreadPoolExecutor(max_workers=50) as ex:
            res = dict(zip(names_, ex.map(resolve, names_)))
        return [n for n in names_ if found[n] & {"cert", "redirect"} or ip_n in res[n]]

    def sni_round():
        """Ask the server for the certificate of every new name via SNI (in parallel,
        only on ports that speak TLS): other vhosts' certificates list further names."""
        t0 = time.monotonic()
        batch = [n for n in hosted_here(n for n in found if n not in seen_sni)][:300]
        seen_sni.update(batch)
        jobs = [(n, p) for n in batch for p in tls_ports]
        if jobs:
            with cf.ThreadPoolExecutor(max_workers=min(30, len(jobs))) as ex:
                for names_ in ex.map(lambda j: cert_names(ip, j[1], j[0], tls_timeout), jobs):
                    for m in names_ or ():
                        add(m, "cert")
        timing["sni"] = timing.get("sni", 0) + time.monotonic() - t0

    # 1) TLS certificate without SNI (default cert) - also tells us which ports speak TLS
    t0 = time.monotonic()
    tls_ports = []
    with cf.ThreadPoolExecutor(max_workers=max(1, len(web_ports))) as ex:
        for p, names_ in zip(web_ports, ex.map(lambda p: cert_names(ip, p, None, tls_timeout), web_ports)):
            if names_ is not None:
                tls_ports.append(p)
                for n in names_:
                    add(n, "cert")
            elif f"{ip}:{p}" in SNI_ONLY or (":" in ip and f"[{ip}]:{p}" in SNI_ONLY):
                tls_ports.append(p)          # TLS, but only with a known hostname
    timing["certs"] = time.monotonic() - t0
    if not found and tls_ports and not any(p for p in tls_ports if f"{ip}:{p}" not in SNI_ONLY):
        log.append("no default certificate (server requires SNI): names must come from "
                   "reverse DNS, passive DNS, CT or --names")
    # 2) where the default site redirects to
    for p in web_ports:
        for h in RESULT_META.get(f"{ip}:{p}", {}).get("hosts", ()):
            if h and not is_ip(h):
                add(h, "redirect")
    # 3) reverse DNS (PTR)
    for n in reverse_dns(ip):
        add(n, "ptr")
    # 4) passive DNS: names that resolved to this IP (the only external way to find
    #    names that appear nowhere on the server itself)
    if a.passive_dns:
        t0 = time.monotonic()
        by_src, plog = passive_dns(ip)
        log += plog
        for src, names_ in by_src.items():
            for n in names_:
                add(n, "pdns")
        timing["pdns"] = time.monotonic() - t0
    # 5) your own list (--names) and hostnames given as targets
    for n in CANDIDATE_NAMES:
        add(n, "list")
    for n in SEED_NAMES.get(ip, ()):
        add(n, "target")
    # 6) certificates of all names found so far
    sni_round()
    # 7) certificate transparency for every domain hosted here (parallel, cached per domain)
    if a.ct:
        t0 = time.monotonic()
        domains = sorted({base_domain(n) for n in hosted_here(found)})[:25]

        def ct(dom):
            try:
                return dom, ct_names(dom, 20), ""
            except Exception as e:  # noqa: BLE001
                return dom, None, str(e)[:80]

        if domains:
            with cf.ThreadPoolExecutor(max_workers=min(5, len(domains))) as ex:   # crt.sh rate-limits
                for dom, names_, err in ex.map(ct, domains):
                    if names_ is None:
                        log.append(f"crt.sh {dom}: failed ({err})")
                    for n in names_ or ():
                        add(n, "ct")
        timing["ct"] = time.monotonic() - t0
    # 8) certificates of the names CT added
    sni_round()
    total = time.monotonic() - t_start
    log.append(f"discovery took {total:.1f}s (" + ", ".join(f"{k} {v:.1f}s" for k, v in timing.items())
               + f"; TLS ports {tls_ports or 'none'})")

    # DNS check ("nslookup") for every name
    with cf.ThreadPoolExecutor(max_workers=20) as ex:
        dns = dict(zip(found, ex.map(resolve, list(found))))

    ip_norm = str(ipaddress.ip_address(ip.strip("[]")))
    keep = {}
    for n, srcs in found.items():
        here = ip_norm in dns[n]
        # names from this server's own certs/redirects are configured here even if DNS
        # points elsewhere (CDN, old cert); names from ct/pdns/ptr/list must resolve here
        if here or srcs & {"cert", "redirect"}:
            keep[n] = srcs
    names = sorted(keep, key=lambda n: (ip_norm not in dns[n], n))[:a.max_vhosts]
    return {n: keep[n] for n in names}, dns, log


def main():
    ap = argparse.ArgumentParser(
        description="cmsscan - PHP/CMS detection with integrated TCP port scan. "
                    "Targets: IPs, IP ranges (CIDR), hostnames, URLs or files.",
        epilog="Example: cmsscan.py 203.0.113.10 203.0.113.11 198.51.100.0/28 example.ch")
    ap.add_argument("targets", nargs="*", help="IP, CIDR range, hostname, URL or file")
    ap.add_argument("-U", "--update-rules", action="store_true",
                    help="download a fresher copy of the embedded fingerprint database (webappanalyzer) "
                         "into ~/.cache/cmsscan; it then takes precedence over the embedded one")
    ap.add_argument("--rules", default=RULES_DIR,
                    help="fingerprint database directory or JSON file (default: ~/.cache/cmsscan/technologies)")
    ap.add_argument("--no-rules", action="store_true", help="use only the ~120 hand-written fingerprints")
    ap.add_argument("-p", "--ports", default="web",
                    help="ports to scan: 'web' (default: 20 common web/panel ports), 'all' (1-65535), "
                         "or a list like 80,443,8000-8100")
    ap.add_argument("-n", "--no-scan", action="store_true",
                    help="skip the port scan, only try 443/80")
    ap.add_argument("-o", "--out", help="optionally also write a CSV file")
    ap.add_argument("-w", "--workers", type=int, default=20, help="parallel HTTP checks (default 20)")
    ap.add_argument("-t", "--timeout", type=float, default=6, help="HTTP timeout in seconds (default 6)")
    ap.add_argument("--scan-workers", type=int, default=0,
                    help="parallel port probes (default: 200 for short lists, up to 2000 for all ports)")
    ap.add_argument("--scan-timeout", type=float, default=0.8,
                    help="TCP connect timeout per port in seconds (default 0.8)")
    ap.add_argument("-a", "--all", action="store_true",
                    help="also list unreachable targets (hidden by default for IP ranges)")
    ap.add_argument("-d", "--debug", action="count", default=0,
                    help="-d: show port scan, requests, response headers, matches and errors (stderr); "
                         "-dd: also full Python tracebacks")
    ap.add_argument("--no-vhosts", dest="vhosts", action="store_false",
                    help="don't discover/scan vhosts (default: on - TLS certificates, redirects, reverse DNS "
                         "and certificate transparency, with a DNS check for every name)")
    ap.add_argument("--no-ct", dest="ct", action="store_false",
                    help="skip the certificate transparency lookup (crt.sh) during vhost discovery")
    ap.add_argument("--no-passive-dns", dest="passive_dns", action="store_false",
                    help="skip passive DNS lookups (default: on - AlienVault OTX and HackerTarget, no "
                         "keys needed; sends the scanned IPs to these services)")
    ap.add_argument("--vt-key", metavar="KEY",
                    help="VirusTotal API key: adds VirusTotal passive DNS "
                         "(prefer env CMSSCAN_VT_KEY; command-line values are visible in ps)")
    ap.add_argument("--shodan-key", metavar="KEY",
                    help="Shodan API key: adds Shodan hostnames/domains (prefer env CMSSCAN_SHODAN_KEY)")
    ap.add_argument("--securitytrails-key", metavar="KEY",
                    help="SecurityTrails API key: adds SecurityTrails reverse-IP lookup "
                         "(prefer env CMSSCAN_SECURITYTRAILS_KEY)")
    ap.add_argument("--names", action="append", default=[], metavar="FILE",
                    help="file with hostnames from your own data (vhost configs, customer domain list); "
                         "names resolving to a scanned IP are checked as vhosts on it. Repeatable.")
    ap.add_argument("--max-vhosts", type=int, default=200, help="max vhosts per IP (default 200)")
    ap.add_argument("-q", "--no-banner", action="store_true", help="don't print the banner")
    a = ap.parse_args()
    if not a.no_banner:
        print_banner()
    if a.update_rules:
        print("Updating fingerprint database...", file=sys.stderr, flush=True)
        update_rules(a.rules if not a.rules.endswith(".json") else RULES_DIR)
    if not a.targets:
        if a.update_rules:
            return
        ap.error("no targets given")
    n_db, source = 0, ""
    if not a.no_rules:
        try:
            n_db, source = load_rules(a.rules)
        except Exception as e:  # noqa: BLE001
            print(f"Warning: could not load fingerprint database: {e}", file=sys.stderr)
    msg = f"Fingerprints: {BUILTIN_APPS} built-in PHP apps"
    if n_db:
        msg += f" + {n_db} from {source}"
    print(msg, file=sys.stderr, flush=True)
    global DEBUG
    DEBUG = a.debug
    if a.debug:
        a.all = True

    cli_keys = {"virustotal": a.vt_key, "shodan": a.shodan_key, "securitytrails": a.securitytrails_key}
    for src, env in KEY_ENV.items():
        key = cli_keys[src] or os.environ.get(env, "")   # command line overrides the environment
        if key.strip():
            API_KEYS[src] = key.strip()
    if any(cli_keys.values()):
        print("Note: API keys on the command line are visible to other local users (ps); "
              "use the CMSSCAN_*_KEY environment variables instead.", file=sys.stderr, flush=True)
    if a.passive_dns:
        used = ["otx", "hackertarget"] + sorted(API_KEYS)
        print(f"Passive DNS: {', '.join(used)}", file=sys.stderr, flush=True)
    for fn in a.names:
        with open(fn, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0]
                for tok in re.split(r"[\s,;]+", line):
                    tok = tok.strip().lower().rstrip(".")
                    if tok and HOSTNAME_RX.match(tok):
                        CANDIDATE_NAMES.add(tok)
    if a.names:
        print(f"Loaded {len(CANDIDATE_NAMES)} candidate hostname(s) from {', '.join(a.names)}",
              file=sys.stderr, flush=True)

    targets = list(dict.fromkeys(t for arg in a.targets for t in expand(arg)))
    ports = parse_ports(a.ports)
    rows, counts = [], {}
    scanned = set()      # endpoints found by the scan (may be non-HTTP services)
    W = 44

    def add_row(row, hidden=False, key=None):
        rows.append(row)
        key = key or ("PHP" if row[3].startswith("PHP") else row[3])
        if row[3] == "ERROR" and row[0] in scanned:
            key = "NOT HTTP"            # open port, but no web server on it
            row[3] = "NOT HTTP"
        counts[key] = counts.get(key, 0) + 1
        if hidden and not a.all:
            return
        if row[3] in ("ERROR", "NOT HTTP") and not a.all and (len(targets) > 1 or row[0] in scanned):
            return
        print(f"{row[0]:<{W}} {row[3]:<16} {row[5][:24]:<24} {row[6][:28]:<28} {row[7]}", flush=True)

    # --- phase 1: quick TCP connect scan on web ports ---------------------
    checks = []          # "host:port" or URL items for the HTTP phase
    to_scan = []         # (target, host, port)
    no_port_rows = []    # targets where no web port was open
    for t in targets:
        addr = t.split("@", 1)[1] if ("@" in t and "://" not in t) else t   # vhost@ip
        host, port = split_hostport(addr)
        if a.no_scan or "://" in t or port is not None:
            checks.append(t)
        else:
            to_scan += [(t, host, p) for p in ports]

    if to_scan:
        n_hosts = len({x[0] for x in to_scan})
        limit = max_sockets()
        workers = a.scan_workers or (2000 if len(ports) > 1000 else 200)
        if workers > limit:
            print(f"Note: limiting scan workers to {limit} (open-file limit, see 'ulimit -n')",
                  file=sys.stderr)
            workers = limit
        print(f"Scanning {n_hosts} host(s) x {len(ports)} port(s) with {workers} parallel probes...",
              file=sys.stderr, flush=True)
        open_ports = scan(to_scan, workers, a.scan_timeout)
        n_open = 0
        for t in dict.fromkeys(x[0] for x in to_scan):
            found = sorted(open_ports.get(t, []))
            n_open += len(found)
            if DEBUG:
                print(f"[SCAN] {t}: open {found or 'none'}", file=sys.stderr, flush=True)
            if found:
                eps = [f"{t}:{p}" for p in found]
                checks += eps
                scanned.update(eps)
            else:
                no_port_rows.append([t, "", "", "ERROR", "", "", "",
                                     f"no open port (scanned {len(ports)} ports)"])
        print(f"Found {n_open} open port(s), checking each for HTTP/PHP...\n",
              file=sys.stderr, flush=True)

    cols = ["target", "final_url", "http_status", "verdict", "php_version",
            "php_apps", "server", "evidence"]
    print(f"{'TARGET':<{W}} {'VERDICT':<16} {'APPS':<24} {'SERVER':<28} EVIDENCE")
    for row in no_port_rows:
        add_row(row)
    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        for row in ex.map(lambda t: check(t, a.timeout), checks):
            add_row(row)

    # --- phase 3: vhost discovery + scan of every vhost on its IP ----------
    if a.vhosts:
        web = {}                                     # ip -> [web ports]
        already_scanned = set()                      # (hostname, ip, port) given as targets
        for r in list(rows):
            t = r[0]
            if "@" in t or "://" in t or r[3] in ("ERROR", "NOT HTTP"):
                continue
            h, p = split_hostport(t)
            if not is_ip(h):                         # hostname target: discover on its IP
                ips = sorted(resolve(h))
                if not ips:
                    continue
                already_scanned.add((h.lower(), ips[0], p))
                SEED_NAMES.setdefault(ips[0], set()).add(h.lower())   # start discovery from it
                if r[1].startswith("https://") and p is not None:
                    SNI_ONLY.add(f"{ips[0]}:{p}")                     # port speaks TLS (with SNI)
                h = ips[0]
            if p is None:                            # -n mode: port from the final URL
                p = 443 if r[1].startswith("https") else 80
            web.setdefault(h, []).append(p)
        if not web:
            print("\nNo web server found on any IP, no vhosts to discover.", file=sys.stderr)
        else:
            print(f"\nDiscovering vhosts on {len(web)} IP(s)...", file=sys.stderr, flush=True)
            vchecks, vinfo = [], {}
            with cf.ThreadPoolExecutor(max_workers=10) as ex:
                futs = {ex.submit(discover_vhosts, ip, sorted(set(ps)), a): ip for ip, ps in web.items()}
                for f in cf.as_completed(futs):
                    ip = futs[f]
                    names, dns, dlog = f.result()
                    ip_norm = str(ipaddress.ip_address(ip))
                    n_here = sum(ip_norm in dns[n] for n in names)
                    by_src = {}
                    for srcs in names.values():
                        for s in srcs:
                            by_src[s] = by_src.get(s, 0) + 1
                    src_txt = ", ".join(f"{k} {v}" for k, v in sorted(by_src.items()))
                    print(f"[VHOST] {ip}: {len(names)} name(s) ({src_txt or 'none'}), "
                          f"{n_here} resolve to this IP", file=sys.stderr, flush=True)
                    for line in dlog:
                        print(f"[VHOST] {ip}: {line}", file=sys.stderr, flush=True)
                    for n, srcs in names.items():
                        if DEBUG:
                            print(f"[VHOST]   {n:<40} src={','.join(sorted(srcs)):<16} "
                                  f"dns={','.join(sorted(dns[n])) or 'none'}", file=sys.stderr)
                        if ip_norm in dns[n]:
                            dns_txt = "dns ok"
                        elif dns[n]:
                            dns_txt = "dns -> " + ",".join(sorted(dns[n])[:2])
                        else:
                            dns_txt = "no dns"
                        for p in sorted(set(web[ip])):
                            if (n, ip, p) in already_scanned:     # was a target itself
                                continue
                            vt = f"{n}@{ip}:{p}" if ":" not in ip else f"{n}@[{ip}]:{p}"
                            vchecks.append(vt)
                            vinfo[vt] = (ip, p, f"[{','.join(sorted(srcs))}; {dns_txt}]")

            if vchecks:
                print(f"Checking {len(vchecks)} vhost endpoint(s)...\n", file=sys.stderr, flush=True)
                W = max(W, max(len(v) for v in vchecks) + 1)     # long names: keep columns aligned
                print(f"\n{'VHOST@IP:PORT':<{W}} {'VERDICT':<16} {'APPS':<24} {'SERVER':<28} EVIDENCE")
                with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
                    for row in ex.map(lambda t: check(t, a.timeout), vchecks):
                        ip, p, tag = vinfo[row[0]]
                        default = RESULT_META.get(f"{ip}:{p}") or RESULT_META.get(ip)
                        mine = RESULT_META.get(row[0])
                        same = bool(default and mine and default["hash"] == mine["hash"])
                        vhost = row[0].split("@", 1)[0]
                        # HTTP vhost that only redirects to its own HTTPS version: the HTTPS
                        # row already covers it
                        fu = urlparse(row[1]) if row[1] else None
                        to_https = bool(fu and fu.scheme == "https"
                                        and (fu.hostname or "").lower() == vhost
                                        and (fu.port or 443) != p
                                        and f"{vhost}@{ip}:{fu.port or 443}" in vinfo)
                        row[7] = (f"{tag} " + ("same as default site; " if same else "")
                                  + ("redirects to https; " if to_https else "") + row[7])
                        if row[3] == "ERROR":
                            add_row(row, hidden=True)
                        elif same:
                            add_row(row, hidden=True, key="SAME AS DEFAULT")
                        else:
                            add_row(row, hidden=to_https, key="HTTP->HTTPS" if to_https else None)

    if a.out:
        with open(a.out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(cols)
            w.writerows(rows)

    summary = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
    print(f"\n{len(targets)} target(s), {len(rows)} result(s) ({summary})" + (f" -> {a.out}" if a.out else ""))


if __name__ == "__main__":
    main()
