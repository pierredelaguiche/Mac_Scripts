#!/usr/bin/env python3
"""
bookmark_organizer.py — check, dedupe, and adaptively re-organize
Netscape-format bookmark exports (Firefox/Chrome/Safari "Export bookmarks").

USAGE
  python3 bookmark_organizer.py bookmarks.html                 # full run
  python3 bookmark_organizer.py old.html new.html              # merge exports
  python3 bookmark_organizer.py bookmarks.html --skip-check    # organize only
  python3 bookmark_organizer.py bookmarks.html -o out.html

WHAT IT DOES
  1. Parses every bookmark from one or more exports. The old folder tree is
     not preserved, but its folder names are kept as a categorization signal
     (they encode intent). Markers this script added on a previous run
     ("[?] ", "[HTTP 404] ", ...) are stripped, so re-runs are idempotent.
  2. The browser toolbar (PERSONAL_TOOLBAR_FOLDER) is preserved VERBATIM:
     original order, original (possibly empty) titles, never re-categorized,
     never moved to the Graveyard. Problems are reported, not acted on.
  3. Dedupes: URLs are normalized (scheme collapsed, utm_* junk stripped,
     query params sorted, fragments dropped, host lowercased); duplicates
     collapse to one entry. Priority: toolbar copy > copy from the
     later-listed input file > first seen. Earliest ADD_DATE and any
     available icon are merged in.
  4. Checks http(s) links concurrently (stdlib only):
       ALIVE      2xx/3xx end state
       DEAD       404/410 **confirmed by GET** (HEAD lies: bot-walls answer
                  HEAD with 404/403), DNS failure, connection refused
       AMBIGUOUS  401/403/405/429/5xx, timeouts, SSL errors — kept in place,
                  marked [?] (a missing site should not be confused with a
                  rude one)
     Results are cached (~/.bookmark_organizer/cache.json). ALIVE/DEAD age
     out after 30 days, AMBIGUOUS after 1 day. Non-http(s) links
     (moz-extension:, about:, file:, ...) are never checked and never
     silently dropped.
  5. Re-clusters into a hierarchy (category paths like
     "Entertainment/Streaming", max 5 levels):
       - rule engine, signal strength order: domain > original folder
         path > title keywords; first matching rule wins within each pass
       - uncategorized domains with >= MIN_CATEGORY entries get their own
         folder under Misc; the long tail goes to Misc
       - leaves smaller than MIN_CATEGORY merge into their parent (or Misc
         at top level); domains with >= DOMAIN_SUBFOLDER links inside one
         category get a subfolder
       - dead links land in a "Graveyard" folder, error noted in the title
  6. Writes a new importable bookmarks HTML plus a Markdown report
     (including unmatched domains, so the rules can be tuned run over run).

SAFETY MODEL
  Read-only on the inputs. All output goes to new files. Import the result
  into your browser only after reviewing the report; your original exports
  and the browser's own bookmarks are untouched until you choose to replace
  them.
"""

import argparse
import concurrent.futures
import html
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from html.parser import HTMLParser

STATE_DIR = os.path.expanduser("~/.bookmark_organizer")
CACHE_FILE = os.path.join(STATE_DIR, "cache.json")
CACHE_VERSION = 2          # bump when check semantics change: old verdicts stale
TTL_SETTLED = 30 * 86400   # ALIVE / DEAD
TTL_AMBIGUOUS = 86400      # transient failures deserve a fresh look
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0 Safari/537.36")
MIN_CATEGORY = 3      # leaves smaller than this merge upward
DOMAIN_SUBFOLDER = 5  # a single domain with >= this many links gets a subfolder
MAX_DEPTH = 5         # hard cap on folder nesting

# ---------------------------------------------------------------------------
# Category rules: (category path, domain regex, folder-path regex, title regex).
# "/" in the category nests folders. First match wins within each signal pass;
# order = specificity. Tune freely — it's just data.
# ---------------------------------------------------------------------------
RULES = [
    # --- AI -----------------------------------------------------------------
    ("AI/Chat & Code",
     r"(chat\.openai|openai\.com|claude\.ai|phind\.com|blackbox\.ai|useblackbox|perplexity\.ai|poe\.com)",
     None, None),
    ("AI/Image & Media",
     r"(upscale\.media|photoeditor\.ai|watermarkremover|genmo\.ai|midjourney|elevenlabs|replicate\.com)",
     None, None),
    ("AI/Writing & Detection",
     r"(quillbot|copy\.ai|copyscape|twaingpt|grubby\.ai|stealthgpt|turbolearn|ihatereading|writer\.com)",
     None, None),
    ("AI",
     r"(huggingface|gpt3demo|donotpay|gamma\.app|arena\.ai|synthesia\.io)",
     r"(AI Tools|Tools/AI|^AI$)",
     r"\b(gpt|llm|chatbot|humaniz\w*|ai tool)\b"),
    # --- Dev & Tech ----------------------------------------------------------
    ("Dev & Tech/Learning",
     r"(edx\.org|javascript30|learn-anything|pll\.harvard\.edu|coursera|codecademy|vinhgiang)",
     r"(courses|coding)", None),
    ("Dev & Tech/Security & Hacking",
     r"(owasp|hackerone|zenk-security|theswissbay|objective-see|hackthebox|tryhackme)",
     r"(hacking|Security & Hacking)", None),
    ("Dev & Tech/Firefox Tweaks",
     r"(mrotherguy\.github\.io)", r"(Firefox Tweaks)", None),
    ("Dev & Tech",
     r"(github\.com|gitlab|stackoverflow|stackexchange\.com|developer\.mozilla|docs\.python|pypi\.org|npmjs|"
     r"readthedocs|kaggle|screenshotmachine|opensourcealternative)",
     r"(Dev & T)",
     r"\b(python|javascript|api|repo|framework|compiler)\b"),
    # --- Tools ---------------------------------------------------------------
    ("Tools/Files & Converters",
     r"(cloudconvert|convertio|freeconvert|tinywow|convertcase|ezgif|heictojpg|heic\.online|iloveimg|"
     r"ilovepdf|pdf24|imgonline|ocr2edit|corruptmyfile|jumpshare|createzip)",
     r"(Files & Converters|^Tools/Files)",
     r"\bconvert(er)?\b"),
    ("Tools/Design & Diagrams",
     r"(photopea|vectr\.com|smartdraw|slidesgo|padlet|figma\.com|canva\.com|excalidraw)",
     None, None),
    ("Tools/Privacy & Adblock",
     r"(10minutemail|temp-mail|virustotal|tosdr\.org|tineye|12ft\.io)",
     r"(Privacy & Adblock)",
     r"\b(temp(orary)? mail|adblock|paywall)\b"),
    ("Tools/macOS",
     r"(mackeeper|macpaw|hexnode|macrumors)",
     r"(Computer Maintenance|macOS)",
     r"\bmacos\b"),
    ("Tools",
     r"(turboscribe|qifi\.org)", None, None),
    # --- Reference -----------------------------------------------------------
    ("Reference/Libraries & Archives",
     r"(gutenberg|libgen|archive\.org|archive\.is|jstor|doabooks|open\.umn\.edu|swisscovery|dblp\.org|"
     r"arxiv\.org|yes-pdf|ddosecrets|annas-archive|z-lib)",
     r"(Libraries & Archives|^Libraries$)", None),
    ("Reference/Math & Science",
     r"(desmos|symbolab|wolframalpha|geogebra|chemequations|chemix\.org|chemicalaid|periodic-table|"
     r"circuitverse|ophysics|hyperphysics|falstad)",
     r"(Math & Science)", None),
    ("Reference/Languages",
     r"(learngerman|dw\.com|duolingo|deepl\.com|simple\.wikipedia|leo\.org|linguee)",
     r"(Languages)",
     r"\b(german|vocabulary|language course)\b"),
    ("Reference/Reading Tools",
     r"(speechify|spreeder)", r"(Reading Tools)", None),
    ("Reference",
     r"(wikipedia\.org|wiktionary|britannica\.com|merriam-webster|dictionary\.com)",
     None, None),
    # --- Writing -------------------------------------------------------------
    ("Writing/Grammar & Style",
     r"(languagetool|hemingwayapp|losethevery|grammarly)",
     r"(Grammar & Style)", None),
    ("Writing/LaTeX",
     r"(overleaf|tablesgenerator|tableconvert|mathcha|tikz\.net|ctan\.org|bibtex\.com|foobar\.to)",
     r"(LaTeX|Formatting)",
     r"\b(latex|bibtex|biblatex|typeset)\b"),
    ("Writing/Citations & Format",
     r"(citationmachine|apastyle|owl\.purdue|mybib|zbib|zotero|scribbr)",
     r"(Citations & Format)",
     r"\b(citation|bibliograph\w*|apa style|mla)\b"),
    ("Writing",
     None, r"(For essays|Writing & LaTeX|^Writing$)", None),
    # --- Entertainment -------------------------------------------------------
    ("Entertainment/Streaming",
     r"(fmhy\.net|123movies|myflixer|theflixer|cinemadeck|hydrahd|popcornmovies|wcofun|nepu\.to|twoseven|"
     r"netflix-codes|myretrotvs|petittube|incognitube|unlistedvideos|youtube\.com|youtu\.be|vimeo|twitch\.tv)",
     r"(Films|Video & Streaming|^Streaming$)", None),
    ("Entertainment/Torrents & Downloads",
     r"(1337x|fitgirl-repacks|crackshash|kickasstorrents|limetorrents|torrentz2|rarbg|auctor\.tv|"
     r"thepiratebay|yts\.mx|nyaa\.si)",
     r"(Torrents)",
     r"\btorrent\b"),
    ("Entertainment/Manga & Comics",
     r"(everythingmoe|frieren\.online|mangaplus|shueisha|lackadaisycats|mangadex)",
     r"(Manga & Comics)",
     r"\bmanga\b"),
    ("Entertainment/Music & Audio",
     r"(everynoise|music-map|musicmap\.info|discogs|asoftmurmur|noisli|myinstants|all-guitar-chords|"
     r"quinnfetrowsguitarmachines|strudel\.cc|bandcamp|spotify)",
     r"(^Music$|Music & Audio)", None),
    ("Entertainment/Games",
     r"(dos\.zone|firstpersontetris|slowroads\.io|dotsandboxes|redactle|itch\.io|oldgamesdownload|"
     r"windows93|chronophoto|kikibouba|neal\.fun|orteil)",
     r"(^Games$)", None),
    ("Entertainment/Useless Web & Fun",
     r"(theuselessweb|boredbutton|totallyuselesswebsites|damn\.dog|pointerpointer|justtypestuff|"
     r"just-shower-thoughts|told-you\.so|tylervigen|apolloinrealtime|ascii-art-generator|hackertyper|"
     r"docutyper|fakeupdate\.net|letmegooglethat|starwarsintrocreator|shitexpress|thispersondoesnotexist|"
     r"thiscatdoesnotexist|playpartygame|i\.imgur\.com)",
     r"(Fun\(ny\)|Games & Fun|Useless Web|Bathroom|This Does Not Exist)", None),
    # --- Business ------------------------------------------------------------
    ("Business/Dropshipping & E-commerce",
     r"(autods|zendrop|shopify|cjdropshipping|alidropship|pipiads|automizely|famoid|aliexpress|supplyleader)",
     r"(Dropshipping)",
     r"\bdropship\w*\b"),
    ("Business/Company Setup (CH)",
     r"(easygov\.swiss|kmu\.admin\.ch)",
     None,
     r"\bset up a company\b"),
    ("Business/Freelance & Gigs",
     r"(gotranscript|proofreading\.org|userlytics|sidehustlestack|diversifying\.io|quester\.io|upwork|fiverr)",
     r"(Freelance)", None),
    ("Business/Product & Publishing",
     r"(ghost\.org|webflow|design2market|creativepool)",
     r"(Product & Publishing)", None),
    ("Business",
     None, r"(^Job$|Work & Business|^Work$|^Business$)", None),
    # --- Life Admin (CH) -----------------------------------------------------
    ("Life Admin (CH)/Driving",
     r"(itheorie|firstmed\.ch|samaritains|secouristes|fahrschule|asa\.ch|vks\.ch)",
     r"(Driving)",
     r"\b(driving licen|sauveteur|permis de conduire)\w*"),
    ("Life Admin (CH)/Money & Housing",
     r"(wisebread|comparis\.ch|homegate|moneyland|ebanking|ubs\.com)",
     r"(Money & Housing)", None),
    ("Life Admin (CH)/Travel",
     r"(skiplagged|sbb\.ch|betterbahn|bahn\.de|rome2rio|omio|skyscanner|kayak\.com|airbnb|booking\.com|"
     r"powderhounds|chamonix|chamkeys|bergfex|skiresort\.info|trainline|hostelworld|tripadvisor)",
     r"(CHAMONIX|Chamonix|^Travel$)",
     r"\b(flight|hostel|itinerary|ski (rental|resort)|piste)\b"),
    ("Life Admin (CH)/Shopping",
     r"(alexotos|stockx|grailed|vinted|ricardo\.ch|galaxus|digitec|chrono24|displate|vestiaire|"
     r"hellomerch|notonthehighstreet|keebmonkey|recordsale)",
     r"(Wants|shoes|Vinyls|^Shopping$)", None),
    ("Life Admin (CH)",
     r"(^ch\.ch$|^www\.ch\.ch$|alternativweb)",
     None, None),
    # --- Wellbeing -----------------------------------------------------------
    ("Wellbeing",
     r"(iamawesome\.com|onedayyoullfindyourself|depression-chat-rooms|nutritionix)",
     r"(Mental health|Wellbeing)", None),
    # --- generic buckets -----------------------------------------------------
    ("News",
     r"(bbc\.(com|co\.uk)|nytimes|theguardian|reuters|lemonde|nzz\.ch|srf\.ch|20min\.ch|economist\.com)",
     None, None),
    ("Social & Forums",
     r"(reddit\.com|twitter\.com|x\.com|instagram|telegram|discord|facebook)",
     None, None),
    ("Google",
     r"^(docs|drive|mail|photos|keep|calendar|meet)\.google\.com$",
     None, None),
    # --- legacy: keeps old school-era exports from polluting Misc ------------
    ("School (legacy)",
     r"(managebac|clastify|quizlet|revisionvillage|savemyexams|ibdocs\.re|znotes|ib-academy|thinkib|"
     r"gradesaver|sparknotes|litcharts|supersummary|bookrags|kognity|physicsandmathstutor|exam-mate|"
     r"gradegorilla|ibrevision|ibdone1|christosnikolaidis|andymasley|masseychem|ibalmaths|tok2022)",
     r"(School|Revision|\bIA\b|TOK|\bCAS\b|EE tabs|Exams|English Essay)",
     r"\b(ib |past paper|revision note|flashcard|syllabus)\b"),
    ("Universities (legacy)",
     r"(rwth-aachen|ethz\.ch|tudelft|tue\.nl|tum\.de|uni-assist|swissuniversities|humboldt-institut|"
     r"studyportals|topuniversities|daad\.de|\.edu$)",
     r"(Unis|University research|Universities & Admissions)",
     r"\b(admission|bachelor|matriculation|entrance exam)\w*"),
]

# Top-level display order; unknown categories follow alphabetically,
# Misc second-to-last, Graveyard last.
CATEGORY_ORDER = ["AI", "Dev & Tech", "Tools", "Reference", "Writing",
                  "Entertainment", "Business", "Life Admin (CH)", "Wellbeing",
                  "News", "Social & Forums", "Google",
                  "School (legacy)", "Universities (legacy)"]

# Markers this script may have written into titles on a previous run.
MARKER_RE = re.compile(
    r"^(?:\[(?:\?|HTTP \d+|DNS failure|connection refused|timeout|unreachable"
    r"|SSL:[^\]]*|\w+Error[^\]]*)\]\s*)+")

TRACKING_PARAMS = re.compile(
    r"^(utm_\w+|fbclid|gclid|mc_cid|mc_eid|ref_src|igshid)$", re.I)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
class Bookmark:
    __slots__ = ("url", "title", "add_date", "icon", "folder", "in_toolbar",
                 "source", "index", "norm", "status", "detail", "category")

    def __init__(self, url, title, add_date, icon, folder, in_toolbar, source):
        self.url = url
        self.title = title            # may be "" (icon-only toolbar entries)
        self.add_date = add_date
        self.icon = icon
        self.folder = folder          # original folder path (signal + report)
        self.in_toolbar = in_toolbar
        self.source = source          # input file index; later files win ties
        self.index = 0                # global parse order
        self.norm = normalize_url(url)
        self.status = "UNCHECKED"     # ALIVE / DEAD / AMBIGUOUS / SKIPPED
        self.detail = ""
        self.category = None          # "/"-separated path after clustering

    @property
    def checkable(self):
        return self.url.startswith(("http://", "https://"))


class NetscapeParser(HTMLParser):
    """Parser for the Netscape bookmarks format (DL/DT/H3/A soup).

    Folder names are pushed when their <DL> OPENS (not when the <H3> closes),
    and popped on </DL> — so stray or missing lists cannot shift the whole
    tree. The toolbar folder is detected via PERSONAL_TOOLBAR_FOLDER.
    """

    def __init__(self, source=0):
        super().__init__(convert_charrefs=True)
        self.source = source
        self.stack = []              # (folder name, is_toolbar) per open <DL>
        self.bookmarks = []
        self.toolbar_name = None
        self._pending_h3 = None      # folder awaiting its <DL>
        self._cur = None             # (tag, attrs) of <a>/<h3> being read
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag in ("a", "h3"):
            self._cur = (tag, dict(attrs))
            self._text = []
        elif tag == "dl":
            self.stack.append(self._pending_h3 or ("", False))
            self._pending_h3 = None

    def handle_endtag(self, tag):
        if tag in ("a", "h3") and self._cur:
            ctag, attrs = self._cur
            text = "".join(self._text).strip()  # convert_charrefs already unescaped
            if ctag == "h3":
                is_toolbar = "personal_toolbar_folder" in attrs
                self._pending_h3 = (text, is_toolbar)
                if is_toolbar:
                    self.toolbar_name = text
            elif attrs.get("href"):
                self.bookmarks.append(Bookmark(
                    url=attrs["href"],
                    title=MARKER_RE.sub("", text),
                    add_date=attrs.get("add_date", ""),
                    icon=attrs.get("icon", ""),
                    folder="/".join(n for n, _ in self.stack if n),
                    in_toolbar=any(t for _, t in self.stack),
                    source=self.source,
                ))
            self._cur = None
        elif tag == "dl" and self.stack:
            self.stack.pop()

    def handle_data(self, data):
        if self._cur:
            self._text.append(data)


def normalize_url(url):
    """Canonical KEY for dedupe/cache — not for display. Collapses scheme,
    lowercases host, drops www./fragment/tracking params, sorts the query."""
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    if p.scheme not in ("http", "https"):
        return url
    host = p.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    query = "&".join(sorted(
        kv for kv in p.query.split("&")
        if kv and not TRACKING_PARAMS.match(kv.split("=", 1)[0])))
    path = p.path.rstrip("/") or "/"
    return urllib.parse.urlunsplit(("https", host, path, query, ""))


def domain_of(url):
    try:
        host = urllib.parse.urlsplit(url).netloc.lower()
        return host[4:] if host.startswith("www.") else host
    except ValueError:
        return ""


# ---------------------------------------------------------------------------
# Liveness checking
# ---------------------------------------------------------------------------
DEAD_CODES = {404, 410}
CTX = ssl.create_default_context()


def check_url(url, timeout):
    """Return (status, detail).

    HEAD first for cheapness — but a HEAD error is NEVER final: many servers
    and bot-walls answer HEAD with 403/404/405 while GET works (this is how
    live sites end up in graveyards). Only the GET verdict can declare DEAD.
    Network-level failures (DNS, refused) are final immediately.
    """
    verdict = ("AMBIGUOUS", "unreachable")
    for method in ("HEAD", "GET"):
        headers = {"User-Agent": UA, "Accept": "*/*", "Accept-Language": "en"}
        if method == "GET":
            headers["Range"] = "bytes=0-4095"   # cap the download
        req = urllib.request.Request(url, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=CTX) as resp:
                final_host = domain_of(resp.geturl())
                moved = ""
                if final_host and final_host != domain_of(url):
                    moved = f"redirects to {final_host}"
                return "ALIVE", moved
        except urllib.error.HTTPError as e:
            if e.code in DEAD_CODES:
                verdict = ("DEAD", f"HTTP {e.code}")
            else:
                verdict = ("AMBIGUOUS", f"HTTP {e.code}")
            if method == "GET":
                return verdict
            # HEAD errored: fall through and let GET decide.
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            if isinstance(reason, socket.gaierror):
                return "DEAD", "DNS failure"
            if isinstance(reason, ConnectionRefusedError):
                return "DEAD", "connection refused"
            if isinstance(reason, (socket.timeout, TimeoutError)):
                return "AMBIGUOUS", "timeout"
            if isinstance(reason, ssl.SSLError):
                return "AMBIGUOUS", f"SSL: {getattr(reason, 'reason', reason)}"
            return "AMBIGUOUS", str(reason)[:80]
        except (socket.timeout, TimeoutError):
            return "AMBIGUOUS", "timeout"
        except Exception as e:  # noqa: BLE001 — classify, never crash the run
            return "AMBIGUOUS", f"{type(e).__name__}: {e}"[:80]
    return verdict


def load_cache():
    try:
        with open(CACHE_FILE) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    # Old schema or older semantics: discard rather than trust stale verdicts.
    if data.get("v") != CACHE_VERSION:
        return {}
    return data.get("entries", {})


def save_cache(entries):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump({"v": CACHE_VERSION, "entries": entries}, f)


def check_all(bookmarks, workers, timeout, use_cache):
    cache = load_cache() if use_cache else {}
    now = time.time()
    todo = []
    for b in bookmarks:
        if not b.checkable:
            b.status, b.detail = "SKIPPED", "not http(s)"
            continue
        hit = cache.get(b.norm)
        ttl = TTL_AMBIGUOUS if hit and hit["s"] == "AMBIGUOUS" else TTL_SETTLED
        if hit and now - hit["t"] < ttl:
            b.status, b.detail = hit["s"], (hit.get("d", "") + " (cached)").strip()
        else:
            todo.append(b)

    done = 0
    if todo:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(check_url, b.url, timeout): b for b in todo}
            for fut in concurrent.futures.as_completed(futs):
                b = futs[fut]
                b.status, b.detail = fut.result()
                cache[b.norm] = {"s": b.status, "d": b.detail, "t": now}
                done += 1
                if done % 25 == 0 or done == len(todo):
                    print(f"  checked {done}/{len(todo)}", flush=True)
    if use_cache:
        save_cache(cache)
    return len(todo)


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------
COMPILED = [(cat,
             re.compile(dom, re.I) if dom else None,
             re.compile(fold, re.I) if fold else None,
             re.compile(kw, re.I) if kw else None)
            for cat, dom, fold, kw in RULES]


def categorize(b):
    # Signal strength order: domain > original folder path > title keywords.
    dom = domain_of(b.url)
    for cat, dom_re, _, _ in COMPILED:
        if dom_re and dom and dom_re.search(dom):
            return cat
    for cat, _, fold_re, _ in COMPILED:
        if fold_re and fold_re.search(b.folder):
            return cat
    for cat, _, _, kw_re in COMPILED:
        if kw_re and kw_re.search(b.title):
            return cat
    return None


def cluster(bookmarks):
    """Assign every live/ambiguous non-toolbar bookmark a category path."""
    live = [b for b in bookmarks
            if b.status != "DEAD" and not b.in_toolbar]

    for b in live:
        b.category = categorize(b)

    # Adaptive fallback: uncategorized domains with enough entries become
    # their own folder under Misc; the long tail goes straight to Misc.
    uncat = [b for b in live if b.category is None]
    by_dom = defaultdict(list)
    for b in uncat:
        by_dom[domain_of(b.url) or "other"].append(b)
    for dom, items in by_dom.items():
        cat = f"Misc/{dom}" if len(items) >= MIN_CATEGORY else "Misc"
        for b in items:
            b.category = cat

    # Merge undersized leaves upward: into the parent path if nested,
    # into Misc at top level. Repeat until stable (bounded by depth).
    for _ in range(MAX_DEPTH):
        sizes = Counter(b.category for b in live)
        changed = False
        for b in live:
            if sizes[b.category] >= MIN_CATEGORY or b.category == "Misc":
                continue
            parent = b.category.rsplit("/", 1)[0] if "/" in b.category else "Misc"
            b.category = parent
            changed = True
        if not changed:
            break

    # Domain subfolders inside big categories (never self-nesting, capped depth).
    by_cat = defaultdict(list)
    for b in live:
        by_cat[b.category].append(b)
    for cat, items in by_cat.items():
        if len(cat.split("/")) >= MAX_DEPTH:
            continue
        dom_counts = Counter(domain_of(b.url) for b in items)
        leaf = cat.rsplit("/", 1)[-1]
        for b in items:
            d = domain_of(b.url)
            if d and dom_counts[d] >= DOMAIN_SUBFOLDER and d != leaf:
                b.category = f"{cat}/{d}"


# ---------------------------------------------------------------------------
# Dedupe
# ---------------------------------------------------------------------------
def _epoch(s):
    try:
        return int(s)
    except (TypeError, ValueError):
        return 0


def dedupe(bookmarks):
    """Collapse same normalized URL.

    Winner priority: toolbar copy > copy from the later input file > first
    seen. Earliest ADD_DATE and any icon are merged into the winner.
    """
    groups = defaultdict(list)
    for i, b in enumerate(bookmarks):
        b.index = i
        groups[b.norm].append(b)

    kept, dropped = [], []
    for group in groups.values():
        group.sort(key=lambda b: (-int(b.in_toolbar), -b.source, b.index))
        win = group[0]
        for lose in group[1:]:
            d_win, d_lose = _epoch(win.add_date), _epoch(lose.add_date)
            if d_lose and (not d_win or d_lose < d_win):
                win.add_date = lose.add_date
            if lose.icon and not win.icon:
                win.icon = lose.icon
            dropped.append(lose)
        kept.append(win)
    kept.sort(key=lambda b: b.index)
    return kept, dropped


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def esc(s):
    return html.escape(s, quote=True)


def _entry(b, indent, checked, mark_status=False):
    attrs = f' HREF="{esc(b.url)}"'
    if b.add_date:
        attrs += f' ADD_DATE="{esc(b.add_date)}"'
    if b.icon:
        attrs += f' ICON="{esc(b.icon)}"'
    title = b.title
    if not b.in_toolbar:            # toolbar titles stay verbatim (even empty)
        title = title or b.url
        if mark_status:
            title = f"[{b.detail or b.status}] {title}"
        elif b.status == "AMBIGUOUS" and checked:
            title = f"[?] {title}"
    return f'{" " * indent}<DT><A{attrs}>{esc(title)}</A>\n'


def _top_key(name):
    try:
        return (0, CATEGORY_ORDER.index(name), "")
    except ValueError:
        return (2, 0, "") if name == "Misc" else (1, 0, name.lower())


def write_bookmarks_html(path, bookmarks, toolbar_name, checked):
    """Netscape format: toolbar verbatim first, category tree, Graveyard last."""
    toolbar = [b for b in bookmarks if b.in_toolbar]
    dead = [b for b in bookmarks if b.status == "DEAD" and not b.in_toolbar]
    live = [b for b in bookmarks if b.status != "DEAD" and not b.in_toolbar]

    def node():
        return {"links": [], "subs": {}}

    root = {}
    for b in live:
        parts = b.category.split("/")
        level = root.setdefault(parts[0], node())
        for part in parts[1:]:
            level = level["subs"].setdefault(part, node())
        level["links"].append(b)

    def write_node(f, n, indent):
        for b in sorted(n["links"], key=lambda x: (x.title or x.url).lower()):
            f.write(_entry(b, indent + 4, checked))
        for sub in sorted(n["subs"]):
            f.write(f'{" " * (indent + 4)}<DT><H3>{esc(sub)}</H3>\n'
                    f'{" " * (indent + 4)}<DL><p>\n')
            write_node(f, n["subs"][sub], indent + 4)
            f.write(f'{" " * (indent + 4)}</DL><p>\n')

    with open(path, "w", encoding="utf-8") as f:
        f.write('<!DOCTYPE NETSCAPE-Bookmark-file-1>\n'
                '<!-- Generated by bookmark_organizer.py -->\n'
                '<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">\n'
                '<TITLE>Bookmarks</TITLE>\n<H1>Bookmarks</H1>\n<DL><p>\n')
        if toolbar:
            f.write(f'    <DT><H3 PERSONAL_TOOLBAR_FOLDER="true">'
                    f'{esc(toolbar_name or "Bookmarks Toolbar")}</H3>\n    <DL><p>\n')
            for b in toolbar:                       # original order, untouched
                f.write(_entry(b, 8, checked))
            f.write('    </DL><p>\n')
        for cat in sorted(root, key=_top_key):
            f.write(f'    <DT><H3>{esc(cat)}</H3>\n    <DL><p>\n')
            write_node(f, root[cat], 4)
            f.write('    </DL><p>\n')
        if dead:
            f.write('    <DT><H3>Graveyard</H3>\n    <DL><p>\n')
            for b in sorted(dead, key=lambda x: (x.title or x.url).lower()):
                f.write(_entry(b, 8, checked, mark_status=True))
            f.write('    </DL><p>\n')
        f.write('</DL><p>\n')


def write_report(path, bookmarks, dropped, checked):
    toolbar = [b for b in bookmarks if b.in_toolbar]
    body = [b for b in bookmarks if not b.in_toolbar]
    live = [b for b in body if b.status == "ALIVE"]
    dead = [b for b in body if b.status == "DEAD"]
    ambig = [b for b in body if b.status == "AMBIGUOUS"]
    special = [b for b in body if not b.checkable]
    moved = [b for b in live if b.detail.startswith("redirects")]
    toolbar_issues = [b for b in toolbar if b.status in ("DEAD", "AMBIGUOUS")]

    cat_sizes = Counter(b.category for b in body if b.status != "DEAD")
    misc_domains = Counter(domain_of(b.url) for b in body
                           if b.status != "DEAD"
                           and (b.category or "").split("/")[0] == "Misc")

    with open(path, "w", encoding="utf-8") as f:
        w = f.write
        w(f"# Bookmark organizer report — {time.strftime('%Y-%m-%d %H:%M')}\n\n")
        w(f"Bookmarks parsed: {len(bookmarks) + len(dropped)}  \n")
        w(f"Duplicates collapsed: {len(dropped)}  \n")
        w(f"Toolbar (preserved verbatim): {len(toolbar)}  \n")
        if not checked:
            w("Link checking: SKIPPED (--skip-check)  \n")
        else:
            w(f"Alive: {len(live)} — Dead (Graveyard): {len(dead)} — "
              f"Ambiguous (kept, marked [?]): {len(ambig)}  \n")
        w("\n## Categories\n\n")
        for cat in sorted(cat_sizes, key=lambda c: -cat_sizes[c]):
            w(f"- {cat}: {cat_sizes[cat]}\n")
        if toolbar_issues:
            w("\n## Toolbar links with problems (left in place — fix by hand)\n\n")
            for b in toolbar_issues:
                w(f"- [{b.detail or b.status}] {b.title or b.url} — {b.url}\n")
        if dead:
            w("\n## Graveyard (dead links)\n\n")
            for b in sorted(dead, key=lambda x: (x.title or x.url).lower()):
                w(f"- {b.title or b.url} — {b.url} — {b.detail} "
                  f"(was in: {b.folder or 'root'})\n")
        if ambig:
            w("\n## Ambiguous (couldn't verify — bot-walls, timeouts)\n\n")
            for b in sorted(ambig, key=lambda x: x.detail):
                w(f"- [{b.detail}] {b.title or b.url} — {b.url}\n")
        if moved:
            w("\n## Domain changed (redirects — consider updating)\n\n")
            for b in moved:
                w(f"- {b.title or b.url} — {b.url} ({b.detail})\n")
        if special:
            w("\n## Non-http(s) links (kept, never checked)\n\n")
            for b in special:
                w(f"- {b.title or b.url} — {b.url}\n")
        top_misc = [(d, n) for d, n in misc_domains.most_common(15) if n >= 2]
        if top_misc:
            w("\n## Unmatched domains in Misc (rule-tuning candidates)\n\n")
            for d, n in top_misc:
                w(f"- {d}: {n}\n")
        if dropped:
            w("\n## Collapsed duplicates\n\n")
            for b in dropped:
                w(f"- {b.url} (was in: {b.folder or 'root'})\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Check, dedupe and re-organize bookmark exports.")
    ap.add_argument("inputs", nargs="+",
                    help="bookmarks HTML export(s); later files win dedupe ties")
    ap.add_argument("-o", "--output",
                    help="output HTML (default: <first input>_organized.html)")
    ap.add_argument("--workers", type=int, default=24,
                    help="concurrent checks (default 24)")
    ap.add_argument("--timeout", type=float, default=10.0,
                    help="per-request timeout seconds")
    ap.add_argument("--skip-check", action="store_true",
                    help="organize only, no network")
    ap.add_argument("--no-cache", action="store_true",
                    help="ignore/skip the result cache")
    args = ap.parse_args()

    bookmarks, toolbar_name = [], None
    for idx, path in enumerate(args.inputs):
        with open(path, encoding="utf-8", errors="replace") as f:
            parser = NetscapeParser(source=idx)
            parser.feed(f.read())
            parser.close()
        print(f"Parsed {len(parser.bookmarks)} bookmarks from {path}")
        bookmarks.extend(parser.bookmarks)
        toolbar_name = parser.toolbar_name or toolbar_name
    if not bookmarks:
        sys.exit("No bookmarks found — are these Netscape-format exports?")

    bookmarks, dropped = dedupe(bookmarks)
    print(f"Deduped: {len(dropped)} duplicates collapsed, {len(bookmarks)} remain")

    if args.skip_check:
        for b in bookmarks:
            b.status = "SKIPPED"
        print("Link checking skipped.")
    else:
        n_check = sum(1 for b in bookmarks if b.checkable)
        print(f"Checking {n_check} links "
              f"({args.workers} workers, {args.timeout:.0f}s timeout)...")
        fresh = check_all(bookmarks, args.workers, args.timeout, not args.no_cache)
        cached = n_check - fresh
        if cached:
            print(f"  ({cached} results from cache)")

    cluster(bookmarks)

    out_html = args.output or os.path.splitext(args.inputs[0])[0] + "_organized.html"
    # Report goes next to the OUTPUT (the input's directory may be read-only).
    out_report = os.path.splitext(out_html)[0] + "_report.md"
    write_bookmarks_html(out_html, bookmarks, toolbar_name,
                         checked=not args.skip_check)
    write_report(out_report, bookmarks, dropped, checked=not args.skip_check)

    dead_n = sum(1 for b in bookmarks if b.status == "DEAD" and not b.in_toolbar)
    ambig_n = sum(1 for b in bookmarks if b.status == "AMBIGUOUS")
    print(f"\nDone. Dead: {dead_n} (Graveyard), ambiguous: {ambig_n} (marked [?])")
    print(f"Organized bookmarks: {out_html}")
    print(f"Report:              {out_report}")
    print("Input files untouched. Review the report before importing.")


if __name__ == "__main__":
    main()
