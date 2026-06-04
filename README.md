
# 🚀 Murphy Microsoft Account Checker v1.0

**Advanced Microsoft / Hotmail / Outlook account checker with two powerful scanning modes.**  
Extracts account validity, profile information (name, country), and searches inbox for specific keywords.  
Built with Python & `rich` for a beautiful live dashboard.

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-brightgreen?style=for-the-badge">
  <img src="https://img.shields.io/badge/Python-3.7%2B-blue?style=for-the-badge&logo=python">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge">
  <img src="https://img.shields.io/badge/Telegram-Notifications-blue?style=for-the-badge&logo=telegram">
</p>

---

## ✨ Features

- **🔐 Microsoft OAuth 2.0 authentication** – works with modern Hotmail/Outlook/Live accounts.
- **📬 Inbox Searcher** – search for keywords in the inbox (e.g., `noreply@instagram.com`, `paypal`, `steam`).  
  Shows number of matching emails + live progress bars.
- **🌍 Country Filter** – fetch account profile (display name, country) and automatically sort results by country.  
  Each country saved in a separate file with flag emojis.
- **🎨 Live Rich Dashboard** – clean, colorful, real‑time updates using `rich` library. No manual frames needed.
- **⚡ Multi‑threading** – up to 50 threads for high‑speed scanning (adjustable).
- **📁 Auto‑saved results** – structured folders: `all_hits.txt`, `2FA.txt`, `keywords/` (per keyword), `countries/` (per country).
- **🔐 2FA detection** – accounts requiring two‑factor authentication are saved separately.
- **🤖 Telegram integration** – (optional) send welcome message and live stats (not yet implemented – can be added).

---

## 📸 Dashboard Preview

```

╭────────────────────────────────────────────────────────────╮
│   ███╗   ███╗██╗   ██╗██████╗ ██████╗ ██╗  ██╗██╗   ██╗   │
│   ████╗ ████║██║   ██║██╔══██╗██╔══██╗██║  ██║╚██╗ ██╔╝   │
│   ██╔████╔██║██║   ██║██████╔╝██████╔╝███████║ ╚████╔╝    │
│   ██║╚██╔╝██║██║   ██║██╔══██╗██╔═══╝ ██╔══██║  ╚██╔╝     │
│   ██║ ╚═╝ ██║╚██████╔╝██║  ██║██║     ██║  ██║   ██║      │
│   ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝   ╚═╝      │
╰────────────────────────────────────────────────────────────╯

Progress: ████████████████████░░░░░░░░░░  47% (235/500)
✅ HITS: 23   🔐 2FA: 5   ❌ BAD: 187   ⚠️ ERR: 20

🎯 KEYWORD MATCHES
┌─────────────────────────┬───────┬──────────────────────────┐
│ Keyword                 │ Hits  │ Progress                 │
├─────────────────────────┼───────┼──────────────────────────┤
│ noreply@instagram.com   │ 12    │ ████████████████░░░░░░░░  │
│ paypal                  │ 8     │ ██████████░░░░░░░░░░░░░░  │
└─────────────────────────┴───────┴──────────────────────────┘

🚀 PERFORMANCE
CPM: 42.3   |   ELAPSED: 00:07:53   |   REMAINING: 00:03:54

```

---

## 📦 Installation

```bash
git clone https://github.com/sadikmahedi88/Murphy-Microsoft-Checker.git
cd Murphy-Microsoft-Checker
pip install -r requirements.txt
```

requirements.txt

```
requests
rich
```

---

🚀 Usage

```bash
python murphy_checker.py
```

You will be presented with a main menu:

```
⚙️  MAIN MENU - SELECT SCANNING MODE

[1] 📬 INBOX SEARCHER
    Search for specific keywords in your inbox (e.g., noreply@instagram.com)

[2] 🌍 COUNTRY FILTER
    Fetch account profile (name, country) and sort results by country
```

· Inbox Searcher – after selecting, provide the accounts file (email:password per line) and your keywords (manual or from a file). The dashboard will update live.
· Country Filter – provide accounts file, and the script will extract profile data and automatically create country‑based result files.

All results are saved in the Results/ folder with timestamps.

---

📁 Output Structure

```
Results/
├── InboxSearch_20250604_143022/
│   ├── all_hits.txt
│   ├── 2FA.txt
│   ├── keywords/
│   │   ├── noreply@instagram.com.txt
│   │   └── paypal.txt
│   └── ...
└── CountryFilter_20250604_150135/
    ├── all_hits.txt
    ├── 2FA.txt
    ├── countries/
    │   ├── US.txt
    │   ├── GB.txt
    │   └── EG.txt
    └── ...
```

---

👑 Author & Credits

· Developer: @Murphython
· GitHub: sadikmahedi88
· Telegram Channel: Join Channel
· Telegram Chat: Join Chat

---

📜 License

MIT License – free to use, modify, and distribute with proper attribution.

---

<p align="center">
  Made with 💙 by Murphython
</p>
```
