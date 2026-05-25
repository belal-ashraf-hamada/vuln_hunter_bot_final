#!/usr/bin/env python3
"""
1-Day Vulnerability Hunter Bot v3
Features added:
  1. Smart CVE filtering by vuln type
  2. Priority scoring
  3. Alert history
  4. Monitor heartbeat/crash alert
  5. Platform filter
  6. Daily summary
"""

import os
import re
import json
import asyncio
import logging
import subprocess
import urllib.parse
from datetime import datetime, timedelta

import aiohttp
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, filters, ContextTypes
)

from bb_monitor_v3 import (
    monitor_loop, fetch_all_bb_programs, match_cve_to_programs,
    calc_priority, priority_label, detect_vuln_type,
    load_history, VULN_TYPES,
)

# ── Config ────────────────────────────────────────────────────────────────────
BOT_TOKEN      = os.getenv("TELEGRAM_BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
SHODAN_KEY     = os.getenv("SHODAN_API_KEY", "")
ALERT_CHAT_IDS = [
    int(x) for x in os.getenv("ALERT_CHAT_IDS", "").split(",")
    if x.strip().lstrip("-").isdigit()
]
MIN_CVSS         = float(os.getenv("MIN_CVSS", "7.0"))
MONITOR_INTERVAL = int(os.getenv("MONITOR_INTERVAL_MIN", "30"))

# Per-user settings (in-memory)
# user_settings[chat_id] = {"vuln_filter": [], "platform_filter": []}
user_settings: dict = {}

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(message)s",
    level=logging.INFO
)
log = logging.getLogger(__name__)

# ── NVD ───────────────────────────────────────────────────────────────────────

async def fetch_cve(cve_id: str) -> dict:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status != 200:
                return {}
            data = await r.json()
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {}
    cve      = vulns[0]["cve"]
    metrics  = cve.get("metrics", {})
    cvss3    = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
    cvss2    = metrics.get("cvssMetricV2", [])
    score = severity = vector = 0
    if cvss3:
        d        = cvss3[0]["cvssData"]
        score    = d.get("baseScore", 0)
        severity = d.get("baseSeverity", "N/A")
        vector   = d.get("vectorString", "N/A")
    elif cvss2:
        d        = cvss2[0]["cvssData"]
        score    = d.get("baseScore", 0)
        severity = cvss2[0].get("baseSeverity", "N/A")
        vector   = d.get("vectorString", "N/A")
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "N/A")
    refs = [r["url"] for r in cve.get("references", [])[:5]]
    cpes = []
    for node in cve.get("configurations", []):
        for n in node.get("nodes", []):
            for m in n.get("cpeMatch", []):
                if m.get("vulnerable"):
                    cpes.append(m.get("criteria", ""))
    return {
        "id": cve_id.upper(), "description": desc, "score": score,
        "severity": severity, "vector": vector,
        "published": cve.get("published", "")[:10],
        "references": refs, "cpes": cpes[:10],
        "vuln_type": detect_vuln_type(desc),
    }


async def fetch_recent_cves(days: int = 1, min_score: float = 7.0) -> list:
    end   = datetime.utcnow()
    start = end - timedelta(days=days)
    fmt   = "%Y-%m-%dT%H:%M:%S.000"
    url   = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={start.strftime(fmt)}&pubEndDate={end.strftime(fmt)}"
        f"&cvssV3Severity=HIGH&resultsPerPage=20"
    )
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
            if r.status != 200:
                return []
            data = await r.json()
    results = []
    for v in data.get("vulnerabilities", []):
        cve     = v["cve"]
        metrics = cve.get("metrics", {})
        cvss3   = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
        if not cvss3:
            continue
        score = cvss3[0]["cvssData"].get("baseScore", 0)
        if score < min_score:
            continue
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        results.append({
            "id":       cve["id"],
            "score":    score,
            "severity": cvss3[0]["cvssData"].get("baseSeverity", ""),
            "desc":     desc[:120] + "..." if len(desc) > 120 else desc,
            "vuln_type": detect_vuln_type(desc),
        })
    return sorted(results, key=lambda x: x["score"], reverse=True)


# ── Recon ─────────────────────────────────────────────────────────────────────

async def shodan_search(query: str) -> list:
    if not SHODAN_KEY:
        return []
    url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_KEY}&query={urllib.parse.quote(query)}&limit=10"
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status != 200:
                return []
            data = await r.json()
    return [
        {
            "ip": m.get("ip_str",""), "port": m.get("port",""),
            "org": m.get("org","Unknown"),
            "country": m.get("location",{}).get("country_name",""),
            "product": m.get("product",""), "version": m.get("version",""),
        }
        for m in data.get("matches", [])[:10]
    ]


async def crtsh_subdomains(domain: str) -> list:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
            if r.status != 200:
                return []
            try:
                data = await r.json(content_type=None)
            except Exception:
                return []
    subs = set()
    for entry in data:
        for sub in entry.get("name_value", "").split("\n"):
            sub = sub.strip().lstrip("*.")
            if sub and domain in sub:
                subs.add(sub)
    return sorted(subs)[:30]


async def get_github_patch(cve_id: str) -> list:
    url     = f"https://api.github.com/search/commits?q={cve_id}&sort=committer-date&order=desc"
    headers = {"Accept": "application/vnd.github.cloak-preview"}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status != 200:
                return []
            data = await r.json()
    return [
        {
            "repo":    item.get("repository", {}).get("full_name", ""),
            "message": item.get("commit", {}).get("message", "")[:100],
            "url":     item.get("html_url", ""),
            "date":    item.get("commit", {}).get("committer", {}).get("date", "")[:10],
        }
        for item in data.get("items", [])[:5]
    ]


async def search_exploitdb(cve_id: str) -> list:
    url     = f"https://www.exploit-db.com/search?cve={cve_id.replace('CVE-','')}&type=&platform=&order_by=date&sort=desc&search=true"
    headers = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status != 200:
                return []
            try:
                data = await r.json()
            except Exception:
                return []
    return [
        {
            "id": item.get("id",""), "description": item.get("description",""),
            "date": item.get("date_published",""),
            "url": f"https://www.exploit-db.com/exploits/{item.get('id','')}",
        }
        for item in data.get("data", [])[:3]
    ]


async def extract_software_from_cpe(cpes: list) -> list:
    sw = []
    for cpe in cpes:
        parts = cpe.split(":")
        if len(parts) >= 5:
            vendor  = parts[3].replace("_", " ")
            product = parts[4].replace("_", " ")
            version = parts[5] if len(parts) > 5 else "*"
            sw.append({
                "vendor": vendor, "product": product, "version": version,
                "shodan_query": f'"{product}" version:"{version}"' if version != "*" else f'"{product}"',
            })
    return sw


async def run_nuclei(target: str, cve_id: str) -> str:
    try:
        subprocess.run(["nuclei", "-version"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "⚠️ Nuclei not installed."
    try:
        result = subprocess.run(
            ["nuclei", "-target", target, "-id", cve_id.lower(), "-silent", "-timeout", "10"],
            capture_output=True, text=True, timeout=60
        )
        out = result.stdout.strip()
        return out if out else f"No findings for {cve_id} on {target}"
    except subprocess.TimeoutExpired:
        return "⏱ Timed out"
    except Exception as e:
        return f"Error: {e}"


# ── Helpers ───────────────────────────────────────────────────────────────────

def severity_emoji(score: float) -> str:
    if score >= 9.0: return "🔴 CRITICAL"
    if score >= 7.0: return "🟠 HIGH"
    if score >= 4.0: return "🟡 MEDIUM"
    return "🟢 LOW"

def vector_summary(vector: str) -> str:
    if not vector or vector == "N/A":
        return "N/A"
    parts = {}
    for p in vector.split("/"):
        if ":" in p:
            k, v = p.split(":", 1)
            parts[k] = v
    av = {"N":"Network","A":"Adjacent","L":"Local","P":"Physical"}.get(parts.get("AV",""),"?")
    ac = {"L":"Low","H":"High"}.get(parts.get("AC",""),"?")
    pr = {"N":"None","L":"Low","H":"High"}.get(parts.get("PR",""),"?")
    ui = "Required" if parts.get("UI") == "R" else "None"
    return f"Access: {av} | Complexity: {ac} | Privileges: {pr} | UI: {ui}"

def get_user_settings(chat_id: int) -> dict:
    return user_settings.get(chat_id, {"vuln_filter": [], "platform_filter": []})


# ── Keyboards ─────────────────────────────────────────────────────────────────

def main_menu_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔍 Analyze CVE",       callback_data="menu_cve")],
        [InlineKeyboardButton("📡 Recon Domain",      callback_data="menu_recon")],
        [InlineKeyboardButton("📰 Latest CVEs",       callback_data="menu_latest")],
        [InlineKeyboardButton("🎯 BB Match",          callback_data="menu_bbmatch")],
        [InlineKeyboardButton("⚙️ My Settings",       callback_data="menu_settings")],
        [InlineKeyboardButton("📊 Alert History",     callback_data="menu_history")],
        [InlineKeyboardButton("📡 Monitor Status",    callback_data="menu_monitor")],
        [InlineKeyboardButton("🛠 Tools",             callback_data="menu_tools")],
    ])

def cve_actions_keyboard(cve_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🎯 BB Match",            callback_data=f"bb_{cve_id}")],
        [InlineKeyboardButton("🔎 Find Patch",          callback_data=f"patch_{cve_id}")],
        [InlineKeyboardButton("💥 Search Exploits",     callback_data=f"exploit_{cve_id}")],
        [InlineKeyboardButton("🌐 Shodan",              callback_data=f"shodan_{cve_id}")],
        [InlineKeyboardButton("🔙 Main Menu",           callback_data="menu_main")],
    ])

def settings_keyboard(chat_id: int) -> InlineKeyboardMarkup:
    s = get_user_settings(chat_id)
    vf = ", ".join(s["vuln_filter"]) if s["vuln_filter"] else "All"
    pf = ", ".join(s["platform_filter"]) if s["platform_filter"] else "All"
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(f"🐛 Vuln Filter: {vf}",     callback_data="set_vuln")],
        [InlineKeyboardButton(f"🌐 Platform Filter: {pf}", callback_data="set_platform")],
        [InlineKeyboardButton("🔄 Reset Settings",         callback_data="set_reset")],
        [InlineKeyboardButton("🔙 Main Menu",              callback_data="menu_main")],
    ])

def vuln_filter_keyboard(chat_id: int) -> InlineKeyboardMarkup:
    s       = get_user_settings(chat_id)
    current = s["vuln_filter"]
    btns    = []
    for vtype in VULN_TYPES:
        tick = "✅" if vtype in current else "⬜"
        btns.append([InlineKeyboardButton(f"{tick} {vtype}", callback_data=f"vf_{vtype}")])
    btns.append([InlineKeyboardButton("✅ All (clear filter)", callback_data="vf_clear")])
    btns.append([InlineKeyboardButton("🔙 رجوع", callback_data="menu_settings")])
    return InlineKeyboardMarkup(btns)

def platform_filter_keyboard(chat_id: int) -> InlineKeyboardMarkup:
    s        = get_user_settings(chat_id)
    current  = s["platform_filter"]
    platforms = ["hackerone", "bugcrowd", "intigriti", "wehacktheplanet"]
    btns = []
    for p in platforms:
        tick = "✅" if p in current else "⬜"
        btns.append([InlineKeyboardButton(f"{tick} {p.capitalize()}", callback_data=f"pf_{p}")])
    btns.append([InlineKeyboardButton("✅ All (clear filter)", callback_data="pf_clear")])
    btns.append([InlineKeyboardButton("🔙 رجوع", callback_data="menu_settings")])
    return InlineKeyboardMarkup(btns)


# ── Handlers ──────────────────────────────────────────────────────────────────

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    status  = "✅ Active" if chat_id in ALERT_CHAT_IDS else "❌ Not subscribed"
    s       = get_user_settings(chat_id)
    vf      = ", ".join(s["vuln_filter"]) if s["vuln_filter"] else "All types"
    text = (
        "🎯 *1-Day Vulnerability Hunter Bot v3*\n\n"
        f"📡 Monitor: {status}\n"
        f"🐛 Vuln filter: {vf}\n\n"
        "*Commands:*\n"
        "`/cve CVE-2024-X` — تحليل CVE\n"
        "`/bbmatch CVE-2024-X` — BB matching\n"
        "`/recon domain.com` — Recon\n"
        "`/latest` — آخر CVEs\n"
        "`/history` — سجل الـ alerts\n"
        "`/settings` — إعداداتك\n"
        "`/subscribe` — اشترك في التنبيهات\n"
        "`/unsubscribe` — إلغاء الاشتراك\n"
        "`/nuclei target CVE-X` — Nuclei scan\n"
    )
    await update.message.reply_text(text, parse_mode="Markdown",
                                    reply_markup=main_menu_keyboard())


async def cmd_subscribe(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    if chat_id not in ALERT_CHAT_IDS:
        ALERT_CHAT_IDS.append(chat_id)
        await update.message.reply_text(
            f"✅ *تم الاشتراك!*\n\n"
            f"• CVSS ≥ {MIN_CVSS}\n"
            f"• كل {MONITOR_INTERVAL} دقيقة\n"
            f"• Daily summary الساعة 8 الصبح\n"
            f"🆔 Chat ID: `{chat_id}`\n\n"
            f"استخدم /settings عشان تفلتر نوع الثغرات أو الـ platforms.",
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text(f"ℹ️ مشترك بالفعل! 🆔 `{chat_id}`", parse_mode="Markdown")


async def cmd_unsubscribe(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    if chat_id in ALERT_CHAT_IDS:
        ALERT_CHAT_IDS.remove(chat_id)
        await update.message.reply_text("✅ تم إلغاء الاشتراك.")
    else:
        await update.message.reply_text("ℹ️ مش مشترك أصلاً.")


async def cmd_settings(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    s       = get_user_settings(chat_id)
    vf      = ", ".join(s["vuln_filter"])      if s["vuln_filter"]      else "All"
    pf      = ", ".join(s["platform_filter"])  if s["platform_filter"]  else "All"
    text = (
        f"⚙️ *إعداداتك*\n{'─'*35}\n"
        f"🐛 Vuln Filter: `{vf}`\n"
        f"🌐 Platform Filter: `{pf}`\n\n"
        "_اضغط على أي إعداد لتغييره_"
    )
    await update.message.reply_text(text, parse_mode="Markdown",
                                    reply_markup=settings_keyboard(chat_id))


async def cmd_history(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    history = load_history()
    if not history:
        await update.message.reply_text("📊 مفيش alerts محفوظة لحد دلوقتي.")
        return
    last10  = history[-10:][::-1]
    text    = f"📊 *آخر {len(last10)} Alerts:*\n{'─'*35}\n"
    for h in last10:
        p_icon = "🔥" if h["priority"] >= 80 else ("⚡" if h["priority"] >= 60 else "📌")
        match_txt = f" | 🎯 {len(h['matches'])} programs" if h["matches"] else ""
        text += (
            f"{p_icon} `{h['cve_id']}` — {h['vuln_type']}\n"
            f"   Score: {h['score']} | Priority: {h['priority']}/100{match_txt}\n"
            f"   📅 {h['timestamp']}\n\n"
        )
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("🔙 Main Menu", callback_data="menu_main")]
    ])
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=keyboard)


async def cmd_cve(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("❌ `/cve CVE-2024-XXXX`", parse_mode="Markdown")
        return
    cve_id = ctx.args[0].upper()
    if not re.match(r"CVE-\d{4}-\d+", cve_id):
        await update.message.reply_text("❌ صيغة CVE غلط.", parse_mode="Markdown")
        return
    msg = await update.message.reply_text(f"⏳ تحليل `{cve_id}`...", parse_mode="Markdown")
    cve = await fetch_cve(cve_id)
    if not cve:
        await msg.edit_text(f"❌ مش لاقي `{cve_id}`.", parse_mode="Markdown")
        return

    score     = cve["score"]
    vtype     = cve.get("vuln_type", "Other")
    worth_it  = "✅ يستاهل!" if score >= MIN_CVSS else f"⚠️ Score منخفض ({score})"
    cpes_text = ""
    if cve["cpes"]:
        sw = await extract_software_from_cpe(cve["cpes"][:3])
        if sw:
            cpes_text = "\n\n*🖥 Affected:*\n"
            for s in sw:
                cpes_text += f"• `{s['vendor']} / {s['product']}` v`{s['version']}`\n"

    # Quick priority estimate
    programs = await fetch_all_bb_programs()
    matches  = match_cve_to_programs(cve, programs)
    priority = await calc_priority(cve, matches)

    text = (
        f"*{cve_id}* — {severity_emoji(score)}\n"
        f"{'─'*35}\n"
        f"📅 Published: `{cve['published']}`\n"
        f"📊 CVSS: `{score}` ({cve['severity']})\n"
        f"🐛 Type: `{vtype}`\n"
        f"🏆 Priority: `{priority_label(priority)}` ({priority}/100)\n"
        f"🧭 `{vector_summary(cve['vector'])}`\n\n"
        f"📝 _{cve['description'][:380]}{'...' if len(cve['description']) > 380 else ''}_"
        f"{cpes_text}\n\n"
        f"🎯 *Triage: {worth_it}*"
    )
    await msg.edit_text(text, parse_mode="Markdown",
                        reply_markup=cve_actions_keyboard(cve_id),
                        disable_web_page_preview=True)


async def cmd_bbmatch(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("❌ `/bbmatch CVE-2024-XXXX`", parse_mode="Markdown")
        return
    cve_id = ctx.args[0].upper()
    msg    = await update.message.reply_text(f"⏳ BB matching لـ `{cve_id}`...", parse_mode="Markdown")
    cve    = await fetch_cve(cve_id)
    if not cve:
        await msg.edit_text(f"❌ مش لاقي `{cve_id}`.", parse_mode="Markdown")
        return
    await msg.edit_text("⏳ جاري تحميل BB programs...", parse_mode="Markdown")
    programs = await fetch_all_bb_programs()
    matches  = match_cve_to_programs(cve, programs)
    await _send_bb_result(msg, cve_id, matches, programs)


async def _send_bb_result(msg, cve_id: str, matches: list, programs: list):
    picon = {"Intigriti": "🏴", "WeHackThePlanet": "🌍"}
    if not matches:
        text = (
            f"🎯 *BB Match: {cve_id}*\n{'─'*35}\n"
            f"❌ مش لاقي match.\n📊 Checked: {len(programs)} programs"
        )
    else:
        text = (
            f"🎯 *BB Match: {cve_id}*\n{'─'*35}\n"
            f"✅ *{len(matches)} program(s) matched!*\n\n"
        )
        for m in matches[:6]:
            icon  = "💰" if "Chaos" in m["platform"] else picon.get(m["platform"], "🎯")
            text += (
                f"{icon} *{m['name']}* _({m['platform']})_\n"
                f"🔑 `{'`, `'.join(m['matched'][:4])}`\n"
                f"🌐 `{'`, `'.join(m['scopes'][:3])}`\n"
                f"🔗 {m['url']}\n\n"
            )
        text += f"📊 Checked: {len(programs)} programs"
    keyboard = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Main Menu", callback_data="menu_main")]])
    await msg.edit_text(text, parse_mode="Markdown",
                        reply_markup=keyboard, disable_web_page_preview=True)


async def cmd_recon(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("❌ `/recon example.com`", parse_mode="Markdown")
        return
    domain = re.sub(r"^https?://", "", ctx.args[0].lower()).split("/")[0]
    msg    = await update.message.reply_text(f"⏳ Recon `{domain}`...", parse_mode="Markdown")
    subs   = await crtsh_subdomains(domain)
    text   = f"🌐 *Recon: {domain}*\n{'─'*35}\n📡 Subdomains: `{len(subs)}`\n"
    if subs:
        text += "\n".join(f"• `{s}`" for s in subs[:15])
        if len(subs) > 15:
            text += f"\n_... و {len(subs)-15} أكتر_"
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("🌍 All Subdomains", callback_data=f"subs_{domain}")],
        [InlineKeyboardButton("🔙 Main Menu",      callback_data="menu_main")],
    ])
    await msg.edit_text(text, parse_mode="Markdown", reply_markup=keyboard)


async def cmd_latest(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    msg  = await update.message.reply_text("⏳ جاري جلب آخر CVEs...", parse_mode="Markdown")
    cves = await fetch_recent_cves(days=1, min_score=MIN_CVSS)
    if not cves:
        await msg.edit_text("❌ مش لاقي CVEs جديدة.")
        return
    text = f"🔥 *CVEs آخر 24 ساعة (CVSS ≥ {MIN_CVSS})*\n{'─'*35}\n"
    for c in cves[:10]:
        icon = "🔴" if c["score"] >= 9 else "🟠"
        text += f"{icon} `{c['id']}` *{c['score']}* — {c['vuln_type']}\n_{c['desc']}_\n\n"
    keyboard = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Main Menu", callback_data="menu_main")]])
    await msg.edit_text(text, parse_mode="Markdown", reply_markup=keyboard)


async def cmd_nuclei(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if len(ctx.args) < 2:
        await update.message.reply_text("❌ `/nuclei target.com CVE-2024-X`", parse_mode="Markdown")
        return
    target = ctx.args[0]
    cve_id = ctx.args[1].upper()
    msg    = await update.message.reply_text(f"⏳ Nuclei `{target}` / `{cve_id}`...", parse_mode="Markdown")
    result = await run_nuclei(target, cve_id)
    await msg.edit_text(f"🔬 *Nuclei:*\n```\n{result[:3000]}\n```", parse_mode="Markdown")


# ── Callback Handler ──────────────────────────────────────────────────────────

async def handle_callback(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query   = update.callback_query
    await query.answer()
    data    = query.data
    chat_id = query.message.chat_id

    # ── Navigation ────────────────────────────────────────────────────────────
    if data == "menu_main":
        await query.edit_message_text(
            "🎯 *1-Day Vulnerability Hunter Bot v3*\nاختار من القائمة:",
            parse_mode="Markdown", reply_markup=main_menu_keyboard()
        )
        return

    if data == "menu_cve":
        await query.edit_message_text("🔍 ابعت:\n`/cve CVE-2024-XXXX`", parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙", callback_data="menu_main")]]))
        return

    if data == "menu_recon":
        await query.edit_message_text("📡 ابعت:\n`/recon example.com`", parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙", callback_data="menu_main")]]))
        return

    if data == "menu_bbmatch":
        await query.edit_message_text("🎯 ابعت:\n`/bbmatch CVE-2024-XXXX`", parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙", callback_data="menu_main")]]))
        return

    if data == "menu_latest":
        await query.edit_message_text("⏳ جاري جلب آخر CVEs...", parse_mode="Markdown")
        cves = await fetch_recent_cves(days=1, min_score=MIN_CVSS)
        if not cves:
            text = "❌ مش لاقي CVEs جديدة."
        else:
            text = f"🔥 *CVEs آخر 24 ساعة*\n{'─'*35}\n"
            for c in cves[:10]:
                icon = "🔴" if c["score"] >= 9 else "🟠"
                text += f"{icon} `{c['id']}` *{c['score']}* — {c['vuln_type']}\n_{c['desc']}_\n\n"
        await query.edit_message_text(text, parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Main Menu", callback_data="menu_main")]]))
        return

    # ── Settings ──────────────────────────────────────────────────────────────
    if data == "menu_settings":
        s  = get_user_settings(chat_id)
        vf = ", ".join(s["vuln_filter"])     if s["vuln_filter"]     else "All"
        pf = ", ".join(s["platform_filter"]) if s["platform_filter"] else "All"
        await query.edit_message_text(
            f"⚙️ *إعداداتك*\n{'─'*35}\n"
            f"🐛 Vuln Filter: `{vf}`\n"
            f"🌐 Platform Filter: `{pf}`",
            parse_mode="Markdown", reply_markup=settings_keyboard(chat_id)
        )
        return

    if data == "set_vuln":
        await query.edit_message_text(
            "🐛 *اختار أنواع الثغرات اللي تهمك:*\n_(ممكن تختار أكتر من واحد)_",
            parse_mode="Markdown", reply_markup=vuln_filter_keyboard(chat_id)
        )
        return

    if data == "set_platform":
        await query.edit_message_text(
            "🌐 *اختار الـ platforms:*",
            parse_mode="Markdown", reply_markup=platform_filter_keyboard(chat_id)
        )
        return

    if data == "set_reset":
        user_settings[chat_id] = {"vuln_filter": [], "platform_filter": []}
        await query.edit_message_text(
            "✅ تم reset الإعدادات — هيوصلك كل حاجة.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Main Menu", callback_data="menu_main")]]))
        return

    if data.startswith("vf_"):
        vtype = data[3:]
        s     = user_settings.setdefault(chat_id, {"vuln_filter": [], "platform_filter": []})
        if vtype == "clear":
            s["vuln_filter"] = []
        elif vtype in s["vuln_filter"]:
            s["vuln_filter"].remove(vtype)
        else:
            s["vuln_filter"].append(vtype)
        await query.edit_message_text(
            f"🐛 *Vuln Filter:* `{', '.join(s['vuln_filter']) or 'All'}`\n\nاختار أكتر أو اضغط رجوع:",
            parse_mode="Markdown", reply_markup=vuln_filter_keyboard(chat_id)
        )
        return

    if data.startswith("pf_"):
        platform = data[3:]
        s        = user_settings.setdefault(chat_id, {"vuln_filter": [], "platform_filter": []})
        if platform == "clear":
            s["platform_filter"] = []
        elif platform in s["platform_filter"]:
            s["platform_filter"].remove(platform)
        else:
            s["platform_filter"].append(platform)
        await query.edit_message_text(
            f"🌐 *Platform Filter:* `{', '.join(s['platform_filter']) or 'All'}`\n\nاختار أكتر أو اضغط رجوع:",
            parse_mode="Markdown", reply_markup=platform_filter_keyboard(chat_id)
        )
        return

    # ── History ───────────────────────────────────────────────────────────────
    if data == "menu_history":
        history = load_history()
        if not history:
            text = "📊 مفيش alerts محفوظة لحد دلوقتي."
        else:
            last10 = history[-10:][::-1]
            text   = f"📊 *آخر {len(last10)} Alerts:*\n{'─'*35}\n"
            for h in last10:
                p_icon = "🔥" if h["priority"] >= 80 else ("⚡" if h["priority"] >= 60 else "📌")
                match_txt = f" | 🎯 {len(h['matches'])}" if h["matches"] else ""
                text += (
                    f"{p_icon} `{h['cve_id']}` — {h['vuln_type']}\n"
                    f"   P:{h['priority']}/100 | CVSS:{h['score']}{match_txt}\n"
                    f"   📅 {h['timestamp']}\n\n"
                )
        await query.edit_message_text(text, parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Main Menu", callback_data="menu_main")]]))
        return

    # ── Monitor ───────────────────────────────────────────────────────────────
    if data == "menu_monitor":
        s           = get_user_settings(chat_id)
        subscribed  = chat_id in ALERT_CHAT_IDS
        vf          = ", ".join(s["vuln_filter"])     if s["vuln_filter"]     else "All"
        pf          = ", ".join(s["platform_filter"]) if s["platform_filter"] else "All"
        text = (
            f"📡 *Monitor Status*\n{'─'*35}\n"
            f"{'✅' if subscribed else '❌'} {'Subscribed' if subscribed else 'Not subscribed'}\n"
            f"⏱ Interval: every *{MONITOR_INTERVAL} min*\n"
            f"📊 Min CVSS: *{MIN_CVSS}*\n"
            f"🐛 Vuln filter: `{vf}`\n"
            f"🌐 Platform filter: `{pf}`\n"
            f"👥 Subscribers: *{len(ALERT_CHAT_IDS)}*\n"
            f"📅 Daily summary: 8:00 AM UTC"
        )
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Subscribe",   callback_data="do_subscribe")],
            [InlineKeyboardButton("❌ Unsubscribe", callback_data="do_unsubscribe")],
            [InlineKeyboardButton("🔙 Main Menu",   callback_data="menu_main")],
        ])
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=keyboard)
        return

    if data == "do_subscribe":
        if chat_id not in ALERT_CHAT_IDS:
            ALERT_CHAT_IDS.append(chat_id)
            await query.edit_message_text(
                f"✅ *تم الاشتراك!*\n🆔 Chat ID: `{chat_id}`",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙", callback_data="menu_main")]]))
        else:
            await query.answer("مشترك بالفعل!", show_alert=True)
        return

    if data == "do_unsubscribe":
        if chat_id in ALERT_CHAT_IDS:
            ALERT_CHAT_IDS.remove(chat_id)
            await query.edit_message_text("✅ تم إلغاء الاشتراك.",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙", callback_data="menu_main")]]))
        else:
            await query.answer("مش مشترك أصلاً!", show_alert=True)
        return

    # ── Tools ─────────────────────────────────────────────────────────────────
    if data == "menu_tools":
        tools = {"nuclei":"🔬 Nuclei","httpx":"🌐 httpx","subfinder":"📡 Subfinder",
                 "wafw00f":"🛡 wafw00f","nmap":"🔍 nmap"}
        lines = ["*🛠 Tool Status:*\n"]
        for tool, desc in tools.items():
            try:
                subprocess.run([tool,"--version"], capture_output=True, timeout=3)
                status = "✅"
            except FileNotFoundError:
                status = "❌"
            except subprocess.TimeoutExpired:
                status = "✅"
            lines.append(f"{desc}: {status}")
        lines.append(f"\n🔑 Shodan: {'✅' if SHODAN_KEY else '❌'}")
        await query.edit_message_text("\n".join(lines), parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙", callback_data="menu_main")]]))
        return

    # ── CVE actions ───────────────────────────────────────────────────────────
    if data.startswith("bb_"):
        cve_id   = data[3:]
        await query.edit_message_text(f"⏳ BB matching `{cve_id}`...", parse_mode="Markdown")
        cve      = await fetch_cve(cve_id)
        programs = await fetch_all_bb_programs()
        matches  = match_cve_to_programs(cve, programs) if cve else []
        await _send_bb_result(query.message, cve_id, matches, programs)
        return

    if data.startswith("patch_"):
        cve_id  = data[6:]
        await query.edit_message_text(f"⏳ بحث patches `{cve_id}`...", parse_mode="Markdown")
        patches = await get_github_patch(cve_id)
        if not patches:
            text = f"❌ مش لاقي patches لـ `{cve_id}`"
        else:
            text = f"🔎 *Patches for {cve_id}:*\n{'─'*35}\n"
            for p in patches:
                text += f"📁 `{p['repo']}`\n📅 {p['date']}\n💬 _{p['message']}_\n🔗 {p['url']}\n\n"
        await query.edit_message_text(text, parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("💥 Exploits", callback_data=f"exploit_{cve_id}")],
                [InlineKeyboardButton("🔙", callback_data="menu_main")],
            ]), disable_web_page_preview=True)
        return

    if data.startswith("exploit_"):
        cve_id   = data[8:]
        await query.edit_message_text(f"⏳ بحث exploits `{cve_id}`...", parse_mode="Markdown")
        exploits = await search_exploitdb(cve_id)
        if not exploits:
            text = f"❌ مش لاقي exploits لـ `{cve_id}`"
        else:
            text = f"💥 *Exploits for {cve_id}:*\n{'─'*35}\n"
            for e in exploits:
                text += f"EDB-{e['id']} | {e['date']}\n{e['description']}\n{e['url']}\n\n"
        await query.edit_message_text(text, parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🌐 Shodan", callback_data=f"shodan_{cve_id}")],
                [InlineKeyboardButton("🔙", callback_data="menu_main")],
            ]), disable_web_page_preview=True)
        return

    if data.startswith("shodan_"):
        cve_id = data[7:]
        await query.edit_message_text("⏳ بحث على Shodan...", parse_mode="Markdown")
        if not SHODAN_KEY:
            text = "❌ Shodan API key مش موجود."
        else:
            cve_data = await fetch_cve(cve_id)
            sw       = await extract_software_from_cpe(cve_data.get("cpes", []))
            if sw:
                hosts = await shodan_search(sw[0]["shodan_query"])
                if hosts:
                    text = f"🌐 *Shodan: {cve_id}*\n`{sw[0]['shodan_query']}`\n{'─'*35}\n"
                    for h in hosts[:8]:
                        text += f"🖥 `{h['ip']}:{h['port']}` | {h['org']} ({h['country']})\n"
                        if h["product"]:
                            text += f"   📦 {h['product']} {h['version']}\n"
                else:
                    text = "❌ مش لاقي نتايج على Shodan"
            else:
                text = "❌ مش عارف أستخرج software"
        await query.edit_message_text(text, parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙", callback_data="menu_main")]]))
        return

    if data.startswith("subs_"):
        domain = data[5:]
        await query.edit_message_text(f"⏳ Subdomains `{domain}`...", parse_mode="Markdown")
        subs = await crtsh_subdomains(domain)
        if not subs:
            text = f"❌ مش لاقي subdomains لـ `{domain}`"
        else:
            text = f"📡 *Subdomains: {domain}* ({len(subs)})\n{'─'*35}\n"
            text += "\n".join(f"• `{s}`" for s in subs[:25])
            if len(subs) > 25:
                text += f"\n_... و {len(subs)-25} أكتر_"
        await query.edit_message_text(text, parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙", callback_data="menu_main")]]))
        return


# ── Message auto-detect ───────────────────────────────────────────────────────

async def handle_message(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    if re.match(r"(?i)CVE-\d{4}-\d+", text):
        ctx.args = [text.split()[0]]
        await cmd_cve(update, ctx)
    elif re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", text):
        ctx.args = [text]
        await cmd_recon(update, ctx)
    else:
        await update.message.reply_text(
            "مش فاهم. ابعت CVE ID أو domain أو /start",
            reply_markup=main_menu_keyboard()
        )


async def error_handler(update: object, ctx: ContextTypes.DEFAULT_TYPE):
    log.error("Exception:", exc_info=ctx.error)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("❌ حط TELEGRAM_BOT_TOKEN في environment variables")
        return

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start",       cmd_start))
    app.add_handler(CommandHandler("subscribe",   cmd_subscribe))
    app.add_handler(CommandHandler("unsubscribe", cmd_unsubscribe))
    app.add_handler(CommandHandler("settings",    cmd_settings))
    app.add_handler(CommandHandler("history",     cmd_history))
    app.add_handler(CommandHandler("cve",         cmd_cve))
    app.add_handler(CommandHandler("bbmatch",     cmd_bbmatch))
    app.add_handler(CommandHandler("recon",       cmd_recon))
    app.add_handler(CommandHandler("latest",      cmd_latest))
    app.add_handler(CommandHandler("nuclei",      cmd_nuclei))
    app.add_handler(CallbackQueryHandler(handle_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_error_handler(error_handler)

    async def post_init(application):
        if ALERT_CHAT_IDS:
            s = get_user_settings(ALERT_CHAT_IDS[0])
            asyncio.create_task(monitor_loop(
                bot=application.bot,
                chat_ids=ALERT_CHAT_IDS,
                interval_minutes=MONITOR_INTERVAL,
                min_score=MIN_CVSS,
                vuln_filter=s.get("vuln_filter", []),
                platform_filter=s.get("platform_filter", []),
            ))
        else:
            log.info("No ALERT_CHAT_IDS — use /subscribe to enable alerts.")

    app.post_init = post_init
    log.info("🚀 Bot v3 starting...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
