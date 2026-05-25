#!/usr/bin/env python3
"""
1-Day Vulnerability Hunter Bot v2
+ Auto CVE monitoring
+ Bug Bounty matching (HackerOne, Intigriti, We Hack The Planet)
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

from bb_monitor import monitor_loop, fetch_all_bb_programs, match_cve_to_programs

# ── Config ────────────────────────────────────────────────────────────────────
BOT_TOKEN      = os.getenv("TELEGRAM_BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
SHODAN_KEY     = os.getenv("SHODAN_API_KEY", "")
ALERT_CHAT_IDS = [
    int(x) for x in os.getenv("ALERT_CHAT_IDS", "").split(",") if x.strip().lstrip("-").isdigit()
]
MIN_CVSS         = float(os.getenv("MIN_CVSS", "7.0"))
MONITOR_INTERVAL = int(os.getenv("MONITOR_INTERVAL_MIN", "30"))

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
    score    = 0.0
    severity = "N/A"
    vector   = "N/A"
    if cvss3:
        d = cvss3[0]["cvssData"]
        score    = d.get("baseScore", 0)
        severity = d.get("baseSeverity", "N/A")
        vector   = d.get("vectorString", "N/A")
    elif cvss2:
        d = cvss2[0]["cvssData"]
        score    = d.get("baseScore", 0)
        severity = cvss2[0].get("baseSeverity", "N/A")
        vector   = d.get("vectorString", "N/A")

    desc  = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "N/A")
    refs  = [r["url"] for r in cve.get("references", [])[:5]]
    cpes  = []
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
        cpes = []
        for node in cve.get("configurations", []):
            for n in node.get("nodes", []):
                for m in n.get("cpeMatch", []):
                    if m.get("vulnerable"):
                        cpes.append(m.get("criteria", ""))
        results.append({
            "id":       cve["id"],
            "score":    score,
            "severity": cvss3[0]["cvssData"].get("baseSeverity", ""),
            "desc":     desc[:120] + "..." if len(desc) > 120 else desc,
            "cpes":     cpes[:5],
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
    results = []
    for m in data.get("matches", [])[:10]:
        results.append({
            "ip":      m.get("ip_str", ""),
            "port":    m.get("port", ""),
            "org":     m.get("org", "Unknown"),
            "country": m.get("location", {}).get("country_name", ""),
            "product": m.get("product", ""),
            "version": m.get("version", ""),
        })
    return results


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
    results = []
    for item in data.get("items", [])[:5]:
        commit = item.get("commit", {})
        repo   = item.get("repository", {})
        results.append({
            "repo":    repo.get("full_name", ""),
            "message": commit.get("message", "")[:100],
            "url":     item.get("html_url", ""),
            "date":    commit.get("committer", {}).get("date", "")[:10],
        })
    return results


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
    results = []
    for item in data.get("data", [])[:3]:
        results.append({
            "id":          item.get("id", ""),
            "description": item.get("description", ""),
            "date":        item.get("date_published", ""),
            "url":         f"https://www.exploit-db.com/exploits/{item.get('id','')}",
        })
    return results


async def extract_software_from_cpe(cpes: list) -> list:
    software = []
    for cpe in cpes:
        parts = cpe.split(":")
        if len(parts) >= 5:
            vendor  = parts[3].replace("_", " ")
            product = parts[4].replace("_", " ")
            version = parts[5] if len(parts) > 5 else "*"
            software.append({
                "vendor":  vendor, "product": product, "version": version,
                "shodan_query": f'"{product}" version:"{version}"' if version != "*" else f'"{product}"',
            })
    return software


async def run_nuclei(target: str, cve_id: str) -> str:
    try:
        subprocess.run(["nuclei", "-version"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "⚠️ Nuclei not installed."
    cmd = ["nuclei", "-target", target, "-id", cve_id.lower(), "-silent", "-timeout", "10"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        out = result.stdout.strip()
        return out if out else f"No findings for {cve_id} on {target}"
    except subprocess.TimeoutExpired:
        return "⏱ Timed out (60s)"
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
    av = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}.get(parts.get("AV", ""), "?")
    ac = {"L": "Low", "H": "High"}.get(parts.get("AC", ""), "?")
    pr = {"N": "None", "L": "Low", "H": "High"}.get(parts.get("PR", ""), "?")
    ui = "Required" if parts.get("UI") == "R" else "None"
    return f"Access: {av} | Complexity: {ac} | Privileges: {pr} | UI: {ui}"


# ── Keyboards ─────────────────────────────────────────────────────────────────

def main_menu_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔍 Analyze CVE",       callback_data="menu_cve")],
        [InlineKeyboardButton("📡 Recon Domain",      callback_data="menu_recon")],
        [InlineKeyboardButton("📰 Latest CVEs",       callback_data="menu_latest")],
        [InlineKeyboardButton("🎯 BB Match (manual)", callback_data="menu_bbmatch")],
        [InlineKeyboardButton("📡 Monitor Status",    callback_data="menu_monitor")],
        [InlineKeyboardButton("🛠 Tools",             callback_data="menu_tools")],
    ])

def cve_actions_keyboard(cve_id: str) -> InlineKeyboardMarkup:
    cve = cve_id.upper()
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🎯 BB Match",            callback_data=f"bb_{cve}")],
        [InlineKeyboardButton("🔎 Find Patch (GitHub)", callback_data=f"patch_{cve}")],
        [InlineKeyboardButton("💥 Search Exploits",     callback_data=f"exploit_{cve}")],
        [InlineKeyboardButton("🌐 Shodan Search",       callback_data=f"shodan_{cve}")],
        [InlineKeyboardButton("🔙 Main Menu",           callback_data="menu_main")],
    ])

def recon_keyboard(domain: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🌍 Subdomains", callback_data=f"subs_{domain}")],
        [InlineKeyboardButton("🔙 Main Menu",  callback_data="menu_main")],
    ])


# ── Handlers ──────────────────────────────────────────────────────────────────

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    monitor_status = "✅ Active" if chat_id in ALERT_CHAT_IDS else "❌ Not subscribed"
    text = (
        "🎯 *1-Day Vulnerability Hunter Bot v2*\n\n"
        f"📡 Monitor: {monitor_status}\n\n"
        "*Commands:*\n"
        "`/cve CVE-2024-XXXX` — تحليل CVE\n"
        "`/recon domain.com` — Recon\n"
        "`/latest` — آخر CVEs\n"
        "`/bbmatch CVE-2024-X` — Bug Bounty matching\n"
        "`/subscribe` — اشترك في التنبيهات\n"
        "`/unsubscribe` — إلغاء الاشتراك\n"
        "`/nuclei target.com CVE-X` — Nuclei scan\n"
    )
    await update.message.reply_text(text, parse_mode="Markdown",
                                    reply_markup=main_menu_keyboard())


async def cmd_subscribe(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    if chat_id not in ALERT_CHAT_IDS:
        ALERT_CHAT_IDS.append(chat_id)
        await update.message.reply_text(
            f"✅ *تم الاشتراك في التنبيهات!*\n\n"
            f"هتوصلك alert تلقائياً كل ما في CVE جديدة:\n"
            f"• CVSS ≥ {MIN_CVSS}\n"
            f"• موجودة في Bug Bounty scope\n\n"
            f"📡 الـ monitor بيتفقد كل *{MONITOR_INTERVAL} دقيقة*\n"
            f"🆔 Chat ID: `{chat_id}`",
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text(
            f"ℹ️ انت مشترك بالفعل!\n🆔 Chat ID: `{chat_id}`",
            parse_mode="Markdown"
        )


async def cmd_unsubscribe(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    if chat_id in ALERT_CHAT_IDS:
        ALERT_CHAT_IDS.remove(chat_id)
        await update.message.reply_text("✅ تم إلغاء الاشتراك في التنبيهات.")
    else:
        await update.message.reply_text("ℹ️ مش مشترك أصلاً.")


async def cmd_cve(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("❌ الاستخدام: `/cve CVE-2024-XXXX`", parse_mode="Markdown")
        return
    cve_id = ctx.args[0].upper()
    if not re.match(r"CVE-\d{4}-\d+", cve_id):
        await update.message.reply_text("❌ صيغة CVE غلط.", parse_mode="Markdown")
        return

    msg = await update.message.reply_text(f"⏳ جاري تحليل `{cve_id}`...", parse_mode="Markdown")
    cve = await fetch_cve(cve_id)
    if not cve:
        await msg.edit_text(f"❌ مش لاقي `{cve_id}` في NVD.", parse_mode="Markdown")
        return

    score    = cve["score"]
    worth_it = "✅ يستاهل!" if score >= MIN_CVSS else f"⚠️ Score منخفض ({score})"
    cpes_text = ""
    if cve["cpes"]:
        sw = await extract_software_from_cpe(cve["cpes"][:3])
        if sw:
            cpes_text = "\n\n*🖥 Affected Software:*\n"
            for s in sw:
                cpes_text += f"• `{s['vendor']} / {s['product']}` v`{s['version']}`\n"

    text = (
        f"*{cve_id}* — {severity_emoji(score)}\n"
        f"{'─'*35}\n"
        f"📅 Published: `{cve['published']}`\n"
        f"📊 CVSS: `{score}` ({cve['severity']})\n"
        f"🧭 `{vector_summary(cve['vector'])}`\n\n"
        f"📝 _{cve['description'][:400]}{'...' if len(cve['description']) > 400 else ''}_"
        f"{cpes_text}\n\n"
        f"🎯 *Triage: {worth_it}*"
    )
    await msg.edit_text(text, parse_mode="Markdown",
                        reply_markup=cve_actions_keyboard(cve_id),
                        disable_web_page_preview=True)


async def cmd_bbmatch(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Manual BB match for a CVE."""
    if not ctx.args:
        await update.message.reply_text("❌ الاستخدام: `/bbmatch CVE-2024-XXXX`", parse_mode="Markdown")
        return
    cve_id = ctx.args[0].upper()
    msg    = await update.message.reply_text(
        f"⏳ جاري البحث عن Bug Bounty programs لـ `{cve_id}`...",
        parse_mode="Markdown"
    )
    cve = await fetch_cve(cve_id)
    if not cve:
        await msg.edit_text(f"❌ مش لاقي `{cve_id}` في NVD.", parse_mode="Markdown")
        return

    await msg.edit_text(
        f"⏳ جاري تحميل Bug Bounty programs (HackerOne + Intigriti + WeHackThePlanet)...",
        parse_mode="Markdown"
    )
    programs = await fetch_all_bb_programs()
    matches  = match_cve_to_programs(cve, programs)

    await _send_bb_result(msg, cve_id, matches, programs)


async def _send_bb_result(msg, cve_id: str, matches: list, programs: list):
    platform_icon = {
        "HackerOne":       "💰",
        "Intigriti":       "🏴",
        "WeHackThePlanet": "🌍",
    }
    if not matches:
        text = (
            f"🎯 *BB Match: {cve_id}*\n"
            f"{'─'*35}\n"
            f"❌ مش لاقي match في أي Bug Bounty program.\n\n"
            f"📊 Checked: {len(programs)} programs\n"
            f"_(HackerOne + Intigriti + WeHackThePlanet)_"
        )
    else:
        text = (
            f"🎯 *BB Match: {cve_id}*\n"
            f"{'─'*35}\n"
            f"✅ *{len(matches)} program(s) matched!*\n\n"
        )
        for m in matches[:6]:
            icon = platform_icon.get(m["platform"], "🎯")
            text += (
                f"{icon} *{m['name']}* _({m['platform']})_\n"
                f"🔑 Matched: `{'`, `'.join(m['matched'][:4])}`\n"
                f"🌐 Scope: `{'`, `'.join(m['scopes'][:3])}`\n"
                f"🔗 {m['url']}\n\n"
            )
        text += f"📊 Checked: {len(programs)} programs total"

    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("🔙 Main Menu", callback_data="menu_main")]
    ])
    await msg.edit_text(text, parse_mode="Markdown",
                        reply_markup=keyboard, disable_web_page_preview=True)


async def cmd_recon(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("❌ الاستخدام: `/recon example.com`", parse_mode="Markdown")
        return
    domain = re.sub(r"^https?://", "", ctx.args[0].lower()).split("/")[0]
    msg    = await update.message.reply_text(f"⏳ Recon على `{domain}`...", parse_mode="Markdown")
    subs   = await crtsh_subdomains(domain)
    text   = f"🌐 *Recon: {domain}*\n{'─'*35}\n📡 Subdomains (crt.sh): `{len(subs)}`\n"
    if subs:
        text += "\n".join(f"• `{s}`" for s in subs[:15])
        if len(subs) > 15:
            text += f"\n_... و {len(subs)-15} أكتر_"
    await msg.edit_text(text, parse_mode="Markdown", reply_markup=recon_keyboard(domain))


async def cmd_latest(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    msg  = await update.message.reply_text("⏳ جاري جلب آخر CVEs...", parse_mode="Markdown")
    cves = await fetch_recent_cves(days=1, min_score=MIN_CVSS)
    if not cves:
        await msg.edit_text("❌ مش لاقي CVEs جديدة.")
        return
    text = f"🔥 *CVEs آخر 24 ساعة (CVSS ≥ {MIN_CVSS})*\n{'─'*35}\n"
    for c in cves[:10]:
        emoji = "🔴" if c["score"] >= 9 else "🟠"
        text += f"{emoji} `{c['id']}` — *{c['score']}*\n_{c['desc']}_\n\n"
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("🔙 Main Menu", callback_data="menu_main")]
    ])
    await msg.edit_text(text, parse_mode="Markdown", reply_markup=keyboard)


async def cmd_nuclei(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if len(ctx.args) < 2:
        await update.message.reply_text(
            "❌ الاستخدام: `/nuclei target.com CVE-2024-XXXX`", parse_mode="Markdown"
        )
        return
    target = ctx.args[0]
    cve_id = ctx.args[1].upper()
    msg    = await update.message.reply_text(
        f"⏳ Nuclei على `{target}` for `{cve_id}`...", parse_mode="Markdown"
    )
    result = await run_nuclei(target, cve_id)
    await msg.edit_text(
        f"🔬 *Nuclei Result:*\n```\n{result[:3000]}\n```", parse_mode="Markdown"
    )


async def cmd_monitor_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id     = update.effective_chat.id
    subscribed  = chat_id in ALERT_CHAT_IDS
    status_icon = "✅" if subscribed else "❌"
    text = (
        f"📡 *Monitor Status*\n{'─'*35}\n"
        f"Status: {status_icon} {'Subscribed' if subscribed else 'Not subscribed'}\n"
        f"Interval: every *{MONITOR_INTERVAL} min*\n"
        f"Min CVSS: *{MIN_CVSS}*\n"
        f"Platforms: HackerOne, Intigriti, WeHackThePlanet\n"
        f"Active subscribers: *{len(ALERT_CHAT_IDS)}*\n\n"
        f"_البوت بيتفقد NVD كل {MONITOR_INTERVAL} دقيقة_\n"
        f"_لو في CVE جديدة ومتطابقة مع BB scope هيبعتلك alert تلقائي_"
    )
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ Subscribe",   callback_data="do_subscribe")],
        [InlineKeyboardButton("❌ Unsubscribe", callback_data="do_unsubscribe")],
        [InlineKeyboardButton("🔙 Main Menu",   callback_data="menu_main")],
    ])
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=keyboard)


# ── Callback Handler ──────────────────────────────────────────────────────────

async def handle_callback(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data    = query.data
    chat_id = query.message.chat_id

    if data == "menu_main":
        await query.edit_message_text(
            "🎯 *1-Day Vulnerability Hunter Bot v2*\nاختار من القائمة:",
            parse_mode="Markdown", reply_markup=main_menu_keyboard()
        )
        return

    if data == "menu_cve":
        await query.edit_message_text(
            "🔍 ابعت:\n`/cve CVE-2024-XXXX`", parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 رجوع", callback_data="menu_main")]]))
        return

    if data == "menu_recon":
        await query.edit_message_text(
            "📡 ابعت:\n`/recon example.com`", parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 رجوع", callback_data="menu_main")]]))
        return

    if data == "menu_bbmatch":
        await query.edit_message_text(
            "🎯 ابعت:\n`/bbmatch CVE-2024-XXXX`\n\nالبوت هيدور على HackerOne + Intigriti + WeHackThePlanet",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 رجوع", callback_data="menu_main")]]))
        return

    if data == "menu_monitor":
        subscribed = chat_id in ALERT_CHAT_IDS
        status_icon = "✅" if subscribed else "❌"
        text = (
            f"📡 *Monitor Status*\n{'─'*35}\n"
            f"Status: {status_icon} {'Subscribed' if subscribed else 'Not subscribed'}\n"
            f"Interval: every *{MONITOR_INTERVAL} min*\n"
            f"Min CVSS: *{MIN_CVSS}*\n"
            f"Platforms: HackerOne + Intigriti + WeHackThePlanet\n"
            f"Active subscribers: *{len(ALERT_CHAT_IDS)}*"
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
                f"✅ *تم الاشتراك!*\nهتوصلك CVE alerts تلقائياً.\n🆔 Chat ID: `{chat_id}`",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Main Menu", callback_data="menu_main")]]))
        else:
            await query.answer("انت مشترك بالفعل!", show_alert=True)
        return

    if data == "do_unsubscribe":
        if chat_id in ALERT_CHAT_IDS:
            ALERT_CHAT_IDS.remove(chat_id)
            await query.edit_message_text(
                "✅ تم إلغاء الاشتراك.",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Main Menu", callback_data="menu_main")]]))
        else:
            await query.answer("مش مشترك أصلاً!", show_alert=True)
        return

    if data == "menu_latest":
        await query.edit_message_text("⏳ جاري جلب آخر CVEs...", parse_mode="Markdown")
        cves = await fetch_recent_cves(days=1, min_score=MIN_CVSS)
        if not cves:
            text = "❌ مش لاقي CVEs جديدة."
        else:
            text = f"🔥 *CVEs آخر 24 ساعة (CVSS ≥ {MIN_CVSS})*\n{'─'*35}\n"
            for c in cves[:10]:
                emoji = "🔴" if c["score"] >= 9 else "🟠"
                text += f"{emoji} `{c['id']}` — *{c['score']}*\n_{c['desc']}_\n\n"
        keyboard = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Main Menu", callback_data="menu_main")]])
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=keyboard)
        return

    if data == "menu_tools":
        tools = {"nuclei": "🔬 Nuclei", "httpx": "🌐 httpx", "subfinder": "📡 Subfinder",
                 "wafw00f": "🛡 wafw00f", "nmap": "🔍 nmap"}
        lines = ["*🛠 Tool Status:*\n"]
        for tool, desc in tools.items():
            try:
                subprocess.run([tool, "--version"], capture_output=True, timeout=3)
                status = "✅"
            except FileNotFoundError:
                status = "❌"
            except subprocess.TimeoutExpired:
                status = "✅"
            lines.append(f"{desc}: {status}")
        shodan_st = "✅ Configured" if SHODAN_KEY else "❌ No API key"
        lines.append(f"\n🔑 Shodan: {shodan_st}")
        keyboard = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Main Menu", callback_data="menu_main")]])
        await query.edit_message_text("\n".join(lines), parse_mode="Markdown", reply_markup=keyboard)
        return

    # ── CVE actions ───────────────────────────────────────────────────────────
    if data.startswith("bb_"):
        cve_id = data[3:]
        await query.edit_message_text(f"⏳ BB matching لـ `{cve_id}`...", parse_mode="Markdown")
        cve      = await fetch_cve(cve_id)
        programs = await fetch_all_bb_programs()
        matches  = match_cve_to_programs(cve, programs) if cve else []
        await _send_bb_result(query.message, cve_id, matches, programs)
        return

    if data.startswith("patch_"):
        cve_id  = data[6:]
        await query.edit_message_text(f"⏳ بحث عن patches لـ `{cve_id}`...", parse_mode="Markdown")
        patches = await get_github_patch(cve_id)
        if not patches:
            text = f"❌ مش لاقي patches على GitHub لـ `{cve_id}`"
        else:
            text = f"🔎 *GitHub Patches for {cve_id}:*\n{'─'*35}\n"
            for p in patches:
                text += f"📁 `{p['repo']}`\n📅 {p['date']}\n💬 _{p['message']}_\n🔗 {p['url']}\n\n"
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("💥 Search Exploits", callback_data=f"exploit_{cve_id}")],
            [InlineKeyboardButton("🔙 Main Menu",       callback_data="menu_main")],
        ])
        await query.edit_message_text(text, parse_mode="Markdown",
                                      reply_markup=keyboard, disable_web_page_preview=True)
        return

    if data.startswith("exploit_"):
        cve_id   = data[8:]
        await query.edit_message_text(f"⏳ بحث عن exploits لـ `{cve_id}`...", parse_mode="Markdown")
        exploits = await search_exploitdb(cve_id)
        if not exploits:
            text = f"❌ مش لاقي exploits لـ `{cve_id}` على ExploitDB"
        else:
            text = f"💥 *Exploits for {cve_id}:*\n{'─'*35}\n"
            for e in exploits:
                text += f"🆔 EDB-{e['id']} | 📅 {e['date']}\n📝 {e['description']}\n🔗 {e['url']}\n\n"
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("🌐 Shodan", callback_data=f"shodan_{cve_id}")],
            [InlineKeyboardButton("🔙 Main Menu", callback_data="menu_main")],
        ])
        await query.edit_message_text(text, parse_mode="Markdown",
                                      reply_markup=keyboard, disable_web_page_preview=True)
        return

    if data.startswith("shodan_"):
        cve_id = data[7:]
        await query.edit_message_text("⏳ بحث على Shodan...", parse_mode="Markdown")
        if not SHODAN_KEY:
            text = "❌ Shodan API key مش موجود.\nحط `SHODAN_API_KEY` في environment variables."
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
                text = "❌ مش عارف أستخرج software من الـ CVE"
        keyboard = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Main Menu", callback_data="menu_main")]])
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=keyboard)
        return

    if data.startswith("subs_"):
        domain = data[5:]
        await query.edit_message_text(f"⏳ Subdomains لـ `{domain}`...", parse_mode="Markdown")
        subs = await crtsh_subdomains(domain)
        if not subs:
            text = f"❌ مش لاقي subdomains لـ `{domain}`"
        else:
            text = f"📡 *Subdomains of {domain}:* ({len(subs)} found)\n{'─'*35}\n"
            text += "\n".join(f"• `{s}`" for s in subs[:25])
            if len(subs) > 25:
                text += f"\n_... و {len(subs)-25} أكتر_"
        keyboard = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Main Menu", callback_data="menu_main")]])
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=keyboard)
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
    app.add_handler(CommandHandler("cve",         cmd_cve))
    app.add_handler(CommandHandler("bbmatch",     cmd_bbmatch))
    app.add_handler(CommandHandler("recon",       cmd_recon))
    app.add_handler(CommandHandler("latest",      cmd_latest))
    app.add_handler(CommandHandler("nuclei",      cmd_nuclei))
    app.add_handler(CommandHandler("monitor",     cmd_monitor_status))
    app.add_handler(CallbackQueryHandler(handle_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_error_handler(error_handler)

    async def post_init(application):
        if ALERT_CHAT_IDS:
            log.info(f"Starting monitor for {len(ALERT_CHAT_IDS)} chat(s)...")
            asyncio.create_task(
                monitor_loop(
                    bot=application.bot,
                    chat_ids=ALERT_CHAT_IDS,
                    interval_minutes=MONITOR_INTERVAL,
                    min_score=MIN_CVSS,
                )
            )
        else:
            log.info("No ALERT_CHAT_IDS set. Use /subscribe to enable alerts.")

    app.post_init = post_init

    log.info("🚀 Bot v2 starting...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
