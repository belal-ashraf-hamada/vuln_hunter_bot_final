#!/usr/bin/env python3
"""
Bug Bounty CVE Monitor v3
Features:
  1. Smart CVE filtering by vuln type (RCE, SQLi, Auth Bypass, etc.)
  2. Priority scoring (CVSS + PoC + Patch + BB payout)
  3. Alert history (JSON persistence)
  4. Monitor heartbeat / crash alert
  5. Platform filter (H1 only / Intigriti only / etc.)
  6. Daily summary at 8 AM
"""

import os
import re
import json
import asyncio
import logging
import aiohttp
from datetime import datetime, timedelta

log = logging.getLogger(__name__)

CHAOS_API_KEY = os.getenv("CHAOS_API_KEY", "")
SEEN_FILE     = "seen_cves.json"
HISTORY_FILE  = "alert_history.json"

# ── Vuln type keywords ────────────────────────────────────────────────────────
VULN_TYPES = {
    "RCE":         ["remote code execution", "rce", "arbitrary code", "command injection",
                    "code execution", "os command"],
    "SQLi":        ["sql injection", "sqli", "sql query", "database injection"],
    "Auth Bypass": ["authentication bypass", "auth bypass", "improper authentication",
                    "unauthenticated", "missing authentication", "broken auth"],
    "SSRF":        ["server-side request forgery", "ssrf"],
    "XXE":         ["xml external entity", "xxe"],
    "LFI/RFI":     ["local file inclusion", "remote file inclusion", "path traversal",
                    "directory traversal", "lfi", "rfi"],
    "XSS":         ["cross-site scripting", "xss", "reflected xss", "stored xss"],
    "Deserialization": ["deserialization", "insecure deserialization", "java deserialization"],
    "Privilege Escalation": ["privilege escalation", "privesc", "local privilege",
                              "elevation of privilege"],
    "IDOR":        ["insecure direct object", "idor", "broken access control"],
}

# ── Persistence ───────────────────────────────────────────────────────────────

def load_seen() -> set:
    try:
        with open(SEEN_FILE) as f:
            return set(json.load(f))
    except Exception:
        return set()

def save_seen(seen: set):
    try:
        with open(SEEN_FILE, "w") as f:
            json.dump(list(seen), f)
    except Exception:
        pass

def load_history() -> list:
    try:
        with open(HISTORY_FILE) as f:
            return json.load(f)
    except Exception:
        return []

def save_history(history: list):
    try:
        # Keep last 500 alerts only
        with open(HISTORY_FILE, "w") as f:
            json.dump(history[-500:], f, indent=2)
    except Exception:
        pass

def add_to_history(cve: dict, matches: list, priority: int):
    history = load_history()
    history.append({
        "cve_id":    cve["id"],
        "score":     cve["score"],
        "severity":  cve["severity"],
        "vuln_type": cve.get("vuln_type", "Unknown"),
        "priority":  priority,
        "matches":   [m["name"] for m in matches],
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
    })
    save_history(history)


# ── Vuln Type Detection ───────────────────────────────────────────────────────

def detect_vuln_type(description: str) -> str:
    desc_lower = description.lower()
    for vtype, keywords in VULN_TYPES.items():
        if any(kw in desc_lower for kw in keywords):
            return vtype
    return "Other"

def matches_filter(vuln_type: str, allowed_types: list) -> bool:
    """Check if vuln type passes the user's filter."""
    if not allowed_types:
        return True  # no filter = allow all
    return vuln_type in allowed_types


# ── Priority Scoring ──────────────────────────────────────────────────────────

async def calc_priority(cve: dict, matches: list) -> int:
    """
    Score from 0-100:
      - CVSS score        → up to 40 pts
      - Vuln type         → up to 20 pts (RCE/SSRF highest)
      - BB match exists   → 20 pts
      - BB program count  → up to 10 pts
      - Network exploitable → 10 pts
    """
    score = 0

    # CVSS (0-40)
    cvss = cve.get("score", 0)
    score += int((cvss / 10) * 40)

    # Vuln type (0-20)
    vtype = cve.get("vuln_type", "Other")
    vtype_scores = {
        "RCE": 20, "SSRF": 17, "SQLi": 15, "Deserialization": 15,
        "Auth Bypass": 13, "LFI/RFI": 12, "XXE": 11,
        "Privilege Escalation": 10, "IDOR": 8, "XSS": 5, "Other": 3,
    }
    score += vtype_scores.get(vtype, 3)

    # BB matches (0-20)
    if matches:
        score += 20

    # BB program count bonus (0-10)
    score += min(len(matches) * 2, 10)

    # Network exploitable (0-10)
    vec = cve.get("vector", "")
    if "AV:N" in vec:
        score += 10

    return min(score, 100)

def priority_label(score: int) -> str:
    if score >= 80: return "🔥 P1 — Critical Priority"
    if score >= 60: return "⚡ P2 — High Priority"
    if score >= 40: return "📌 P3 — Medium Priority"
    return "📋 P4 — Low Priority"


# ── Platform Fetchers ─────────────────────────────────────────────────────────

async def fetch_chaos_programs(platform_filter: list = None) -> list:
    if not CHAOS_API_KEY:
        log.warning("CHAOS_API_KEY not set")
        return []
    url      = "https://chaos-data.projectdiscovery.io/index.json"
    headers  = {"Authorization": CHAOS_API_KEY}
    programs = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=30)) as r:
                if r.status == 401:
                    log.error("Chaos: invalid API key")
                    return []
                if r.status != 200:
                    return []
                data = await r.json(content_type=None)

        for p in data:
            platform = p.get("platform", "")
            # Apply platform filter if set
            if platform_filter and platform.lower() not in [x.lower() for x in platform_filter]:
                continue
            programs.append({
                "platform": f"Chaos/{platform}",
                "name":     p.get("name", ""),
                "handle":   p.get("name", "").lower().replace(" ", "-"),
                "url":      "https://chaos.projectdiscovery.io/#programs",
                "scopes":   [u.lstrip("*.").lower() for u in p.get("urls", []) if u],
                "tech":     [],
            })
        log.info(f"Chaos: {len(programs)} programs loaded")
    except Exception as e:
        log.warning(f"Chaos error: {e}")
    return programs


async def fetch_intigriti_programs() -> list:
    url      = "https://api.intigriti.com/core/researcher/programs?limit=200&offset=0&status=2"
    headers  = {"Accept": "application/json", "User-Agent": "Mozilla/5.0"}
    programs = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status != 200:
                    return []
                data = await r.json()
        records = data.get("records", data) if isinstance(data, dict) else data
        for p in records:
            name   = p.get("name", "") or p.get("companyHandle", "")
            handle = p.get("handle", "") or p.get("programHandle", "")
            scopes = [d.get("endpoint", "").lstrip("*.").lower()
                      for d in p.get("domains", []) if d.get("endpoint")]
            programs.append({
                "platform": "Intigriti",
                "name":     name,
                "handle":   handle,
                "url":      f"https://app.intigriti.com/programs/{handle}",
                "scopes":   scopes,
                "tech":     [],
            })
        log.info(f"Intigriti: {len(programs)} programs loaded")
    except Exception as e:
        log.warning(f"Intigriti error: {e}")
    return programs


async def fetch_wehacktheplanet_programs() -> list:
    programs = [
        {
            "platform": "WeHackThePlanet",
            "name":     "Swisscom",
            "handle":   "swisscom",
            "url":      "https://wehackthe.net/programs/swisscom",
            "scopes":   ["swisscom.ch", "swisscom.com"],
            "tech":     ["cisco", "juniper", "fortinet"],
        },
        {
            "platform": "WeHackThePlanet",
            "name":     "PostFinance",
            "handle":   "postfinance",
            "url":      "https://wehackthe.net/programs/postfinance",
            "scopes":   ["postfinance.ch"],
            "tech":     ["apache", "nginx", "spring"],
        },
        {
            "platform": "WeHackThePlanet",
            "name":     "SBB CFF FFS",
            "handle":   "sbb",
            "url":      "https://wehackthe.net/programs/sbb",
            "scopes":   ["sbb.ch"],
            "tech":     ["java", "spring boot"],
        },
        # أضف programs تانية هنا
    ]
    log.info(f"WeHackThePlanet: {len(programs)} programs (curated)")
    return programs


async def fetch_all_bb_programs(platform_filter: list = None) -> list:
    chaos, inti, whtp = await asyncio.gather(
        fetch_chaos_programs(platform_filter),
        fetch_intigriti_programs(),
        fetch_wehacktheplanet_programs(),
    )
    # Apply platform filter to Intigriti/WHTP
    result = chaos
    if not platform_filter or "intigriti" in [x.lower() for x in platform_filter]:
        result += inti
    if not platform_filter or "wehacktheplanet" in [x.lower() for x in platform_filter]:
        result += whtp
    log.info(f"Total BB programs: {len(result)}")
    return result


# ── CVE ↔ BB Matching ─────────────────────────────────────────────────────────

def extract_keywords_from_cve(cve: dict) -> list:
    keywords = set()
    for cpe in cve.get("cpes", []):
        parts = cpe.split(":")
        if len(parts) >= 5:
            vendor  = parts[3].replace("_", " ").lower()
            product = parts[4].replace("_", " ").lower()
            if vendor  and vendor  != "*": keywords.add(vendor)
            if product and product != "*": keywords.add(product)
            for w in product.split():
                if len(w) > 3: keywords.add(w)

    stopwords = {
        "this","that","with","from","have","been","when","which","they","their",
        "there","could","would","allows","remote","attacker","local","system",
        "using","through","version","before","after","affects","unauthenticated",
        "authenticated","privilege","execute","arbitrary","code","crafted",
        "request","specially","cause","denial","service","injection","cross",
        "site","scripting","buffer","overflow","memory","corruption","null",
        "pointer","vulnerability","component","product",
    }
    desc = cve.get("description", "").lower()
    for w in re.findall(r'\b[a-z][a-z0-9\-]{3,}\b', desc):
        if w not in stopwords and len(w) > 4:
            keywords.add(w)
    return list(keywords)


def match_cve_to_programs(cve: dict, programs: list) -> list:
    keywords = extract_keywords_from_cve(cve)
    matches  = []
    for prog in programs:
        all_text   = " ".join([
            " ".join(prog.get("scopes", [])),
            " ".join(prog.get("tech",   [])),
            prog.get("name", ""),
        ]).lower()
        matched_on = [kw for kw in keywords if len(kw) > 4 and kw in all_text]
        if matched_on:
            matches.append({
                "platform": prog["platform"],
                "name":     prog["name"],
                "url":      prog["url"],
                "matched":  list(set(matched_on))[:5],
                "scopes":   prog.get("scopes", [])[:5],
            })
    return matches


# ── NVD Poller ────────────────────────────────────────────────────────────────

async def poll_new_cves(min_score: float = 7.0) -> list:
    end   = datetime.utcnow()
    start = end - timedelta(hours=2)
    fmt   = "%Y-%m-%dT%H:%M:%S.000"
    url   = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={start.strftime(fmt)}&pubEndDate={end.strftime(fmt)}"
        f"&resultsPerPage=50"
    )
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
                if r.status != 200:
                    return []
                data = await r.json()
    except Exception as e:
        log.warning(f"NVD poll error: {e}")
        return []

    results = []
    for v in data.get("vulnerabilities", []):
        cve     = v["cve"]
        cve_id  = cve["id"]
        metrics = cve.get("metrics", {})
        cvss3   = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
        cvss2   = metrics.get("cvssMetricV2", [])

        score = 0.0
        if cvss3:   score = cvss3[0]["cvssData"].get("baseScore", 0)
        elif cvss2: score = cvss2[0]["cvssData"].get("baseScore", 0)
        if score < min_score:
            continue

        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), ""
        )
        cpes = []
        for node in cve.get("configurations", []):
            for n in node.get("nodes", []):
                for m in n.get("cpeMatch", []):
                    if m.get("vulnerable"):
                        cpes.append(m.get("criteria", ""))

        severity = vector = "N/A"
        if cvss3:
            severity = cvss3[0]["cvssData"].get("baseSeverity", "N/A")
            vector   = cvss3[0]["cvssData"].get("vectorString", "N/A")

        vuln_type = detect_vuln_type(desc)

        results.append({
            "id":          cve_id,
            "score":       score,
            "severity":    severity,
            "vector":      vector,
            "description": desc,
            "cpes":        cpes[:10],
            "published":   cve.get("published", "")[:16].replace("T", " "),
            "vuln_type":   vuln_type,
        })

    return sorted(results, key=lambda x: x["score"], reverse=True)


# ── Alert Formatter ───────────────────────────────────────────────────────────

def format_alert(cve: dict, matches: list, priority: int) -> str:
    score     = cve["score"]
    sev_icon  = "🔴" if score >= 9 else ("🟠" if score >= 7 else "🟡")
    vec       = cve.get("vector", "")
    av        = "Network" if "AV:N" in vec else ("Local" if "AV:L" in vec else "Other")
    pr        = "None"    if "PR:N" in vec else ("Low"   if "PR:L" in vec else "High")
    vtype     = cve.get("vuln_type", "Other")
    p_label   = priority_label(priority)

    vtype_icons = {
        "RCE": "💣", "SQLi": "🗄", "Auth Bypass": "🔓", "SSRF": "🔁",
        "XXE": "📄", "LFI/RFI": "📂", "XSS": "🖥", "Deserialization": "⚙️",
        "Privilege Escalation": "⬆️", "IDOR": "🔐", "Other": "🐛",
    }
    vtype_icon = vtype_icons.get(vtype, "🐛")

    lines = [
        f"{sev_icon} *NEW CVE ALERT*",
        f"{'─'*35}",
        f"🆔 `{cve['id']}`",
        f"📊 CVSS: *{score}* ({cve['severity']})",
        f"{vtype_icon} Type: *{vtype}*",
        f"🏆 Priority: *{p_label}* ({priority}/100)",
        f"📅 Published: `{cve['published']}`",
        f"🧭 Access: {av} | Privileges: {pr}",
        "",
        f"📝 _{cve['description'][:280]}{'...' if len(cve['description']) > 280 else ''}_",
    ]

    if cve.get("cpes"):
        affected = []
        for cpe in cve["cpes"][:3]:
            parts = cpe.split(":")
            if len(parts) >= 5:
                affected.append(f"`{parts[3]}:{parts[4]}`")
        if affected:
            lines += ["", "🖥 *Affected:* " + " · ".join(affected)]

    platform_icon = {"Intigriti": "🏴", "WeHackThePlanet": "🌍"}

    if matches:
        lines += ["", f"🎯 *BB Match! ({len(matches)} program(s)):*"]
        for m in matches[:5]:
            icon = "💰" if "Chaos" in m["platform"] else platform_icon.get(m["platform"], "🎯")
            lines.append(f"{icon} *{m['name']}* _({m['platform']})_")
            lines.append(f"   🔑 `{'`, `'.join(m['matched'][:3])}`")
            if m.get("scopes"):
                lines.append(f"   🌐 `{'`, `'.join(m['scopes'][:2])}`")
    else:
        lines += ["", "ℹ️ _No BB match — CRITICAL score alert_"]

    return "\n".join(lines)


def format_daily_summary(history: list) -> str:
    """Build daily summary from alert history."""
    today     = datetime.utcnow().strftime("%Y-%m-%d")
    today_alerts = [h for h in history if h.get("timestamp", "").startswith(today)]

    if not today_alerts:
        return "📊 *Daily Summary*\n\nمفيش CVE alerts النهارده."

    total     = len(today_alerts)
    p1        = sum(1 for h in today_alerts if h["priority"] >= 80)
    p2        = sum(1 for h in today_alerts if 60 <= h["priority"] < 80)
    with_match = sum(1 for h in today_alerts if h["matches"])

    # Top vuln types
    vtype_count = {}
    for h in today_alerts:
        vt = h.get("vuln_type", "Other")
        vtype_count[vt] = vtype_count.get(vt, 0) + 1
    top_types = sorted(vtype_count.items(), key=lambda x: x[1], reverse=True)[:3]

    lines = [
        f"📊 *Daily Summary — {today}*",
        f"{'─'*35}",
        f"📨 Total alerts: *{total}*",
        f"🔥 P1 Critical: *{p1}*",
        f"⚡ P2 High: *{p2}*",
        f"🎯 With BB match: *{with_match}*",
        "",
        "*Top Vuln Types:*",
    ]
    for vt, count in top_types:
        lines.append(f"  • {vt}: {count}")

    if today_alerts:
        top = sorted(today_alerts, key=lambda x: x["priority"], reverse=True)[:3]
        lines += ["", "*🏆 Top CVEs Today:*"]
        for t in top:
            lines.append(
                f"  🆔 `{t['cve_id']}` — {t['vuln_type']} "
                f"(Priority: {t['priority']}/100)"
            )

    return "\n".join(lines)


# ── Monitor Loop ──────────────────────────────────────────────────────────────

async def monitor_loop(bot, chat_ids: list, interval_minutes: int = 30,
                       min_score: float = 7.0, vuln_filter: list = None,
                       platform_filter: list = None):
    """
    Main monitoring loop.
    vuln_filter: list of vuln types to alert on, e.g. ["RCE", "SQLi"]
                 Empty = alert on all types
    platform_filter: list of platforms, e.g. ["hackerone", "intigriti"]
                     Empty = all platforms
    """
    seen            = load_seen()
    bb_programs     = []
    last_bb_refresh = datetime.min
    last_daily      = None
    consecutive_failures = 0

    log.info(
        f"Monitor v3 started — every {interval_minutes}min | "
        f"CVSS≥{min_score} | filter={vuln_filter or 'all'} | "
        f"{len(chat_ids)} subscriber(s)"
    )

    while True:
        try:
            now = datetime.utcnow()

            # ── Daily summary at 08:00 UTC ────────────────────────────────────
            if (last_daily is None or last_daily.date() < now.date()) and now.hour == 8:
                history = load_history()
                summary = format_daily_summary(history)
                for chat_id in chat_ids:
                    try:
                        await bot.send_message(
                            chat_id=chat_id,
                            text=summary,
                            parse_mode="Markdown",
                        )
                    except Exception as e:
                        log.error(f"Daily summary error → {chat_id}: {e}")
                last_daily = now
                log.info("Daily summary sent.")

            # ── Refresh BB programs every 6h ──────────────────────────────────
            if (now - last_bb_refresh).total_seconds() > 6 * 3600:
                log.info("Refreshing BB programs cache...")
                bb_programs     = await fetch_all_bb_programs(platform_filter)
                last_bb_refresh = now

            # ── Poll NVD ──────────────────────────────────────────────────────
            new_cves = await poll_new_cves(min_score=min_score)
            log.info(f"NVD poll: {len(new_cves)} CVEs ≥ {min_score}")
            consecutive_failures = 0  # reset on success

            for cve in new_cves:
                cve_id = cve["id"]
                if cve_id in seen:
                    continue
                seen.add(cve_id)
                save_seen(seen)

                # Vuln type filter
                if vuln_filter and cve["vuln_type"] not in vuln_filter:
                    log.info(f"  {cve_id} type={cve['vuln_type']} — filtered out")
                    continue

                matches  = match_cve_to_programs(cve, bb_programs)
                priority = await calc_priority(cve, matches)

                # Skip low priority with no BB match
                if not matches and cve["score"] < 9.0:
                    log.info(f"  {cve_id} — no BB match + score<9, skip")
                    continue

                # Save to history
                add_to_history(cve, matches, priority)

                alert_text = format_alert(cve, matches, priority)

                for chat_id in chat_ids:
                    try:
                        await bot.send_message(
                            chat_id=chat_id,
                            text=alert_text,
                            parse_mode="Markdown",
                            disable_web_page_preview=True,
                        )
                        log.info(f"  ✅ Alert → {chat_id}: {cve_id} (P={priority})")
                    except Exception as e:
                        log.error(f"  ❌ {chat_id}: {e}")
                await asyncio.sleep(1)

        except Exception as e:
            log.error(f"Monitor error: {e}")
            consecutive_failures += 1

            # ── Crash alert after 3 consecutive failures ──────────────────────
            if consecutive_failures >= 3:
                for chat_id in chat_ids:
                    try:
                        await bot.send_message(
                            chat_id=chat_id,
                            text=(
                                "⚠️ *Monitor Warning*\n"
                                f"فشل {consecutive_failures} مرات متتالية.\n"
                                f"آخر error: `{str(e)[:200]}`\n"
                                "_البوت هيكمل يحاول تلقائياً._"
                            ),
                            parse_mode="Markdown",
                        )
                    except Exception:
                        pass
                consecutive_failures = 0

        await asyncio.sleep(interval_minutes * 60)
