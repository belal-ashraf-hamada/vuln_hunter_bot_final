#!/usr/bin/env python3
"""
Bug Bounty CVE Monitor — Auto-alert module
Sources: Chaos (projectdiscovery.io) + Intigriti + WeHackThePlanet
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

# ── Seen CVEs persistence ─────────────────────────────────────────────────────

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


# ── Platform Fetchers ─────────────────────────────────────────────────────────

async def fetch_chaos_programs() -> list:
    """
    Fetch all Bug Bounty programs from Chaos (projectdiscovery.io).
    Chaos aggregates HackerOne, Bugcrowd, and others — 5000+ programs.
    API key from: https://chaos.projectdiscovery.io
    """
    if not CHAOS_API_KEY:
        log.warning("CHAOS_API_KEY not set — skipping Chaos fetch")
        return []

    url     = "https://chaos-data.projectdiscovery.io/index.json"
    headers = {"Authorization": CHAOS_API_KEY}
    programs = []

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=30)) as r:
                if r.status == 401:
                    log.error("Chaos API: invalid key")
                    return []
                if r.status != 200:
                    log.warning(f"Chaos API returned {r.status}")
                    return []
                data = await r.json(content_type=None)

        for p in data:
            name     = p.get("name", "")
            platform = p.get("platform", "")
            urls     = p.get("urls", [])        # list of scope URLs/domains
            programs.append({
                "platform": f"Chaos/{platform}",
                "name":     name,
                "handle":   name.lower().replace(" ", "-"),
                "url":      f"https://chaos.projectdiscovery.io/#programs",
                "scopes":   [u.lstrip("*.").lower() for u in urls if u],
                "tech":     [],
            })

        log.info(f"Chaos: loaded {len(programs)} programs")
    except Exception as e:
        log.warning(f"Chaos fetch error: {e}")

    return programs


async def fetch_intigriti_programs() -> list:
    """Fetch public programs from Intigriti API."""
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
            scopes = []
            for domain in p.get("domains", []):
                ep = domain.get("endpoint", "")
                if ep:
                    scopes.append(ep.lstrip("*.").lower())
            programs.append({
                "platform": "Intigriti",
                "name":     name,
                "handle":   handle,
                "url":      f"https://app.intigriti.com/programs/{handle}",
                "scopes":   scopes,
                "tech":     [],
            })
        log.info(f"Intigriti: loaded {len(programs)} programs")
    except Exception as e:
        log.warning(f"Intigriti fetch error: {e}")
    return programs


async def fetch_wehacktheplanet_programs() -> list:
    """
    We Hack The Planet — no public API, use curated list.
    Add your programs here manually.
    """
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
        # ── أضف programs تانية هنا ────────────────────────────────────────────
        # {
        #     "platform": "WeHackThePlanet",
        #     "name":     "Program Name",
        #     "handle":   "handle",
        #     "url":      "https://wehackthe.net/programs/handle",
        #     "scopes":   ["example.com"],
        #     "tech":     ["nginx", "php"],
        # },
    ]
    log.info(f"WeHackThePlanet: {len(programs)} programs (curated)")
    return programs


async def fetch_all_bb_programs() -> list:
    """Fetch all programs from all platforms concurrently."""
    chaos, inti, whtp = await asyncio.gather(
        fetch_chaos_programs(),
        fetch_intigriti_programs(),
        fetch_wehacktheplanet_programs(),
    )
    total = chaos + inti + whtp
    log.info(f"Total BB programs loaded: {len(total)}")
    return total


# ── CVE ↔ BB Matching Engine ──────────────────────────────────────────────────

def extract_keywords_from_cve(cve: dict) -> list:
    """Extract vendor/product keywords from CVE CPEs + description."""
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

    desc      = cve.get("description", "").lower()
    stopwords = {
        "this","that","with","from","have","been","when","which","they",
        "their","there","could","would","allows","remote","attacker","local",
        "system","using","through","version","before","after","affects",
        "unauthenticated","authenticated","privilege","execute","arbitrary",
        "code","crafted","request","specially","cause","denial","service",
        "injection","cross","site","scripting","buffer","overflow","memory",
        "corruption","null","pointer","vulnerability","component","product",
    }
    for w in re.findall(r'\b[a-z][a-z0-9\-]{3,}\b', desc):
        if w not in stopwords and len(w) > 4:
            keywords.add(w)

    return list(keywords)


def match_cve_to_programs(cve: dict, programs: list) -> list:
    """Match CVE keywords against BB program scopes. Returns matched programs."""
    keywords = extract_keywords_from_cve(cve)
    matches  = []

    for prog in programs:
        scope_text = " ".join(prog.get("scopes", [])).lower()
        tech_text  = " ".join(prog.get("tech",   [])).lower()
        name_text  = prog.get("name", "").lower()
        all_text   = f"{scope_text} {tech_text} {name_text}"

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
    """Poll NVD for CVEs published in the last 2 hours."""
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

        results.append({
            "id":          cve_id,
            "score":       score,
            "severity":    severity,
            "vector":      vector,
            "description": desc,
            "cpes":        cpes[:10],
            "published":   cve.get("published", "")[:16].replace("T", " "),
        })

    return sorted(results, key=lambda x: x["score"], reverse=True)


# ── Alert Formatter ───────────────────────────────────────────────────────────

def format_alert(cve: dict, matches: list) -> str:
    score    = cve["score"]
    sev_icon = "🔴" if score >= 9 else ("🟠" if score >= 7 else "🟡")
    vec      = cve.get("vector", "")
    av       = "Network" if "AV:N" in vec else ("Local" if "AV:L" in vec else "Other")
    pr       = "None"    if "PR:N" in vec else ("Low"   if "PR:L" in vec else "High")

    lines = [
        f"{sev_icon} *NEW CVE ALERT*",
        f"{'─'*35}",
        f"🆔 `{cve['id']}`",
        f"📊 CVSS: *{score}* ({cve['severity']})",
        f"📅 Published: `{cve['published']}`",
        f"🧭 Access: {av} | Privileges: {pr}",
        "",
        f"📝 _{cve['description'][:300]}{'...' if len(cve['description']) > 300 else ''}_",
    ]

    if cve.get("cpes"):
        affected = []
        for cpe in cve["cpes"][:3]:
            parts = cpe.split(":")
            if len(parts) >= 5:
                affected.append(f"`{parts[3]}:{parts[4]}`")
        if affected:
            lines += ["", "🖥 *Affected:* " + " · ".join(affected)]

    platform_icon = {
        "Intigriti":      "🏴",
        "WeHackThePlanet": "🌍",
    }

    if matches:
        lines += ["", f"🎯 *Bug Bounty Match! ({len(matches)} program(s)):*"]
        for m in matches[:5]:
            # Chaos programs have platform like "Chaos/hackerone"
            icon = "💰" if "Chaos" in m["platform"] else platform_icon.get(m["platform"], "🎯")
            lines.append(f"{icon} *{m['name']}* _({m['platform']})_")
            lines.append(f"   🔑 Matched: `{'`, `'.join(m['matched'][:3])}`")
            if m.get("scopes"):
                lines.append(f"   🌐 Scope: `{'`, `'.join(m['scopes'][:3])}`")
            lines.append(f"   🔗 {m['url']}")
    else:
        lines += ["", "ℹ️ _No Bug Bounty program match found_"]

    return "\n".join(lines)


# ── Monitor Loop ──────────────────────────────────────────────────────────────

async def monitor_loop(bot, chat_ids: list,
                       interval_minutes: int = 30, min_score: float = 7.0):
    seen            = load_seen()
    bb_programs     = []
    last_bb_refresh = datetime.min

    log.info(f"Monitor started — every {interval_minutes}min, CVSS≥{min_score}, {len(chat_ids)} subscriber(s)")

    while True:
        try:
            # Refresh BB cache every 6h
            if (datetime.utcnow() - last_bb_refresh).total_seconds() > 6 * 3600:
                log.info("Refreshing BB programs cache...")
                bb_programs     = await fetch_all_bb_programs()
                last_bb_refresh = datetime.utcnow()

            new_cves = await poll_new_cves(min_score=min_score)
            log.info(f"NVD poll: {len(new_cves)} CVEs ≥ {min_score}")

            for cve in new_cves:
                cve_id = cve["id"]
                if cve_id in seen:
                    continue
                seen.add(cve_id)
                save_seen(seen)

                matches = match_cve_to_programs(cve, bb_programs)

                # Alert only if BB match exists OR critical (≥9)
                if not matches and cve["score"] < 9.0:
                    log.info(f"  {cve_id} — no BB match, skip")
                    continue

                alert_text = format_alert(cve, matches)
                for chat_id in chat_ids:
                    try:
                        await bot.send_message(
                            chat_id=chat_id,
                            text=alert_text,
                            parse_mode="Markdown",
                            disable_web_page_preview=True,
                        )
                        log.info(f"  ✅ Alert → {chat_id}: {cve_id}")
                    except Exception as e:
                        log.error(f"  ❌ Alert failed → {chat_id}: {e}")
                await asyncio.sleep(1)

        except Exception as e:
            log.error(f"Monitor error: {e}")

        await asyncio.sleep(interval_minutes * 60)
