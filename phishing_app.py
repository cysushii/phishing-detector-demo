# phishing_app.py

2
# Run: streamlit run phishing_app.py

import re, asyncio, random, time, io, math, wave, struct
from email import message_from_string
import streamlit as st

# ----------------------------
# Utilities (URL extraction + simple rules)
# ----------------------------
def extract_urls(text: str):
    if not text:
        return []
    return re.findall(r"(https?://[^\s]+)", text)

def is_suspicious_keyword(url: str):
    suspicious_patterns = ["login", "verify", "bank", "update", "secure", "account", "reset", "re-activate"]
    return any(p in url.lower() for p in suspicious_patterns)

# Simple alert sound helper (Streamlit cloud fallback included)
def play_alert_sound():
    try:
        import winsound
        winsound.Beep(1000, 300)
    except Exception:
        # generate simple wav and stream via st.audio (works in browser)
        sample_rate = 22050
        duration_s = 0.25
        frequency = 880.0
        n_samples = int(sample_rate * duration_s)
        buf = io.BytesIO()
        with wave.open(buf, "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(sample_rate)
            for i in range(n_samples):
                t = i / sample_rate
                amplitude = 0.25 * 32767
                value = int(amplitude * math.sin(2 * math.pi * frequency * t))
                wf.writeframes(struct.pack('<h', value))
        buf.seek(0)
        try:
            st.audio(buf.read(), format="audio/wav")
        except Exception:
            pass

# ----------------------------
# Cyber-DNA PoC state (mock employees + org policy)
# ----------------------------
EMPLOYEES = {
    "E001": {"name": "Asha R", "email": "asha.r@company.local"},
    "E002": {"name": "Ravi K", "email": "ravi.k@company.local"},
    "E003": {"name": "Sneha M", "email": "sneha.m@company.local"},
}

# store runtime state: recent events per employee and baseline stats
STATE = {
    "events": {eid: [] for eid in EMPLOYEES.keys()},  # each event: dict
    "visit_counts": {eid: [] for eid in EMPLOYEES.keys()},  # history of counts per interval
    "risk_scores": {eid: 0.0 for eid in EMPLOYEES.keys()},
}

# org policy: trusted domains (whitelist)
ORG_TRUSTED_DOMAINS = {"company.local", "intranet.company.local"}

# some test URLs (phishing + safe)
PHISHING_URLS = [
    "http://secure-chasebank-login.top/verify",
    "http://paypal.com.verify-account.cn/reset",
    "http://example.com/login-update",
    "https://amazon.account-update.io",
]
SAFE_URLS = [
    "https://www.google.com",
    "https://www.company.local/dashboard",
    "https://www.github.com",
]

# ----------------------------
# Core functions
# ----------------------------
def domain_of(url: str):
    try:
        return re.sub(r"^https?://", "", url).split("/")[0].lower()
    except Exception:
        return ""

def is_trusted_domain(url: str):
    d = domain_of(url)
    return any(d.endswith(td) for td in ORG_TRUSTED_DOMAINS)

def evaluate_url_for_employee(eid: str, url: str):
    """Return (is_phish, evidence_list) and update event log"""
    evidence = []
    phish = False
    if is_trusted_domain(url):
        evidence.append("trusted domain (org policy)")
    if is_suspicious_keyword(url):
        evidence.append("suspicious keyword in URL")
        phish = True
    d = domain_of(url)
    # simple lookalike heuristic: digits/letters replacing letters (e.g., amaz0n)
    if re.search(r"[0-9]+", d) and any(x in d for x in ("amazon","paypal","bank","login")):
        evidence.append("possible lookalike domain/homoglyph")
        phish = True
    # update event
    event = {"time": time.time(), "type": "url_visit", "url": url, "phish": phish, "evidence": evidence}
    STATE["events"][eid].insert(0, event)
    # keep only recent 50 events
    STATE["events"][eid] = STATE["events"][eid][:50]
    # update visit_counts for baseline (count per interval)
    if not STATE["visit_counts"][eid]:
        STATE["visit_counts"][eid].append(1)
    else:
        STATE["visit_counts"][eid][-1] += 1
    return phish, evidence

def compute_risk_score(eid: str):
    """Compute a simple risk score from recent events and baseline anomalies"""
    events = STATE["events"].get(eid, [])
    # base score = fraction of recent events flagged phish (weighted)
    if not events:
        base = 0.0
    else:
        last_n = events[:20]
        phish_count = sum(1 for e in last_n if e.get("phish"))
        base = phish_count / max(1, len(last_n))
    # baseline anomaly: if last interval count is 3x median previous -> increase risk
    counts = STATE["visit_counts"].get(eid, [])
    anomaly = 0.0
    if len(counts) >= 4:
        median = sorted(counts[:-1])[len(counts[:-1])//2]
        last = counts[-1]
        if median > 0 and last >= 3 * median:
            anomaly = 0.4
    # malware simulation: count malware events
    malware_count = sum(1 for e in events if e.get("type")=="malware" and (time.time()-e["time"])<3600)
    mal_score = min(0.5, 0.2 * malware_count)
    score = min(1.0, base * 0.6 + anomaly + mal_score)
    STATE["risk_scores"][eid] = round(score, 3)
    return STATE["risk_scores"][eid]

# ----------------------------
# Simulated periodic system checker (async)
# ----------------------------
async def simulated_system_checks(run_seconds=30, interval=5):
    """Simulate background checks: every `interval` seconds, for each employee:
       - reset a visit counter for the upcoming interval
       - randomly generate a few URL visits (using safe+phish lists)
       - sometimes generate a 'malware' event
    """
    # we'll run for run_seconds seconds in demo; in production this would be infinite
    start = time.time()
    while time.time() - start < run_seconds:
        # new interval: append a zero counter for each employee
        for eid in EMPLOYEES.keys():
            STATE["visit_counts"][eid].append(0)
            # cap history length
            if len(STATE["visit_counts"][eid])>12:
                STATE["visit_counts"][eid].pop(0)
        # simulate activity
        for eid in EMPLOYEES.keys():
            # each employee visits between 0..4 URLs this interval
            visits = random.randint(0,4)
            for _ in range(visits):
                # 70% safe, 30% phishing
                url = random.choice(SAFE_URLS) if random.random() < 0.7 else random.choice(PHISHING_URLS)
                phish, evidence = evaluate_url_for_employee(eid, url)
                if phish:
                    play_alert_sound()
                # small delay to let UI update nicely
                await asyncio.sleep(0.1)
            # sometimes (5% chance) a malware event appears
            if random.random() < 0.05:
                ev = {"time": time.time(), "type": "malware", "desc": "Possible malware behavior detected (simulated)"}
                STATE["events"][eid].insert(0, ev)
        # after interval compute risk scores
        for eid in EMPLOYEES.keys():
            compute_risk_score(eid)
        await asyncio.sleep(interval)

# ----------------------------
# Streamlit UI
# ----------------------------
st.set_page_config(page_title="Cyber-DNA Phishing + Employee Monitor", layout="wide")
st.title("Cyber-DNA PoC — Employee Phishing Monitor")

# Left column: controls / employee selection
col1, col2 = st.columns([1,2])

with col1:
    st.header("Controls")
    run_sim = st.button("▶ Start simulated system checks (30s)")
    stop_sim = st.button("⏹ Stop simulation (no-op in demo)")
    st.write("Trusted org domains (comma-separated):")
    td_input = st.text_input("Trusted domains", value=",".join(ORG_TRUSTED_DOMAINS))
    if td_input.strip():
        ORG_TRUSTED_DOMAINS.clear()
        for d in [x.strip().lower() for x in td_input.split(",") if x.strip()]:
            ORG_TRUSTED_DOMAINS.add(d)
    st.markdown("---")
    st.subheader("Sync URL for Employee")
    sel_eid = st.selectbox("Employee", list(EMPLOYEES.keys()))
    input_url = st.text_input("Paste URL to sync/check for selected employee")
    if st.button("Check URL for Employee"):
        if input_url.strip():
            phish, evidence = evaluate_url_for_employee(sel_eid, input_url.strip())
            compute_risk_score(sel_eid)
            if phish:
                st.error(f"⚠ URL flagged for {sel_eid}: {evidence}")
                play_alert_sound()
            else:
                st.success(f"✅ URL looks safe for {sel_eid}. {evidence or ''}")

with col2:
    st.header("Employee Dashboard")
    # show risk scores and recent events
    rows = []
    for eid, meta in EMPLOYEES.items():
        score = compute_risk_score(eid)
        rows.append((eid, meta["name"], meta["email"], score))
    # table style
    st.subheader("Risk Summary")
    for eid, name, email, score in rows:
        if score >= 0.6:
            st.markdown(f"**{eid} — {name} ({email}) — RISK: {score}** 🔴")
        elif score >= 0.3:
            st.markdown(f"**{eid} — {name} ({email}) — RISK: {score}** 🟠")
        else:
            st.markdown(f"**{eid} — {name} ({email}) — RISK: {score}** 🟢")
    st.markdown("---")
    st.subheader("Recent Events (per employee)")
    eid_view = st.selectbox("Choose employee to view events", list(EMPLOYEES.keys()), index=0)
    evs = STATE["events"].get(eid_view, [])
    if not evs:
        st.write("No recent events.")
    else:
        for ev in evs[:10]:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ev["time"]))
            if ev["type"] == "url_visit":
                tag = "PHISH" if ev["phish"] else "SAFE"
                st.write(f"- [{ts}] URL visit — {ev['url']} — {tag} — evidence: {', '.join(ev['evidence']) if ev['evidence'] else 'none'}")
            else:
                st.write(f"- [{ts}] {ev['type'].upper()} — {ev.get('desc','')}")

    st.markdown("---")
    st.subheader("Quick actions")
    if st.button("Scan all test URLs now"):
        # run a quick synchronous scan (demo)
        scan_results = []
        for url in PHISHING_URLS + SAFE_URLS:
            ph = is_suspicious_keyword(url)
            scan_results.append({"url": url, "status": "PHISH" if ph else "SAFE"})
            if ph:
                play_alert_sound()
        st.table(scan_results)

# Start simulated checks when button pressed
if run_sim:
    st.info("Starting simulated system checks for 30 seconds...")
    # run the coroutine (demo-length)
    asyncio.run(simulated_system_checks(run_seconds=30, interval=4))
    st.success("Simulation complete. Check dashboard for updates.")
