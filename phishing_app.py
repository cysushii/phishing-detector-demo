

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

# Sound helper
def play_alert_sound():
    try:
        import winsound
        winsound.Beep(1000, 300)
    except Exception:
        # create small sine WAV and play via st.audio
        sample_rate = 22050
        duration_s = 0.22
        frequency = 880.0
        n_samples = int(sample_rate * duration_s)
        buf = io.BytesIO()
        with wave.open(buf, "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(sample_rate)
            for i in range(n_samples):
                t = i / sample_rate
                value = int((0.25 * 32767) * math.sin(2 * math.pi * frequency * t))
                wf.writeframes(struct.pack('<h', value))
        buf.seek(0)
        try:
            st.audio(buf.read(), format="audio/wav")
        except Exception:
            pass

# ----------------------------
# Mock employees (auto-generate many entries)
# ----------------------------
NUM_EMPLOYEES = 30
EMPLOYEES = {}
for i in range(1, NUM_EMPLOYEES + 1):
    eid = f"E{i:03d}"
    name = f"Employee {i}"
    email = f"employee{i}@company.local"
    EMPLOYEES[eid] = {"name": name, "email": email}

# runtime state: events per employee
STATE = {
    "events": {eid: [] for eid in EMPLOYEES.keys()},  # each event: dict
    "visit_counts": {eid: [] for eid in EMPLOYEES.keys()},  # counters per interval
}

# org trusted domains (whitelist)
ORG_TRUSTED_DOMAINS = {"company.local", "intranet.company.local"}

# Test URL lists
PHISHING_URLS = [
    "http://example.com/login-update",
    "http://secure-bank.verify.me",
    "https://paypal.com.verify-account.cn",
    "http://apple.id-login-reset.com",
    "http://secure-update-account.net",
    "https://microsoft-support-login.ru",
    "http://bankofamerica.secure-access.info",
    "https://dropbox-login-files.net",
    "http://facebook-security-check.xyz",
    "http://instagram.verify-login.pw",
    "https://amazon.account-update.io",
    "http://google.drive-secure-login.ga",
    "https://netflix.re-activate-account.shop",
    "http://secure-chasebank-login.top",
    "http://paypal.com.security-check.tk",
    "https://icloud-verify-account.cf",
    "http://yahoo.recovery-login.ml",
]

SAFE_URLS = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://www.github.com",
    "https://www.stackoverflow.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.amazon.in",
    "https://www.netflix.com",
    "https://www.nytimes.com",
    "https://www.bbc.com",
    "https://www.linkedin.com",
    "https://www.reddit.com",
    "https://www.instagram.com",
    "https://www.whatsapp.com",
    "https://www.dropbox.com",
]

# Mock mailbox (keeps earlier behavior)
MOCK_MAILBOX = [
    """Subject: Meeting tomorrow
From: teamlead@company.com
To: you@example.com

Hi, just a reminder about tomorrow's meeting. 
Here’s the agenda: http://company.com/agenda
""",
    """Subject: Urgent - Verify your account now!
From: fakebank@secure-login.com
To: you@example.com

Dear user,
Please verify your account immediately by clicking the link:
http://secure-chasebank-login.top/verify
""",
    f"""Subject: Please check these links
From: alerts@random.com
To: you@example.com

Hi,
Please review:
- {SAFE_URLS[0]}
- {PHISHING_URLS[0]}
- {SAFE_URLS[2]}
Thanks.
""",
    """Subject: Your account has been locked
From: support@payment-update.example
To: you@example.com

We detected suspicious sign-in. Reset immediately:
https://paypal.com.verify-account.cn/reset
""",
]

# ----------------------------
# Core helpers
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
    """Return (is_phish, evidence_list) and update event log (no scoring)."""
    evidence = []
    phish = False
    if is_trusted_domain(url):
        evidence.append("trusted domain (org policy)")
    if is_suspicious_keyword(url):
        evidence.append("suspicious keyword in URL")
        phish = True
    d = domain_of(url)
    if re.search(r"[0-9]+", d) and any(x in d for x in ("amazon", "paypal", "bank", "login")):
        evidence.append("possible lookalike domain/homoglyph")
        phish = True
    event = {"time": time.time(), "type": "url_visit", "url": url, "phish": phish, "evidence": evidence}
    STATE["events"][eid].insert(0, event)
    STATE["events"][eid] = STATE["events"][eid][:500]  # keep recent history
    # update visit count for current interval
    if not STATE["visit_counts"][eid]:
        STATE["visit_counts"][eid].append(1)
    else:
        STATE["visit_counts"][eid][-1] += 1
    return phish, evidence

# ----------------------------
# Simulated periodic system checks (no scoring)
# ----------------------------
async def simulated_system_checks(run_seconds=30, interval=5):
    start = time.time()
    while time.time() - start < run_seconds:
        # start new interval counters
        for eid in EMPLOYEES.keys():
            STATE["visit_counts"][eid].append(0)
            if len(STATE["visit_counts"][eid]) > 40:
                STATE["visit_counts"][eid].pop(0)
        # simulate activity
        for eid in EMPLOYEES.keys():
            visits = random.randint(0, 3)  # small activity per interval
            for _ in range(visits):
                url = random.choice(SAFE_URLS) if random.random() < 0.76 else random.choice(PHISHING_URLS)
                phish, evidence = evaluate_url_for_employee(eid, url)
                if phish:
                    play_alert_sound()
                await asyncio.sleep(0.02)
            # small chance of malware event
            if random.random() < 0.03:
                ev = {"time": time.time(), "type": "malware", "desc": "Simulated malware-like behavior detected"}
                STATE["events"][eid].insert(0, ev)
        await asyncio.sleep(interval)

# ----------------------------
# Async email parsing (simple)
# ----------------------------
async def parse_email(raw_email: str):
    msg = message_from_string(raw_email)
    subject = msg.get("subject", "(no subject)")
    body = msg.get_payload() or ""
    urls = extract_urls(str(body))
    flagged = [url for url in urls if is_suspicious_keyword(url)]
    return subject, urls, flagged

# ----------------------------
# Summary helpers
# ----------------------------
def summarize_employee_events(eid: str):
    evs = STATE["events"].get(eid, [])
    total = sum(1 for e in evs if e.get("type") == "url_visit")
    phish = sum(1 for e in evs if e.get("type") == "url_visit" and e.get("phish"))
    safe = total - phish
    malware = sum(1 for e in evs if e.get("type") == "malware")
    return {"total_visits": total, "phish_visits": phish, "safe_visits": safe, "malware_events": malware}

# ----------------------------
# Streamlit UI
# ----------------------------
st.set_page_config(page_title="Phishing PoC — Many Employees", layout="wide")
st.title("Phishing Detector PoC — Many Employees (Simplified Summary)")

col1, col2 = st.columns([1, 2])

with col1:
    st.header("Controls")
    run_sim = st.button("▶ Start simulation (30s)")
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
            if phish:
                st.error(f"⚠ URL flagged for {sel_eid}: {', '.join(evidence) if evidence else ''}")
                play_alert_sound()
            else:
                st.success(f"✅ URL logged as safe for {sel_eid}. Evidence: {', '.join(evidence) if evidence else 'none'}")

with col2:
    st.header("Employee Events & Summary")
    # summary table for all employees
    st.subheader("Summary table")
    summary_rows = []
    for eid, meta in EMPLOYEES.items():
        s = summarize_employee_events(eid)
        summary_rows.append({"Employee ID": eid, "Name": meta["name"], "Email": meta["email"],
                             "Total Visits": s["total_visits"], "Phish Visits": s["phish_visits"],
                             "Safe Visits": s["safe_visits"], "Malware Events": s["malware_events"]})
    st.table(summary_rows)

    st.markdown("---")
    st.subheader("View recent events for an employee")
    eid_view = st.selectbox("Choose employee to view events", list(EMPLOYEES.keys()), index=0)
    evs = STATE["events"].get(eid_view, [])
    if not evs:
        st.write("No recent events for this employee.")
    else:
        for ev in evs[:60]:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ev["time"]))
            if ev["type"] == "url_visit":
                tag = "PHISH" if ev["phish"] else "SAFE"
                st.write(f"- [{ts}] URL visit — {ev['url']} — {tag} — evidence: {', '.join(ev['evidence']) if ev['evidence'] else 'none'}")
            else:
                st.write(f"- [{ts}] {ev['type'].upper()} — {ev.get('desc','')}")

st.markdown("---")
st.subheader("Mailbox & URL scanning")
placeholder = st.empty()
results_placeholder = st.empty()

if st.button("📩 Run Mock Mailbox Scan"):
    st.info("Scanning mock mailbox...")
    async def run_mail_scan():
        rows = []
        for idx, mail in enumerate(MOCK_MAILBOX, 1):
            subject, urls, flagged = await parse_email(mail)
            with placeholder.container():
                st.write(f"**Email {idx}:** {subject}")
                st.write(f"**URLs Found:** {urls if urls else 'None found'}")
                if flagged:
                    st.error(f"⚠ Suspicious links detected: {flagged}")
                    play_alert_sound()
                else:
                    st.success("✅ No suspicious links found!")
            rows.append({"Email": idx, "Subject": subject, "URLs": ", ".join(urls) if urls else "", "Flagged": ", ".join(flagged) if flagged else ""})
            await asyncio.sleep(1.0)
        results_placeholder.table(rows)
    asyncio.run(run_mail_scan())

if st.button("🔎 Scan Test URL Lists now"):
    st.info("Scanning test URL lists...")
    scan_results = []
    for url in PHISHING_URLS + SAFE_URLS:
        ph = is_suspicious_keyword(url)
        scan_results.append({"url": url, "status": "PHISH" if ph else "SAFE"})
        if ph:
            play_alert_sound()
    st.table(scan_results)

if run_sim:
    st.info("Starting simulation (30 seconds)...")
    asyncio.run(simulated_system_checks(run_seconds=30, interval=4))
    st.success("Simulation finished. Summary updated.")

st.markdown(
    "----\n**Notes:** This is an educational demo using keyword heuristics. For production: add robust parsing, URL expansion, reputation checks, and human review."
)
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
