# phishing_app.py
# Phishing Detector PoC — more employees + simplified per-employee summary
# - auto-generates 30 mock employees (E001..E030)
# - simulated system checks, per-employee URL sync/check
# - per-employee summary table: total visits, phish visits, safe visits
# - alerts + sound
#
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
# ----------------------------
# Mock employee directory with seeded activity
# ----------------------------
EMPLOYEES = [
    {"id": 101, "name": "Alice",   "email": "alice@company.com",   "history": []},
    {"id": 102, "name": "Bob",     "email": "bob@company.com",     "history": []},
    {"id": 103, "name": "Charlie", "email": "charlie@company.com", "history": []},
    {"id": 104, "name": "Diana",   "email": "diana@company.com",   "history": []},
    {"id": 105, "name": "Eve",     "email": "eve@company.com",     "history": []},
    {"id": 106, "name": "Frank",   "email": "frank@company.com",   "history": []},
    {"id": 107, "name": "Grace",   "email": "grace@company.com",   "history": []},
    {"id": 108, "name": "Henry",   "email": "henry@company.com",   "history": []},
]

def seed_employee_history():
    """Pre-fill some visits so summary table looks alive."""
    sample_visits = [
        {"url": "https://www.google.com", "status": "SAFE"},
        {"url": "http://secure-bank.verify.me", "status": "PHISH"},
        {"url": "https://www.github.com", "status": "SAFE"},
        {"url": "http://apple.id-login-reset.com", "status": "PHISH"},
        {"url": "MALWARE", "status": "MALWARE"},
    ]
    import random
    for emp in EMPLOYEES:
        # Give each employee 3–6 random visits
        emp["history"] = random.sample(sample_visits, k=random.randint(3, 6))

# Call this once at startup
seed_employee_history()

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
