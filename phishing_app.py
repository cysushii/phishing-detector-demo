# phishing_app.py
# CyberDNA Phishing PoC (no sound) — corrected & complete
# - mock mailbox scanning
# - multiple mock employees with seeded histories
# - simulate activity to populate histories
# - simple per-employee summary table (Total / Safe / Phishing / Malware)
# - buttons to run mailbox scan, simulate activity, and scan test URL lists
#
# Run: streamlit run phishing_app.py

import re
import asyncio
import random
import pandas as pd
import streamlit as st
from email import message_from_string

# ---------------------------
# Test URL lists (must be defined early)
# ---------------------------
phishing_test_urls = [
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

safe_test_urls = [
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

# ---------------------------
# Utility: extract URLs
# ---------------------------
def extract_urls(text: str):
    return re.findall(r"(https?://[^\s]+)", text) if text else []

# ---------------------------
# Rule engine for phishing
# ---------------------------
def is_phishing_url(url: str):
    suspicious_patterns = ["login", "verify", "bank", "update", "secure", "password", "account"]
    return any(p in url.lower() for p in suspicious_patterns)

# ---------------------------
# Async parser for emails
# ---------------------------
async def parse_email(raw_email: str):
    msg = message_from_string(raw_email)
    subject = msg.get("subject", "(no subject)")
    body = msg.get_payload() or ""
    urls = extract_urls(str(body))
    flagged = [url for url in urls if is_phishing_url(url)]
    return subject, urls, flagged

# ---------------------------
# Mock Mailbox
# ---------------------------
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
Please verify your account immediately:
http://secure-login.fakebank.com/verify
""",
    """Subject: Security update
From: it-support@company.com
To: you@example.com

Please download the update from: http://company-secure.com/update
""",
]

# ---------------------------
# Mock Employees (seeded histories)
# ---------------------------
EMPLOYEES = [
    {"id": "E101", "name": "Alice",   "email": "alice@company.com",   "history": []},
    {"id": "E102", "name": "Bob",     "email": "bob@company.com",     "history": []},
    {"id": "E103", "name": "Charlie", "email": "charlie@company.com", "history": []},
    {"id": "E104", "name": "David",   "email": "david@company.com",   "history": []},
    {"id": "E105", "name": "Eva",     "email": "eva@company.com",     "history": []},
    {"id": "E106", "name": "Frank",   "email": "frank@company.com",   "history": []},
    {"id": "E107", "name": "Grace",   "email": "grace@company.com",   "history": []},
]

# ---------------------------
# Sample websites (safe + phishing mix)
# ---------------------------
sample_visits = [
    "https://docs.python.org",
    "http://fake-paypal-login.cn",
    "https://outlook.office.com",
    "http://steal-passwords.biz",
    "https://company-portal.com",
    "http://verify-bank-login.ru",
    "https://github.com",
    "http://secure-update-now.cc",
    "https://khanacademy.org",
]

# ---------------------------
# Seed employee history (use random.choices to allow duplicates)
# ---------------------------
def seed_employee_history():
    sample_visits_extended = [
        "https://docs.python.org",
        "http://fake-paypal-login.cn",
        "https://outlook.office.com",
        "http://steal-passwords.biz",
        "https://company-portal.com",
        "http://verify-bank-login.ru",
        "https://github.com",
        "http://secure-update-now.cc",
        "https://khanacademy.org",
        "https://www.google.com",
        "https://www.wikipedia.org",
        "http://apple.id-login-reset.com",
        "http://example.com/login-update",
        "MALWARE"
    ]
    for emp in EMPLOYEES:
        emp["history"] = random.choices(sample_visits_extended, k=random.randint(3, 6))

seed_employee_history()

# ---------------------------
# Employee helpers
# ---------------------------
def add_visit(emp_id, url, status):
    for emp in EMPLOYEES:
        if emp["id"] == emp_id:
            emp["history"].append(url if status != "MALWARE" else "MALWARE")
            return

def build_employee_summary():
    rows = []
    for emp in EMPLOYEES:
        total = len(emp["history"])
        phish = sum(1 for h in emp["history"] if (h != "MALWARE" and is_phishing_url(h)))
        malware = sum(1 for h in emp["history"] if h == "MALWARE")
        safe = total - phish - malware
        rows.append({
            "Employee ID": emp["id"],
            "Name": emp["name"],
            "Email": emp["email"],
            "Total Visits": total,
            "Safe Visits": safe,
            "Phishing Visits": phish,
            "Malware Events": malware,
        })
    return rows

# ---------------------------
# Async tasks (mailbox / scan / simulate)
# ---------------------------
async def monitor_mailbox():
    placeholder = st.empty()
    for idx, mail in enumerate(MOCK_MAILBOX, 1):
        subject, urls, flagged = await parse_email(mail)
        with placeholder.container():
            st.write(f"**Email {idx}:** {subject}")
            st.write(f"**URLs Found:** {urls}")
            if flagged:
                st.error(f"⚠ Suspicious links detected: {flagged}")
            else:
                st.success("✅ No suspicious links found!")
        await asyncio.sleep(2)

async def scan_url_lists(phishing_list, safe_list, results_placeholder):
    combined = []
    for url in phishing_list + safe_list:
        is_flagged = is_phishing_url(url)
        combined.append({"url": url, "status": "PHISH" if is_flagged else "SAFE"})
        if is_flagged:
            with results_placeholder.container():
                st.error(f"⚠ PHISHING: {url}")
        await asyncio.sleep(0.05)
    return combined

async def simulate_employee_activity(rounds=10, delay=1.5):
    for _ in range(rounds):
        emp = random.choice(EMPLOYEES)
        if random.random() < 0.7:
            url = random.choice(sample_visits)
            status = "SAFE" if not is_phishing_url(url) else "PHISH"
        else:
            url = random.choice(sample_visits)
            status = "PHISH" if is_phishing_url(url) else "SAFE"
        add_visit(emp["id"], url, status)
        # small chance of malware event
        if random.random() < 0.08:
            add_visit(emp["id"], "MALWARE", "MALWARE")
        await asyncio.sleep(delay)

# ---------------------------
# Streamlit UI
# ---------------------------
st.set_page_config(page_title="CyberDNA Phishing PoC", layout="wide")
st.title("🔒 CyberDNA — Phishing Detection & Employee Monitor (No Sound)")

col1, col2 = st.columns([1, 2])

with col1:
    st.header("Controls")
    if st.button("Simulate Activity (10 rounds)"):
        asyncio.run(simulate_employee_activity(rounds=10, delay=0.6))
        st.success("Simulation complete — table updated.")
    st.markdown("---")
    st.subheader("Sync URL for Employee")
    emp_ids = [emp["id"] for emp in EMPLOYEES]
    sel_emp = st.selectbox("Employee", emp_ids)
    input_url = st.text_input("Paste URL to log for selected employee")
    if st.button("Check & Log URL"):
        if input_url.strip():
            status = "MALWARE" if input_url.strip().upper() == "MALWARE" else ("PHISH" if is_phishing_url(input_url) else "SAFE")
            add_visit(sel_emp, input_url.strip(), status)
            if status == "PHISH":
                st.error(f"⚠ URL flagged as phishing and logged for {sel_emp}")
            elif status == "MALWARE":
                st.error(f"⚠ Malware-like event logged for {sel_emp}")
            else:
                st.success(f"✅ URL logged as safe for {sel_emp}")

with col2:
    st.header("Employee Activity Summary")
    summary = build_employee_summary()
    df = pd.DataFrame(summary)
    st.table(df)

    st.markdown("---")
    st.subheader("View recent events for an employee")
    view_emp = st.selectbox("Choose employee to view events", emp_ids, index=0)
    emp_obj = next((e for e in EMPLOYEES if e["id"] == view_emp), None)
    if emp_obj is None or not emp_obj["history"]:
        st.write("No recent events for this employee.")
    else:
        # show the most recent 40 events (reverse so newest first)
        for entry in emp_obj["history"][-40:][::-1]:
            if entry == "MALWARE":
                st.write(f"- [MALWARE EVENT] — simulated malware behavior")
            else:
                tag = "PHISH" if is_phishing_url(entry) else "SAFE"
                st.write(f"- [{tag}] {entry}")

st.markdown("---")
st.subheader("Mailbox & URL scanning")
placeholder = st.empty()
results_placeholder = st.empty()

if st.button("Run Mock Mailbox Scan"):
    st.info("Scanning mock mailbox...")
    asyncio.run(monitor_mailbox())

if st.button("Scan Test URL Lists"):
    st.info("Scanning test URL lists...")
    url_results = asyncio.run(scan_url_lists(phishing_test_urls, safe_test_urls, results_placeholder))
    results_placeholder.table(url_results)

st.markdown(
    "----\n**Notes:** This educational demo uses keyword heuristics to flag suspicious URLs. "
    "For production: add robust parsing, URL expansion, reputation checks, SPF/DKIM checks and human review."
)
