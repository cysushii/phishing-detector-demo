# phishing_app.py
import re
import asyncio
import io
import math
import wave
import struct
import random
import streamlit as st
from email import message_from_string

# ----------------------------
# Utilities
# ----------------------------
def extract_urls(text: str):
    """Return list of URLs found in text (simple regex)."""
    if not text:
        return []
    return re.findall(r"(https?://[^\s]+)", text)

def check_suspicious_keyword(url: str):
    """Simple keyword-based suspicion check."""
    suspicious_patterns = ["login", "verify", "bank", "update", "secure", "account", "reset", "re-activate"]
    return any(p in url.lower() for p in suspicious_patterns)

def play_alert_sound():
    """Play a short beep. Uses winsound on Windows, otherwise stream a generated WAV."""
    try:
        import winsound
        winsound.Beep(1000, 400)
    except Exception:
        sample_rate = 44100
        duration_s = 0.35
        frequency = 880.0
        n_samples = int(sample_rate * duration_s)
        buf = io.BytesIO()
        with wave.open(buf, "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(sample_rate)
            for i in range(n_samples):
                t = i / sample_rate
                amplitude = 0.3 * 32767
                value = int(amplitude * math.sin(2 * math.pi * frequency * t))
                data = struct.pack('<h', value)
                wf.writeframesraw(data)
        buf.seek(0)
        try:
            st.audio(buf.read(), format="audio/wav")
        except Exception:
            pass

# ----------------------------
# Test URL lists
# ----------------------------
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

# ----------------------------
# Mock mailbox
# ----------------------------
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
- {safe_test_urls[0]}
- {phishing_test_urls[0]}
- {safe_test_urls[2]}
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
# Employees with seeded history
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
    for emp in EMPLOYEES:
        emp["history"] = random.sample(sample_visits, k=random.randint(3, 6))

seed_employee_history()

# ----------------------------
# Async parsers
# ----------------------------
async def parse_email(raw_email: str):
    msg = message_from_string(raw_email)
    subject = msg.get("subject", "(no subject)")
    body = msg.get_payload() or ""
    urls = extract_urls(str(body))
    flagged = [url for url in urls if check_suspicious_keyword(url)]
    return subject, urls, flagged

# ----------------------------
# Streamlit UI
# ----------------------------
st.set_page_config(page_title="Phishing Detector Demo", layout="centered")
st.title("🔒 Phishing Detector — Demo (Employees + Live Checks)")

st.markdown(
    "This demo scans mock emails, test URLs, and simulates employee activity. "
    "Suspicious links trigger alerts + sound. Employees start with some pre-filled activity."
)

run_emails = st.button("📩 Start Monitoring Mock Mailbox")
scan_urls = st.button("🔎 Scan Test URL Lists")
simulate_emp = st.button("▶ Start simulation (30s)")

placeholder = st.empty()
results_placeholder = st.empty()

# ----------------------------
# Employee helpers
# ----------------------------
def get_employee_summary():
    rows = []
    for emp in EMPLOYEES:
        total = len(emp["history"])
        safe = sum(1 for h in emp["history"] if h["status"] == "SAFE")
        phish = sum(1 for h in emp["history"] if h["status"] == "PHISH")
        malware = sum(1 for h in emp["history"] if h["status"] == "MALWARE")
        rows.append({
            "Employee": emp["name"],
            "Email": emp["email"],
            "Total Visits": total,
            "Safe": safe,
            "Phishing": phish,
            "Malware": malware,
        })
    return rows

def add_visit(emp_id, url, status):
    for emp in EMPLOYEES:
        if emp["id"] == emp_id:
            emp["history"].append({"url": url, "status": status})
            return

# ----------------------------
# Async tasks
# ----------------------------
async def monitor_mailbox():
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
        await asyncio.sleep(2)

async def scan_url_lists():
    combined = []
    for url in phishing_test_urls + safe_test_urls:
        is_flagged = check_suspicious_keyword(url)
        combined.append({"url": url, "status": "PHISH" if is_flagged else "SAFE"})
        if is_flagged:
            with results_placeholder.container():
                st.error(f"⚠ PHISHING: {url}")
                play_alert_sound()
            await asyncio.sleep(0.2)
    return combined

async def simulate_employee_activity():
    for _ in range(10):  # 10 rounds of random actions
        emp = random.choice(EMPLOYEES)
        # Pick either safe or phishing
        if random.random() < 0.7:
            url = random.choice(safe_test_urls)
            status = "SAFE"
        else:
            url = random.choice(phishing_test_urls)
            status = "PHISH"
        add_visit(emp["id"], url, status)
        if random.random() < 0.1:
            add_visit(emp["id"], "MALWARE", "MALWARE")
        await asyncio.sleep(3)

# ----------------------------
# Run buttons
# ----------------------------
if run_emails:
    asyncio.run(monitor_mailbox())

if scan_urls:
    url_results = asyncio.run(scan_url_lists())
    results_placeholder.table(url_results)

if simulate_emp:
    asyncio.run(simulate_employee_activity())

# ----------------------------
# Employee Summary Table
# ----------------------------
st.subheader("📊 Employee Activity Summary")
st.table(get_employee_summary())

st.markdown(
    "----\n**Notes:** This demo combines employee monitoring (mocked), mailbox scanning, "
    "and URL checking. In production, you'd connect to real mail servers, proxies, and "
    "security telemetry for accurate detections."
)
