# phishing_app.py
import re
import asyncio
import io
import math
import wave
import struct
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

# Sound alert helpers: Windows winsound or in-memory WAV for web
def play_alert_sound():
    """Play a short beep. Uses winsound on Windows, otherwise stream a generated WAV to Streamlit audio."""
    try:
        # Try Windows-only winsound (will succeed on local Windows)
        import winsound
        winsound.Beep(1000, 400)  # frequency 1000Hz, duration 400ms
    except Exception:
        # Fallback: generate a short sine-wave WAV and store in buffer
        sample_rate = 44100
        duration_s = 0.35
        frequency = 880.0
        n_samples = int(sample_rate * duration_s)
        buf = io.BytesIO()
        with wave.open(buf, "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)  # 16-bit
            wf.setframerate(sample_rate)
            for i in range(n_samples):
                t = i / sample_rate
                amplitude = 0.3 * 32767
                value = int(amplitude * math.sin(2 * math.pi * frequency * t))
                data = struct.pack('<h', value)
                wf.writeframesraw(data)
        buf.seek(0)
        # Streamlit can play bytes via st.audio
        try:
            st.audio(buf.read(), format="audio/wav")
        except Exception:
            # If audio cannot be played (e.g., running headless), ignore silently
            pass

# ----------------------------
# Test URL lists (phishing + safe)
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
# Mock mailbox (emails embedding safe + phishing URLs)
# ----------------------------
MOCK_MAILBOX = [
    # safe email
    """Subject: Meeting tomorrow
From: teamlead@company.com
To: you@example.com

Hi, just a reminder about tomorrow's meeting. 
Here’s the agenda: http://company.com/agenda
""",
    # phishing email (Amazon lookalike)
    """Subject: Urgent - Verify your account now!
From: fakebank@secure-login.com
To: you@example.com

Dear user,
Please verify your account immediately by clicking the link:
http://secure-chasebank-login.top/verify
""",
    # mixed email with multiple links
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
    # phishing mass-mail style
    """Subject: Your account has been locked
From: support@payment-update.example
To: you@example.com

We detected suspicious sign-in. Reset immediately:
https://paypal.com.verify-account.cn/reset
""",
]

# ----------------------------
# Async parser for emails
# ----------------------------
async def parse_email(raw_email: str):
    msg = message_from_string(raw_email)
    subject = msg.get("subject", "(no subject)")
    # Basic payload handling for demo
    body = msg.get_payload()
    if body is None:
        body = ""
    urls = extract_urls(str(body))
    flagged = [url for url in urls if check_suspicious_keyword(url)]
    return subject, urls, flagged

# ----------------------------
# Streamlit UI
# ----------------------------
st.set_page_config(page_title="Phishing Detector Demo", layout="centered")
st.title("🔒 AI Phishing Detector — Demo (Live + Test URLs) MADE BY SUSHANTH . M AND VISHVATH .M :)")

st.markdown(
    "This demo scans mock emails and test URLs. Suspicious links trigger an alert and a sound."
)

# User controls
run_emails = st.button("📩 Start Monitoring Mock Mailbox")
scan_urls = st.button("🔎 Scan Test URL Lists")
show_examples = st.checkbox("Show test URL lists", value=True)

if show_examples:
    st.info("Phishing test URLs (samples)")
    st.code("\n".join(phishing_test_urls[:10]) + "\n...")  # show a subset to avoid long page
    st.info("Safe test URLs (samples)")
    st.code("\n".join(safe_test_urls[:10]) + "\n...")

# Placeholder areas for dynamic content
placeholder = st.empty()
results_placeholder = st.empty()

# Coroutine: monitor mailbox emails
async def monitor_mailbox():
    results = []
    for idx, mail in enumerate(MOCK_MAILBOX, 1):
        subject, urls, flagged = await parse_email(mail)
        # UI update
        with placeholder.container():
            st.write(f"**Email {idx}:** {subject}")
            st.write(f"**URLs Found:** {urls if urls else 'None found'}")
            if flagged:
                st.error(f"⚠ Suspicious links detected: {flagged}")
                play_alert_sound()
            else:
                st.success("✅ No suspicious links found!")
        results.append({"source": f"email_{idx}", "subject": subject, "urls": urls, "flagged": flagged})
        await asyncio.sleep(2)
    return results

# Coroutine: scan lists of URLs (safe + phishing)
async def scan_url_lists():
    combined = []
    # scan phishing list
    for url in phishing_test_urls:
        is_flagged = check_suspicious_keyword(url)
        combined.append({"url": url, "status": "PHISH" if is_flagged else "SAFE"})
        if is_flagged:
            # show alert and play sound
            with results_placeholder.container():
                st.error(f"⚠ PHISHING: {url}")
                play_alert_sound()
            await asyncio.sleep(0.3)
    # scan safe list
    for url in safe_test_urls:
        is_flagged = check_suspicious_keyword(url)
        combined.append({"url": url, "status": "PHISH" if is_flagged else "SAFE"})
        if is_flagged:
            with results_placeholder.container():
                st.error(f"⚠ PHISHING: {url}")
                play_alert_sound()
            await asyncio.sleep(0.1)
    return combined

# Run the requested actions
if run_emails:
    st.info("Monitoring mock mailbox...")
    email_results = asyncio.run(monitor_mailbox())
    # show a summary table
    rows = []
    for r in email_results:
        rows.append(
            {
                "Source": r["source"],
                "Subject": r["subject"],
                "URLs Found": ", ".join(r["urls"]) if r["urls"] else "",
                "Flagged": ", ".join(r["flagged"]) if r["flagged"] else "",
            }
        )
    results_placeholder.table(rows)

if scan_urls:
    st.info("Scanning test URL lists...")
    url_results = asyncio.run(scan_url_lists())
    results_placeholder.table(url_results)

st.markdown(
    "----\n**Notes:** This demo uses simple keyword rules to flag URLs (for learning/demo purposes). "
    "In production you would add robust parsing, domain reputation checks, SPF/DKIM checks and human-in-the-loop review."
)

