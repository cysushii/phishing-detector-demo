# phishing_app.py
import re
import asyncio
import streamlit as st
from email import message_from_string

def extract_urls(text: str):
    return re.findall(r"(https?://[^\s]+)", text)

def check_suspicious(url: str):
    suspicious_patterns = ["login", "verify", "bank", "update", "secure"]
    return any(p in url.lower() for p in suspicious_patterns)

async def parse_email(raw_email: str):
    msg = message_from_string(raw_email)
    subject = msg.get("subject", "(no subject)")
    body = msg.get_payload()
    if body is None:
        body = ""
    urls = extract_urls(str(body))
    flagged = [url for url in urls if check_suspicious(url)]
    return subject, urls, flagged

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
http://secure-login.fakebank.com/verify
""",
    """Subject: Security update
From: it-support@company.com
To: you@example.com

Please download the update from: http://company-secure.com/update
""",
]

st.set_page_config(page_title="Phishing Detector Demo", layout="centered")
st.title("🔒 AI-Powered Phishing Detection (Real-Time Demo)")

if st.button("Start Monitoring Mailbox"):
    st.info("📩 Monitoring mailbox... (mock simulation)")
    placeholder = st.empty()

    async def monitor_mailbox():
        for idx, mail in enumerate(MOCK_MAILBOX, 1):
            subject, urls, flagged = await parse_email(mail)

            with placeholder.container():
                st.write(f"**📧 Email {idx}:** {subject}")
                st.write(f"**URLs Found:** {urls or 'None found'}")

                if flagged:
                    st.error(f"⚠ Suspicious links detected: {flagged}")
                else:
                    st.success("✅ No suspicious links found!")

            await asyncio.sleep(3)

    asyncio.run(monitor_mailbox())
