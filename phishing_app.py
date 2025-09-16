# phishing_app.py
import re
import asyncio
import io
import math
import wave
import struct
import random
import time
import streamlit as st
from email import message_from_string
from datetime import datetime, timedelta

# ----------------------------
# MOCK ORG DATA (Cyber-DNA elements)
# ----------------------------
EMPLOYEES = {
    "E001": {"name": "Asha Rao", "email": "asha.rao@company.com", "role": "Engineer"},
    "E002": {"name": "Rahul Sen", "email": "rahul.sen@company.com", "role": "Analyst"},
    "E003": {"name": "Neha Iyer", "email": "neha.iyer@company.com", "role": "HR"},
    "E004": {"name": "Vikram Patel", "email": "vikram.patel@company.com", "role": "Manager"},
}

# Organization policy (trusted domains / VIPs) - Cyber-DNA
ORG_POLICY = {
    "trusted_domains": ["company.com", "intranet.company.com"],
    "vip_emails": ["vikram.patel@company.com"],
}

# Store per-employee activity & detections in-memory (PoC)
EMP_ACTIVITY = {eid: {"checked_urls": [], "flagged_urls": [], "anomalies": [], "risk_score": 0.0} for eid in EMPLOYEES}

# ----------------------------
# URL / phishing detection utilities
# ----------------------------
def extract_urls(text: str):
    if not text:
        return []
    return re.findall(r"(https?://[^\s,<>\"']+)", text)

def check_suspicious_keyword(url: str):
    patterns = ["login", "verify", "bank", "update", "secure", "account", "reset", "re-activate"]
    return any(p in url.lower() for p in patterns)

def domain_from_url(url: str):
    try:
        return re.sub(r"^https?://", "", url.split("/")[0]).lower()
    except Exception:
        return url.lower()

def is_trusted_domain(url: str):
    dom = domain_from_url(url)
    for t in ORG_POLICY["trusted_domains"]:
        if dom.endswith(t):
            return True
    return False

# ----------------------------
# Sound (same as before) - best-effort
# ----------------------------
def play_alert_sound():
    try:
        import winsound
        winsound.Beep(1000, 350)
    except Exception:
        # fallback: short generated WAV via st.audio (best for cloud)
        sample_rate = 44100
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
# System check simulation (malware / irregular behaviour)
# ----------------------------
def simulate_system_check(eid: str):
    """
    PoC: Randomly simulate anomalies like 'process spike', 'strange file write', or 'suspicious connection'.
    Higher severity anomalies increase employee risk_score.
    """
    choices = [
        (0.02, "malware_signature_detected", 4),   # rare but severe
        (0.05, "unexpected_process_spike", 3),
        (0.07, "suspicious_outbound_connection", 3),
        (0.12, "failed_login_bursts", 2),
        (0.20, "suspicious_file_write", 2),
    ]
    r = random.random()
    cumulative = 0.0
    for prob, desc, severity in choices:
        cumulative += prob
        if r <= cumulative:
            ts = datetime.now().isoformat(timespec='seconds')
            anomaly = {"time": ts, "type": desc, "severity": severity}
            EMP_ACTIVITY[eid]["anomalies"].append(anomaly)
            # increase risk score (simple additive model)
            EMP_ACTIVITY[eid]["risk_score"] += severity * 0.1
            return anomaly
    # No anomaly
    return None

# ----------------------------
# Behavioral baseline check (simple PoC)
# ----------------------------
def check_behavioral_baseline(eid: str):
    """
    PoC baseline: if number of flagged URLs today > 2 or anomalies > 1 -> mark deviation.
    """
    today = datetime.now().date()
    # For PoC we don't store per-day counts beyond current session. Use existing lists.
    flagged_today = len(EMP_ACTIVITY[eid]["flagged_urls"])
    anomalies = len(EMP_ACTIVITY[eid]["anomalies"])
    deviated = flagged_today > 2 or anomalies > 1
    if deviated:
        EMP_ACTIVITY[eid]["risk_score"] += 0.2
    return deviated

# ----------------------------
# URL sync / check function
# ----------------------------
def sync_and_check_url(eid: str, url: str):
    """
    Called when an employee syncs/visits a URL. We record, check, and update risk.
    """
    ts = datetime.now().isoformat(timespec='seconds')
    record = {"url": url, "time": ts}
    EMP_ACTIVITY[eid]["checked_urls"].append(record)

    # trusted domain reduces suspicion
    if is_trusted_domain(url):
        return {"status": "SAFE", "reason": "trusted_domain"}

    flagged = check_suspicious_keyword(url)
    if flagged:
        EMP_ACTIVITY[eid]["flagged_urls"].append({"url": url, "time": ts})
        EMP_ACTIVITY[eid]["risk_score"] += 0.15
        return {"status": "PHISH", "reason": "keyword_match"}
    return {"status": "SAFE", "reason": "no_keyword"}

# ----------------------------
# Simple email parser for mock mailbox (keeps previous app behavior)
# ----------------------------
def extract_from_email(raw_email: str):
    msg = message_from_string(raw_email)
    subject = msg.get("subject", "(no subject)")
    body = msg.get_payload() or ""
    urls = extract_urls(str(body))
    return subject, urls

# ----------------------------
# Streamlit UI
# ----------------------------
st.set_page_config(page_title="Phish + Cyber-DNA Demo", layout="wide")
st.title("🔒 Phishing Detector + Cyber-DNA Features (Demo)")

col
