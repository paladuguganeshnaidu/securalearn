"""
app/services/firebase_service.py — Chat History Storage
=========================================================
Saves and retrieves every conversation automatically.

Storage priority (automatic, no manual config needed):
  1. Firebase Firestore  — cloud database, used if serviceAccountKey.json exists
  2. Local SQLite DB     — file on disk (instance/history.db), always works

What gets saved per message:
  - topic        (auto-detected from the message, e.g. "SQL Injection")
  - mode          (red_team / pentest / education)
  - skill_level   (Beginner / Intermediate / Advanced / Expert — auto-detected)
  - user_message  (what the user typed)
  - ai_response   (what the AI replied)
  - timestamp     (UTC time)

Public functions used by chat.py:
  save_chat(user_id, mode, user_message, ai_response)
  get_history(user_id, limit=50)
  get_history_by_topic(user_id, topic, limit=20)
"""

import os
import re
import sqlite3
import logging
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Firebase (optional) ───────────────────────────────────────────────────────
_db      = None
_fb_init = False

def _init_firebase():
    global _db, _fb_init
    if _fb_init:
        return _db
    _fb_init = True

    key_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..', '..', 'serviceAccountKey.json')
    )
    if not os.path.exists(key_path):
        logger.info("No serviceAccountKey.json — using local SQLite history.")
        return None

    try:
        import firebase_admin
        from firebase_admin import credentials, firestore
        if not firebase_admin._apps:
            cred = credentials.Certificate(key_path)
            firebase_admin.initialize_app(cred)
        _db = firestore.client()
        logger.info("Firebase Firestore enabled.")
        return _db
    except Exception as e:
        logger.error("Firebase init failed (%s) — falling back to SQLite.", e)
        return None


def get_db():
    return _init_firebase()


# ── SQLite fallback ───────────────────────────────────────────────────────────
_sqlite_lock  = threading.Lock()
_sqlite_ready = False
_DB_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..', 'instance', 'history.db')
)

def _ensure_sqlite():
    global _sqlite_ready
    if _sqlite_ready:
        return
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    with sqlite3.connect(_DB_PATH) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id      TEXT NOT NULL,
                topic        TEXT,
                mode         TEXT,
                skill_level  TEXT,
                user_message TEXT,
                ai_response  TEXT,
                timestamp    TEXT
            )
        """)
        con.commit()
    _sqlite_ready = True


def _sqlite_save(user_id, mode, topic, skill, user_message, ai_response):
    _ensure_sqlite()
    ts = datetime.now(timezone.utc).isoformat()
    with _sqlite_lock:
        with sqlite3.connect(_DB_PATH) as con:
            con.execute(
                "INSERT INTO history "
                "(user_id, topic, mode, skill_level, user_message, ai_response, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (user_id, topic, mode, skill, user_message, ai_response[:5000], ts)
            )
            con.commit()


def _sqlite_get(user_id, limit=50, topic_filter=None):
    _ensure_sqlite()
    with _sqlite_lock:
        with sqlite3.connect(_DB_PATH) as con:
            con.row_factory = sqlite3.Row
            if topic_filter:
                cur = con.execute(
                    "SELECT * FROM history WHERE user_id=? AND topic=? "
                    "ORDER BY id DESC LIMIT ?",
                    (user_id, topic_filter, limit)
                )
            else:
                cur = con.execute(
                    "SELECT * FROM history WHERE user_id=? "
                    "ORDER BY id DESC LIMIT ?",
                    (user_id, limit)
                )
            rows = [dict(r) for r in cur.fetchall()]
            for r in rows:
                r['id'] = str(r['id'])
            return rows


# ── Topic extraction ──────────────────────────────────────────────────────────
_TOPIC_PATTERNS = [
    (r'\b(sql\s*injection|sqli)\b', 'SQL Injection'),
    (r'\b(xss|cross.site\s*scripting)\b', 'XSS'),
    (r'\b(csrf|cross.site\s*request\s*forgery)\b', 'CSRF'),
    (r'\b(ssrf|server.side\s*request\s*forgery)\b', 'SSRF'),
    (r'\b(xxe|xml\s*external\s*entity)\b', 'XXE'),
    (r'\b(idor|insecure\s*direct\s*object)\b', 'IDOR'),
    (r'\bssti\b', 'SSTI'),
    (r'\b(command\s*injection|cmd\s*injection|os\s*injection)\b', 'Command Injection'),
    (r'\b(lfi|rfi|local\s*file\s*inclusion|remote\s*file\s*inclusion)\b', 'LFI/RFI'),
    (r'\b(path\s*traversal|directory\s*traversal)\b', 'Path Traversal'),
    (r'\b(file\s*upload|webshell)\b', 'File Upload'),
    (r'\b(priv(ilege)?\s*esc(alation)?|privesc)\b', 'Privilege Escalation'),
    (r'\b(kerberoast|as.rep\s*roast|golden\s*ticket|silver\s*ticket|pass.the.hash|dcsync)\b', 'Active Directory'),
    (r'\b(active\s*directory|bloodhound|mimikatz|ldap)\b', 'Active Directory'),
    (r'\b(metasploit|msfvenom|meterpreter|cobalt\s*strike|c2|c&c)\b', 'Exploitation Frameworks'),
    (r'\b(recon|reconnaissance|nmap|masscan|osint|shodan|amass)\b', 'Recon'),
    (r'\b(aws|azure|gcp|cloud|s3\s*bucket|iam\s*(role|policy))\b', 'Cloud Security'),
    (r'\b(burp\s*suite|burp|zap|proxy)\b', 'Web Proxy Tools'),
    (r'\b(jwt|json\s*web\s*token)\b', 'JWT'),
    (r'\b(oauth|saml|sso|openid)\b', 'Authentication'),
    (r'\b(buffer\s*overflow|rop|heap|shellcode|exploit\s*dev)\b', 'Exploit Development'),
    (r'\b(malware|trojan|ransomware|rootkit|backdoor|rat)\b', 'Malware'),
    (r'\b(network|mitm|arp\s*spoof|wireshark|sniff)\b', 'Network Attacks'),
    (r'\b(wireless|wifi|wpa2?|wep|evil\s*twin|deauth)\b', 'Wireless'),
    (r'\b(crypto|encryption|hash(ing)?|rsa|aes|padding\s*oracle)\b', 'Cryptography'),
    (r'\b(android|ios|mobile|apk|frida|objection)\b', 'Mobile Security'),
    (r'\b(docker|kubernetes|container|k8s)\b', 'Containers & K8s'),
    (r'\b(cicd|ci/cd|github\s*actions|jenkins|pipeline)\b', 'CI/CD Security'),
    (r'\b(phish|social\s*engineering|vishing|smishing)\b', 'Social Engineering'),
    (r'\b(linux|unix|bash|shell|suid|sudo)\b', 'Linux Security'),
    (r'\b(windows|powershell|uac|lsass|sam\s*hive)\b', 'Windows Security'),
    (r'\b(forensics|incident\s*response|dfir|memory\s*dump)\b', 'Forensics & IR'),
    (r'\b(reverse\s*engineering|disassembly|ghidra|ida)\b', 'Reverse Engineering'),
    (r'\b(api|rest|graphql|grpc|swagger|openapi)\b', 'API Security'),
    (r'\b(deserialization|ysoserial|pickle|gadget\s*chain)\b', 'Deserialization'),
]

def extract_topic(user_message: str) -> str:
    """Detect topic from user message via keyword patterns. Falls back to 'General'."""
    text = user_message.lower()
    for pattern, label in _TOPIC_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return label
    # Use first 5 meaningful words as fallback
    words = [w for w in user_message.split() if len(w) > 2][:5]
    return ' '.join(words).capitalize() if words else 'General'


def detect_skill_level(user_message: str) -> str:
    """Roughly estimate skill level from vocabulary in the message."""
    text = user_message.lower()
    expert_terms = [
        'gadget chain', 'rop', 'heap spray', 'dcsync', 'rbcd', 'kerberoast', 'edr bypass',
        'amsi', 'etw', 'ret2libc', 'use-after-free', 'tcache', 'format string', 'oob read',
        'shadow credentials', 'golden ticket', 'ysoserial', 'lsass', 'sam hive',
    ]
    advanced_terms = [
        'blind sqli', 'ssrf', 'xxe', 'deserialization', 'ssti', 'jwt confusion', 'oauth',
        'privesc', 'lfi', 'path traversal', 'metasploit', 'burp suite', 'mimikatz',
        'bloodhound', 'pass the hash', 'lateral movement', 'command injection',
    ]
    intermediate_terms = [
        'sql injection', 'xss', 'csrf', 'nmap', 'dirb', 'gobuster', 'ffuf',
        'reverse shell', 'netcat', 'exploit', 'payload', 'vulnerability',
    ]

    for t in expert_terms:
        if t in text:
            return 'Expert'
    for t in advanced_terms:
        if t in text:
            return 'Advanced'
    for t in intermediate_terms:
        if t in text:
            return 'Intermediate'
    return 'Beginner'


# ── Main functions ────────────────────────────────────────────────────────────

def save_chat(user_id: str, mode: str, user_message: str, ai_response: str) -> bool:
    """Save a chat exchange. Uses Firestore if available, otherwise SQLite."""
    topic = extract_topic(user_message)
    skill = detect_skill_level(user_message)

    # Try Firestore first
    db = _init_firebase()
    if db is not None:
        try:
            db.collection('users').document(user_id).collection('history').add({
                'topic':        topic,
                'mode':         mode,
                'user_message': user_message,
                'ai_response':  ai_response[:5000],
                'skill_level':  skill,
                'timestamp':    datetime.now(timezone.utc),
            })
            logger.debug("Firestore save OK [%s] %s", user_id, topic)
            return True
        except Exception as e:
            logger.error("Firestore save failed (%s) — falling back to SQLite.", e)

    # SQLite fallback (always available)
    try:
        _sqlite_save(user_id, mode, topic, skill, user_message, ai_response)
        logger.debug("SQLite save OK [%s] %s", user_id, topic)
        return True
    except Exception as e:
        logger.error("SQLite save_chat failed: %s", e)
        return False


def get_history(user_id: str, limit: int = 50) -> list:
    """Return last `limit` records for user, newest first."""
    db = _init_firebase()
    if db is not None:
        try:
            docs = (
                db.collection('users').document(user_id)
                  .collection('history')
                  .order_by('timestamp', direction='DESCENDING')
                  .limit(limit).stream()
            )
            records = []
            for doc in docs:
                d = doc.to_dict()
                ts = d.get('timestamp')
                d['timestamp'] = ts.isoformat() if hasattr(ts, 'isoformat') else str(ts)
                d['id'] = doc.id
                records.append(d)
            return records
        except Exception as e:
            logger.error("Firestore get_history failed (%s) — falling back to SQLite.", e)

    # SQLite fallback
    try:
        return _sqlite_get(user_id, limit)
    except Exception as e:
        logger.error("SQLite get_history failed: %s", e)
        return []


def get_history_by_topic(user_id: str, topic: str, limit: int = 20) -> list:
    """Return history filtered by topic."""
    db = _init_firebase()
    if db is not None:
        try:
            docs = (
                db.collection('users').document(user_id)
                  .collection('history')
                  .where('topic', '==', topic)
                  .order_by('timestamp', direction='DESCENDING')
                  .limit(limit).stream()
            )
            records = []
            for doc in docs:
                d = doc.to_dict()
                ts = d.get('timestamp')
                d['timestamp'] = ts.isoformat() if hasattr(ts, 'isoformat') else str(ts)
                d['id'] = doc.id
                records.append(d)
            return records
        except Exception as e:
            logger.error("Firestore get_history_by_topic failed (%s).", e)

    # SQLite fallback
    try:
        return _sqlite_get(user_id, limit, topic_filter=topic)
    except Exception as e:
        logger.error("SQLite get_history_by_topic failed: %s", e)
        return []
