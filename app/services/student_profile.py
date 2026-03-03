"""
app/services/student_profile.py — Student Adaptive Engine
===========================================================
Manages per-student learning profiles for adaptive AI responses.

Storage:  Firebase Firestore (preferred) → SQLite fallback
Firestore collection: students/{student_id}

Profile schema:
    student_id        : string
    skill_level       : "beginner" | "intermediate" | "advanced"
    strengths         : list[str]  — topics the student handles well
    weaknesses        : list[str]  — topics where gaps are detected
    recent_topics     : list[str]  — last 10 topics discussed
    progression_score : float      — 0–100 cumulative learning score
    mistake_patterns  : list[str]  — recurring error-type labels

Public API:
    detect_skill_level(message)           → "beginner" | "intermediate" | "advanced"
    get_student_profile(student_id)       → profile dict
    update_student_profile(student_id, interaction_data)  → bool
    adjust_response_depth(profile)        → str  (system prompt injection block)
"""

import os
import re
import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Reuse the Firebase app already initialised in firebase_service ─────────────
from app.services.firebase_service import get_db  # noqa: E402

# ── SQLite fallback (same DB file as history) ─────────────────────────────────
_sqlite_lock    = threading.Lock()
_profiles_ready = False
_DB_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..', 'instance', 'history.db')
)


def _ensure_profiles_table() -> None:
    global _profiles_ready
    if _profiles_ready:
        return
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    with sqlite3.connect(_DB_PATH) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS student_profiles (
                student_id        TEXT PRIMARY KEY,
                skill_level       TEXT DEFAULT 'beginner',
                strengths         TEXT DEFAULT '[]',
                weaknesses        TEXT DEFAULT '[]',
                recent_topics     TEXT DEFAULT '[]',
                progression_score REAL DEFAULT 0.0,
                mistake_patterns  TEXT DEFAULT '[]',
                updated_at        TEXT
            )
        """)
        con.commit()
    _profiles_ready = True


# ── Keyword maps for skill detection ──────────────────────────────────────────
_ADVANCED_TERMS = [
    'gadget chain', 'rop', 'heap spray', 'dcsync', 'rbcd', 'kerberoast',
    'edr bypass', 'amsi', 'etw', 'ret2libc', 'use-after-free', 'tcache',
    'format string', 'oob read', 'shadow credentials', 'golden ticket',
    'ysoserial', 'lsass', 'sam hive', 'blind sqli', 'ssrf', 'xxe',
    'deserialization', 'ssti', 'jwt confusion', 'oauth', 'privesc', 'lfi',
    'path traversal', 'metasploit', 'burp suite', 'mimikatz', 'bloodhound',
    'pass the hash', 'lateral movement', 'command injection',
]

_INTERMEDIATE_TERMS = [
    'sql injection', 'sqli', 'xss', 'csrf', 'nmap', 'dirb', 'gobuster',
    'ffuf', 'reverse shell', 'netcat', 'exploit', 'payload', 'vulnerability',
    'injection', 'enumeration', 'burp', 'hydra', 'john', 'hashcat',
]

# ── Mistake-pattern detectors ─────────────────────────────────────────────────
_MISTAKE_PATTERNS = [
    (
        r'\b(what\s+is|explain|define|meaning\s+of)\b.{0,40}'
        r'\b(sqli|xss|csrf|ssrf|lfi|rfi)\b',
        'Asks for basic definitions — still building foundational knowledge',
    ),
    (
        r'\b(not\s+working|doesn.t\s+work|why\s+(isn.t|doesn.t)|error)\b',
        'Troubleshooting without a methodical approach',
    ),
    (
        r'\bhow\s+to\s+hack\b',
        'Uses vague "how to hack" phrasing — lacks specificity',
    ),
    (
        r'\b(tool\s+to\s+use|which\s+tool|best\s+tool)\b',
        'Tool-first mindset — skipping concept-first learning',
    ),
    (
        r'\b(just\s+give|give\s+me\s+the|paste|copy)\b',
        'Seeks copy-paste answers without understanding',
    ),
]

# ── Skill-level rank (for upgrade-only logic) ─────────────────────────────────
_LEVEL_RANK = {'beginner': 0, 'intermediate': 1, 'advanced': 2}

# ── Depth instructions per level ─────────────────────────────────────────────
_DEPTH_INSTRUCTIONS = {
    'beginner': (
        "Explain concepts from first principles. Avoid jargon without definition. "
        "Use analogies. Keep examples simple and well-commented."
    ),
    'intermediate': (
        "Assume familiarity with basic concepts. Go deeper into mechanics. "
        "Show real tool usage with flags. Introduce more advanced techniques progressively."
    ),
    'advanced': (
        "Skip introductory explanations. Dive straight into deep technical detail. "
        "Provide raw payloads, PoC code, and full tool chains. Reference CVEs where relevant."
    ),
}


# ── Helpers ───────────────────────────────────────────────────────────────────
def _json_list(val) -> list:
    """Safely coerce a stored value into a Python list."""
    if isinstance(val, list):
        return val
    try:
        return json.loads(val) if val else []
    except Exception:
        return []


def _default_profile(student_id: str) -> dict:
    return {
        'student_id':        student_id,
        'skill_level':       'beginner',
        'strengths':         [],
        'weaknesses':        [],
        'recent_topics':     [],
        'progression_score': 0.0,
        'mistake_patterns':  [],
    }


# ── Public API ─────────────────────────────────────────────────────────────────

def detect_skill_level(message: str) -> str:
    """
    Estimate student skill level from message vocabulary.

    Returns:
        "beginner" | "intermediate" | "advanced"
    """
    text = message.lower()
    for term in _ADVANCED_TERMS:
        if term in text:
            return 'advanced'
    for term in _INTERMEDIATE_TERMS:
        if term in text:
            return 'intermediate'
    return 'beginner'


def get_student_profile(student_id: str) -> dict:
    """
    Fetch the student profile from Firestore or SQLite.
    Creates a default profile on first access.

    Args:
        student_id: Unique student / session identifier.

    Returns:
        Profile dict matching the schema.
    """
    # ── Firestore ──────────────────────────────────────────────────────────────
    db = get_db()
    if db is not None:
        try:
            doc_ref = db.collection('students').document(student_id)
            doc = doc_ref.get()
            if doc.exists:
                data = doc.to_dict()
                data.setdefault('student_id',        student_id)
                data.setdefault('skill_level',       'beginner')
                data.setdefault('strengths',         [])
                data.setdefault('weaknesses',        [])
                data.setdefault('recent_topics',     [])
                data.setdefault('progression_score', 0.0)
                data.setdefault('mistake_patterns',  [])
                return data
            # First access — create default
            profile = _default_profile(student_id)
            doc_ref.set(profile)
            return profile
        except Exception as e:
            logger.error(
                "Firestore get_student_profile failed (%s) — falling back to SQLite.", e
            )

    # ── SQLite fallback ────────────────────────────────────────────────────────
    try:
        _ensure_profiles_table()
        with _sqlite_lock:
            with sqlite3.connect(_DB_PATH) as con:
                con.row_factory = sqlite3.Row
                row = con.execute(
                    "SELECT * FROM student_profiles WHERE student_id = ?",
                    (student_id,),
                ).fetchone()
                if row:
                    d = dict(row)
                    for field in ('strengths', 'weaknesses', 'recent_topics', 'mistake_patterns'):
                        d[field] = _json_list(d.get(field))
                    return d
                # First access — insert default
                profile = _default_profile(student_id)
                con.execute(
                    "INSERT INTO student_profiles "
                    "(student_id, skill_level, strengths, weaknesses, "
                    " recent_topics, progression_score, mistake_patterns, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        student_id,
                        profile['skill_level'],
                        json.dumps(profile['strengths']),
                        json.dumps(profile['weaknesses']),
                        json.dumps(profile['recent_topics']),
                        profile['progression_score'],
                        json.dumps(profile['mistake_patterns']),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                con.commit()
                return profile
    except Exception as e:
        logger.error("SQLite get_student_profile failed (%s) — returning default.", e)
        return _default_profile(student_id)


def update_student_profile(student_id: str, interaction_data: dict) -> bool:
    """
    Update the student profile based on a new interaction.

    Args:
        student_id:       Unique student / session identifier.
        interaction_data: dict with optional keys:
            - topic        (str)  topic detected from the message
            - skill_level  (str)  detected level ("beginner"/"intermediate"/"advanced")
            - user_message (str)  raw user message (used for mistake-pattern detection)

    Returns:
        True on success, False on failure.
    """
    try:
        profile      = get_student_profile(student_id)
        topic        = interaction_data.get('topic', '')
        new_skill    = interaction_data.get('skill_level', '')
        user_message = interaction_data.get('user_message', '')

        # ── Skill level: only upgrade, never downgrade ─────────────────────────
        current_rank  = _LEVEL_RANK.get(profile['skill_level'], 0)
        detected_rank = _LEVEL_RANK.get(new_skill, 0)
        if detected_rank > current_rank:
            profile['skill_level'] = new_skill

        # ── Recent topics (sliding window, max 10) ─────────────────────────────
        if topic and topic not in ('General', ''):
            recent = _json_list(profile.get('recent_topics', []))
            if topic in recent:
                recent.remove(topic)          # bubble topic to front
            recent.insert(0, topic)
            recent = recent[:10]
            profile['recent_topics'] = recent

            # Strength / weakness heuristic:
            #   Topic seen ≥ 2 times in recent window → move to strengths
            #   Otherwise keep (or add) in weaknesses
            strengths  = _json_list(profile.get('strengths', []))
            weaknesses = _json_list(profile.get('weaknesses', []))
            topic_freq = sum(1 for t in recent if t == topic)

            if topic_freq >= 2:
                if topic not in strengths:
                    strengths.append(topic)
                if topic in weaknesses:
                    weaknesses.remove(topic)
            else:
                if topic not in strengths and topic not in weaknesses:
                    weaknesses.append(topic)

            profile['strengths']  = strengths[:20]
            profile['weaknesses'] = weaknesses[:20]

        # ── Progression score (incremental, capped at 100) ────────────────────
        delta = {'beginner': 1.0, 'intermediate': 2.5, 'advanced': 5.0}
        profile['progression_score'] = min(
            100.0,
            float(profile.get('progression_score', 0.0))
            + delta.get(profile['skill_level'], 1.0),
        )

        # ── Mistake-pattern detection ─────────────────────────────────────────
        if user_message:
            patterns = _json_list(profile.get('mistake_patterns', []))
            for regex, label in _MISTAKE_PATTERNS:
                if re.search(regex, user_message, re.IGNORECASE) and label not in patterns:
                    patterns.append(label)
            profile['mistake_patterns'] = patterns[:10]

        return _persist_profile(student_id, profile)

    except Exception as e:
        logger.error("update_student_profile failed: %s", e)
        return False


def _persist_profile(student_id: str, profile: dict) -> bool:
    """Write the updated profile back to Firestore or SQLite."""
    db = get_db()
    if db is not None:
        try:
            db.collection('students').document(student_id).set(profile)
            return True
        except Exception as e:
            logger.error("Firestore _persist_profile failed (%s) — trying SQLite.", e)

    try:
        _ensure_profiles_table()
        with _sqlite_lock:
            with sqlite3.connect(_DB_PATH) as con:
                con.execute(
                    """
                    INSERT INTO student_profiles
                        (student_id, skill_level, strengths, weaknesses,
                         recent_topics, progression_score, mistake_patterns, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(student_id) DO UPDATE SET
                        skill_level       = excluded.skill_level,
                        strengths         = excluded.strengths,
                        weaknesses        = excluded.weaknesses,
                        recent_topics     = excluded.recent_topics,
                        progression_score = excluded.progression_score,
                        mistake_patterns  = excluded.mistake_patterns,
                        updated_at        = excluded.updated_at
                    """,
                    (
                        student_id,
                        profile['skill_level'],
                        json.dumps(profile.get('strengths', [])),
                        json.dumps(profile.get('weaknesses', [])),
                        json.dumps(profile.get('recent_topics', [])),
                        float(profile.get('progression_score', 0.0)),
                        json.dumps(profile.get('mistake_patterns', [])),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                con.commit()
        return True
    except Exception as e:
        logger.error("SQLite _persist_profile failed: %s", e)
        return False


def adjust_response_depth(profile: dict) -> str:
    """
    Build a profile-aware context block to inject into the LLM system prompt.

    The returned string is prepended to the user's message so the LLM adapts
    its explanation depth, vocabulary, and focus areas automatically.

    Args:
        profile: Student profile dict from get_student_profile().

    Returns:
        A multi-line context string ready for LLM injection.
    """
    skill    = profile.get('skill_level', 'beginner')
    score    = float(profile.get('progression_score', 0.0))
    topics   = _json_list(profile.get('recent_topics', []))[:5]
    strong   = _json_list(profile.get('strengths', []))[:5]
    weak     = _json_list(profile.get('weaknesses', []))[:5]
    patterns = _json_list(profile.get('mistake_patterns', []))[:3]

    lines = [
        "=== STUDENT ADAPTIVE CONTEXT ===",
        f"Skill Level     : {skill.upper()}",
        f"Progression     : {score:.1f} / 100",
        f"Recent Topics   : {', '.join(topics) if topics else 'None yet'}",
        f"Strengths       : {', '.join(strong)  if strong  else 'None identified'}",
        f"Weaknesses      : {', '.join(weak)    if weak    else 'None identified'}",
    ]
    if patterns:
        lines.append(f"Mistake Patterns: {'; '.join(patterns)}")

    lines += [
        "",
        "Adaptive Instruction:",
        _DEPTH_INSTRUCTIONS.get(skill, _DEPTH_INSTRUCTIONS['beginner']),
        "=== END STUDENT CONTEXT ===",
    ]
    return "\n".join(lines)
