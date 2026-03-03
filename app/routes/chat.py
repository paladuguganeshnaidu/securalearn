"""
app/routes/chat.py — Chat Routes (URL Handlers)
=================================================
This file defines all the /chat/ URLs:

  GET  /chat/         → Show the chat page (chat.html)
  POST /chat/message  → Receive user message, get AI response, save to history
  GET  /chat/history  → Return saved history as JSON
  POST /chat/clear    → Clear the in-memory conversation for this session
  GET  /chat/mode     → Return the active mode for debug purposes

How a message flows:
  Browser  →  POST /chat/message
           →  groq_client.py  (calls Groq AI API)
           →  firebase_service.py  (saves to SQLite or Firestore)
           →  returns JSON  →  Browser streams the response as typewriter text
"""

import uuid
from flask import Blueprint, request, jsonify, render_template, session
from app.services.groq_client import GroqClient
from app.services import firebase_service
from app.services import student_profile

# Blueprint groups all /chat/ routes together
chat_bp = Blueprint('chat', __name__, url_prefix='/chat')

# One shared AI client — holds conversation history per session
client = GroqClient()


@chat_bp.route('/')
def chat_page():
    """
    Serve the main chat interface.
    Creates a unique session ID for this browser so history is per-user.
    """
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    return render_template('chat.html')


@chat_bp.route('/message', methods=['POST'])
def send_message():
    """
    Handle an incoming chat message.

    Expects JSON body:  { "message": "...", "mode": "red_team" }
    Returns JSON:       { "success": true, "response": "...", "mode": "..." }

    Mode options:
      - "red_team"   → Offensive attack techniques
      - "pentest"    → Professional penetration testing
      - "education"  → Beginner-friendly security learning
    """
    data = request.get_json()

    # Validate input
    if not data or 'message' not in data:
        return jsonify({'success': False, 'response': 'No message provided'}), 400

    user_message = data['message'].strip()
    if not user_message:
        return jsonify({'success': False, 'response': 'Empty message'}), 400

    mode       = data.get('mode', 'education')   # default to education mode
    session_id = session.get('session_id', 'default')

    # ── Adaptive engine: fetch profile & build context block ──────────────────
    profile          = student_profile.get_student_profile(session_id)
    adaptive_context = student_profile.adjust_response_depth(profile)

    # Inject the adaptive context as a prefix to the user message so the LLM
    # adapts depth/vocabulary without touching Groq connection logic.
    enriched_message = f"{adaptive_context}\n\n---\n\nUser Query:\n{user_message}"

    # Ask the AI (calls Groq API with the right system prompt for the chosen mode)
    result = client.generate_response(enriched_message, session_id, mode=mode)

    # ── Update student profile after a successful interaction ─────────────────
    if result.get('success'):
        detected_level = student_profile.detect_skill_level(user_message)
        topic          = firebase_service.extract_topic(user_message)
        student_profile.update_student_profile(session_id, {
            'topic':        topic,
            'skill_level':  detected_level,
            'user_message': user_message,
        })

    # Auto-save to history (SQLite locally, or Firestore if configured)
    # This never crashes the chat — errors are logged and silently ignored
    if result.get('success') and result.get('response'):
        firebase_service.save_chat(session_id, mode, user_message, result['response'])

    return jsonify(result)


@chat_bp.route('/history', methods=['GET'])
def get_history():
    """
    Return saved chat history for this session.

    Optional query param:  ?topic=XSS   (filter by topic)
    Returns JSON: { "success": true, "history": [ {...}, ... ] }
    """
    session_id = session.get('session_id', 'default')
    topic = request.args.get('topic')  # optional topic filter

    if topic:
        history = firebase_service.get_history_by_topic(session_id, topic)
    else:
        history = firebase_service.get_history(session_id)

    return jsonify({'success': True, 'history': history})


@chat_bp.route('/clear', methods=['POST'])
def clear_chat():
    """
    Clear this session's in-memory conversation history.
    Note: this does NOT delete saved history from the database.
    """
    session_id = session.get('session_id', 'default')
    client.clear_session(session_id)
    return jsonify({'success': True, 'message': 'Chat cleared'})


@chat_bp.route('/mode', methods=['GET'])
def get_mode():
    """Return the current active mode for this session (for debugging)."""
    session_id = session.get('session_id', 'default')
    mode = client.get_current_mode(session_id)
    return jsonify({'mode': mode or 'education'})
