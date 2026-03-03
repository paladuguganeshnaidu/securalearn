"""app/services/groq_client.py — AI Brain
========================================
Handles all communication with the Groq AI API.

This module:
  - Loads the system prompt per mode from prompts/system_prompt.txt
  - Keeps conversation history per user session (so the AI remembers context)
  - Sends messages to the Groq API and returns the response

Modes:
  - red_team
  - pentest
  - education

Model used:  llama-3.3-70b-versatile
API key:     Set GROQ_API_KEY in your .env file

Important:
  The system prompt content is not hardcoded in Python.
"""

from __future__ import annotations

import os
import re
from typing import Final

from groq import Groq


_REQUIRED_MODES: Final[set[str]] = {"red_team", "pentest", "education"}


def _load_system_prompts() -> dict[str, str]:
    """Load mode-specific system prompts from prompts/system_prompt.txt.

    File format:
        [red_team]
        ...
        [/red_team]

        [pentest]
        ...
        [/pentest]

        [education]
        ...
        [/education]
    """
    prompts_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "prompts", "system_prompt.txt")
    )

    if not os.path.exists(prompts_path):
        raise FileNotFoundError(
            f"Missing prompts file: {prompts_path}. Expected prompts/system_prompt.txt"
        )

    with open(prompts_path, "r", encoding="utf-8") as f:
        content = f.read()

    pattern = re.compile(
        r"\[(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\]\s*(?P<body>.*?)\s*\[/\1\]",
        re.DOTALL,
    )

    prompts: dict[str, str] = {}
    for match in pattern.finditer(content):
        name = match.group("name").strip()
        body = match.group("body").strip()
        if name and body:
            prompts[name] = body

    missing = _REQUIRED_MODES - set(prompts.keys())
    if missing:
        missing_list = ", ".join(sorted(missing))
        raise ValueError(
            "prompts/system_prompt.txt is missing required sections: "
            f"{missing_list}"
        )

    return {mode: prompts[mode] for mode in sorted(_REQUIRED_MODES)}


SYSTEM_PROMPTS: Final[dict[str, str]] = _load_system_prompts()


class GroqClient:
    """Client for Groq API — SecuraLearn multi-mode assistant."""

    DEFAULT_MODEL: Final[str] = "llama-3.3-70b-versatile"
    VALID_MODES: Final[set[str]] = set(SYSTEM_PROMPTS.keys())

    def __init__(self, model: str | None = None):
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise ValueError("GROQ_API_KEY not set in environment variables")
        self.client = Groq(api_key=api_key)
        self.model = model or self.DEFAULT_MODEL
        # session_id → {"mode": str, "messages": list[dict]}
        self.chat_sessions: dict[str, dict] = {}

    # ── session helpers ──────────────────────────────────────────────

    def _build_session(self, session_id: str, mode: str) -> dict:
        """Create a fresh session with the given mode's system prompt."""
        session = {
            "mode": mode,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPTS[mode]},
            ],
        }
        self.chat_sessions[session_id] = session
        return session

    def get_session(self, session_id: str, mode: str = "education") -> dict:
        """Get existing session or create one. If mode changed, reset."""
        if session_id not in self.chat_sessions:
            return self._build_session(session_id, mode)
        session = self.chat_sessions[session_id]
        if session["mode"] != mode:
            return self._build_session(session_id, mode)
        return session

    def clear_session(self, session_id: str = "default") -> None:
        """Clear a chat session."""
        if session_id in self.chat_sessions:
            del self.chat_sessions[session_id]

    def get_current_mode(self, session_id: str) -> str | None:
        """Return the current mode for a session, or None."""
        if session_id in self.chat_sessions:
            return self.chat_sessions[session_id]["mode"]
        return None

    # ── core generation ──────────────────────────────────────────────

    def generate_response(
        self,
        prompt: str,
        session_id: str = "default",
        mode: str = "education",
        model: str | None = None,
    ) -> dict:
        """Generate a response via Groq chat completion.

        Args:
            prompt:     The user's message.
            session_id: Identifier for multi-turn conversation history.
            mode:       One of 'red_team', 'pentest', 'education'.
            model:      Override the default model for this call.

        Returns:
            dict with keys ``success`` (bool) and ``response`` (str).
        """
        if mode not in self.VALID_MODES:
            mode = "education"

        chosen_model = model or self.model

        try:
            session = self.get_session(session_id, mode)
            messages = session["messages"]
            messages.append({"role": "user", "content": prompt})

            # All modes get high token limit; lower temp for accuracy
            temp = 0.5 if mode == "red_team" else 0.4
            tokens = 8192

            completion = self.client.chat.completions.create(
                model=chosen_model,
                messages=messages,
                temperature=temp,
                max_tokens=tokens,
            )

            assistant_msg = completion.choices[0].message.content
            messages.append({"role": "assistant", "content": assistant_msg})

            return {"success": True, "response": assistant_msg, "mode": mode}

        except Exception as e:
            error_text = str(e)
            if "rate_limit" in error_text.lower():
                return {
                    "success": False,
                    "response": "⚠️ Rate limit reached. Please wait a moment and try again.",
                }
            if "timeout" in error_text.lower():
                return {
                    "success": False,
                    "response": "⚠️ Request timed out. Please try again.",
                }
            if "authentication" in error_text.lower() or "401" in error_text:
                return {
                    "success": False,
                    "response": "⚠️ Invalid API key. Check GROQ_API_KEY in .env.",
                }
            return {"success": False, "response": f"Error: {error_text}"}
