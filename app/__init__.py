"""
app/__init__.py — Flask App Factory
=====================================
create_app() builds the Flask application and wires everything together.

Call order:
  run.py  →  create_app()  →  register /chat/ routes  →  start server
"""

from flask import Flask
from config import DevelopmentConfig


def create_app(config_class=DevelopmentConfig):
    """Build and return the configured Flask application."""
    app = Flask(__name__)

    # Load settings (SECRET_KEY, DEBUG flag, etc.)
    app.config.from_object(config_class)

    # Register the chat blueprint — all /chat/ URLs are defined in app/routes/chat.py
    from app.routes.chat import chat_bp
    app.register_blueprint(chat_bp)

    return app
