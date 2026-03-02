"""
config.py — App Settings
========================
All settings live here.

Values come from the .env file — do NOT hardcode real secrets here.
.env is listed in .gitignore so it is never pushed to GitHub.
"""

import os


class Config:
    """Base settings shared by all environments."""
    # Used to sign session cookies — keep this secret in production!
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')


class DevelopmentConfig(Config):
    """Local development — debug mode ON (shows error detail, auto-reloads code)."""
    DEBUG = True


class ProductionConfig(Config):
    """Production — debug mode OFF (hides errors from users, more secure)."""
    DEBUG = False
