"""
run.py — START HERE
===================
This is the entry point for the ShieldWall app.

How to run:
    python run.py

The server starts at:  http://127.0.0.1:5000/chat/
"""

# Step 1: Load .env file so GROQ_API_KEY and SECRET_KEY are available
from dotenv import load_dotenv
load_dotenv()

# Step 2: Import the app factory
from app import create_app

if __name__ == '__main__':
    app = create_app()
    # debug=True → auto-reloads when you save code, shows error details in browser
    app.run(debug=True)
