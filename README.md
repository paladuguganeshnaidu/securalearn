# 🛡️ ShieldWall — ToriiMinds CyberOffense Intelligence Agent
**This project was developed using AI-assisted implementation to accelerate development.
System architecture, design decisions, validation, security review, refactoring, and final approval were performed manually.
AI was used as a productivity tool — not as a substitute for engineering judgment or ownership.
A **private AI-powered cybersecurity chatbot** built with Flask and Groq (LLaMA 3.3 70B).
Automatically saves every conversation to local storage (or Firebase Firestore if configured).

---

## ✨ Features

| Feature | Details |
|---|---|
| 🤖 3 AI Modes | Red Team · Pentest · Education |
| ⚡ Fast Streaming | Typewriter-style response animation |
| 📚 Chat History | Auto-saved, searchable, grouped by topic |
| 🧠 Deep Knowledge | 10-section research reports per topic |
| 💾 Dual Storage | SQLite (local, zero-config) → Firestore (cloud, optional) |
| 🎯 Skill Detection | Auto-tags each query: Beginner / Intermediate / Advanced / Expert |

---

## 📁 Project Structure

```
ShieldWall/
│
├── run.py                        ← START HERE — runs the app
├── config.py                     ← App settings (reads from .env)
├── requirements.txt              ← Python packages
├── .env                          ← Your secrets (never commit this!)
├── serviceAccountKey.json        ← Firebase credentials (optional)
│
└── app/
    ├── __init__.py               ← Creates the Flask app
    │
    ├── routes/
    │   └── chat.py               ← URL handlers: /chat/, /chat/message, /chat/history
    │
    ├── services/
    │   ├── groq_client.py        ← Talks to Groq AI API, manages conversation history
    │   └── firebase_service.py   ← Saves/retrieves chat history (SQLite or Firestore)
    │
    └── templates/
        └── chat.html             ← The entire front-end (HTML + CSS + JS in one file)
```

---

## 🚀 Quick Start

### 1. Clone and enter the folder
```bash
cd "ShieldWall"
```

### 2. Create a virtual environment
```bash
python -m venv .venv
```

### 3. Activate it
```bash
# Windows:
.\.venv\Scripts\activate

# Mac / Linux:
source .venv/bin/activate
```

### 4. Install dependencies
```bash
pip install -r requirements.txt
```

### 5. Create your `.env` file
Create a file called `.env` in the project root with:
```
GROQ_API_KEY=gsk_your_key_here
SECRET_KEY=any-random-string-you-choose
```
Get your free Groq API key at: https://console.groq.com

### 6. Run the app
```bash
python run.py
```

### 7. Open in browser
```
http://127.0.0.1:5000/chat/
```

---

## 💬 AI Modes

Switch between modes using the tabs at the top of the chat interface.

| Mode | Audience | Focus |
|---|---|---|
| 🔴 Red Team | Experienced attackers | Offensive techniques, exploit development, attack chains |
| 🔵 Pentest | Security professionals | Assessment methodology, tooling, reporting |
| 🟢 Education | Beginners & learners | Clear explanations, learning paths, concepts |

Each mode gives a **10-section deep research report** covering:
> Conceptual Foundation · Technical Mechanism · Variants · Exploitation Conditions ·  
> Detection · Defense · Automation · Case Studies · Offensive Exploitation · Advanced Insights

---

## 📚 Chat History

Every AI response is **automatically saved** — no action needed.

- Click the **📚 button** (top-right) to open the history drawer
- Search by topic, keyword, or mode
- Click any card to expand and see the full Q&A
- History persists between browser sessions (stored on the server)

### Storage backend (automatic):

```
serviceAccountKey.json present?
    YES → saves to Firebase Firestore (cloud, any device can access)
    NO  → saves to instance/history.db (SQLite file, local only)
```

---

## 🔥 Firebase Firestore Setup (Optional)

Only needed if you want cloud-synced history accessible from multiple devices.

1. Go to https://console.firebase.google.com → create a project
2. Enable **Firestore Database** (start in test mode)
3. Go to **Project Settings → Service Accounts → Generate new private key**
4. Rename the downloaded file to `serviceAccountKey.json`
5. Place it in the project root (same folder as `run.py`)
6. Restart the server — Firestore activates automatically

> **Security:** `serviceAccountKey.json` is in `.gitignore` — it will never be committed to Git.

---

## 🌐 API Endpoints

| Method | URL | Description |
|---|---|---|
| `GET` | `/chat/` | Main chat page |
| `POST` | `/chat/message` | Send a message, get AI response |
| `GET` | `/chat/history` | Get saved history (add `?topic=XSS` to filter) |
| `POST` | `/chat/clear` | Clear in-memory conversation |
| `GET` | `/chat/mode` | Get current active mode |

**POST /chat/message** body:
```json
{ "message": "explain sql injection", "mode": "education" }
```

---

## ⚙️ Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GROQ_API_KEY` | ✅ Yes | Your Groq API key |
| `SECRET_KEY` | ✅ Yes | Flask session signing key |

---

## 🔒 Security Notes

- `serviceAccountKey.json` and `.env` are in `.gitignore` — never pushed to GitHub
- This tool is for **authorized security research and education only**
- Never run attacks against systems you do not own or have written permission to test

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.13 · Flask 3.x |
| AI | Groq API · LLaMA 3.3 70B Versatile |
| Storage | SQLite (default) · Firebase Firestore (optional) |
| Frontend | Vanilla HTML + CSS + JavaScript (single file) |

---

*ToriiMinds CyberOffense Intelligence Agent — Private Project*
#

