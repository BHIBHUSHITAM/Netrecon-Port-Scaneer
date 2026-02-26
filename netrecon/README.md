# 🛡️ NetRecon — Network & Web Intelligence Dashboard

> A professional full-stack cybersecurity reconnaissance tool  
> Built with Python (Flask) · HTML · CSS · JavaScript  
> **For educational and authorized testing only**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?logo=flask)
![Google OAuth](https://img.shields.io/badge/Auth-Google%20OAuth2-4285F4?logo=google)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📋 Table of Contents

1. [Features](#features)
2. [Project Structure](#project-structure)
3. [Requirements](#requirements)
4. [Installation - Localhost](#installation-localhost)
5. [Google OAuth Setup - Step by Step](#google-oauth-setup)
6. [Running the App](#running-the-app)
7. [Demo Mode - No Login Needed](#demo-mode)
8. [API Reference](#api-reference)
9. [Deployment - Server](#deployment)
10. [Troubleshooting](#troubleshooting)

---

## Features

| Feature | Description |
|---|---|
| Port Scanner | Fast concurrent TCP port scanning with service detection, banner grabbing, and risk rating |
| Tech Fingerprinter | Detects 40+ frameworks, CMSs, servers (React, WordPress, Django, Nginx, etc.) |
| Security Header Audit | Analyzes 10 critical HTTP security headers and gives an A-F grade |
| SSL Certificate Checker | Validates SSL/TLS certs, issuer, subject, and expiry date |
| Google OAuth Login | Sign in with Google - shows your name, email, and avatar |
| Personal Dashboard | Personalized greeting, scan history, live stats |
| Demo Mode | Try all features without any Google login setup |
| Scan History | All scans saved to database, viewable per user |

---

## Project Structure

```
netrecon/
├── app.py                  <- Main Flask app, routes, Google OAuth, database models
├── requirements.txt        <- All Python dependencies
├── .env.example            <- Environment variable template (copy to .env)
├── .env                    <- Your config file (you create this, never commit to git)
├── .gitignore              <- Excludes .env, venv, __pycache__, etc.
├── Procfile                <- For deployment on Render / Railway / Heroku
├── README.md               <- This file
│
├── utils/
│   ├── __init__.py         <- Makes utils a Python package
│   ├── port_scanner.py     <- TCP port scanning engine (concurrent, fast)
│   └── url_scanner.py      <- Tech fingerprinter + security header analyzer
│
├── templates/
│   ├── login.html          <- Animated cyberpunk login page with Google OAuth button
│   ├── dashboard.html      <- Main dashboard with greeting, stats, scan history
│   ├── port_scanner.html   <- Port scanner UI with real-time progress and results table
│   └── url_scanner.html    <- URL/Tech scanner UI with tech cards and security score
│
└── static/
    ├── css/                <- Custom stylesheets
    ├── js/                 <- Custom scripts
    └── img/                <- Images and icons
```

---

## Requirements

- Python 3.10 or newer
- pip (comes with Python)
- Internet connection (for Google OAuth and scanning websites)
- A Google account (for OAuth login, or use Demo Mode to skip this)

---

## Installation Localhost

Follow these steps exactly in order.

### Step 1 - Download and extract the project

Extract the `netrecon.zip` file. You should have a folder called `netrecon`.

### Step 2 - Open Command Prompt inside the project folder

Open Command Prompt and navigate into the folder:
```cmd
cd path\to\netrecon
```

For example if it is on your Desktop:
```cmd
cd C:\Users\YourName\Desktop\netrecon
```

### Step 3 - Create a virtual environment

```cmd
python -m venv venv
```

This creates a `venv` folder. No output is normal, it means it worked.

### Step 4 - Activate the virtual environment

Windows Command Prompt:
```cmd
venv\Scripts\activate
```

Windows PowerShell:
```powershell
venv\Scripts\Activate.ps1
```

If PowerShell gives a permission error, first run this then try activate again:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Mac or Linux:
```bash
source venv/bin/activate
```

After activation you will see (venv) at the start of your prompt:
```
(venv) C:\Users\YourName\Desktop\netrecon>
```

### Step 5 - Install dependencies

```cmd
pip install -r requirements.txt
```

This installs Flask, BeautifulSoup, requests, and all other packages. It may take 1 to 2 minutes.

### Step 6 - Create your .env file

Windows CMD:
```cmd
copy .env.example .env
```

Mac or Linux:
```bash
cp .env.example .env
```

Now open `.env` in Notepad and fill in your values. See the Google OAuth section below for how to get the client ID and secret.

---

## Google OAuth Setup

This section explains exactly how to get your Google Client ID and Secret to enable Sign in with Google. Follow every step carefully.

### Step 1 - Go to Google Cloud Console

Open your browser and go to:
https://console.cloud.google.com

Sign in with your Google account.

---

### Step 2 - Create a new project

1. At the very top of the page, click the project dropdown (it may say "Select a project" or show an existing project name).
2. In the popup, click "New Project" in the top right corner.
3. Enter Project name: NetRecon
4. Leave Organization as default.
5. Click "Create".
6. Wait a few seconds, then make sure NetRecon is selected in the project dropdown at the top.

---

### Step 3 - Configure the OAuth Consent Screen

Before creating credentials, you must set up the consent screen. This is what users see when they log in.

1. In the left sidebar go to: APIs & Services then OAuth consent screen
2. Select "External" then click "Create"
3. Fill in the required fields:
   - App name: NetRecon
   - User support email: select your Gmail address from the dropdown
   - Developer contact information: type your Gmail address
4. Click "Save and Continue"
5. On the Scopes page, click "Save and Continue" (no changes needed)
6. On the Test users page, click "+ Add Users", add your Gmail address, then click "Save and Continue"
7. On the Summary page, click "Back to Dashboard"

---

### Step 4 - Create OAuth 2.0 Credentials

1. In the left sidebar go to: APIs & Services then Credentials
2. Click "+ Create Credentials" at the top
3. Select "OAuth 2.0 Client ID"
4. For Application type select: "Web application"
5. For Name enter: NetRecon Web Client
6. Under "Authorized redirect URIs" click "+ Add URI" and paste exactly:
   ```
   http://localhost:5000/login/google/authorized
   ```
   If you later deploy to a server, also add your production URL, for example:
   ```
   https://yourdomain.com/login/google/authorized
   ```
7. Click "Create"

---

### Step 5 - Copy your credentials

After clicking Create, a popup appears showing:
- Your Client ID, which looks like: 123456789-abc123xyz.apps.googleusercontent.com
- Your Client Secret, which looks like: GOCSPX-abc123xyz...

Copy both values. You can also click "Download JSON" as a backup.

Keep these secret. Never share them publicly or commit them to GitHub.

---

### Step 6 - Add credentials to your .env file

Open the `.env` file in Notepad and fill it in exactly like this, replacing the placeholder values:

```
SECRET_KEY=any-random-string-you-make-up-like-netrecon2024secret
GOOGLE_CLIENT_ID=paste-your-client-id-here.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=paste-your-client-secret-here
FLASK_ENV=development
FLASK_DEBUG=1
DATABASE_URL=sqlite:///netrecon.db
HOST=0.0.0.0
PORT=5000
```

Save the file.

---

## Running the App

Make sure your virtual environment is active (you see (venv) in the prompt), then run:

```cmd
python app.py
```

You should see output like this:
```
 * Running on http://127.0.0.1:5000
 * Running on http://0.0.0.0:5000
```

Open your browser and go to: http://localhost:5000

To stop the app press Ctrl+C in the terminal.

---

## Demo Mode

Do not want to set up Google OAuth yet? Use Demo Mode. It skips login completely and gives full access to all features.

Open your browser and go to:
```
http://localhost:5000/demo
```

You will be logged in instantly as Demo User and can use the Port Scanner and URL Scanner right away.

---

## API Reference

All API endpoints require login or a demo session.

| Method | Endpoint | Description |
|---|---|---|
| GET | / | Redirect to login or dashboard |
| GET | /login | Login page |
| GET | /demo | Demo login, no OAuth needed |
| GET | /logout | Log out current user |
| GET | /dashboard | Main dashboard |
| GET | /scanner/port | Port scanner page |
| GET | /scanner/url | URL scanner page |
| POST | /api/scan/port | Run a port scan |
| POST | /api/scan/url | Run a URL and tech scan |
| GET | /api/history | Get current user scan history |
| GET | /api/user | Get current user info |

Port Scan request body example:
```json
{
  "target": "192.168.1.1",
  "range": "common"
}
```

Range options: "common" scans 70 common ports, "top1000" scans first 1000, "full" scans all 65535, "custom" uses your custom_ports value.

URL Scan request body example:
```json
{
  "url": "https://example.com"
}
```

---

## Deployment

### Option A - Render.com (Free, Recommended for Students)

1. Push your project to GitHub (make sure .env is in .gitignore)
2. Go to https://render.com and sign up for free
3. Click "New" then "Web Service"
4. Connect your GitHub repository
5. Set Runtime to Python, Build Command to `pip install -r requirements.txt`, Start Command to `gunicorn app:app`
6. Go to the Environment tab and add all your .env variables one by one
7. Click "Create Web Service"

Your app will be live at https://yourapp.onrender.com

Also add https://yourapp.onrender.com/login/google/authorized to your Google OAuth authorized redirect URIs.

---

### Option B - VPS with Nginx (Ubuntu Server)

```bash
sudo apt update && sudo apt install python3-pip python3-venv nginx -y
cd /var/www
git clone https://github.com/yourusername/netrecon.git
cd netrecon
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install gunicorn
cp .env.example .env
nano .env
gunicorn -w 4 -b 127.0.0.1:5000 app:app
```

Then configure Nginx to proxy requests to port 5000.

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| 'python' is not recognized | Python not in PATH | Reinstall Python from python.org and check "Add to PATH" |
| source not recognized | Windows CMD does not support source | Use venv\Scripts\activate instead |
| Error 400 invalid_request | Google OAuth credentials missing | Fill in .env with your Client ID and Secret, or use /demo |
| ModuleNotFoundError | Dependencies not installed | Run pip install -r requirements.txt with venv active |
| Port 5000 already in use | Another app using port 5000 | Change PORT=5001 in .env |
| PowerShell activate error | Execution policy blocked | Run Set-ExecutionPolicy RemoteSigned -Scope CurrentUser |
| Google login fails after setup | Redirect URI mismatch | Make sure http://localhost:5000/login/google/authorized is added in Google Console |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask 3.0 |
| Authentication | Google OAuth 2.0 via Flask-Dance |
| Database | SQLite for development, PostgreSQL for production |
| Port Scanning | Python socket, concurrent.futures |
| Tech Detection | requests, BeautifulSoup4, lxml |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Fonts | Syne, JetBrains Mono from Google Fonts |
| Deployment | Gunicorn, Nginx, Render.com |

---

## Legal Notice

This tool is for educational and authorized security testing only. Only scan systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your country. The authors are not responsible for any misuse of this tool.

---

*Made for college project - Educational purposes only*
