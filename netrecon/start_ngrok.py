import os
import subprocess
import sys
import urllib.request
import zipfile
import platform

# ==========================
# CONFIGURATION
# ==========================
NGROK_AUTH_TOKEN = "3A4Er1uBOkgKnf3K7Jq4hR4eqra_4gvCoWVRY8harCucqfu3x"
LOCAL_PORT = "5000"   # Change to your localhost port
# ==========================

def download_ngrok():
    system = platform.system().lower()
    
    if system == "windows":
        url = "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip"
        zip_name = "ngrok.zip"
    elif system == "darwin":
        url = "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-darwin-amd64.zip"
        zip_name = "ngrok.zip"
    else:
        url = "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.zip"
        zip_name = "ngrok.zip"

    print("Downloading ngrok...")
    urllib.request.urlretrieve(url, zip_name)

    print("Extracting ngrok...")
    with zipfile.ZipFile(zip_name, 'r') as zip_ref:
        zip_ref.extractall(".")

    os.remove(zip_name)
    print("Ngrok ready.")

def ensure_ngrok():
    if not os.path.exists("ngrok") and not os.path.exists("ngrok.exe"):
        download_ngrok()

def authenticate():
    print("Authenticating ngrok...")
    subprocess.run(["ngrok", "config", "add-authtoken", NGROK_AUTH_TOKEN])

def start_tunnel():
    print(f"Starting tunnel on port {LOCAL_PORT}...")
    subprocess.run(["ngrok", "http", LOCAL_PORT])

if __name__ == "__main__":
    ensure_ngrok()
    authenticate()
    start_tunnel()