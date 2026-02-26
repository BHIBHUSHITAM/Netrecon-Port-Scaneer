"""
NetRecon - Technology Stack & URL Scanner Module
Detects technologies, frameworks, servers, and security headers.
"""

import re
import json
import socket
import ssl
import time
from urllib.parse import urlparse
from typing import Optional
import requests
from bs4 import BeautifulSoup


# Technology fingerprints (inspired by Wappalyzer patterns)
TECH_FINGERPRINTS = {
    # Web Servers
    "Apache": {
        "headers": {"Server": r"Apache"},
        "category": "Web Server", "icon": "🔴"
    },
    "Nginx": {
        "headers": {"Server": r"nginx"},
        "category": "Web Server", "icon": "🟢"
    },
    "IIS": {
        "headers": {"Server": r"IIS"},
        "category": "Web Server", "icon": "🔵"
    },
    "Cloudflare": {
        "headers": {"Server": r"cloudflare", "CF-Ray": r".*"},
        "category": "CDN", "icon": "🟠"
    },
    "AWS CloudFront": {
        "headers": {"Via": r"CloudFront", "X-Amz-Cf-Id": r".*"},
        "category": "CDN", "icon": "🟡"
    },
    "Vercel": {
        "headers": {"X-Vercel-Id": r".*", "Server": r"Vercel"},
        "category": "Hosting", "icon": "⚫"
    },
    "Netlify": {
        "headers": {"Server": r"Netlify", "X-Nf-Request-Id": r".*"},
        "category": "Hosting", "icon": "🔵"
    },

    # JavaScript Frameworks
    "React": {
        "html": [r"react", r"__REACT", r"data-reactroot", r"_reactFiber"],
        "scripts": [r"react\.js", r"react\.min\.js", r"react-dom"],
        "category": "JavaScript Framework", "icon": "⚛️"
    },
    "Vue.js": {
        "html": [r"vue\.js", r"vue\.min\.js", r"__vue__", r"data-v-"],
        "scripts": [r"vue\.js", r"vue\.min"],
        "category": "JavaScript Framework", "icon": "💚"
    },
    "Angular": {
        "html": [r"ng-version", r"angular\.js", r"ng-app", r"ng-controller"],
        "scripts": [r"angular\.js", r"angular\.min"],
        "category": "JavaScript Framework", "icon": "🔴"
    },
    "Next.js": {
        "html": [r"__NEXT_DATA__", r"_next/static"],
        "headers": {"X-Powered-By": r"Next\.js"},
        "category": "JavaScript Framework", "icon": "⚫"
    },
    "Nuxt.js": {
        "html": [r"__nuxt", r"nuxt-link"],
        "category": "JavaScript Framework", "icon": "💚"
    },
    "Svelte": {
        "html": [r"svelte-", r"__svelte"],
        "category": "JavaScript Framework", "icon": "🔴"
    },
    "jQuery": {
        "html": [r"jquery"],
        "scripts": [r"jquery[-\.]"],
        "category": "JavaScript Library", "icon": "🔵"
    },

    # Backend Frameworks
    "Django": {
        "headers": {"X-Frame-Options": r".*", "Set-Cookie": r"csrftoken"},
        "html": [r"csrfmiddlewaretoken", r"django"],
        "category": "Backend Framework", "icon": "🟢"
    },
    "Flask": {
        "headers": {"Server": r"Werkzeug"},
        "category": "Backend Framework", "icon": "⚫"
    },
    "Laravel": {
        "headers": {"Set-Cookie": r"laravel_session"},
        "html": [r"laravel"],
        "category": "Backend Framework", "icon": "🔴"
    },
    "WordPress": {
        "html": [r"wp-content", r"wp-includes", r"wordpress"],
        "headers": {"X-Powered-By": r".*"},
        "category": "CMS", "icon": "🔵"
    },
    "Drupal": {
        "html": [r"drupal", r"Drupal\.settings"],
        "headers": {"X-Generator": r"Drupal"},
        "category": "CMS", "icon": "🔵"
    },
    "Joomla": {
        "html": [r"joomla", r"/components/com_"],
        "category": "CMS", "icon": "🔴"
    },
    "Shopify": {
        "html": [r"shopify", r"Shopify\.theme"],
        "category": "E-Commerce", "icon": "🟢"
    },
    "WooCommerce": {
        "html": [r"woocommerce"],
        "category": "E-Commerce", "icon": "🟣"
    },

    # Languages/Runtimes
    "PHP": {
        "headers": {"X-Powered-By": r"PHP"},
        "html": [r"\.php"],
        "category": "Programming Language", "icon": "🐘"
    },
    "Node.js": {
        "headers": {"X-Powered-By": r"Express|Node"},
        "category": "Runtime", "icon": "🟢"
    },
    "ASP.NET": {
        "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r".*"},
        "category": "Backend Framework", "icon": "🔵"
    },
    "Ruby on Rails": {
        "headers": {"X-Runtime": r"[\d.]+", "X-Powered-By": r"Phusion Passenger"},
        "category": "Backend Framework", "icon": "🔴"
    },

    # Analytics & Tools
    "Google Analytics": {
        "html": [r"google-analytics\.com/analytics\.js", r"gtag\(", r"UA-\d+"],
        "category": "Analytics", "icon": "📊"
    },
    "Google Tag Manager": {
        "html": [r"googletagmanager\.com"],
        "category": "Tag Manager", "icon": "📊"
    },
    "Bootstrap": {
        "html": [r"bootstrap\.css", r"bootstrap\.min\.css"],
        "scripts": [r"bootstrap\.js", r"bootstrap\.min"],
        "category": "CSS Framework", "icon": "🟣"
    },
    "Tailwind CSS": {
        "html": [r"tailwind"],
        "category": "CSS Framework", "icon": "🔵"
    },
    "Font Awesome": {
        "html": [r"font-awesome", r"fontawesome"],
        "category": "Icon Library", "icon": "🅰️"
    },
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]


def normalize_url(url: str) -> str:
    """Ensure URL has scheme."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


def check_ssl(hostname: str) -> dict:
    """Check SSL certificate details."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            return {
                "valid": True,
                "subject": dict(x[0] for x in cert.get('subject', [])),
                "issuer": dict(x[0] for x in cert.get('issuer', [])),
                "expires": cert.get('notAfter', 'Unknown'),
                "san": cert.get('subjectAltName', [])
            }
    except ssl.SSLError as e:
        return {"valid": False, "error": str(e)}
    except Exception as e:
        return {"valid": None, "error": str(e)}


def detect_technologies(html: str, headers: dict, scripts: list) -> list:
    """Detect technologies from HTML, headers and scripts."""
    detected = []
    html_lower = html.lower()
    scripts_str = ' '.join(scripts).lower()

    for tech_name, patterns in TECH_FINGERPRINTS.items():
        found = False

        # Check headers
        if 'headers' in patterns:
            for header_name, pattern in patterns['headers'].items():
                header_value = headers.get(header_name, '') or headers.get(header_name.lower(), '')
                if header_value and re.search(pattern, header_value, re.IGNORECASE):
                    found = True
                    break

        if not found and 'html' in patterns:
            for pattern in patterns['html']:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    found = True
                    break

        if not found and 'scripts' in patterns:
            for pattern in patterns['scripts']:
                if re.search(pattern, scripts_str, re.IGNORECASE):
                    found = True
                    break

        if found:
            detected.append({
                "name": tech_name,
                "category": patterns.get("category", "Other"),
                "icon": patterns.get("icon", "🔧")
            })

    return detected


def analyze_security_headers(headers: dict) -> dict:
    """Analyze security headers and score."""
    present = []
    missing = []

    for header in SECURITY_HEADERS:
        if header.lower() in {k.lower(): v for k, v in headers.items()}:
            present.append(header)
        else:
            missing.append(header)

    score = int((len(present) / len(SECURITY_HEADERS)) * 100)
    grade = "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"

    return {
        "score": score,
        "grade": grade,
        "present": present,
        "missing": missing
    }


def scan_url(url: str) -> dict:
    """
    Main URL/tech scanner function.
    Returns full analysis of the target URL.
    """
    url = normalize_url(url)
    parsed = urlparse(url)
    hostname = parsed.hostname

    start_time = time.time()
    result = {
        "url": url,
        "hostname": hostname,
        "error": None,
        "status_code": None,
        "ip": None,
        "technologies": [],
        "security": {},
        "ssl": {},
        "headers": {},
        "meta": {},
        "links": {"internal": 0, "external": 0},
        "scan_time": 0
    }

    # Resolve IP
    try:
        result["ip"] = socket.gethostbyname(hostname)
    except Exception:
        pass

    # HTTP Request
    try:
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; NetRecon/1.0; +https://github.com/netrecon)'
        })

        resp = session.get(url, timeout=10, allow_redirects=True, verify=False)
        result["status_code"] = resp.status_code
        result["final_url"] = resp.url
        headers = dict(resp.headers)
        result["headers"] = headers

        # Security analysis
        result["security"] = analyze_security_headers(headers)

        # Parse HTML
        soup = BeautifulSoup(resp.text, 'lxml')

        # Extract scripts
        scripts = [s.get('src', '') for s in soup.find_all('script') if s.get('src')]

        # Detect technologies
        result["technologies"] = detect_technologies(resp.text, headers, scripts)

        # Meta info
        title = soup.find('title')
        desc = soup.find('meta', attrs={'name': 'description'})
        generator = soup.find('meta', attrs={'name': 'generator'})
        viewport = soup.find('meta', attrs={'name': 'viewport'})
        robots = soup.find('meta', attrs={'name': 'robots'})

        result["meta"] = {
            "title": title.get_text(strip=True) if title else None,
            "description": desc.get('content', '') if desc else None,
            "generator": generator.get('content', '') if generator else None,
            "viewport": viewport.get('content', '') if viewport else None,
            "robots": robots.get('content', '') if robots else None,
            "word_count": len(resp.text.split()),
            "html_size": f"{len(resp.content) / 1024:.1f} KB"
        }

        # Count links
        all_links = soup.find_all('a', href=True)
        internal = sum(1 for a in all_links if hostname in a['href'] or a['href'].startswith('/'))
        external = len(all_links) - internal
        result["links"] = {"internal": internal, "external": external, "total": len(all_links)}

        # Group technologies by category
        categories = {}
        for tech in result["technologies"]:
            cat = tech["category"]
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(tech)
        result["tech_categories"] = categories

    except requests.exceptions.SSLError:
        # Try HTTP fallback
        try:
            resp = session.get(url.replace('https://', 'http://'), timeout=10)
            result["status_code"] = resp.status_code
            result["ssl_error"] = "SSL verification failed"
        except Exception as e:
            result["error"] = str(e)
    except requests.exceptions.ConnectionError:
        result["error"] = "Connection refused or host unreachable"
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
    except Exception as e:
        result["error"] = str(e)

    # SSL Check
    result["ssl"] = check_ssl(hostname)

    result["scan_time"] = round(time.time() - start_time, 2)
    return result
