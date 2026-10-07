import requests, ssl, socket, datetime, threading, dns.resolver

# ---------- Security Headers ----------
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
]

def scan_headers(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=10, allow_redirects=True)
        result = {}
        for h in SECURITY_HEADERS:
            val = r.headers.get(h)
            result[h] = {"value": val, "status": "موجود" if val else "مفقود"}
        result["_server"] = r.headers.get("Server", "مخفي")
        result["_powered_by"] = r.headers.get("X-Powered-By", "مخفي")
        return result
    except Exception as e:
        return {"error": str(e)}

# ---------- SSL Check ----------
def scan_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            proto = s.version()
        expiry = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_left = (expiry - datetime.datetime.utcnow()).days
        return {
            "subject": dict(x[0] for x in cert['subject']),
            "issuer": dict(x[0] for x in cert['issuer']),
            "expires": cert['notAfter'],
            "days_left": days_left,
            "expired": days_left < 0,
            "protocol": proto,
        }
    except Exception as e:
        return {"error": str(e)}

# ---------- DNS ----------
def scan_dns(domain):
    out = {}
    for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA']:
        try:
            ans = dns.resolver.resolve(domain, rtype, lifetime=5)
            out[rtype] = [str(a) for a in ans]
        except Exception:
            out[rtype] = None
    return out

# ---------- Subdomains ----------
def scan_subdomains(domain):
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20)
        content_type = r.headers.get("Content-Type", "")
        if "application/json" not in content_type and not r.text.strip().startswith(("[", "{")):
            return {"error": "crt.sh أعاد رد غير JSON (ممكن حظر مؤقت). جرب لاحقاً."}
        data = r.json()
        subs = set()
        for entry in data:
            for name in entry.get('name_value', '').split('\n'):
                name = name.strip().lower()
                if name and '*' not in name:
                    subs.add(name)
        return sorted(subs)[:100]
    except Exception as e:
        return {"error": f"فشل جلب النطاقات الفرعية: {str(e)}"}

# ---------- Tech Detect ----------
SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes"],
    "React": ["react", "_next"],
    "Vue.js": ["vue.js", "__vue__"],
    "jQuery": ["jquery"],
    "Bootstrap": ["bootstrap"],
    "Cloudflare": ["cloudflare"],
    "PHP": ["php"],
    "Laravel": ["laravel_session"],
    "Django": ["csrftoken"],
}

def scan_tech(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=10)
        combined = (r.text + " " + str(r.headers)).lower()
        tech = [name for name, sigs in SIGNATURES.items() if any(s in combined for s in sigs)]
        return {
            "detected": tech,
            "server": r.headers.get("Server", "unknown"),
            "powered_by": r.headers.get("X-Powered-By", "unknown"),
        }
    except Exception as e:
        return {"error": str(e)}

# ---------- Exposed Files ----------
PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/.htaccess",
    "/wp-config.php.bak", "/config.php.bak",
    "/wp-admin/", "/phpmyadmin/", "/admin/",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/backup.zip", "/db.sql", "/.DS_Store",
]

def scan_exposed(domain):
    out = {}
    for p in PATHS:
        try:
            r = requests.head(f"https://{domain}{p}", timeout=6, allow_redirects=False)
            if r.status_code == 200:
                r2 = requests.get(f"https://{domain}{p}", timeout=6)
                ct = r2.headers.get("Content-Type", "")
                if "text/html" in ct and len(r2.content) > 5000:
                    out[p] = "مشبوه (صفحة خطأ محتملة)"
                else:
                    out[p] = f"مكشوف ({len(r2.content)} bytes)"
            elif r.status_code == 403:
                out[p] = "محمي (403)"
            elif r.status_code == 404:
                out[p] = "غير موجود"
            else:
                out[p] = f"حالة {r.status_code}"
        except Exception:
            out[p] = "خطأ"
    return out

# ---------- Payment Logic (Staging فقط) ----------
def scan_payment(base_url):
    results = {}

    def safe_post(path, payload, headers=None):
        try:
            r = requests.post(f"{base_url}{path}", json=payload, headers=headers or {}, timeout=5)
            return {"status": r.status_code, "body": r.text[:300]}
        except Exception as e:
            return {"error": str(e)}

    results["negative_amount"] = safe_post("/api/withdraw", {"amount": -100})
    results["zero_amount"] = safe_post("/api/withdraw", {"amount": 0})
    results["huge_amount"] = safe_post("/api/withdraw", {"amount": 999999999})

    h = {"Idempotency-Key": "test-123"}
    results["idempotency"] = {
        "first": safe_post("/api/withdraw", {"amount": 50}, h),
        "second": safe_post("/api/withdraw", {"amount": 50}, h),
    }

    race = []
    def withdraw():
        try:
            r = requests.post(f"{base_url}/api/withdraw", json={"amount": 100}, timeout=5)
            race.append(r.status_code)
        except Exception as e:
            race.append(str(e))
    threads = [threading.Thread(target=withdraw) for _ in range(5)]
    for t in threads: t.start()
    for t in threads: t.join()
    results["race_condition"] = race

    results["webhook_forgery"] = safe_post("/webhook/payment", {"status": "completed", "order_id": 123})
    return results

# ---------- Telegram Bot ----------
def scan_telegram(bot_token=None):
    if not bot_token:
        return {"error": "Bot token مطلوب"}
    try:
        r = requests.get(f"https://api.telegram.org/bot{bot_token}/getMe", timeout=10)
        data = r.json()
        if not data.get("ok"):
            return {"error": data.get("description", "فشل")}
        return {
            "bot": data["result"],
            "recommendations": [
                "فعّل Webhook مع secret_token",
                "تحقق من initData في كل طلب",
                "لا تخزن التوكن في الكود",
                "استخدم HTTPS للـ Webhook",
            ]
        }
    except Exception as e:
        return {"error": str(e)}
