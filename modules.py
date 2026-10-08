import requests, ssl, socket, datetime, threading, dns.resolver, time, re, base64, json as js

# ============================================================
# Helper: استخراج الدومين فقط (بدون مسار)
# ============================================================
def get_hostname(domain):
    return domain.split("/")[0]

# ============================================================
# Helper: طلب آمن مع Retry
# ============================================================
def safe_request(url, method="GET", timeout=10, headers=None, allow_redirects=True, json_data=None, retries=2):
    h = headers or {"User-Agent": "Mozilla/5.0 (Security-Recon-Tool)"}
    for attempt in range(retries + 1):
        try:
            if method == "GET":
                r = requests.get(url, timeout=timeout, headers=h, allow_redirects=allow_redirects)
            elif method == "HEAD":
                r = requests.head(url, timeout=timeout, headers=h, allow_redirects=allow_redirects)
            elif method == "OPTIONS":
                r = requests.options(url, timeout=timeout, headers=h, allow_redirects=allow_redirects)
            elif method == "POST":
                r = requests.post(url, timeout=timeout, headers=h, json=json_data, allow_redirects=allow_redirects)
            elif method == "PUT":
                r = requests.put(url, timeout=timeout, headers=h, json=json_data, allow_redirects=allow_redirects)
            elif method == "DELETE":
                r = requests.delete(url, timeout=timeout, headers=h, allow_redirects=allow_redirects)
            else:
                return {"error": f"طريقة غير مدعومة: {method}"}
            return {"ok": True, "response": r}
        except requests.exceptions.Timeout:
            if attempt == retries: return {"error": "انتهت مهلة الطلب (Timeout)"}
            time.sleep(1)
        except requests.exceptions.SSLError:
            return {"error": "خطأ في شهادة SSL"}
        except requests.exceptions.ConnectionError:
            if attempt == retries: return {"error": "فشل الاتصال بالسيرفر"}
            time.sleep(1)
        except Exception as e:
            return {"error": f"خطأ غير متوقع: {str(e)}"}
    return {"error": "فشل بعد عدة محاولات"}

# ============================================================
# 1. Security Headers (يدعم المسار)
# ============================================================
SECURITY_HEADERS = ["Strict-Transport-Security","Content-Security-Policy","X-Frame-Options","X-Content-Type-Options","Referrer-Policy","Permissions-Policy","Cross-Origin-Opener-Policy","Cross-Origin-Embedder-Policy"]

def scan_headers(domain):
    res = safe_request(f"https://{domain}")
    if "error" in res: return res
    r = res["response"]
    result = {}
    for h in SECURITY_HEADERS:
        val = r.headers.get(h)
        result[h] = {"value": val, "status": "موجود" if val else "مفقود"}
    result["_server"] = r.headers.get("Server", "مخفي")
    result["_powered_by"] = r.headers.get("X-Powered-By", "مخفي")
    result["_status_code"] = r.status_code
    result["_url_checked"] = f"https://{domain}"
    return result

# ============================================================
# 2. SSL Check (يستخدم الدومين فقط)
# ============================================================
def scan_ssl(domain):
    hostname = get_hostname(domain)
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(10); s.connect((hostname, 443))
            cert = s.getpeercert(); proto = s.version()
        expiry = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_left = (expiry - datetime.datetime.utcnow()).days
        return {"subject": dict(x[0] for x in cert['subject']),"issuer": dict(x[0] for x in cert['issuer']),"expires": cert['notAfter'],"days_left": days_left,"expired": days_left < 0,"protocol": proto}
    except ssl.SSLCertVerificationError as e:
        return {"error": f"شهادة SSL غير موثوقة: {str(e)}"}
    except socket.timeout:
        return {"error": "انتهت مهلة الاتصال بـ SSL"}
    except Exception as e:
        return {"error": f"فشل فحص SSL: {str(e)}"}

# ============================================================
# 3. DNS (يستخدم الدومين فقط)
# ============================================================
def scan_dns(domain):
    hostname = get_hostname(domain)
    out = {}
    for rtype in ['A','AAAA','MX','TXT','NS','CNAME','SOA','CAA']:
        try:
            ans = dns.resolver.resolve(hostname, rtype, lifetime=5)
            out[rtype] = [str(a) for a in ans]
        except Exception:
            out[rtype] = None
    return out

# ============================================================
# 4. Subdomains (يستخدم الدومين فقط)
# ============================================================
def scan_subdomains(domain):
    hostname = get_hostname(domain)
    res = safe_request(f"https://crt.sh/?q=%25.{hostname}&output=json", timeout=25)
    if "error" in res: return {"error": res["error"]}
    r = res["response"]
    ct = r.headers.get("Content-Type", "")
    if "application/json" not in ct and not r.text.strip().startswith(("[","{")):
        return {"error": "crt.sh أعاد رد غير JSON. جرب لاحقاً."}
    try: data = r.json()
    except ValueError: return {"error": "فشل تحويل رد crt.sh إلى JSON"}
    subs = set()
    for entry in data:
        for name in entry.get('name_value','').split('\n'):
            name = name.strip().lower()
            if name and '*' not in name: subs.add(name)
    return sorted(subs)[:100]

# ============================================================
# 5. Tech Detect (يدعم المسار)
# ============================================================
SIGNATURES = {"WordPress":["wp-content","wp-includes"],"React":["react","_next"],"Vue.js":["vue.js","__vue__"],"jQuery":["jquery"],"Bootstrap":["bootstrap"],"Cloudflare":["cloudflare"],"PHP":["php"],"Laravel":["laravel_session"],"Django":["csrftoken"],"Nginx":["nginx"],"Apache":["apache"]}

def scan_tech(domain):
    res = safe_request(f"https://{domain}")
    if "error" in res: return res
    r = res["response"]
    combined = (r.text + " " + str(r.headers)).lower()
    tech = [name for name, sigs in SIGNATURES.items() if any(s in combined for s in sigs)]
    return {"detected": tech,"server": r.headers.get("Server","unknown"),"powered_by": r.headers.get("X-Powered-By","unknown"),"status_code": r.status_code,"url_checked": f"https://{domain}"}

# ============================================================
# 6. Exposed Files (يستخدم الدومين فقط - الملفات عادة في الروت)
# ============================================================
PATHS = ["/.env","/.git/config","/.git/HEAD","/.htaccess","/wp-config.php.bak","/config.php.bak","/wp-admin/","/phpmyadmin/","/admin/","/robots.txt","/sitemap.xml","/.well-known/security.txt","/backup.zip","/db.sql","/.DS_Store"]

def scan_exposed(domain):
    hostname = get_hostname(domain)
    out = {}
    for p in PATHS:
        res = safe_request(f"https://{hostname}{p}", method="HEAD", timeout=6, allow_redirects=False)
        if "error" in res:
            out[p] = "خطأ في الطلب"; continue
        code = res["response"].status_code
        if code == 200: out[p] = "مكشوف (200)"
        elif code == 403: out[p] = "محمي (403)"
        elif code == 404: out[p] = "غير موجود"
        elif code in (301,302): out[p] = f"تحويل ({code})"
        else: out[p] = f"حالة {code}"
    return out

# ============================================================
# 7. HTTP Methods (يدعم المسار)
# ============================================================
def scan_http_methods(domain):
    res = safe_request(f"https://{domain}", method="OPTIONS", timeout=8)
    if "error" in res: return res
    allow = res["response"].headers.get("Allow","")
    methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
    dangerous = [m for m in methods if m in ("PUT","DELETE","PATCH","TRACE")]
    return {"allowed_methods": methods,"dangerous_methods": dangerous,"status": "تحذير: طرق خطيرة مفعّلة" if dangerous else "آمن نسبياً"}

# ============================================================
# 8. Cookie Security (يدعم المسار)
# ============================================================
def scan_cookies(domain):
    res = safe_request(f"https://{domain}")
    if "error" in res: return res
    r = res["response"]
    if not r.cookies: return {"message": "لا يوجد كوكيز في الرد"}
    out = []
    for c in r.cookies:
        out.append({"name": c.name,"secure": c.secure,"httponly": c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly"),"samesite": c.get_nonstandard_attr("SameSite","غير محدد")})
    return out

# ============================================================
# 9. CORS Check (يدعم المسار)
# ============================================================
def scan_cors(domain):
    headers = {"Origin": "https://evil-example.com"}
    res = safe_request(f"https://{domain}", headers=headers, timeout=8)
    if "error" in res: return res
    r = res["response"]
    acao = r.headers.get("Access-Control-Allow-Origin","")
    acac = r.headers.get("Access-Control-Allow-Credentials","")
    if acao == "*" and acac.lower() == "true":
        return {"status": "خطر: CORS مفتوح مع Credentials","acao": acao,"acac": acac}
    elif acao == "*":
        return {"status": "CORS مفتوح (بدون credentials)","acao": acao}
    elif acao:
        return {"status": "CORS محدد","acao": acao}
    return {"status": "لا يوجد CORS"}

# ============================================================
# 10. Open Redirect (يدعم المسار)
# ============================================================
def scan_open_redirect(domain):
    hostname = get_hostname(domain)
    payloads = [f"https://{hostname}/?redirect=https://evil-example.com",f"https://{hostname}/?url=https://evil-example.com",f"https://{hostname}/?next=https://evil-example.com"]
    findings = []
    for url in payloads:
        res = safe_request(url, timeout=6, allow_redirects=False)
        if "error" in res: continue
        location = res["response"].headers.get("Location","")
        if "evil-example.com" in location:
            findings.append({"url": url,"location": location})
    if findings:
        return {"status": "خطر: Open Redirect محتمل","findings": findings}
    return {"status": "لا يوجد Open Redirect واضح"}

# ============================================================
# 11. JWT Analysis (يدعم المسار)
# ============================================================
def scan_jwt(domain):
    res = safe_request(f"https://{domain}")
    if "error" in res: return res
    pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
    matches = set(pattern.findall(res["response"].text))
    findings = []
    for m in matches:
        parts = m.split(".")
        try:
            header = js.loads(base64.urlsafe_b64decode(parts[0] + "==="))
            payload = js.loads(base64.urlsafe_b64decode(parts[1] + "==="))
            findings.append({"header": header,"payload": payload})
        except Exception: continue
    if findings: return {"status": "تم العثور على JWT","tokens": findings[:5]}
    return {"status": "لا يوجد JWT ظاهر في الرد"}

# ============================================================
# 12. Rate Limiting (يدعم المسار)
# ============================================================
def scan_rate_limit(domain):
    statuses = []
    for _ in range(10):
        res = safe_request(f"https://{domain}", timeout=5)
        statuses.append("error" if "error" in res else res["response"].status_code)
    blocked = any(s == 429 for s in statuses)
    return {"statuses": statuses,"rate_limited": blocked,"status": "يوجد Rate Limiting" if blocked else "لا يوجد Rate Limiting واضح"}

# ============================================================
# 13. Payment Logic (Staging فقط)
# ============================================================
def scan_payment(base_url):
    results = {}
    def safe_post(path, payload, headers=None):
        res = safe_request(f"{base_url}{path}", method="POST", json_data=payload, headers=headers, timeout=5)
        if "error" in res: return {"error": res["error"]}
        return {"status": res["response"].status_code, "body": res["response"].text[:300]}
    results["negative_amount"] = safe_post("/api/withdraw", {"amount": -100})
    results["zero_amount"] = safe_post("/api/withdraw", {"amount": 0})
    results["huge_amount"] = safe_post("/api/withdraw", {"amount": 999999999})
    h = {"Idempotency-Key": "test-123"}
    results["idempotency"] = {"first": safe_post("/api/withdraw", {"amount": 50}, h),"second": safe_post("/api/withdraw", {"amount": 50}, h)}
    race = []
    def withdraw():
        res = safe_request(f"{base_url}/api/withdraw", method="POST", json_data={"amount": 100}, timeout=5)
        race.append("error" if "error" in res else res["response"].status_code)
    threads = [threading.Thread(target=withdraw) for _ in range(5)]
    for t in threads: t.start()
    for t in threads: t.join()
    results["race_condition"] = race
    results["webhook_forgery"] = safe_post("/webhook/payment", {"status": "completed", "order_id": 123})
    return results

# ============================================================
# 14. Telegram Bot
# ============================================================
def scan_telegram(bot_token=None):
    if not bot_token: return {"error": "Bot token مطلوب"}
    res = safe_request(f"https://api.telegram.org/bot{bot_token}/getMe")
    if "error" in res: return res
    try: data = res["response"].json()
    except ValueError: return {"error": "رد غير JSON من Telegram API"}
    if not data.get("ok"): return {"error": data.get("description","فشل")}
    return {"bot": data["result"],"recommendations": ["فعّل Webhook مع secret_token","تحقق من initData في كل طلب","لا تخزن التوكن في الكود","استخدم HTTPS للـ Webhook"]}

# ============================================================
# 15. WAF Detection (يدعم المسار)
# ============================================================
def scan_waf(domain):
    res = safe_request(f"https://{domain}")
    if "error" in res: return res
    headers = str(res["response"].headers).lower()
    wafs = []
    if "cloudflare" in headers: wafs.append("Cloudflare")
    if "sucuri" in headers: wafs.append("Sucuri")
    if "akamai" in headers: wafs.append("Akamai")
    if "incapsula" in headers: wafs.append("Imperva Incapsula")
    return {"waf_detected": wafs, "status": "يوجد WAF" if wafs else "لا يوجد WAF واضح"}

# ============================================================
# 16. Server Info Leak (يدعم المسار)
# ============================================================
def scan_server_info(domain):
    res = safe_request(f"https://{domain}")
    if "error" in res: return res
    h = res["response"].headers
    return {"server": h.get("Server","مخفي"),"x_powered_by": h.get("X-Powered-By","مخفي"),"x_aspnet_version": h.get("X-AspNet-Version","مخفي"),"via": h.get("Via","مخفي")}

# ============================================================
# 17. Directory Listing (يستخدم الدومين فقط)
# ============================================================
def scan_directory_listing(domain):
    hostname = get_hostname(domain)
    paths = ["/", "/images/", "/uploads/", "/files/", "/backup/", "/assets/"]
    out = {}
    for p in paths:
        res = safe_request(f"https://{hostname}{p}", timeout=6)
        if "error" in res: continue
        text = res["response"].text.lower()
        if "index of /" in text or "directory listing" in text:
            out[p] = "مفتوح للتصفح"
        else:
            out[p] = "مغلق"
    return out

# ============================================================
# 18. Sensitive Files (يستخدم الدومين فقط)
# ============================================================
def scan_sensitive_files(domain):
    hostname = get_hostname(domain)
    files = ["/config.json","/config.php","/wp-config.php","/.aws/credentials","/credentials.json","/secrets.json","/database.yml"]
    out = {}
    for f in files:
        res = safe_request(f"https://{hostname}{f}", method="HEAD", timeout=6, allow_redirects=False)
        if "error" in res: out[f] = "خطأ"; continue
        code = res["response"].status_code
        out[f] = "مكشوف" if code == 200 else "محمي" if code == 403 else "غير موجود"
    return out

# ============================================================
# 19. Email Security (يستخدم الدومين فقط)
# ============================================================
def scan_email_security(domain):
    hostname = get_hostname(domain)
    out = {}
    try:
        txt = dns.resolver.resolve(hostname, 'TXT', lifetime=5)
        spf = [str(t) for t in txt if 'v=spf1' in str(t)]
        out['SPF'] = spf[0] if spf else "مفقود"
    except Exception:
        out['SPF'] = "خطأ"
    try:
        dmarc = dns.resolver.resolve(f"_dmarc.{hostname}", 'TXT', lifetime=5)
        out['DMARC'] = [str(t) for t in dmarc]
    except Exception:
        out['DMARC'] = "مفقود"
    return out

# ============================================================
# 20. Security.txt (يستخدم الدومين فقط)
# ============================================================
def scan_security_txt(domain):
    hostname = get_hostname(domain)
    res = safe_request(f"https://{hostname}/.well-known/security.txt", timeout=6)
    if "error" in res: return {"status": "خطأ في الطلب"}
    if res["response"].status_code == 200:
        return {"status": "موجود", "content": res["response"].text[:500]}
    return {"status": "غير موجود"}
