from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import os, json
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

load_dotenv()

from auth import verify_api_key
from db import SessionLocal, ScanReport
import modules

app = FastAPI(title="Security Recon Suite v3.0")

# Rate Limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

ALLOW_PAYMENT_TESTS = os.getenv("ALLOW_PAYMENT_TESTS", "false").lower() == "true"
PAYMENT_TEST_URL = os.getenv("PAYMENT_TEST_URL", "http://localhost:8000")

class ScanRequest(BaseModel):
    domain: str
    bot_token: str = None

def sanitize(domain):
    return domain.strip().replace("https://","").replace("http://","").replace("www.","").split("/")[0]

def save_report(domain, scan_type, result, cvss=0.0):
    db = SessionLocal()
    try:
        db.add(ScanReport(domain=domain, scan_type=scan_type, result=json.dumps(result, ensure_ascii=False), cvss_score=cvss))
        db.commit()
    finally:
        db.close()

@app.get("/")
def root():
    return {"status": "ok", "version": "3.0"}

@app.post("/scan/headers")
@limiter.limit("10/minute")
def s_headers(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_headers(d)
    save_report(d, "headers", res)
    return res

@app.post("/scan/ssl")
@limiter.limit("10/minute")
def s_ssl(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_ssl(d)
    save_report(d, "ssl", res)
    return res

@app.post("/scan/dns")
@limiter.limit("10/minute")
def s_dns(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_dns(d)
    save_report(d, "dns", res)
    return res

@app.post("/scan/subdomains")
@limiter.limit("5/minute")
def s_sub(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_subdomains(d)
    save_report(d, "subdomains", res)
    return res

@app.post("/scan/tech")
@limiter.limit("10/minute")
def s_tech(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_tech(d)
    save_report(d, "tech", res)
    return res

@app.post("/scan/exposed")
@limiter.limit("5/minute")
def s_exposed(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_exposed(d)
    save_report(d, "exposed", res)
    return res

@app.post("/scan/http_methods")
@limiter.limit("10/minute")
def s_http_methods(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_http_methods(d)
    save_report(d, "http_methods", res)
    return res

@app.post("/scan/cookies")
@limiter.limit("10/minute")
def s_cookies(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_cookies(d)
    save_report(d, "cookies", res)
    return res

@app.post("/scan/cors")
@limiter.limit("10/minute")
def s_cors(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_cors(d)
    save_report(d, "cors", res)
    return res

@app.post("/scan/open_redirect")
@limiter.limit("10/minute")
def s_open_redirect(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_open_redirect(d)
    save_report(d, "open_redirect", res)
    return res

@app.post("/scan/jwt")
@limiter.limit("10/minute")
def s_jwt(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_jwt(d)
    save_report(d, "jwt", res)
    return res

@app.post("/scan/rate_limit")
@limiter.limit("5/minute")
def s_rate_limit(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_rate_limit(d)
    save_report(d, "rate_limit", res)
    return res

@app.post("/scan/waf")
@limiter.limit("10/minute")
def s_waf(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_waf(d)
    save_report(d, "waf", res)
    return res

@app.post("/scan/server_info")
@limiter.limit("10/minute")
def s_server_info(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_server_info(d)
    save_report(d, "server_info", res)
    return res

@app.post("/scan/directory_listing")
@limiter.limit("5/minute")
def s_dir_listing(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_directory_listing(d)
    save_report(d, "directory_listing", res)
    return res

@app.post("/scan/sensitive_files")
@limiter.limit("5/minute")
def s_sensitive_files(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_sensitive_files(d)
    save_report(d, "sensitive_files", res)
    return res

@app.post("/scan/email_security")
@limiter.limit("10/minute")
def s_email_security(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_email_security(d)
    save_report(d, "email_security", res)
    return res

@app.post("/scan/security_txt")
@limiter.limit("10/minute")
def s_security_txt(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_security_txt(d)
    save_report(d, "security_txt", res)
    return res

@app.post("/scan/payment")
@limiter.limit("3/minute")
def s_payment(request: Request, _=Depends(verify_api_key)):
    if not ALLOW_PAYMENT_TESTS:
        raise HTTPException(403, "Payment tests disabled. Set ALLOW_PAYMENT_TESTS=true for staging only.")
    res = modules.scan_payment(PAYMENT_TEST_URL)
    save_report("staging", "payment", res)
    return res

@app.post("/scan/telegram")
@limiter.limit("5/minute")
def s_telegram(request: Request, req: ScanRequest, _=Depends(verify_api_key)):
    if not req.bot_token:
        raise HTTPException(400, "bot_token مطلوب")
    res = modules.scan_telegram(req.bot_token)
    save_report("telegram", "telegram", res)
    return res

@app.get("/reports")
def get_reports(domain: str = None, _=Depends(verify_api_key)):
    db = SessionLocal()
    try:
        q = db.query(ScanReport)
        if domain:
            q = q.filter(ScanReport.domain == domain)
        reports = q.order_by(ScanReport.created_at.desc()).limit(100).all()
        return [{"id": r.id, "domain": r.domain, "type": r.scan_type, "cvss": r.cvss_score, "date": r.created_at, "result": json.loads(r.result)} for r in reports]
    finally:
        db.close()
