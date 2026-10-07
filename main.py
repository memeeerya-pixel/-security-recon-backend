from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import os, json

load_dotenv()

from auth import verify_api_key
from db import SessionLocal, ScanReport
import modules

app = FastAPI(title="Security Recon Suite v2.0")

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

def sanitize(domain: str):
    return domain.strip().replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]

def save_report(domain, scan_type, result):
    db = SessionLocal()
    try:
        db.add(ScanReport(domain=domain, scan_type=scan_type, result=json.dumps(result, ensure_ascii=False)))
        db.commit()
    finally:
        db.close()

@app.get("/")
def root():
    return {"status": "ok", "version": "2.0"}

@app.post("/scan/headers")
def s_headers(req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_headers(d)
    save_report(d, "headers", res)
    return res

@app.post("/scan/ssl")
def s_ssl(req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_ssl(d)
    save_report(d, "ssl", res)
    return res

@app.post("/scan/dns")
def s_dns(req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_dns(d)
    save_report(d, "dns", res)
    return res

@app.post("/scan/subdomains")
def s_sub(req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_subdomains(d)
    save_report(d, "subdomains", res)
    return res

@app.post("/scan/tech")
def s_tech(req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_tech(d)
    save_report(d, "tech", res)
    return res

@app.post("/scan/exposed")
def s_exposed(req: ScanRequest, _=Depends(verify_api_key)):
    d = sanitize(req.domain)
    res = modules.scan_exposed(d)
    save_report(d, "exposed", res)
    return res

@app.post("/scan/payment")
def s_payment(req: ScanRequest, _=Depends(verify_api_key)):
    if not ALLOW_PAYMENT_TESTS:
        raise HTTPException(403, "Payment tests disabled. Set ALLOW_PAYMENT_TESTS=true for staging only.")
    res = modules.scan_payment(PAYMENT_TEST_URL)
    save_report("staging", "payment", res)
    return res

@app.post("/scan/telegram")
def s_telegram(req: ScanRequest, _=Depends(verify_api_key)):
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
        return [{"id": r.id, "domain": r.domain, "type": r.scan_type, "date": r.created_at, "result": json.loads(r.result)} for r in reports]
    finally:
        db.close()
