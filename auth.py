from fastapi import Header, HTTPException
import os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("API_KEY", "change-me")

def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return True
