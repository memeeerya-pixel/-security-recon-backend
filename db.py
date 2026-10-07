from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import os

DB_URL = os.getenv("DB_URL", "sqlite:///./recon.db")
engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if "sqlite" in DB_URL else {})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class ScanReport(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), index=True)
    scan_type = Column(String(50))
    result = Column(Text)
    cvss_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(engine)
