from fastapi import FastAPI

from backend.api.targets import router as target_router
from backend.api.scans import router as scan_router
from backend.database import Base, engine
from backend import models 
from backend.api.findings import router as findings_router


Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="ReconX",
    description="Intelligent Recon Automation Platform",
    version="0.1.0"
)


app.include_router(target_router)
app.include_router(scan_router)
app.include_router(findings_router)

@app.get("/")
def root():
    return {
        "project": "ReconX",
        "status": "online"
    } 