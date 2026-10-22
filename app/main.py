"""
FastAPI backend for the PE malware detector.

Security model
  * Uploaded bytes are held in memory only, parsed with pefile, never written to disk or executed.
  * Size cap (MAX_UPLOAD_MB), per-IP rate limit, sanitized filenames, generic client errors
    (details go to server logs with a reference id), strict security headers, same-origin CORS.
"""
import hashlib, logging, os, pathlib, re, time, uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .model_service import ModelService
from .pe_features import NotAPEFile, extract_features

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("detector.api")

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATIC = pathlib.Path(__file__).resolve().parent / "static"
SAMPLES = ROOT / "test_files"
MAX_UPLOAD = int(float(os.getenv("MAX_UPLOAD_MB", "50")) * 1024 * 1024)
RATE_LIMIT, RATE_WINDOW = int(os.getenv("RATE_LIMIT_PER_MIN", "30")), 60
SAMPLE_FILES = {"benign_sample.bin": "Benign sample (inert header-only PE)",
                "simulated_malicious_sample.bin": "Simulated malicious sample (inert header-only PE)"}

service = ModelService()


@asynccontextmanager
async def lifespan(_app):
    service.load()
    yield


app = FastAPI(title="PE Malware Detector", version="1.0.0", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)   # no public API docs surface

_hits = defaultdict(deque)


@app.middleware("http")
async def guard(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.method == "POST":   # throttle scans only
        ip = request.client.host if request.client else "unknown"
        now, q = time.monotonic(), _hits[ip]
        while q and now - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return JSONResponse({"error": {"code": "RATE_LIMITED", "message": "Too many requests. Wait a minute and try again."}},
                                status_code=429, headers={"Retry-After": "60"})
        q.append(now)
    if request.url.path.startswith("/api/") and request.method == "POST":
        cl = request.headers.get("content-length")
        if request.method == "POST" and cl and cl.isdigit() and int(cl) > MAX_UPLOAD + 64 * 1024:
            return JSONResponse({"error": {"code": "TOO_LARGE", "message": f"File exceeds the {MAX_UPLOAD // 2**20} MB limit."}},
                                status_code=413)
    resp = await call_next(request)
    resp.headers.update({
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Content-Security-Policy": ("default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
                                    "font-src https://fonts.gstatic.com; img-src 'self' data:; "
                                    "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
    })
    if request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def err(status, code, message):
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status)


@app.exception_handler(RequestValidationError)
async def bad_request(_request, _exc):
    return err(400, "BAD_REQUEST", "Upload a file using the 'file' form field.")


@app.exception_handler(404)
async def not_found(_request, _exc):
    return err(404, "NOT_FOUND", "Not found.")


def safe_name(name: str) -> str:
    base = os.path.basename((name or "upload").replace("\\", "/"))
    base = re.sub(r"[\x00-\x1f\x7f<>\"'`]", "", base).strip()
    return (base or "upload")[:120]


def analyze(data: bytes, filename: str):
    started = time.perf_counter()
    try:
        feats = extract_features(data)
    except NotAPEFile as exc:
        return err(422, "NOT_A_PE_FILE",
                   "This is not a Windows PE file (.exe/.dll/.sys). The models only analyse PE header features, "
                   f"so no prediction was made. ({exc})")
    result = service.predict(feats)
    return {
        "file": {"name": safe_name(filename), "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()},
        "extracted_features": feats,
        **result,
        "feature_mapping": {"status": service.mapping_status, "note": service.mapping_note},
        "decision_rule": f"A model flags 'Benign' when P(benign) > {service.threshold} (same rule as the training evaluation); overall verdict is the majority of model votes.",
        "analysis_ms": round((time.perf_counter() - started) * 1000, 1),
    }


@app.get("/api/health")
def health():
    return {"status": "ok", "models_loaded": sorted(service.models), "models_failed": service.errors,
            "feature_mapping_status": service.mapping_status}


@app.get("/api/models")
def models_info():
    return {"features_used": service.features, "feature_mapping_status": service.mapping_status,
            "threshold_benign": service.threshold, "max_upload_mb": MAX_UPLOAD // 2**20,
            "models": [{"name": n, "loaded": n in service.models, "training_metrics": service.metrics.get(n)}
                       for n in ["RandomForest", "XGBoost", "LightGBM", "CatBoost", "Stacking"]],
            "samples": [{"file": k, "label": v} for k, v in SAMPLE_FILES.items() if (SAMPLES / k).exists()]}


@app.post("/api/scan")
async def scan(file: UploadFile = File(...)):
    try:
        data = bytearray()
        while chunk := await file.read(1024 * 1024):
            data += chunk
            if len(data) > MAX_UPLOAD:
                return err(413, "TOO_LARGE", f"File exceeds the {MAX_UPLOAD // 2**20} MB limit.")
        if not data:
            return err(400, "EMPTY_FILE", "The uploaded file is empty.")
        return analyze(bytes(data), file.filename)
    except Exception:
        ref = uuid.uuid4().hex[:8]
        log.exception("scan failed ref=%s", ref)
        return err(500, "INTERNAL_ERROR", f"The scan failed unexpectedly. Reference: {ref}")
    finally:
        await file.close()


@app.post("/api/scan-sample/{name}")
def scan_sample(name: str):
    if name not in SAMPLE_FILES or not (SAMPLES / name).is_file():     # whitelist: no path traversal
        return err(404, "UNKNOWN_SAMPLE", "No such bundled sample.")
    try:
        return analyze((SAMPLES / name).read_bytes(), name)
    except Exception:
        ref = uuid.uuid4().hex[:8]
        log.exception("sample scan failed ref=%s", ref)
        return err(500, "INTERNAL_ERROR", f"The scan failed unexpectedly. Reference: {ref}")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
