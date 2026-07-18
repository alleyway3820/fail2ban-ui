import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from api.auth import ensure_default_admin
from api.background import start_background_tasks, stop_background_tasks
from api.database import init_db
from api.routers import router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(__file__)
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "web", "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting f2b-sync-api...")
    await init_db()
    await ensure_default_admin()
    start_background_tasks()
    yield
    stop_background_tasks()
    logger.info("f2b-sync-api stopped")


app = FastAPI(
    title="f2b-sync-api",
    description="Centralized fail2ban sync service",
    version="1.0.0",
    lifespan=lifespan,
)

# F2B_CORS_ORIGINS: comma-separated allowed origins (default: "*").
# Set to a specific origin (e.g., "https://example.com") to enable credentials.
# Using wildcard ("*") with allow_credentials=True is rejected by browsers.
_cors_origins = [o.strip() for o in os.getenv("F2B_CORS_ORIGINS", "*").split(",")]
_allow_credentials = _cors_origins != ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "web", "static")), name="static")
app.include_router(router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "f2b-sync-api"}


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/geo-countries", response_class=HTMLResponse)
async def geo_countries_page(request: Request):
    return templates.TemplateResponse("geo-countries.html", {"request": request})


@app.get("/servers", response_class=HTMLResponse)
async def servers_page(request: Request):
    return templates.TemplateResponse("servers.html", {"request": request})


@app.get("/whitelist", response_class=HTMLResponse)
async def whitelist_page(request: Request):
    return templates.TemplateResponse("whitelist.html", {"request": request})


@app.exception_handler(404)
async def not_found(request: Request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "Not found"}, status_code=404)
    return templates.TemplateResponse("login.html", {"request": request}, status_code=404)
