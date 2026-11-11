from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import time
import unicodedata
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Callable, Literal, TypeVar
from urllib.parse import unquote

import anyio
import joblib
from anyio import to_thread
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import DateTime, Float, Integer, String, create_engine, delete, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from starlette.exceptions import HTTPException as StarletteHTTPException

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


# ==============================================================================================
# CONFIG
# All configuration comes from environment variables (or a local .env file).
#
# Nothing secret lives in source code. Copy .env.example to .env and edit it.
# ==============================================================================================
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


def _float(name: str, default: float) -> float:
    return float(os.getenv(name, str(default)))


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # Front-end origins allowed by CORS (comma separated). Never "*".
    allowed_origins: list[str] = field(default_factory=lambda: [
        o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",") if o.strip()
    ])

    model_path: Path = Path(os.getenv("MODEL_PATH", str(BASE_DIR / "model" / "phishing_model.joblib")))
    # Expected SHA-256 of the model file. The server refuses to start if it does not match.
    model_sha256: str = os.getenv("MODEL_SHA256", "").strip().lower()

    database_url: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'data' / 'history.db'}")

    # --- input size limits (section 2.3 + DoS defence) ---
    max_body_bytes: int = _int("MAX_BODY_BYTES", 8 * 1024)      # whole request body
    max_url_length: int = _int("MAX_URL_LENGTH", 2048)          # characters in the URL field

    # --- DoS defence: bounded inference pool ---
    max_concurrent_inferences: int = _int("MAX_CONCURRENT_INFERENCES", 2)
    max_queued_requests: int = _int("MAX_QUEUED_REQUESTS", 8)
    queue_timeout_s: float = _float("QUEUE_TIMEOUT_S", 1.0)
    inference_timeout_s: float = _float("INFERENCE_TIMEOUT_S", 5.0)

    # --- model decision ---
    phishing_threshold: float = _float("PHISHING_THRESHOLD", 0.5)
    # "block": a host disguised with look-alike characters is always reported as phishing.
    # "flag": only normalise + show a warning signal, the model alone decides.
    homoglyph_policy: str = os.getenv("HOMOGLYPH_POLICY", "block").strip().lower()

    # --- demo switch for the video ---
    # "secure" (default) or "insecure". Insecure turns OFF the DoS and SQL injection defences
    # and the URL normalisation so the attacks can be shown succeeding. Never deploy insecure.
    security_mode: str = os.getenv("SECURITY_MODE", "secure").strip().lower()

    enable_docs: bool = _bool("ENABLE_DOCS", True)
    history_limit_max: int = _int("HISTORY_LIMIT_MAX", 100)

    @property
    def insecure(self) -> bool:
        return self.security_mode == "insecure"


settings = Settings()


# ==============================================================================================
# ERRORS
# One JSON error format for every error the API can return.
#
#     {"error": {"code": "...", "message": "...", "details": [...] | null, "request_id": "..."}}
#
# Stack traces and exception text are never sent to the client; they go to the server log,
# tagged with the same request_id so a reported error can be traced.
# ==============================================================================================
log = logging.getLogger("app.errors")


class APIError(Exception):
    """Raise this anywhere in the app for a controlled, client-safe error."""

    def __init__(self, status_code: int, code: str, message: str,
                 details: list | None = None, headers: dict | None = None):
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details
        self.headers = headers or {}


def error_body(request: Request, code: str, message: str, details: list | None = None) -> dict:
    return {"error": {
        "code": code,
        "message": message,
        "details": details,
        "request_id": getattr(request.state, "request_id", None),
    }}


def error_response(request: Request, status: int, code: str, message: str,
                   details: list | None = None, headers: dict | None = None) -> JSONResponse:
    return JSONResponse(error_body(request, code, message, details), status_code=status, headers=headers)


_HTTP_CODES = {
    400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
    405: "method_not_allowed", 413: "payload_too_large", 415: "unsupported_media_type",
    429: "too_many_requests", 503: "service_unavailable",
}


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(APIError)
    async def _api_error(request: Request, exc: APIError):
        return error_response(request, exc.status_code, exc.code, exc.message, exc.details, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        # Only safe fields are echoed: where the problem is and what is wrong.
        # The rejected input itself is NOT echoed back (it could be huge or hostile).
        details = [
            {"field": ".".join(str(p) for p in err.get("loc", []) if p != "body") or "body",
             "problem": err.get("msg", "invalid value")}
            for err in exc.errors()
        ]
        return error_response(request, 422, "invalid_input",
                              "The request was not valid. See details.", details)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        code = _HTTP_CODES.get(exc.status_code, "http_error")
        message = exc.detail if isinstance(exc.detail, str) else "Request failed."
        if exc.status_code == 404:
            message = "No such endpoint."
        return error_response(request, exc.status_code, code, message, headers=getattr(exc, "headers", None))

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception):
        log.exception("Unhandled error (request_id=%s)", getattr(request.state, "request_id", None))
        return error_response(request, 500, "internal_error",
                              "Something went wrong on our side. Please try again.")


# ==============================================================================================
# NORMALISE
# Detection-evasion defence (section 2.8): normalise a URL before the model sees it.
#
# A phisher can change what the model sees without changing what a person sees:
#     pаypal.com      (Cyrillic 'а' instead of Latin 'a')
#     ｐａｙｐａｌ.com  (full-width letters)
#     pay​pal.com (zero-width space)
#     %70aypal.com    (percent-encoded 'p')
#     xn--pypal-4ve.com (punycode form of a look-alike domain)
#
# The model was trained on plain ASCII URLs, so each of these turns known-bad tokens into
# tokens it has never seen. This module undoes the disguise so the model sees the same text
# a human reads, and reports which tricks were found so they can be shown as warning signals.
#
# Every step here is linear in the input length: no backtracking regular expressions, so a
# crafted URL cannot make normalisation itself slow (see the DoS defence).
# ==============================================================================================
# Look-alike characters -> the ASCII letter a reader would see.
# Based on the Unicode confusables data (UTS #39) for the scripts most used in IDN phishing.
CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "һ": "h", "і": "i", "ј": "j", "к": "k",
    "ӏ": "l", "м": "m", "п": "n", "о": "o", "р": "p", "ԛ": "q", "г": "r", "ѕ": "s", "т": "t",
    "ц": "u", "ѵ": "v", "ԝ": "w", "х": "x", "у": "y", "з": "3", "ь": "b", "ꙇ": "i",
    "А": "a", "В": "b", "С": "c", "Е": "e", "Н": "h", "І": "i", "Ј": "j", "К": "k", "М": "m",
    "О": "o", "Р": "p", "Ѕ": "s", "Т": "t", "Х": "x", "У": "y", "Ԝ": "w",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "γ": "y", "ω": "w",
    "Α": "a", "Β": "b", "Ε": "e", "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o",
    "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x", "Ζ": "z",
    # Armenian / Latin extras / others commonly abused
    "օ": "o", "ս": "u", "ց": "g", "ɑ": "a", "ɡ": "g", "ı": "i", "ȷ": "j", "ɩ": "i", "ʟ": "l",
    "ℓ": "l", "ǀ": "l", "ꞁ": "l", "Ɩ": "l", "ɒ": "a", "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d",
    "ᴇ": "e", "ɢ": "g", "ʜ": "h", "ɪ": "i", "ᴊ": "j", "ᴋ": "k", "ᴍ": "m", "ɴ": "n", "ᴏ": "o",
    "ᴘ": "p", "ʀ": "r", "ꜱ": "s", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ʏ": "y", "ᴢ": "z",
    # Punctuation look-alikes used to fake separators
    "․": ".", "‧": ".", "。": ".", "．": ".", "｡": ".", "∕": "/", "⁄": "/", "／": "/",
    "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "－": "-",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "zip", "mov", "work", "click", "link",
    "country", "kim", "loan", "men", "review", "rest", "cam", "buzz", "monster", "icu",
}
LONG_URL = 75          # characters; common threshold in phishing-URL research
MANY_SUBDOMAINS = 4    # dots in the host


@dataclass
class Signal:
    id: str
    label: str
    severity: str  # "info" | "warning" | "danger"
    detail: str


@dataclass
class NormalisedURL:
    original: str
    normalised: str
    host: str
    homoglyph_in_host: bool = False
    signals: list[Signal] = field(default_factory=list)


def _strip_invisible(s: str) -> tuple[str, int]:
    """Remove zero-width / format / control characters (Unicode categories Cf and Cc)."""
    out = [c for c in s if unicodedata.category(c) not in ("Cf", "Cc")]
    return "".join(out), len(s) - len(out)


def _percent_decode(s: str, rounds: int = 3) -> tuple[str, bool]:
    """Undo percent-encoding, including double encoding (%2570 -> %70 -> p). Bounded rounds."""
    changed = False
    for _ in range(rounds):
        if "%" not in s:
            break
        decoded = unquote(s, errors="replace")
        if decoded == s:
            break
        s, changed = decoded, True
    return s, changed


def _split_host(url: str) -> tuple[str, str, str]:
    """Return (scheme_part, host, rest) without regular expressions."""
    scheme = ""
    lower = url.lower()
    for prefix in ("https://", "http://"):
        if lower.startswith(prefix):
            scheme, url = url[: len(prefix)], url[len(prefix):]
            break
    cut = len(url)
    for sep in ("/", "?", "#"):
        i = url.find(sep)
        if i != -1:
            cut = min(cut, i)
    authority, rest = url[:cut], url[cut:]
    host = authority.rsplit("@", 1)[-1]          # drop user:pass@
    if host.startswith("[") and "]" in host:     # IPv6 literal
        host = host[: host.index("]") + 1]
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]             # drop :port
    prefix = authority[: len(authority) - len(authority.rsplit("@", 1)[-1])]
    port = authority[len(prefix) + len(host):]
    return scheme + prefix, host, port + rest


def _decode_punycode_host(host: str) -> tuple[str, bool]:
    labels, found = [], False
    for label in host.split("."):
        if label.lower().startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
                found = True
                continue
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels), found


def _fold(s: str) -> tuple[str, int, set[str]]:
    """Map look-alikes to ASCII. Returns (folded, number_replaced, scripts_seen)."""
    out, replaced, scripts = [], 0, set()
    for ch in s:
        if ch.isascii():
            out.append(ch)
            if ch.isalpha():
                scripts.add("LATIN")
            continue
        mapped = CONFUSABLES.get(ch)
        if mapped is None:
            # é -> e, ñ -> n: drop accents the reader barely notices
            base = "".join(c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c))
            mapped = base if base and base.isascii() else None
        if ch.isalpha():
            try:
                scripts.add(unicodedata.name(ch).split(" ")[0])
            except ValueError:
                pass
        if mapped is not None:
            out.append(mapped)
            replaced += 1
        else:
            out.append(ch)
    return "".join(out), replaced, scripts


def normalise_url(raw: str) -> NormalisedURL:
    signals: list[Signal] = []
    s = raw.strip()

    s, invisible = _strip_invisible(s)
    if invisible:
        signals.append(Signal("invisible_chars", "Hidden characters", "danger",
                              f"{invisible} invisible character(s) were removed."))

    s, decoded = _percent_decode(s)
    if decoded:
        signals.append(Signal("percent_encoding", "Encoded characters", "warning",
                              "Percent-encoded characters were decoded before checking."))
        s, more = _strip_invisible(s)  # encoded zero-width chars appear only after decoding
        invisible += more

    nfkc = unicodedata.normalize("NFKC", s)       # full-width, ligatures, maths letters
    widened = nfkc != s
    s = nfkc

    prefix, host, rest = _split_host(s)
    host, had_puny = _decode_punycode_host(host)
    if had_puny:
        signals.append(Signal("punycode", "Punycode domain", "warning",
                              "The domain is written in punycode (xn--), which can hide look-alike letters."))

    folded_host, host_replaced, scripts = _fold(host)
    folded_rest, rest_replaced, _ = _fold(rest)
    homoglyph_in_host = host_replaced > 0 or (had_puny and folded_host.isascii() and folded_host != host)

    if host_replaced or widened:
        signals.append(Signal("lookalike_chars", "Look-alike characters", "danger",
                              f"The domain uses characters that imitate normal letters; it reads as '{folded_host.lower()}'."))
    elif rest_replaced:
        signals.append(Signal("lookalike_chars_path", "Look-alike characters in path", "warning",
                              "The path uses characters that imitate normal letters."))
    if len(scripts) > 1:
        signals.append(Signal("mixed_scripts", "Mixed alphabets", "danger",
                              "The domain mixes letters from different alphabets: " + ", ".join(sorted(scripts)) + "."))

    normalised = (prefix + folded_host + folded_rest).lower()
    host_l = folded_host.lower().rstrip(".")

    # --- plain structural signals (explanations for the user, not used by the model) ---
    bare = host_l.strip("[]")
    try:
        ipaddress.ip_address(bare)
        signals.append(Signal("ip_host", "IP address instead of a name", "danger",
                              "Legitimate sites almost always use a domain name, not a raw IP address."))
    except ValueError:
        pass
    if "@" in prefix:
        signals.append(Signal("userinfo", "'@' in address", "danger",
                              "Everything before '@' is ignored by the browser, which can disguise the real site."))
    tld = host_l.rsplit(".", 1)[-1] if "." in host_l else ""
    if tld in SUSPICIOUS_TLDS:
        signals.append(Signal("suspicious_tld", "Unusual domain ending", "warning",
                              f"'.{tld}' is cheap or free to register and is common in phishing."))
    if len(raw) > LONG_URL:
        signals.append(Signal("long_url", "Very long address", "info",
                              f"The address is {len(raw)} characters long; long addresses can hide the real domain."))
    if host_l.count(".") >= MANY_SUBDOMAINS:
        signals.append(Signal("many_subdomains", "Many sub-domains", "warning",
                              "Lots of sub-domains can push the real domain out of view."))
    if host_l.count("-") >= 3:
        signals.append(Signal("many_hyphens", "Many hyphens in domain", "info",
                              "Domains like secure-login-account-verify are typical of phishing."))
    if s.lower().startswith("http://"):
        signals.append(Signal("no_https", "Not using HTTPS", "info", "The address does not use an encrypted connection."))

    return NormalisedURL(original=raw, normalised=normalised, host=host_l,
                         homoglyph_in_host=homoglyph_in_host, signals=signals)


# ==============================================================================================
# MODEL SERVICE
# Loads the Assignment 2 model once, safely, and runs predictions.
#
# The model is a scikit-learn Pipeline (TF-IDF -> RandomForest) saved with joblib.
# joblib/pickle can run code hidden in the file, so the file's SHA-256 is checked
# against MODEL_SHA256 BEFORE it is unpickled. A mismatch stops the server starting.
# ==============================================================================================
log = logging.getLogger("app.model")

CLASS_NAMES = {0: "phishing", 1: "benign", 2: "defacement", 3: "malware"}
BENIGN = 1


class ModelIntegrityError(RuntimeError):
    pass


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def preprocess(url: str) -> str:
    """Identical to simple_preprocess() in the Assignment 2 notebook."""
    url = url.replace("https://", "").replace("http://", "").replace("www.", "")
    return url.lower().strip()


class PhishingModel:
    def __init__(self, path: Path, expected_sha256: str):
        if not path.is_file():
            raise ModelIntegrityError(f"Model file not found: {path}")
        if not expected_sha256:
            raise ModelIntegrityError("MODEL_SHA256 is not set; refusing to load an unverified model file.")
        actual = sha256_of(path)
        if not hmac.compare_digest(actual, expected_sha256):
            raise ModelIntegrityError(
                f"Model hash mismatch: expected {expected_sha256[:12]}..., got {actual[:12]}... "
                "The file may have been tampered with; refusing to load it.")
        self.sha256 = actual
        self.pipeline = joblib.load(path)  # only reached after the hash matched
        # One core per prediction: concurrency is controlled by the inference gate instead,
        # so a single request can never grab every CPU core.
        rf = self.pipeline.named_steps.get("rf")
        if rf is not None:
            rf.set_params(n_jobs=1)
        self.classes = [int(c) for c in self.pipeline.classes_]
        log.info("Model loaded and verified (sha256 %s...)", actual[:12])

    def predict(self, url: str) -> dict[str, float]:
        """Return the probability of each class name for one URL."""
        proba = self.pipeline.predict_proba([preprocess(url)])[0]
        return {CLASS_NAMES[c]: float(p) for c, p in zip(self.classes, proba)}


# ==============================================================================================
# INFERENCE GATE
# Denial-of-service defence: a bounded pool for model inference.
#
# Problem: running the model costs far more than sending a request. If inference ran inside
# the async endpoint it would block the event loop, so one slow request would freeze every
# other user, and a flood of requests would queue without limit until memory ran out.
#
# Defence (three parts):
#   1. Inference runs in a worker thread, never on the event loop, so /api/health and
#      other requests keep being answered while the model is busy.
#   2. At most MAX_CONCURRENT_INFERENCES predictions run at once, using a dedicated thread
#      limiter (not FastAPI's shared pool, so the rest of the app is never starved).
#   3. At most MAX_QUEUED_REQUESTS wait for a slot, for at most QUEUE_TIMEOUT_S seconds.
#      Anything beyond that is rejected immediately with 503 + Retry-After instead of piling up.
#
# Together with the body-size limit (middleware) and the URL length limit, the most expensive
# request an attacker can send is bounded, and so is the number of them in flight.
# ==============================================================================================
T = TypeVar("T")


class InferenceGate:
    def __init__(self, max_concurrent: int, max_queued: int, queue_timeout_s: float, timeout_s: float):
        self.max_concurrent = max_concurrent
        self.max_queued = max_queued
        self.queue_timeout_s = queue_timeout_s
        self.timeout_s = timeout_s
        self._slots = asyncio.Semaphore(max_concurrent)
        self._limiter = anyio.CapacityLimiter(max_concurrent)
        self._waiting = 0
        self.rejected = 0

    @property
    def busy(self) -> int:
        return self.max_concurrent - self._slots._value  # noqa: SLF001 - read-only metric

    def _overloaded(self, reason: str) -> APIError:
        self.rejected += 1
        return APIError(503, "server_busy",
                        f"The server is busy ({reason}). Please try again in a moment.",
                        headers={"Retry-After": "2"})

    async def run(self, fn: Callable[..., T], *args) -> T:
        if self._slots.locked() and self._waiting >= self.max_queued:
            raise self._overloaded("queue full")
        self._waiting += 1
        try:
            await asyncio.wait_for(self._slots.acquire(), timeout=self.queue_timeout_s)
        except asyncio.TimeoutError:
            raise self._overloaded("waited too long") from None
        finally:
            self._waiting -= 1
        try:
            # The thread keeps the slot until it really finishes (abandon_on_cancel=False),
            # so a timed-out request can never let more than max_concurrent threads run.
            return await asyncio.wait_for(
                to_thread.run_sync(fn, *args, limiter=self._limiter),
                timeout=self.timeout_s,
            )
        except asyncio.TimeoutError:
            raise APIError(503, "inference_timeout", "The check took too long and was stopped.",
                           headers={"Retry-After": "2"}) from None
        finally:
            self._slots.release()


# ==============================================================================================
# DATABASE
# History of past checks, stored in SQLite through the SQLAlchemy ORM.
#
# SQL injection defence: every query is built by the ORM, which sends user input to the
# database as bound parameters, never as part of the SQL text. A URL such as
#     ' OR '1'='1' --
# is therefore stored and returned as plain data.
#
# search_history_INSECURE() exists ONLY for the video demo (SECURITY_MODE=insecure) to show the
# attack succeeding when input is pasted into the SQL string. It is never used in secure mode.
# ==============================================================================================
class Base(DeclarativeBase):
    pass


class Check(Base):
    __tablename__ = "checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[str] = mapped_column(String(36), index=True)
    url: Mapped[str] = mapped_column(String(2048))
    normalised_url: Mapped[str] = mapped_column(String(2048))
    verdict: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float)
    phishing_probability: Mapped[float] = mapped_column(Float)
    predicted_class: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=lambda: datetime.now(timezone.utc))


class HistoryStore:
    def __init__(self, database_url: str):
        if database_url.startswith("sqlite:///"):
            from pathlib import Path
            Path(database_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(database_url, connect_args={"check_same_thread": False}
                                    if database_url.startswith("sqlite") else {})
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(self.engine, expire_on_commit=False)

    def add(self, **fields) -> Check:
        with self.Session.begin() as db:
            row = Check(**fields)
            db.add(row)
        return row

    def search(self, session_id: str, search: str | None, limit: int) -> list[Check]:
        stmt = select(Check).where(Check.session_id == session_id)
        if search:
            # contains() escapes % and _ too, so they match literally
            stmt = stmt.where(Check.url.contains(search, autoescape=True))
        stmt = stmt.order_by(Check.id.desc()).limit(limit)
        with self.Session() as db:
            return list(db.scalars(stmt))

    def clear(self, session_id: str) -> int:
        with self.Session.begin() as db:
            return db.execute(delete(Check).where(Check.session_id == session_id)).rowcount

    # ---------------------------------------------------------------- DEMO ONLY
    def search_history_INSECURE(self, session_id: str, search: str | None, limit: int) -> list[dict]:
        """VULNERABLE ON PURPOSE. Pastes input into the SQL text. Used only when SECURITY_MODE=insecure."""
        sql = (f"SELECT id, session_id, url, normalised_url, verdict, confidence, phishing_probability, "
               f"predicted_class, created_at FROM checks WHERE session_id = '{session_id}' "
               f"AND url LIKE '%{search or ''}%' ORDER BY id DESC LIMIT {limit}")
        with self.engine.connect() as conn:
            return [dict(r._mapping) for r in conn.execute(text(sql))]


# ==============================================================================================
# SCHEMAS
# Pydantic request and response models (the API contract with the front end).
# ==============================================================================================
class PredictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    url: str = Field(..., min_length=1, max_length=settings.max_url_length,
                     description="The URL to check. It is never visited or fetched.",
                     examples=["http://paypal.verify-account.com/login"])

    @field_validator("url")
    @classmethod
    def no_spaces_inside(cls, v: str) -> str:
        if any(c in v for c in (" ", "\n", "\r", "\t")):
            raise ValueError("a URL cannot contain spaces or line breaks")
        return v


class PredictRequestNoLimit(BaseModel):
    """Used only in SECURITY_MODE=insecure to show the DoS attack without the length limit."""
    url: str


class SignalOut(BaseModel):
    id: str
    label: str
    severity: Literal["info", "warning", "danger"]
    detail: str


class ClassProbabilities(BaseModel):
    benign: float
    phishing: float
    defacement: float
    malware: float


class PredictResponse(BaseModel):
    id: int
    url: str
    normalised_url: str = Field(description="What the model actually saw after look-alike characters were undone.")
    verdict: Literal["phishing", "legitimate"]
    confidence: float = Field(ge=0, le=1, description="Probability of the verdict shown.")
    phishing_probability: float = Field(ge=0, le=1, description="1 - P(benign).")
    predicted_class: Literal["benign", "phishing", "defacement", "malware"]
    class_probabilities: ClassProbabilities
    signals: list[SignalOut]
    overridden_by_rule: bool = Field(description="True when the look-alike-domain rule forced a phishing verdict.")
    checked_at: datetime


class HistoryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    url: str
    normalised_url: str
    verdict: str
    confidence: float
    phishing_probability: float
    predicted_class: str
    created_at: datetime


class HistoryResponse(BaseModel):
    items: list[HistoryItem]
    count: int


class DeletedResponse(BaseModel):
    deleted: int


class HealthResponse(BaseModel):
    status: Literal["ok"]
    model_loaded: bool
    model_sha256: str
    security_mode: str
    inference_busy: int
    inference_capacity: int


# ==============================================================================================
# MIDDLEWARE
# Plain ASGI middleware: request IDs, security headers, last-resort error catcher, body-size limit.
# ==============================================================================================
log = logging.getLogger("app.middleware")

SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-resource-policy", b"same-site"),
    (b"cache-control", b"no-store"),
]
# The API only ever returns JSON, so it needs no scripts, styles or frames at all.
API_CSP = (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'")


def _json_error(status: int, code: str, message: str, request_id: str | None) -> tuple[dict, bytes]:
    body = json.dumps({"error": {"code": code, "message": message, "details": None,
                                 "request_id": request_id}}).encode()
    start = {"type": "http.response.start", "status": status,
             "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]}
    return start, body


class RequestContextMiddleware:
    """Gives every request an ID, adds security headers, and turns any uncaught exception
    into the standard JSON error (inside CORS, so the browser can still read it)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request_id = uuid.uuid4().hex[:16]
        scope.setdefault("state", {})["request_id"] = request_id
        is_docs = scope["path"].startswith(("/docs", "/redoc", "/openapi.json"))
        started = False

        async def send_wrapper(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = list(message.get("headers", [])) + SECURITY_HEADERS
                headers.append((b"x-request-id", request_id.encode()))
                if not is_docs:
                    headers.append(API_CSP)
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:  # noqa: BLE001 - last line of defence, details go to the log only
            log.exception("Unhandled error (request_id=%s)", request_id)
            if not started:
                start, body = _json_error(500, "internal_error",
                                          "Something went wrong on our side. Please try again.", request_id)
                await send_wrapper(start)
                await send({"type": "http.response.body", "body": body})


class BodySizeLimitMiddleware:
    """Rejects request bodies over max_bytes with 413 before the app or the model sees them.

    Checks the Content-Length header first (cheap rejection), then counts the bytes actually
    received, because a client can lie about or omit Content-Length (chunked encoding).
    """

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "OPTIONS", "DELETE"):
            return await self.app(scope, receive, send)
        request_id = scope.get("state", {}).get("request_id")

        async def reject():
            start, body = _json_error(413, "payload_too_large",
                                      f"Request body is larger than the {self.max_bytes}-byte limit.", request_id)
            await send(start)
            await send({"type": "http.response.body", "body": body})

        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    if int(value) > self.max_bytes:
                        return await reject()
                except ValueError:
                    return await reject()

        # Read the (small) body up to the limit, then replay it to the app.
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > self.max_bytes:
                return await reject()
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


# ==============================================================================================
# MAIN
# Application, start-up and routes
# ==============================================================================================
log = logging.getLogger("app")

RULE_CONFIDENCE = 0.95  # confidence reported when the look-alike-domain rule decides


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Loaded ONCE at start-up. If the hash check fails this raises and the server does not start.
    app.state.model = PhishingModel(settings.model_path, settings.model_sha256)
    app.state.history = HistoryStore(settings.database_url)
    app.state.gate = InferenceGate(settings.max_concurrent_inferences, settings.max_queued_requests,
                                   settings.queue_timeout_s, settings.inference_timeout_s)
    if settings.insecure:
        log.warning("SECURITY_MODE=insecure: DoS, SQL injection and evasion defences are OFF (demo only)")
    yield


app = FastAPI(
    title="Phishing URL Detection API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.enable_docs else None,
    redoc_url=None,
    openapi_url="/openapi.json" if settings.enable_docs else None,
)
register_error_handlers(app)

# Order matters: the LAST middleware added is the OUTERMOST.
if not settings.insecure:
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,   # only our own front end, never "*"
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-Session-ID"],
    expose_headers=["X-Request-ID", "Retry-After"],
    max_age=600,
)


# ------------------------------------------------------------------ dependencies
def session_id(x_session_id: Annotated[str | None, Header()] = None) -> str:
    if not x_session_id:
        raise APIError(400, "missing_session", "The X-Session-ID header is required.")
    try:
        return str(uuid.UUID(x_session_id))
    except ValueError:
        raise APIError(400, "invalid_session", "X-Session-ID must be a UUID.") from None


SessionID = Annotated[str, Depends(session_id)]


# ------------------------------------------------------------------ helpers
def _decide(model: PhishingModel, url: str, secure: bool) -> tuple[NormalisedURL, dict, bool]:
    """Normalise (secure mode only), then predict. Runs in a worker thread in secure mode."""
    nu = normalise_url(url) if secure else NormalisedURL(original=url, normalised=url, host="")
    probs = model.predict(nu.normalised)
    return nu, probs, secure


def _build_result(url: str, nu: NormalisedURL, probs: dict, secure: bool) -> dict:
    p_phish = round(1.0 - probs["benign"], 6)
    predicted_class = max(probs, key=probs.get)
    overridden = (secure and settings.homoglyph_policy == "block" and nu.homoglyph_in_host
                  and p_phish < settings.phishing_threshold)
    if overridden:
        verdict, confidence = "phishing", RULE_CONFIDENCE
    elif p_phish >= settings.phishing_threshold:
        verdict, confidence = "phishing", p_phish
    else:
        verdict, confidence = "legitimate", 1.0 - p_phish
    return {
        "url": url,
        "normalised_url": nu.normalised if secure else url,
        "verdict": verdict,
        "confidence": round(confidence, 6),
        "phishing_probability": p_phish,
        "predicted_class": predicted_class,
        "class_probabilities": {k: round(v, 6) for k, v in probs.items()},
        "signals": [s.__dict__ for s in nu.signals] if secure else [],
        "overridden_by_rule": overridden,
    }


# ------------------------------------------------------------------ routes
@app.get("/api/health", response_model=HealthResponse, tags=["system"])
async def health(request: Request):
    gate: InferenceGate = request.app.state.gate
    return HealthResponse(status="ok", model_loaded=True,
                          model_sha256=request.app.state.model.sha256[:12],
                          security_mode=settings.security_mode,
                          inference_busy=gate.busy, inference_capacity=gate.max_concurrent)


async def predict(request: Request, sid: SessionID, body: PredictRequest):
    model: PhishingModel = request.app.state.model
    started = time.perf_counter()
    nu, probs, secure = await request.app.state.gate.run(_decide, model, body.url, True)
    result = _build_result(body.url, nu, probs, secure)
    row = await run_in_threadpool(
        request.app.state.history.add, session_id=sid,
        **{k: result[k] for k in ("url", "normalised_url", "verdict", "confidence",
                                  "phishing_probability", "predicted_class")})
    log.info("predict id=%s verdict=%s p=%.3f %.1fms", row.id, result["verdict"],
             result["phishing_probability"], (time.perf_counter() - started) * 1000)
    return PredictResponse(id=row.id, checked_at=row.created_at, **result)


async def predict_insecure(request: Request, sid: SessionID, body: PredictRequestNoLimit):
    nu, probs, _ = _decide(request.app.state.model, body.url, False)   # blocks every other request
    result = _build_result(body.url, nu, probs, False)
    row = request.app.state.history.add(
        session_id=sid, **{k: result[k][:2048] if isinstance(result[k], str) else result[k]
                           for k in ("url", "normalised_url", "verdict", "confidence",
                                     "phishing_probability", "predicted_class")})
    return PredictResponse(id=row.id, checked_at=row.created_at, **result)


if settings.insecure:
    # Demo only: same path with NO defences (no length limit, inference on the event loop,
    # no inference gate, no normalisation) so the attacks can be shown succeeding.
    app.post("/api/predict", response_model=PredictResponse, tags=["detection"])(predict_insecure)
else:
    app.post("/api/predict", response_model=PredictResponse, tags=["detection"],
             responses={413: {"description": "Body too large"}, 422: {"description": "Invalid URL"},
                        503: {"description": "Server busy, retry later"}})(predict)


@app.get("/api/history", response_model=HistoryResponse, tags=["history"])
def history(request: Request, sid: SessionID,
            search: Annotated[str | None, Query(max_length=200)] = None,
            limit: Annotated[int, Query(ge=1, le=settings.history_limit_max)] = 50):
    store: HistoryStore = request.app.state.history
    if settings.insecure:
        rows = store.search_history_INSECURE(sid, search, limit)
        items = [HistoryItem.model_validate(r) for r in rows]
    else:
        items = [HistoryItem.model_validate(r) for r in store.search(sid, search, limit)]
    return HistoryResponse(items=items, count=len(items))


@app.delete("/api/history", response_model=DeletedResponse, tags=["history"])
def clear_history(request: Request, sid: SessionID):
    return DeletedResponse(deleted=request.app.state.history.clear(sid))
