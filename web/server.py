"""
The local web interface.

Deliberately built on the standard library alone: this runs on a teacher's own
machine, often without administrator rights to install anything, and a tool that
cannot be installed does not get used. It binds to 127.0.0.1 only - it is a
local interface, not a service, and nothing it produces should leave the machine
before the teacher decides to send it.

File uploads arrive as base64 inside a JSON body rather than as multipart form
data. That is not squeamishness: Python 3.13 removed the `cgi` module that used
to parse multipart, and hand-rolling a parser for one file picker is a poor
trade against three lines of FileReader in the page.
"""

from __future__ import annotations

import base64
import json
import mimetypes
import threading
import unicodedata
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

from sebkit import processes as _processes
from sebkit.audit import audit
from sebkit.configkey import compute_config_key
from sebkit.moodle import build_integration, setup_steps
from sebkit.passwords import generate_exam_passwords
from sebkit.profiles import PROFILES, ExamSpec, build_settings, profile_summary
from sebkit.report import audit_report_html, exam_report_html
from sebkit.sebfile import PasswordRequired, SebFileError, dump, loads

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = Path(__file__).resolve().parent / "templates" / "app.html"
OUT_DIR = ROOT / "out"

MAX_UPLOAD_BYTES = 8 * 1024 * 1024


def _safe_name(text: str) -> str:
    keep = [c if (c.isalnum() or c in " -_") else "-" for c in text]
    return "".join(keep).strip().replace(" ", "-")[:60] or "exam"


def _content_disposition(filename: str) -> str:
    """Build a Content-Disposition header that survives non-ASCII exam names.

    HTTP headers are latin-1 on the wire, so an exam named in Arabic - or merely
    containing an accent - either arrives mangled or raises on send. RFC 5987
    solves this with a percent-encoded UTF-8 parameter alongside an ASCII
    fallback for anything that does not understand it.
    """
    ascii_fallback = unicodedata.normalize("NFKD", filename)
    ascii_fallback = ascii_fallback.encode("ascii", "ignore").decode("ascii")
    ascii_fallback = "".join(c for c in ascii_fallback if c not in '"\\') or "configuration.seb"
    encoded = quote(filename, safe="")
    return f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{encoded}"


class Handler(BaseHTTPRequestHandler):
    server_version = "SEBExamKit"

    # Keep the console readable; this is a teacher's screen, not a server log.
    def log_message(self, fmt, *args):  # noqa: A002
        pass

    # -- helpers ----------------------------------------------------------

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_UPLOAD_BYTES:
            raise ValueError("request body is too large")
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _serve_out_file(self, name: str, *, download: bool) -> None:
        # Resolve inside OUT_DIR and refuse anything that escapes it.
        target = (OUT_DIR / unquote(name)).resolve()
        if not str(target).startswith(str(OUT_DIR.resolve())) or not target.is_file():
            self._send(404, b"Not found", "text/plain; charset=utf-8")
            return
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if download:
            self.send_header("Content-Disposition", _content_disposition(target.name))
        self.end_headers()
        self.wfile.write(body)

    # -- routes -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path

        if path in ("/", "/index.html"):
            self._send(200, TEMPLATE.read_bytes(), "text/html; charset=utf-8")
        elif path == "/api/options":
            self._json(200, {
                "profiles": [
                    {"key": p, "summary": profile_summary(p)} for p in PROFILES
                ],
                "categories": [
                    {
                        "key": c.key, "label": c.label, "rationale": c.rationale,
                        "count": len(c.processes), "essential": c.essential,
                    }
                    for c in _processes.CATEGORIES
                ],
            })
        elif path.startswith("/report/"):
            self._serve_out_file(path[len("/report/"):], download=False)
        elif path.startswith("/download/"):
            self._serve_out_file(path[len("/download/"):], download=True)
        else:
            self._send(404, b"Not found", "text/plain; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            payload = self._read_json()
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})
            return

        try:
            if path == "/api/create":
                self._json(200, self._create(payload))
            elif path == "/api/audit":
                self._json(200, self._audit(payload))
            else:
                self._json(404, {"error": "unknown endpoint"})
        except (ValueError, KeyError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:  # surfaced in the UI rather than the console
            self._json(500, {"error": f"{type(exc).__name__}: {exc}"})

    # -- actions ----------------------------------------------------------

    def _create(self, payload: dict) -> dict:
        spec = ExamSpec(
            exam_name=(payload.get("exam_name") or "").strip(),
            quiz_url=(payload.get("quiz_url") or "").strip(),
            quit_url=(payload.get("quit_url") or "").strip(),
            profile=payload.get("profile") or "byod_strict",
            allow_uploads=bool(payload.get("allow_uploads")),
            allow_downloads=bool(payload.get("allow_downloads")),
            allow_spell_check=bool(payload.get("allow_spell_check")),
            allow_audio=bool(payload.get("allow_audio")),
            extra_allowed_urls=[
                line.strip()
                for line in (payload.get("extra_allowed") or "").splitlines()
                if line.strip()
            ],
            process_categories=payload.get("categories") or list(_processes.ESSENTIAL_KEYS),
        )

        pw = generate_exam_passwords()
        settings = build_settings(spec, pw)

        OUT_DIR.mkdir(parents=True, exist_ok=True)
        stem = _safe_name(spec.exam_name)
        seb_path = dump(settings, OUT_DIR / f"{stem}.seb")

        integration = build_integration(settings, spec.quiz_url)
        result = audit(settings, byod=spec.profile.startswith("byod"))

        report_name = f"{stem}-exam-pack.html"
        (OUT_DIR / report_name).write_text(
            exam_report_html(spec, pw, integration, seb_path, audit_result=result),
            encoding="utf-8",
        )

        return {
            "exam_name": spec.exam_name,
            "config_key": integration.config_key,
            "quit_password": pw.quit,
            "admin_password": pw.admin,
            "seb_file": seb_path.name,
            "report_file": report_name,
            "blocked_count": len(settings["prohibitedProcesses"]),
            "grade": result.grade,
            "steps": [
                {"title": s["title"], "body": s["body"], "emphasis": bool(s.get("emphasis"))}
                for s in setup_steps(integration, uploaded=True)
            ],
        }

    def _audit(self, payload: dict) -> dict:
        encoded = payload.get("file_b64") or ""
        if not encoded:
            raise ValueError("no file was supplied")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise ValueError(f"could not read the uploaded file: {exc}") from exc
        if len(raw) > MAX_UPLOAD_BYTES:
            raise ValueError("that file is too large to be a SEB configuration")

        name = (payload.get("filename") or "configuration.seb").strip()
        password = payload.get("password") or None

        try:
            loaded = loads(raw, password)
        except PasswordRequired as exc:
            return {"needs_password": True, "error": str(exc)}
        except SebFileError as exc:
            return {"error": str(exc)}

        result = audit(loaded.settings, byod=not payload.get("lab"))

        OUT_DIR.mkdir(parents=True, exist_ok=True)
        report_name = f"{_safe_name(Path(name).stem)}-audit.html"
        (OUT_DIR / report_name).write_text(
            audit_report_html(
                result, name,
                encoding_description=loaded.encoding_description,
                notes=loaded.notes,
            ),
            encoding="utf-8",
        )

        return {
            "filename": name,
            "grade": result.grade,
            "verdict": result.verdict,
            "encoding": loaded.encoding_description,
            "notes": loaded.notes,
            "config_key": compute_config_key(loaded.settings),
            "report_file": report_name,
            "counts": {
                s: result.count(s) for s in ("critical", "high", "medium", "low", "info")
            },
            "findings": [
                {
                    "severity": f.severity, "title": f.title, "detail": f.detail,
                    "remediation": f.remediation, "key": f.key,
                }
                for f in result.sorted_findings
            ],
        }


def serve(port: int = 8733, *, open_browser: bool = True) -> None:
    """Run the local interface until interrupted."""
    if not TEMPLATE.exists():
        raise SystemExit(f"interface template is missing: {TEMPLATE}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"

    print("MedTech SEB Exam Kit")
    print(f"  Open {url}")
    print(f"  Files are written to {OUT_DIR}")
    print("  Press Ctrl+C to stop.")

    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    serve()
