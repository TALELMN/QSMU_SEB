"""Command-line interface: python -m sebkit <command>."""

from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

from . import processes as _processes
from .audit import audit
from .configkey import compute_config_key, config_key_json
from .moodle import build_integration
from .passwords import generate_exam_passwords
from .profiles import PROFILES, ExamSpec, build_settings
from .report import audit_report_html, exam_report_html
from .sebfile import PasswordRequired, SebFileError, dump, load


def _safe_name(text: str) -> str:
    keep = [c if (c.isalnum() or c in " -_") else "-" for c in text]
    return "".join(keep).strip().replace(" ", "-")[:60] or "exam"


def cmd_create(args: argparse.Namespace) -> int:
    spec = ExamSpec(
        exam_name=args.name,
        quiz_url=args.url,
        quit_url=args.quit_url or "",
        profile=args.profile,
        allow_uploads=args.allow_uploads,
        allow_downloads=args.allow_downloads,
        extra_allowed_urls=args.allow or [],
        process_categories=args.categories or list(_processes.ESSENTIAL_KEYS),
    )

    pw = generate_exam_passwords()
    settings = build_settings(spec, pw)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = _safe_name(spec.exam_name)

    seb_path = dump(settings, out_dir / f"{stem}.seb")
    integration = build_integration(settings, spec.quiz_url)
    result = audit(settings, byod=spec.profile.startswith("byod"))

    report_path = out_dir / f"{stem}-exam-pack.html"
    report_path.write_text(
        exam_report_html(spec, pw, integration, seb_path, audit_result=result),
        encoding="utf-8",
    )

    print(f"Configuration : {seb_path}")
    print(f"Exam pack     : {report_path}")
    print(f"Config Key    : {integration.config_key}")
    print()
    print(f"Quit password     : {pw.quit}")
    print(f"Settings password : {pw.admin}")
    print()
    print("These passwords are shown once and are not stored. They are in the exam pack.")
    if result.findings:
        print(f"\nSelf-check: {result.grade} ({len(result.findings)} note(s)) - see the exam pack.")

    if not args.no_open:
        webbrowser.open(report_path.resolve().as_uri())
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    try:
        loaded = load(args.file, args.password)
    except PasswordRequired as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("Supply the settings password with --password.", file=sys.stderr)
        return 2
    except SebFileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    result = audit(loaded.settings, byod=not args.lab)
    source = Path(args.file).name

    print(f"{source}: {result.grade} - {result.verdict}")
    print(f"Encoding: {loaded.encoding_description}")
    for note in loaded.notes:
        print(f"  note: {note}")
    print()
    for finding in result.sorted_findings:
        print(f"[{finding.severity.upper():>8}] {finding.title}")
        print(f"           {finding.detail}")
        print(f"           Fix: {finding.remediation}")
        print()

    print(f"Config Key: {compute_config_key(loaded.settings)}")

    if args.report:
        path = Path(args.report)
        path.write_text(
            audit_report_html(
                result, source,
                encoding_description=loaded.encoding_description,
                notes=loaded.notes,
            ),
            encoding="utf-8",
        )
        print(f"Report: {path}")
        if not args.no_open:
            webbrowser.open(path.resolve().as_uri())

    return 1 if result.count("critical") else 0


def cmd_key(args: argparse.Namespace) -> int:
    try:
        loaded = load(args.file, args.password)
    except SebFileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(config_key_json(loaded.settings))
    else:
        print(compute_config_key(loaded.settings))
    return 0


def cmd_ui(args: argparse.Namespace) -> int:
    from web.server import serve  # local import: the UI is optional

    serve(port=args.port, open_browser=not args.no_open)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sebkit",
        description="Generate, verify and audit Safe Exam Browser configurations.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="generate a hardened exam configuration")
    create.add_argument("--name", required=True, help="exam name, e.g. 'Anatomy S1 2026'")
    create.add_argument("--url", required=True, help="Moodle quiz URL")
    create.add_argument("--quit-url", help="where to send students after quitting")
    create.add_argument("--profile", default="byod_strict", choices=PROFILES)
    create.add_argument("--allow", action="append", metavar="HOST",
                        help="extra allowed host (repeatable)")
    create.add_argument("--categories", nargs="*", choices=[c.key for c in _processes.CATEGORIES],
                        help="prohibited-process categories (default: the essential ones)")
    create.add_argument("--allow-uploads", action="store_true")
    create.add_argument("--allow-downloads", action="store_true")
    create.add_argument("--out", default="out", help="output directory")
    create.add_argument("--no-open", action="store_true")
    create.set_defaults(func=cmd_create)

    aud = sub.add_parser("audit", help="audit an existing .seb file")
    aud.add_argument("file")
    aud.add_argument("--password", help="settings password, if the file is encrypted")
    aud.add_argument("--lab", action="store_true", help="managed lab machines rather than BYOD")
    aud.add_argument("--report", help="write an HTML report to this path")
    aud.add_argument("--no-open", action="store_true")
    aud.set_defaults(func=cmd_audit)

    key = sub.add_parser("key", help="print the Config Key of a .seb file")
    key.add_argument("file")
    key.add_argument("--password")
    key.add_argument("--json", action="store_true",
                     help="print the canonical SEB-JSON instead of the hash")
    key.set_defaults(func=cmd_key)

    ui = sub.add_parser("ui", help="open the local web interface")
    ui.add_argument("--port", type=int, default=8733)
    ui.add_argument("--no-open", action="store_true")
    ui.set_defaults(func=cmd_ui)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
