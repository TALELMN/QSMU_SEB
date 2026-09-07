"""
Teacher-facing reports.

Two documents come out of this module:

  the exam pack  - passwords, Config Key, the Moodle steps, and a printable
                   invigilator checklist for the room
  the audit      - what an existing configuration actually enforces

Both are self-contained HTML written to disk and opened in the teacher's
browser. They are deliberately printable: the invigilator checklist is used on
paper, in a room, by someone who is not at a computer.

The "what this cannot stop" section is not a disclaimer to be skimmed past. On
student-owned hardware it is the most decision-relevant part of the document,
and it is what tells a teacher which parts of the sitting still need a human.
"""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from . import processes as _processes
from .audit import AuditResult
from .moodle import MoodleIntegration, setup_steps, verification_notes
from .passwords import ExamPasswords
from .profiles import ExamSpec, profile_summary

_CSS = """
:root {
  --ink: #16191d; --muted: #5b6470; --line: #e2e6ea; --bg: #ffffff;
  --panel: #f7f9fa; --accent: #1c4f8b;
  --critical: #a61b1b; --high: #b4530a; --medium: #8a6d1a; --low: #4a6a7a; --info: #4b5563;
  --ok: #1c6b3f;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
.wrap { max-width: 860px; margin: 0 auto; padding: 40px 28px 80px; }
h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -0.01em; }
h2 { font-size: 19px; margin: 40px 0 12px; padding-bottom: 7px; border-bottom: 2px solid var(--line); }
h3 { font-size: 15px; margin: 22px 0 6px; }
p { margin: 0 0 12px; }
.sub { color: var(--muted); font-size: 13.5px; margin-bottom: 26px; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px 18px; margin: 14px 0; }
.grid { display: grid; grid-template-columns: 180px 1fr; gap: 6px 18px; }
.grid dt { color: var(--muted); font-size: 13.5px; }
.grid dd { margin: 0; }
code, .mono { font-family: "SF Mono", Consolas, "Liberation Mono", monospace; font-size: 13px; }
.secret { display: block; background: #fff; border: 1px solid var(--line); border-radius: 6px;
          padding: 10px 12px; font-family: "SF Mono", Consolas, monospace; font-size: 16px;
          letter-spacing: 0.04em; word-break: break-all; }
.key { display: block; background: #fff; border: 1px solid var(--line); border-radius: 6px;
       padding: 10px 12px; font-family: "SF Mono", Consolas, monospace; font-size: 12px;
       word-break: break-all; color: var(--accent); }
.warn { border-left: 4px solid var(--high); background: #fdf6ef; }
.danger { border-left: 4px solid var(--critical); background: #fdf1f1; }
.good { border-left: 4px solid var(--ok); background: #f1f8f3; }
ol, ul { margin: 0 0 14px; padding-left: 22px; }
li { margin-bottom: 7px; }
.step { margin-bottom: 16px; }
.step .t { font-weight: 600; }
.finding { border: 1px solid var(--line); border-left-width: 4px; border-radius: 6px;
           padding: 13px 15px; margin-bottom: 11px; }
.finding.critical { border-left-color: var(--critical); }
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low { border-left-color: var(--low); }
.finding.info { border-left-color: var(--info); }
.finding .head { display: flex; align-items: baseline; gap: 10px; margin-bottom: 5px; }
.finding .title { font-weight: 600; }
.badge { font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.07em;
         font-weight: 700; padding: 2px 7px; border-radius: 3px; color: #fff; white-space: nowrap; }
.badge.critical { background: var(--critical); } .badge.high { background: var(--high); }
.badge.medium { background: var(--medium); } .badge.low { background: var(--low); }
.badge.info { background: var(--info); }
.fix { font-size: 13.5px; color: var(--muted); margin-top: 6px; }
.fix b { color: var(--ink); }
.verdict { font-size: 21px; font-weight: 650; margin-bottom: 4px; }
.check { list-style: none; padding-left: 0; }
.check li { padding-left: 30px; position: relative; margin-bottom: 11px; }
.check li::before { content: ""; position: absolute; left: 0; top: 2px; width: 15px; height: 15px;
                    border: 1.5px solid var(--muted); border-radius: 3px; }
.cols { column-count: 2; column-gap: 26px; font-size: 13.5px; }
.cols li { break-inside: avoid; }
footer { margin-top: 50px; padding-top: 14px; border-top: 1px solid var(--line);
         color: var(--muted); font-size: 12.5px; }
@media print {
  body { font-size: 11.5pt; }
  .wrap { max-width: none; padding: 0; }
  h2 { page-break-after: avoid; }
  .finding, .panel, .step { page-break-inside: avoid; }
  .page-break { page-break-before: always; }
}
"""


def _e(value: object) -> str:
    return html.escape(str(value), quote=False)


def _doc(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{_e(title)}</title><style>{_CSS}</style></head>"
        f"<body><div class=\"wrap\">{body}</div></body></html>"
    )


# --------------------------------------------------------------------------
# What SEB can and cannot do. Kept here, in one place, deliberately.
# --------------------------------------------------------------------------

CANNOT_ENFORCE = [
    ("A second device", "A phone, tablet or second laptop is completely invisible to SEB. "
     "This is the most common method by a wide margin."),
    ("Another person in the room", "Or one reachable by phone from outside it."),
    ("Capture hardware", "An HDMI splitter or capture card feeds the exam screen to a helper "
     "without the exam machine ever seeing it."),
    ("Paper notes", "SEB has no camera."),
    ("A modified machine", "On a laptop the student owns and administers, they can prepare the "
     "system before SEB ever launches. Detection heuristics raise the effort; they do not make "
     "the machine trustworthy."),
]

HUMAN_CONTROLS = [
    "An invigilator physically present, walking the room rather than seated at the front.",
    "Phones collected at the door, or placed face down in a visible tray - not in pockets or bags "
    "at the student's feet.",
    "A seating plan with space between students, and screens angled so they are visible from "
    "behind.",
    "A time limit tight enough that lookups cost more than they return.",
    "Randomised question and answer order, drawn from a bank larger than the paper.",
    "Questions that ask for reasoning rather than recall, so a retrieved answer is worth less.",
]


def exam_report_html(
    spec: ExamSpec,
    pw: ExamPasswords,
    integration: MoodleIntegration,
    seb_path: Path,
    *,
    audit_result: AuditResult | None = None,
) -> str:
    """The exam pack: credentials, Moodle steps, honest limits, room checklist."""
    generated = datetime.now().strftime("%d %B %Y at %H:%M")

    categories = [
        _processes.CATEGORIES_BY_KEY[k]
        for k in spec.process_categories
        if k in _processes.CATEGORIES_BY_KEY
    ]
    blocked_count = sum(len(c.processes) for c in categories)

    parts: list[str] = []
    parts.append(f"<h1>{_e(spec.exam_name)}</h1>")
    parts.append(
        f"<div class=\"sub\">Safe Exam Browser configuration pack &middot; generated {_e(generated)}</div>"
    )

    # --- credentials -------------------------------------------------------
    parts.append("<h2>Passwords for this exam</h2>")
    parts.append(
        "<div class=\"panel danger\">"
        "<p><b>These passwords appear in this document only.</b> They are generated fresh for "
        "this exam and are not stored anywhere by this tool. Save them somewhere you can reach "
        "on exam day, and do not reuse them for the next sitting.</p>"
        "<h3>Quit password</h3>"
        f"<span class=\"secret\">{_e(pw.quit)}</span>"
        "<p class=\"fix\">Give this to invigilators. It is needed to close SEB on a student's "
        "machine - for a genuine technical failure, or at the end of the sitting.</p>"
        "<h3>Settings password</h3>"
        f"<span class=\"secret\">{_e(pw.admin)}</span>"
        "<p class=\"fix\">Keep this to yourself. It is what stops a student opening the "
        "configuration file and reading the exam policy. Do not read it aloud in the room.</p>"
        "</div>"
    )

    # --- files and keys ----------------------------------------------------
    parts.append("<h2>Configuration</h2>")
    parts.append(
        "<div class=\"panel\"><dl class=\"grid\">"
        f"<dt>File</dt><dd class=\"mono\">{_e(seb_path.name)}</dd>"
        f"<dt>Exam address</dt><dd class=\"mono\">{_e(spec.quiz_url)}</dd>"
        f"<dt>Profile</dt><dd>{_e(spec.profile)}</dd>"
        f"<dt>Blocked applications</dt><dd>{blocked_count} across "
        f"{len(categories)} categories</dd>"
        "</dl>"
        f"<p class=\"fix\">{_e(profile_summary(spec.profile))}</p></div>"
    )
    parts.append("<h3>Config Key</h3>")
    parts.append(f"<span class=\"key\">{_e(integration.config_key)}</span>")
    parts.append(
        "<p class=\"fix\">This is the fingerprint of your settings. Moodle uses it to prove a "
        "student's SEB is running <b>this</b> configuration and not something they assembled "
        "themselves. Keep it for your records; in the upload flow below, Moodle computes it "
        "itself.</p>"
    )

    # --- moodle ------------------------------------------------------------
    parts.append("<h2>Setting up the quiz in Moodle</h2>")
    for index, step in enumerate(setup_steps(integration, uploaded=True), start=1):
        klass = " panel warn" if step.get("emphasis") else ""
        body = _e(step["body"]).replace("\n\n", "</p><p>")
        parts.append(
            f"<div class=\"step{klass}\"><div class=\"t\">{index}. {_e(step['title'])}</div>"
            f"<p>{body}</p></div>"
        )

    parts.append("<h3>Before you announce the exam</h3>")
    parts.append("<ul class=\"check\">")
    for note in verification_notes():
        parts.append(f"<li>{_e(note)}</li>")
    parts.append("</ul>")

    # --- enforcement -------------------------------------------------------
    parts.append("<h2>What this configuration enforces</h2>")
    parts.append(
        "<ul>"
        "<li>Moodle verifies the configuration on every request, so the quiz cannot be opened "
        "from an ordinary browser or a SEB carrying different settings.</li>"
        "<li>Browsing is restricted to the exam host; everything else is denied by default.</li>"
        "<li>Quitting SEB requires the quit password; the settings require a separate one.</li>"
        "<li>Only one display is permitted, and mirroring and screen sharing are refused.</li>"
        "<li>SEB refuses to run inside a virtual machine.</li>"
        "<li>Task switching, the Start menu, the developer console and the address bar are off.</li>"
        f"<li>{blocked_count} named applications are terminated or block the exam from starting.</li>"
        "<li>Cookies and browser storage are cleared at both ends of the session.</li>"
        "</ul>"
    )
    parts.append("<h3>Applications blocked</h3><ul class=\"cols\">")
    for category in categories:
        parts.append(f"<li><b>{_e(category.label)}</b> &mdash; {len(category.processes)} tools</li>")
    parts.append("</ul>")

    # --- honest limits -----------------------------------------------------
    parts.append("<h2>What this configuration cannot stop</h2>")
    parts.append(
        "<div class=\"panel warn\"><p>Your students sit the exam on their own laptops. SEB can "
        "only control the machine it runs on, and that machine belongs to the candidate. "
        "The following are outside its reach entirely, no matter how it is configured:</p><ul>"
    )
    for title, detail in CANNOT_ENFORCE:
        parts.append(f"<li><b>{_e(title)}.</b> {_e(detail)}</li>")
    parts.append("</ul><p>None of this makes SEB pointless: it reliably closes off the casual "
                 "routes, and the Moodle key check means a student cannot simply use a normal "
                 "browser. But the remaining gap is closed by people and by exam design, not by "
                 "software.</p></div>")

    parts.append("<h3>What closes the remaining gap</h3><ul>")
    for control in HUMAN_CONTROLS:
        parts.append(f"<li>{_e(control)}</li>")
    parts.append("</ul>")

    # --- audit -------------------------------------------------------------
    if audit_result and audit_result.findings:
        parts.append("<h2>Notes on this configuration</h2>")
        parts.append(_findings_html(audit_result))

    # --- invigilator sheet -------------------------------------------------
    parts.append("<div class=\"page-break\"></div>")
    parts.append(f"<h2>Invigilator sheet &mdash; {_e(spec.exam_name)}</h2>")
    parts.append(
        "<div class=\"panel\"><dl class=\"grid\">"
        f"<dt>Quit password</dt><dd class=\"mono\"><b>{_e(pw.quit)}</b></dd>"
        f"<dt>Configuration file</dt><dd class=\"mono\">{_e(seb_path.name)}</dd>"
        "</dl></div>"
    )
    parts.append("<h3>Before students arrive</h3><ul class=\"check\">")
    for item in [
        "The quiz is open in Moodle and set to require Safe Exam Browser.",
        "You have tested the configuration on one machine this morning.",
        "A tray or box is ready at the door for phones and smart watches.",
        "The seating plan leaves a gap between students where the room allows.",
    ]:
        parts.append(f"<li>{_e(item)}</li>")
    parts.append("</ul>")
    parts.append("<h3>As students sit down</h3><ul class=\"check\">")
    for item in [
        "Phones and watches are in the tray, not in pockets or bags at their feet.",
        "Each laptop shows a single screen - no second monitor, no external display cable.",
        "Bluetooth earbuds are out and visible; check ears, not just desks.",
        "SEB is running fullscreen; the desktop and taskbar are not visible behind it.",
    ]:
        parts.append(f"<li>{_e(item)}</li>")
    parts.append("</ul>")
    parts.append("<h3>During the exam</h3><ul class=\"check\">")
    for item in [
        "Walk the room from the back. Screens are readable from behind; from the front they are not.",
        "Watch for eyes going repeatedly to a lap, a sleeve or a bag.",
        "If SEB closes unexpectedly, note the student, the time and the message before restarting.",
        "Do not read the settings password aloud. Use the quit password only.",
    ]:
        parts.append(f"<li>{_e(item)}</li>")
    parts.append("</ul>")
    parts.append("<h3>If something goes wrong</h3>")
    parts.append(
        "<div class=\"panel\"><p><b>SEB will not start, or reports a configuration problem.</b> "
        "Note the exact message. Move the student to a spare machine if one is available; if not, "
        "record the incident and let them continue on paper or at a later sitting rather than "
        "loosening the configuration mid-exam.</p>"
        "<p><b>The quiz says the browser is not permitted.</b> The student is not in SEB, or is "
        "running a different configuration. Have them close everything and reopen the exam through "
        "the configuration file you distributed.</p>"
        "<p><b>A student must leave the exam.</b> Use the quit password. Note the time.</p></div>"
    )

    parts.append(
        "<footer>Generated by the MedTech SEB Exam Kit. "
        "Passwords in this document are unique to this exam and are not recoverable if lost - "
        "generate a new configuration rather than trying to recover them.</footer>"
    )

    return _doc(f"{spec.exam_name} - SEB exam pack", "".join(parts))


def _findings_html(result: AuditResult) -> str:
    out = []
    for finding in result.sorted_findings:
        out.append(
            f"<div class=\"finding {finding.severity}\">"
            f"<div class=\"head\"><span class=\"badge {finding.severity}\">{finding.severity}</span>"
            f"<span class=\"title\">{_e(finding.title)}</span></div>"
            f"<div>{_e(finding.detail)}</div>"
            f"<div class=\"fix\"><b>Fix:</b> {_e(finding.remediation)}"
            + (f" <code>{_e(finding.key)}</code>" if finding.key else "")
            + "</div></div>"
        )
    return "".join(out)


def audit_report_html(
    result: AuditResult,
    source_name: str,
    *,
    encoding_description: str = "",
    notes: list[str] | None = None,
) -> str:
    """The audit of an existing configuration file."""
    generated = datetime.now().strftime("%d %B %Y at %H:%M")
    grade_class = {
        "Not fit for use": "danger", "Weak": "danger", "Needs attention": "warn",
        "Acceptable": "warn", "Good": "good",
    }[result.grade]

    parts: list[str] = []
    parts.append("<h1>Configuration audit</h1>")
    parts.append(f"<div class=\"sub\">{_e(source_name)} &middot; checked {_e(generated)}</div>")

    counts = " &middot; ".join(
        f"{result.count(s)} {s}"
        for s in ("critical", "high", "medium", "low")
        if result.count(s)
    ) or "no issues found"

    parts.append(
        f"<div class=\"panel {grade_class}\">"
        f"<div class=\"verdict\">{_e(result.grade)}</div>"
        f"<p>{_e(result.verdict)}</p>"
        f"<p class=\"fix\">{counts}"
        + (f" &middot; {_e(encoding_description)}" if encoding_description else "")
        + "</p></div>"
    )

    if notes:
        parts.append("<div class=\"panel\"><p><b>About the file:</b></p><ul>")
        for note in notes:
            parts.append(f"<li>{_e(note)}</li>")
        parts.append("</ul></div>")

    if result.findings:
        parts.append("<h2>Findings</h2>")
        parts.append(_findings_html(result))
    else:
        parts.append(
            "<h2>Findings</h2><div class=\"panel good\"><p>Nothing to report. Every check this "
            "tool performs passed.</p></div>"
        )

    parts.append("<h2>What no configuration can stop</h2>")
    parts.append(
        "<div class=\"panel warn\"><p>A clean audit means the configuration is correct, not that "
        "the exam is secure. On hardware the candidate owns, these remain open regardless:</p><ul>"
    )
    for title, detail in CANNOT_ENFORCE:
        parts.append(f"<li><b>{_e(title)}.</b> {_e(detail)}</li>")
    parts.append("</ul></div>")

    parts.append("<footer>Generated by the MedTech SEB Exam Kit.</footer>")
    return _doc(f"Audit - {source_name}", "".join(parts))
