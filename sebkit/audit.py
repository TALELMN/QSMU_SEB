"""
The configuration auditor.

Given a decoded .seb settings dictionary, report what is actually enforced.
Every check here corresponds to a way a real exam has been undermined, and each
finding carries the concrete consequence rather than a generic warning, because
"allowVirtualMachine is true" means nothing to a teacher and "a student can run
this exam inside a virtual machine and keep the rest of the laptop free" means
everything.

Severity is about exam impact, not about how unusual the setting is:

  critical  the exam's integrity is defeated, not merely weakened
  high      a realistic, low-effort route around the lockdown
  medium    widens the attack surface without opening a direct route
  low       hygiene
  info      worth stating in the report; not a defect
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from . import processes as _processes
from . import urlfilter as _urlfilter
from .passwords import WEAK_PASSWORDS, verify_hash

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class Finding:
    severity: str
    title: str
    detail: str
    remediation: str
    key: str = ""

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class AuditResult:
    findings: list[Finding] = field(default_factory=list)

    def add(self, *args, **kwargs) -> None:
        self.findings.append(Finding(*args, **kwargs))

    @property
    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.rank, f.title))

    def count(self, severity: str) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    @property
    def grade(self) -> str:
        if self.count("critical"):
            return "Not fit for use"
        if self.count("high") >= 3:
            return "Weak"
        if self.count("high"):
            return "Needs attention"
        if self.count("medium") >= 3:
            return "Acceptable"
        return "Good"

    @property
    def verdict(self) -> str:
        return {
            "Not fit for use": (
                "At least one setting defeats the exam outright. Do not use this "
                "configuration until the critical findings are fixed."
            ),
            "Weak": (
                "No single setting defeats the exam, but several easy routes around "
                "the lockdown remain open."
            ),
            "Needs attention": "One realistic route around the lockdown is open.",
            "Acceptable": "Reasonably configured, with some avoidable surface left open.",
            "Good": "Correctly configured for what SEB is able to enforce.",
        }[self.grade]


def _get(settings: dict[str, Any], key: str, default: Any = None) -> Any:
    return settings.get(key, default)


def _truthy(settings: dict[str, Any], key: str, default: bool = False) -> bool:
    return bool(_get(settings, key, default))


def _crack_weak_password(stored_hash: str) -> str | None:
    """Return the plaintext if the stored hash matches a commonly used password."""
    if not stored_hash:
        return None
    candidates = set(WEAK_PASSWORDS)
    for base in list(candidates):
        if not base:
            continue
        candidates.update({base.capitalize(), base.upper(), base + "1", base + "123", base + "2024",
                           base + "2025", base + "2026"})
    for candidate in candidates:
        if candidate and verify_hash(candidate, stored_hash):
            return candidate
    return None


def audit(settings: dict[str, Any], *, byod: bool = True) -> AuditResult:
    """Audit a decoded SEB configuration."""
    result = AuditResult()

    _audit_key_verification(settings, result)
    _audit_passwords(settings, result)
    _audit_url_filter(settings, result)
    _audit_machine(settings, result, byod=byod)
    _audit_processes(settings, result)
    _audit_browser(settings, result)
    _audit_session(settings, result)

    return result


def _audit_key_verification(settings: dict, result: AuditResult) -> None:
    if not _truthy(settings, "sendBrowserExamKey"):
        result.add(
            "critical",
            "SEB is not sending its exam key",
            "With sendBrowserExamKey off, SEB sends no signature with its requests, so "
            "Moodle cannot tell this configuration apart from an ordinary browser. On "
            "student-owned laptops this is the only control that still holds, and it is off.",
            "Turn sendBrowserExamKey on, then register the Config Key on the quiz.",
            key="sendBrowserExamKey",
        )

    if _get(settings, "sebConfigPurpose", 0) == 1:
        result.add(
            "high",
            "This is a client configuration, not an exam configuration",
            "sebConfigPurpose is set to 'configuring a client', which permanently "
            "reconfigures a student's SEB installation instead of starting a single "
            "exam session. Students who open it keep these settings afterwards.",
            "Set sebConfigPurpose to 'starting an exam' (0).",
            key="sebConfigPurpose",
        )

    salt = _get(settings, "examKeySalt")
    if not salt or (isinstance(salt, (bytes, bytearray)) and set(bytes(salt)) == {0}):
        result.add(
            "medium",
            "No exam key salt is set",
            "examKeySalt is empty or all zeroes, which weakens the derivation of the "
            "Browser Exam Key and makes keys more predictable across configurations.",
            "Regenerate the configuration so a fresh random salt is written.",
            key="examKeySalt",
        )

    start_url = str(_get(settings, "startURL", "") or "")
    if start_url and urlsplit(start_url).scheme == "http":
        result.add(
            "high",
            "The exam is served over plain HTTP",
            f"startURL is {start_url}. Exam traffic and the session cookie travel "
            "unencrypted, and anyone on the same network can read or alter them.",
            "Use the https:// address of the quiz.",
            key="startURL",
        )
    if not start_url:
        result.add(
            "high",
            "No start URL is set",
            "startURL is empty, so SEB opens nothing and the configuration cannot "
            "carry students into the exam.",
            "Set startURL to the Moodle quiz address.",
            key="startURL",
        )


def _audit_passwords(settings: dict, result: AuditResult) -> None:
    admin_hash = str(_get(settings, "hashedAdminPassword", "") or "")
    quit_hash = str(_get(settings, "hashedQuitPassword", "") or "")

    if not admin_hash:
        result.add(
            "critical",
            "The settings are not protected by an admin password",
            "Any student can open this .seb file in SEB Config Tool and read the URL "
            "allowlist, the permitted applications and the quit password. The whole "
            "exam policy is legible to anyone who receives the file.",
            "Set an admin (settings) password, unique to this exam.",
            key="hashedAdminPassword",
        )
    else:
        weak = _crack_weak_password(admin_hash)
        if weak:
            result.add(
                "critical",
                "The admin password is guessable",
                f"The stored admin password hash matches {weak!r}, which is in the list "
                "of passwords tried first against exam configurations.",
                "Generate a fresh random admin password for this exam.",
                key="hashedAdminPassword",
            )

    if _truthy(settings, "allowQuit", True) and not quit_hash:
        result.add(
            "critical",
            "Students can quit SEB without a password",
            "Quitting is allowed and no quit password is set, so a student can leave the "
            "locked-down session whenever they choose and use the machine freely.",
            "Set a quit password, or disable quitting entirely.",
            key="hashedQuitPassword",
        )
    elif quit_hash:
        weak = _crack_weak_password(quit_hash)
        if weak:
            result.add(
                "critical",
                "The quit password is guessable",
                f"The stored quit password hash matches {weak!r}.",
                "Generate a fresh random quit password for this exam.",
                key="hashedQuitPassword",
            )

    if admin_hash and quit_hash and admin_hash.lower() == quit_hash.lower():
        result.add(
            "high",
            "The admin and quit passwords are the same",
            "The quit password is given to invigilators and often read aloud in the room. "
            "Sharing it with the settings password hands out the ability to open and read "
            "the exam configuration.",
            "Use two different passwords.",
            key="hashedQuitPassword",
        )

    if _truthy(settings, "allowPreferencesWindow"):
        result.add(
            "high",
            "The SEB settings window can be opened during the exam",
            "allowPreferencesWindow lets a student open SEB's own preferences from inside "
            "the exam session and inspect or change how it is locked down.",
            "Turn allowPreferencesWindow off.",
            key="allowPreferencesWindow",
        )


def _audit_url_filter(settings: dict, result: AuditResult) -> None:
    if not _truthy(settings, "URLFilterEnable"):
        result.add(
            "critical",
            "No URL filtering - SEB can browse anywhere",
            "URLFilterEnable is off, so SEB behaves as an ordinary fullscreen browser. A "
            "student can navigate to a search engine, an AI assistant or their notes in a "
            "cloud drive without leaving SEB at all.",
            "Turn URL filtering on and allow only the Moodle host.",
            key="URLFilterEnable",
        )
        return

    rules = _get(settings, "URLFilterRules", []) or []
    if not rules:
        result.add(
            "high",
            "URL filtering is on but no rules are defined",
            "SEB denies by default, so with no rules the exam page itself may fail to "
            "load. This configuration has almost certainly not been tested.",
            "Add an allow rule for the Moodle host.",
            key="URLFilterRules",
        )
        return

    for finding in _urlfilter.analyse_rules(rules):
        result.add(
            finding.severity,
            f"Over-broad allowlist entry: {finding.expression}",
            finding.reason,
            "Narrow the rule to the exact Moodle host, and add a path where possible.",
            key="URLFilterRules",
        )

    if not _truthy(settings, "URLFilterEnableContentFilter"):
        result.add(
            "medium",
            "Embedded content is not filtered",
            "Only top-level page loads are checked. Images, iframes and scripts pulled from "
            "elsewhere are fetched without going through the allowlist, which leaves an "
            "embedded frame as a way to reach outside content.",
            "Turn URLFilterEnableContentFilter on.",
            key="URLFilterEnableContentFilter",
        )


def _audit_machine(settings: dict, result: AuditResult, *, byod: bool) -> None:
    if _truthy(settings, "allowVirtualMachine"):
        result.add(
            "critical",
            "SEB is allowed to run inside a virtual machine",
            "A student can run the whole exam in a guest VM and leave the host machine "
            "entirely free for notes, search and messaging, on a second screen or behind "
            "the VM window.",
            "Turn allowVirtualMachine off.",
            key="allowVirtualMachine",
        )

    if _truthy(settings, "allowScreenSharing"):
        result.add(
            "critical",
            "Screen sharing is permitted",
            "The exam screen can be shared live with someone outside the room.",
            "Turn allowScreenSharing off.",
            key="allowScreenSharing",
        )

    max_displays = _get(settings, "allowedDisplaysMaxNumber", 1)
    if isinstance(max_displays, int) and max_displays > 1:
        result.add(
            "high",
            f"Up to {max_displays} displays are permitted",
            "A second monitor is the cheapest way to keep an unfiltered screen beside the "
            "exam. SEB locks the display it occupies, not the other one.",
            "Set allowedDisplaysMaxNumber to 1.",
            key="allowedDisplaysMaxNumber",
        )

    if _truthy(settings, "allowDisplayMirroring"):
        result.add(
            "high",
            "Display mirroring is permitted",
            "The exam screen can be mirrored to a projector, TV or capture device, letting "
            "someone else read the paper in real time.",
            "Turn allowDisplayMirroring off.",
            key="allowDisplayMirroring",
        )

    if _truthy(settings, "allowSwitchToApplications"):
        result.add(
            "critical",
            "Students can switch to other applications",
            "The lockdown is effectively off: any already-running application, including a "
            "browser or a messenger, can be brought to the front during the exam.",
            "Turn allowSwitchToApplications off.",
            key="allowSwitchToApplications",
        )

    policy = _get(settings, "sebServicePolicy", 2)
    if policy == 0:
        result.add(
            "high",
            "SEB runs without its Windows service",
            "The service is what applies the registry-level lockdown (task manager, "
            "switching, sticky keys). With the policy set to ignore, SEB starts even when "
            "the service is absent, and those protections silently do not apply.",
            "Set sebServicePolicy to force (2), or at minimum warn (1).",
            key="sebServicePolicy",
        )
    elif policy == 1 and byod:
        result.add(
            "medium",
            "A missing SEB service only produces a warning",
            "On student-owned laptops this is the difference between an enforced lockdown "
            "and a warning a student clicks past.",
            "Set sebServicePolicy to force (2) once you are confident students' "
            "installations are healthy.",
            key="sebServicePolicy",
        )

    for key, title, detail in (
        ("allowUserSwitching", "Windows user switching is permitted",
         "A student can switch to another Windows account, leaving the exam session running "
         "behind an unrestricted desktop."),
        ("allowStickyKeys", "Sticky keys are permitted",
         "The sticky-keys dialog is a long-standing way to break out of a kiosk session."),
        ("enableStartMenu", "The Start menu is available",
         "Any installed application can be launched during the exam."),
        ("allowUserAppFolderInstall", "Applications can be installed during the exam",
         "A student can install a tool from their user folder while the exam is running."),
        ("enableWindowsUpdate", "Windows Update is reachable",
         "The update interface is a route to other parts of Windows mid-exam."),
    ):
        if _truthy(settings, key):
            result.add("high", title, detail, f"Turn {key} off.", key=key)

    for key, title in (
        ("enableAltTab", "Alt+Tab switching is enabled"),
        ("enableAltEsc", "Alt+Esc switching is enabled"),
        ("enableCtrlEsc", "Ctrl+Esc (Start) is enabled"),
        ("enableAltF4", "Alt+F4 is enabled"),
        ("enableEsc", "Esc is enabled"),
        ("enablePrintScreen", "Print Screen is enabled"),
        ("enableRightMouse", "The right mouse button is enabled"),
    ):
        if _truthy(settings, key):
            result.add(
                "medium", title,
                "This key or button gives a student a way to leave, close or capture the "
                "exam window that the lockdown is otherwise closing.",
                f"Turn {key} off.", key=key,
            )


def _audit_processes(settings: dict, result: AuditResult) -> None:
    if not _truthy(settings, "monitorProcesses"):
        result.add(
            "high",
            "Prohibited-process monitoring is off",
            "SEB will not notice screen sharing, remote control or phone-mirroring software "
            "running alongside the exam, whatever the prohibited list says.",
            "Turn monitorProcesses on.",
            key="monitorProcesses",
        )
        return

    prohibited = _get(settings, "prohibitedProcesses", []) or []
    listed = {
        str(entry.get("executable", "")).lower()
        for entry in prohibited
        if isinstance(entry, dict) and entry.get("active", True)
    }

    missing_categories = []
    for category in _processes.CATEGORIES:
        if not category.essential:
            continue
        covered = sum(1 for rule in category.processes if rule.executable.lower() in listed)
        if covered == 0:
            missing_categories.append(category)

    for category in missing_categories:
        result.add(
            "high",
            f"No {category.short_label} software is blocked",
            f"{category.rationale} Not one of the {len(category.processes)} common "
            f"{category.short_label} tools is on the prohibited list.",
            f"Add the '{category.label}' category to prohibitedProcesses.",
            key="prohibitedProcesses",
        )

    if not prohibited:
        return

    permitted = _get(settings, "permittedProcesses", []) or []
    risky = [
        str(entry.get("executable", ""))
        for entry in permitted
        if isinstance(entry, dict)
        and str(entry.get("executable", "")).lower() in _processes.known_executables()
    ]
    if risky:
        result.add(
            "critical",
            "A prohibited category of application is explicitly permitted",
            "These applications are on the permitted list even though they are the kind of "
            f"tool the prohibited list exists to stop: {', '.join(risky)}.",
            "Remove them from permittedProcesses.",
            key="permittedProcesses",
        )

    if not _truthy(settings, "detectStoppedProcess"):
        result.add(
            "medium",
            "A killed monitoring target is not detected",
            "detectStoppedProcess is off, so a student who terminates a watched process to "
            "hide it does not trigger anything.",
            "Turn detectStoppedProcess on.",
            key="detectStoppedProcess",
        )


def _audit_browser(settings: dict, result: AuditResult) -> None:
    if _truthy(settings, "allowDeveloperConsole"):
        result.add(
            "critical",
            "The browser developer console is available",
            "A student can read and modify the quiz page, inspect answers held in the page, "
            "and issue arbitrary network requests from inside the exam.",
            "Turn allowDeveloperConsole off.",
            key="allowDeveloperConsole",
        )

    if _truthy(settings, "browserWindowAllowAddressBar"):
        result.add(
            "critical",
            "The address bar is visible and usable",
            "A student can type any address directly. Combined with a loose allowlist this "
            "is unrestricted browsing.",
            "Turn browserWindowAllowAddressBar off.",
            key="browserWindowAllowAddressBar",
        )

    if _truthy(settings, "enableJava") or _truthy(settings, "enablePlugIns"):
        result.add(
            "medium",
            "Browser plug-ins or Java are enabled",
            "Plug-in content runs outside the browser's own restrictions and widens the "
            "exam's attack surface for no benefit to a Moodle quiz.",
            "Turn enableJava and enablePlugIns off.",
            key="enablePlugIns",
        )

    if _truthy(settings, "allowSpellCheck") or _truthy(settings, "allowDictionaryLookup"):
        result.add(
            "medium",
            "Spell check or dictionary lookup is enabled",
            "Both can reach an online service, and dictionary lookup is a reference tool "
            "in a language exam.",
            "Turn them off unless the paper specifically requires them.",
            key="allowSpellCheck",
        )

    if not _truthy(settings, "enablePrivateClipboard", True):
        result.add(
            "medium",
            "The clipboard is shared with the rest of Windows",
            "Text prepared before the exam can be pasted in, and question text can be copied "
            "out to be shared.",
            "Turn enablePrivateClipboard on.",
            key="enablePrivateClipboard",
        )

    if _truthy(settings, "allowDownloads") or _truthy(settings, "allowUploads"):
        result.add(
            "low",
            "File downloads or uploads are permitted",
            "Reasonable if the paper requires submitting a file; otherwise it is a way to "
            "move material in and out of the session.",
            "Turn off whichever of allowDownloads / allowUploads the exam does not need.",
            key="allowDownloads",
        )


def _audit_session(settings: dict, result: AuditResult) -> None:
    if _truthy(settings, "examSessionReconfigureAllow"):
        result.add(
            "high",
            "The configuration can be swapped during the exam",
            "A student can load a different .seb configuration mid-session, replacing your "
            "lockdown with one of their own.",
            "Turn examSessionReconfigureAllow off.",
            key="examSessionReconfigureAllow",
        )

    if not _truthy(settings, "examSessionClearCookiesOnStart", True):
        result.add(
            "low",
            "Cookies are not cleared when the exam starts",
            "A session left signed in as another user, or a stale Moodle session, carries "
            "into the exam.",
            "Turn examSessionClearCookiesOnStart on.",
            key="examSessionClearCookiesOnStart",
        )

    if not _truthy(settings, "enableLogging", False):
        result.add(
            "low",
            "Logging is off",
            "Without a log there is no evidence to review when an incident is suspected, and "
            "no way to show that a student's session behaved normally.",
            "Turn enableLogging on.",
            key="enableLogging",
        )
