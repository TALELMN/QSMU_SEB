"""
Hardened configuration profiles.

`build_settings` produces a complete SEB settings dictionary from a short exam
description. Every key written here was verified to exist in SEB 3.10.2 rather
than copied from a blog post - a misspelled key is silently ignored by SEB,
which is how configurations end up looking strict and enforcing nothing.

Three profiles:

  byod_strict    student-owned laptops, maximum enforcement (the default)
  byod_balanced  same, with the settings most likely to cause exam-day support
                 calls relaxed; use when a first run has to go smoothly
  lab_managed    institution-managed lab machines, where the OS baseline is
                 already trusted

The profiles differ only in a handful of documented keys; everything else is
identical, so a teacher switching profiles is not silently changing the
security posture in ways the report does not mention.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import processes as _processes
from . import urlfilter as _urlfilter
from .passwords import ExamPasswords

PROFILES = ("byod_strict", "byod_balanced", "lab_managed")

# sebServicePolicy
SERVICE_IGNORE = 0
SERVICE_WARN = 1
SERVICE_FORCE = 2


@dataclass
class ExamSpec:
    """Everything a teacher has to decide to produce an exam configuration."""

    exam_name: str
    quiz_url: str
    quit_url: str = ""
    profile: str = "byod_strict"

    # Capabilities the exam itself needs
    allow_uploads: bool = False
    allow_downloads: bool = False
    allow_spell_check: bool = False
    allow_audio: bool = False       # for listening comprehension papers
    allow_video_capture: bool = False  # for camera-based proctoring add-ons

    extra_allowed_urls: list[str] = field(default_factory=list)
    allow_static_cdn: bool = False

    process_categories: list[str] = field(
        default_factory=lambda: list(_processes.ESSENTIAL_KEYS)
    )

    def __post_init__(self) -> None:
        if self.profile not in PROFILES:
            raise ValueError(f"unknown profile {self.profile!r}; expected one of {PROFILES}")
        if not self.quiz_url.strip():
            raise ValueError("quiz_url is required")
        if not self.exam_name.strip():
            raise ValueError("exam_name is required")


def _function_keys(enabled: bool) -> dict:
    return {f"enableF{n}": enabled for n in range(1, 13)}


def _inside_seb_permissions(enabled: bool) -> dict:
    """The Windows security-screen options available from inside SEB."""
    return {
        "insideSebEnableChangeAPassword": enabled,
        "insideSebEnableEaseOfAccess": enabled,
        "insideSebEnableLockThisComputer": enabled,
        "insideSebEnableLogOff": enabled,
        "insideSebEnableNetworkConnectionSelector": enabled,
        "insideSebEnableShutDown": enabled,
        "insideSebEnableStartTaskManager": enabled,
        "insideSebEnableSwitchUser": enabled,
        "insideSebEnableVmWareClientShade": enabled,
    }


def build_settings(spec: ExamSpec, pw: ExamPasswords) -> dict:
    """Build the full SEB settings dictionary for an exam."""
    strict = spec.profile in ("byod_strict", "lab_managed")
    byod = spec.profile.startswith("byod")

    rules = _urlfilter.build_moodle_rules(
        spec.quiz_url,
        extra_allowed=spec.extra_allowed_urls,
        allow_static_cdn=spec.allow_static_cdn,
    )

    settings: dict = {
        # --- identity -------------------------------------------------------
        "originatorVersion": "SEB_Win_3.10.2",
        "sebConfigPurpose": 0,  # 0 = starting an exam
        "startURL": spec.quiz_url,
        "browserWindowTitleSuffix": spec.exam_name[:60],

        # --- the control that actually holds on unmanaged hardware ----------
        # SEB signs every request with a key derived from these settings;
        # Moodle refuses the attempt when the signature does not match.
        "sendBrowserExamKey": True,
        "browserURLSalt": True,
        "examKeySalt": os.urandom(32),
        "browserExamKey": "",

        # --- passwords ------------------------------------------------------
        "hashedAdminPassword": pw.hashed_admin,
        "hashedQuitPassword": pw.hashed_quit,
        "allowQuit": True,
        "ignoreExitKeys": True,
        "allowPreferencesWindow": False,

        # --- session handling ----------------------------------------------
        "quitURL": spec.quit_url,
        "quitURLConfirm": True,
        "restartExamPasswordProtected": True,
        "restartExamUseStartURL": True,
        "examSessionClearCookiesOnStart": True,
        "examSessionClearCookiesOnEnd": True,
        "examSessionReconfigureAllow": False,  # no swapping config mid-exam
        "removeBrowserProfile": True,
        "removeLocalStorage": True,
        "enablePrivateClipboard": True,

        # --- browser --------------------------------------------------------
        "browserViewMode": 1,  # fullscreen
        "touchOptimized": False,
        "enableBrowserWindowToolbar": False,
        "browserWindowAllowAddressBar": False,
        "browserWindowShowURL": 0,
        "allowBrowsingBackForward": False,
        # Reload is intentionally permitted: a hung quiz page is a real exam-day
        # failure mode, and reloading stays inside the same filtered URL, so it
        # buys nothing for a cheat.
        "browserWindowAllowReload": True,
        "showReloadButton": True,
        "newBrowserWindowByLinkPolicy": 2,
        "newBrowserWindowByScriptPolicy": 2,
        "enableJavaScript": True,   # Moodle quizzes do not work without it
        "enableJava": False,
        "enablePlugIns": False,
        "allowPDFPlugIn": False,
        "allowDeveloperConsole": False,
        "allowFind": False,
        "allowPrint": False,
        "enableZoomPage": True,     # accessibility; no security cost
        "enableZoomText": True,
        "allowSpellCheck": spec.allow_spell_check,
        "allowSpellCheckDictionary": spec.allow_spell_check,
        "allowDictionaryLookup": False,
        "allowDictation": False,
        "allowDownloads": spec.allow_downloads,
        "allowUploads": spec.allow_uploads,
        "allowCustomDownUploadLocation": False,
        "allowAudioCapture": spec.allow_audio,
        "allowVideoCapture": spec.allow_video_capture,

        # --- URL allowlist (deny by default) --------------------------------
        "URLFilterEnable": True,
        "URLFilterEnableContentFilter": True,
        "URLFilterRules": [rule.to_seb() for rule in rules],

        # --- display --------------------------------------------------------
        # One display only: a second monitor is the cheapest way to keep an
        # unfiltered screen beside the exam.
        "allowedDisplaysMaxNumber": 1,
        "allowedDisplayBuiltin": byod,
        "allowedDisplayBuiltinEnforce": False,
        "allowedDisplaysIgnoreFailure": False,
        "allowDisplayMirroring": False,
        "allowScreenSharing": False,
        "enablePrintScreen": False,

        # --- machine environment --------------------------------------------
        "allowVirtualMachine": False,
        "allowSwitchToApplications": False,
        "allowUserSwitching": False,
        "allowStickyKeys": False,
        "allowUserAppFolderInstall": False,
        "allowWlan": False,
        "enableWindowsUpdate": False,
        "createNewDesktop": True,
        "killExplorerShell": False,
        "enableAppSwitcherCheck": True,
        "enableSessionVerification": True,
        "lockOnMessageSocketClose": True,
        "enableTouchExit": False,

        # --- process monitoring ---------------------------------------------
        "monitorProcesses": True,
        "detectStoppedProcess": True,
        "prohibitedProcesses": _processes.build_prohibited_processes(spec.process_categories),
        "permittedProcesses": [],

        # --- keyboard / mouse ------------------------------------------------
        "enableAltTab": False,
        "enableAltEsc": False,
        "enableAltF4": False,
        "enableAltMouseWheel": False,
        "enableCtrlEsc": False,
        "enableEsc": False,
        "enableStartMenu": False,
        "enableRightMouse": False,
        "enableMiddleMouse": False,

        # --- SEB taskbar -----------------------------------------------------
        "showTaskBar": True,
        "showTime": True,           # students need a clock
        "showInputLanguage": True,  # avoids AZERTY/QWERTY panic
        "browserScreenKeyboard": False,

        # --- service and logging ---------------------------------------------
        "sebServicePolicy": SERVICE_FORCE if strict else SERVICE_WARN,
        "sebServiceIgnore": False,
        "enableLogging": True,
        "allowApplicationLog": False,
    }

    settings.update(_function_keys(False))
    settings.update(_inside_seb_permissions(False))

    if spec.profile == "byod_balanced":
        # Relax only what causes support calls, and say so out loud in the report.
        settings["sebServicePolicy"] = SERVICE_WARN
        settings["allowedDisplaysMaxNumber"] = 2
        settings["enableF5"] = True  # refresh, for students who freeze

    if spec.profile == "lab_managed":
        # On managed hardware the built-in-display restriction is wrong: lab
        # machines are desktops with external monitors.
        settings["allowedDisplayBuiltin"] = False

    return settings


def profile_summary(profile: str) -> str:
    return {
        "byod_strict": (
            "Student laptops, maximum enforcement. SEB refuses to run without its "
            "service, only one display is permitted, and every non-essential "
            "capability is off."
        ),
        "byod_balanced": (
            "Student laptops, tuned to reduce exam-day support calls: a missing SEB "
            "service warns instead of blocking, two displays are tolerated, and F5 "
            "works. Measurably weaker than strict - use for a first deployment."
        ),
        "lab_managed": (
            "Institution-managed lab machines. Same enforcement as strict, with the "
            "built-in-display restriction lifted for desktop hardware."
        ),
    }[profile]
