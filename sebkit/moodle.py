"""
Moodle integration.

Moodle's quiz module can require SEB and verify it. The verification is the
part that matters on student-owned laptops, and it is the part most often left
unconfigured - a quiz set to "Require Safe Exam Browser" with no key registered
still refuses ordinary browsers by user-agent, which looks like it is working
and is trivially defeated.

There is also one genuine trap worth stating plainly, because it costs teachers
an exam sitting: when you upload a .seb file, Moodle re-serialises it before
serving it to students. The file students receive is not byte-identical to the
file you uploaded, so a Config Key computed from your local copy will not match.
The key must be computed from the file Moodle serves back.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from .configkey import compute_config_key, request_hash

# Values of the quiz's seb_requiresafeexambrowser setting
REQUIRE_NO = 0
REQUIRE_MANUAL = 1
REQUIRE_TEMPLATE = 2
REQUIRE_UPLOAD_CONFIG = 3
REQUIRE_CLIENT_CONFIG = 4

RECOMMENDED_MODE = REQUIRE_UPLOAD_CONFIG


@dataclass(frozen=True)
class MoodleIntegration:
    quiz_url: str
    config_key: str

    @property
    def expected_header(self) -> str:
        """The X-SafeExamBrowser-ConfigKeyHash value SEB will send for the quiz URL."""
        return request_hash(self.quiz_url, self.config_key)

    @property
    def quiz_settings_url(self) -> str:
        """Best guess at the quiz settings page, to save the teacher a click."""
        parts = urlsplit(self.quiz_url)
        return urlunsplit((parts.scheme, parts.netloc, "/mod/quiz/edit.php", parts.query, ""))


def build_integration(settings: dict, quiz_url: str) -> MoodleIntegration:
    return MoodleIntegration(quiz_url=quiz_url, config_key=compute_config_key(settings))


def setup_steps(integration: MoodleIntegration, *, uploaded: bool = True) -> list[dict]:
    """The ordered steps a teacher follows in Moodle, as structured data."""
    steps: list[dict] = [
        {
            "title": "Open the quiz settings",
            "body": (
                "In your Moodle course, open the quiz, then choose Settings. Expand the "
                "section named Safe Exam Browser."
            ),
        },
        {
            "title": "Set 'Require the use of Safe Exam Browser' to 'Yes - Upload my own config'",
            "body": (
                "This is the mode that lets Moodle verify the configuration itself. Avoid "
                "'Yes - Use SEB client config': it performs no server-side verification of "
                "your settings, which is the only check that still holds on a laptop you "
                "do not control."
            ),
        },
        {
            "title": "Upload the .seb file this tool generated",
            "body": "Use the file picker in that same section to attach the configuration.",
        },
    ]

    if uploaded:
        steps.append({
            "title": "Let Moodle compute the Config Key",
            "body": (
                "Once the file is uploaded and the quiz is saved, Moodle derives the Config "
                "Key from the copy it will actually serve to students. Do not paste a key "
                "by hand in this mode - Moodle re-serialises uploaded files, so a key "
                "computed from your local copy will not match and every student will be "
                "refused."
            ),
            "emphasis": True,
        })
    else:
        steps.append({
            "title": "Paste the Config Key",
            "body": (
                f"Enter this value in the Config Key field:\n\n{integration.config_key}\n\n"
                "Use this only when Moodle is not holding the configuration file itself."
            ),
        })

    steps.extend([
        {
            "title": "Leave the Browser Exam Key field empty unless you are pinning a version",
            "body": (
                "The Config Key verifies your settings and is what you want here. A Browser "
                "Exam Key additionally pins one exact SEB build, so every student must run "
                "that identical version - useful in a managed lab, painful on student "
                "laptops where versions vary. If you do want it, read it from SEB Config "
                "Tool on a machine running the exact build you intend to require."
            ),
        },
        {
            "title": "Save, then verify with a real client before exam day",
            "body": (
                "Open the quiz in an ordinary browser: it must be refused. Then open it "
                "through SEB using this configuration: it must load. A configuration that "
                "has not been through both halves of this check has not been tested."
            ),
            "emphasis": True,
        },
    ])

    return steps


def verification_notes() -> list[str]:
    """Things that commonly go wrong, phrased as checks."""
    return [
        "An ordinary browser is refused by the quiz.",
        "SEB with this configuration reaches the quiz and can submit.",
        "The quiz's own time limit is set - SEB does not enforce exam duration.",
        "Question and answer order are randomised, so a leaked answer sheet from an "
        "earlier sitting is worth less.",
        "The quiz is not visible to students before the sitting, and closes afterwards.",
        "A second sitting for latecomers uses a fresh configuration with new passwords.",
    ]
