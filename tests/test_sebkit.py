"""Tests for sebkit. Run with: python -m pytest -q  (or python tests/test_sebkit.py)"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from sebkit import rncryptor, sebfile, urlfilter
from sebkit.audit import audit
from sebkit.configkey import compute_config_key, config_key_json, request_hash
from sebkit.passwords import (
    ExamPasswords, generate_exam_passwords, hash_password, looks_weak, verify_hash,
)
from sebkit.profiles import ExamSpec, build_settings


# --------------------------------------------------------------------------
# RNCryptor
# --------------------------------------------------------------------------

def test_rncryptor_roundtrip():
    payload = rncryptor.encrypt(b"the quick brown fox", "correct horse")
    assert rncryptor.decrypt(payload, "correct horse").plaintext == b"the quick brown fox"


def test_rncryptor_rejects_wrong_password():
    payload = rncryptor.encrypt(b"secret", "right")
    with pytest.raises(rncryptor.RNCryptorError):
        rncryptor.decrypt(payload, "wrong")


def test_rncryptor_detects_tampering():
    payload = bytearray(rncryptor.encrypt(b"secret payload here", "pw"))
    payload[40] ^= 0x01  # flip a bit inside the ciphertext
    with pytest.raises(rncryptor.RNCryptorError):
        rncryptor.decrypt(bytes(payload), "pw")


def test_rncryptor_reports_prf():
    payload = rncryptor.encrypt(b"x" * 64, "pw", prf="sha256")
    assert rncryptor.decrypt(payload, "pw").prf == "sha256"


# --------------------------------------------------------------------------
# .seb file format
# --------------------------------------------------------------------------

SAMPLE = {
    "startURL": "https://moodle.medtech.tn/mod/quiz/view.php?id=1",
    "allowQuit": True,
    "allowedDisplaysMaxNumber": 1,
    "examKeySalt": b"\x01\x02\x03\x04",
    "URLFilterRules": [{"active": True, "expression": "moodle.medtech.tn/*", "regex": False, "action": 1}],
}


def test_seb_plain_roundtrip():
    loaded = sebfile.loads(sebfile.dumps(SAMPLE))
    assert loaded.settings == SAMPLE
    assert loaded.encrypted is False
    assert loaded.prefix == sebfile.PREFIX_PLAIN


def test_seb_encrypted_roundtrip():
    loaded = sebfile.loads(sebfile.dumps(SAMPLE, "exam-password"), "exam-password")
    assert loaded.settings == SAMPLE
    assert loaded.encrypted is True
    assert loaded.prefix == sebfile.PREFIX_PASSWORD


def test_seb_encrypted_requires_password():
    raw = sebfile.dumps(SAMPLE, "pw")
    with pytest.raises(sebfile.PasswordRequired):
        sebfile.loads(raw)
    with pytest.raises(sebfile.PasswordRequired):
        sebfile.loads(raw, "not-the-password")


def test_seb_client_config_prefix():
    raw = sebfile.dumps(SAMPLE, "pw", purpose=sebfile.PURPOSE_CONFIGURE_CLIENT)
    assert sebfile.loads(raw, "pw").prefix == sebfile.PREFIX_CLIENT_CONFIG


def test_seb_rejects_non_seb_data():
    with pytest.raises(sebfile.SebFileError):
        sebfile.loads(b"this is not a seb file at all")


def test_seb_accepts_bare_xml():
    """Hand-edited configs are sometimes plain XML with no prefix or gzip."""
    loaded = sebfile.loads(sebfile.to_plist_xml(SAMPLE))
    assert loaded.settings == SAMPLE
    assert loaded.notes


# --------------------------------------------------------------------------
# Config Key
# --------------------------------------------------------------------------

def test_config_key_is_stable():
    assert compute_config_key(SAMPLE) == compute_config_key(dict(SAMPLE))


def test_config_key_ignores_key_insertion_order():
    reversed_order = dict(reversed(list(SAMPLE.items())))
    assert compute_config_key(reversed_order) == compute_config_key(SAMPLE)


def test_config_key_excludes_originator_version():
    with_version = dict(SAMPLE, originatorVersion="SEB_Win_3.10.2")
    assert compute_config_key(with_version) == compute_config_key(SAMPLE)


def test_config_key_drops_empty_dicts():
    with_empty = dict(SAMPLE, somethingEmpty={})
    assert compute_config_key(with_empty) == compute_config_key(SAMPLE)


def test_config_key_changes_with_any_setting():
    tightened = dict(SAMPLE, allowQuit=False)
    assert compute_config_key(tightened) != compute_config_key(SAMPLE)


def test_config_key_json_sorts_case_insensitively():
    text = config_key_json({"bravo": 1, "Alpha": 2, "charlie": 3})
    assert text.index('"Alpha"') < text.index('"bravo"') < text.index('"charlie"')


def test_config_key_json_encodes_types():
    text = config_key_json({
        "flag": True, "count": 3, "ratio": 0.5, "whole": 2.0,
        "blob": b"\x00\xff", "name": "x",
    })
    assert '"flag":true' in text
    assert '"count":3' in text
    assert '"ratio":0.5' in text
    assert '"whole":2' in text        # whole reals lose the .0
    assert '"blob":"AP8="' in text     # base64
    assert '"name":"x"' in text


def test_config_key_json_leaves_backslashes_unescaped():
    """The spec calls for no escaping - a regex rule must survive verbatim."""
    text = config_key_json({"expression": r"^https://moodle\.medtech\.tn/.*$"})
    assert r"moodle\.medtech\.tn" in text


def test_request_hash_matches_documented_construction():
    import hashlib
    key = "a" * 64
    url = "https://moodle.medtech.tn/mod/quiz/attempt.php"
    assert request_hash(url, key) == hashlib.sha256((url + key).encode()).hexdigest()


def test_request_hash_ignores_fragment():
    key = "b" * 64
    base = "https://moodle.medtech.tn/quiz"
    assert request_hash(base + "#section", key) == request_hash(base, key)


# --------------------------------------------------------------------------
# Passwords
# --------------------------------------------------------------------------

def test_password_hash_is_lowercase_sha256():
    assert hash_password("abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_verify_hash_is_case_insensitive():
    digest = hash_password("hunter2")
    assert verify_hash("hunter2", digest)
    assert verify_hash("hunter2", digest.upper())
    assert not verify_hash("hunter3", digest)


def test_generated_passwords_are_distinct_and_strong():
    pw = generate_exam_passwords()
    assert pw.admin != pw.quit
    assert looks_weak(pw.admin) is None
    assert looks_weak(pw.quit) is None


def test_looks_weak_catches_common_choices():
    assert looks_weak("") is not None
    assert looks_weak("seb") is not None
    assert looks_weak("12345678") is not None
    assert looks_weak("medtech") is not None


# --------------------------------------------------------------------------
# URL filter
# --------------------------------------------------------------------------

def test_moodle_rules_are_scoped_to_the_host():
    rules = urlfilter.build_moodle_rules("https://moodle.medtech.tn/mod/quiz/view.php?id=9")
    assert all("moodle.medtech.tn" in r.expression for r in rules)
    assert all(r.action == urlfilter.ACTION_ALLOW for r in rules)


def test_analyse_flags_match_all_regex():
    findings = urlfilter.analyse_rules([
        {"active": True, "action": 1, "regex": True, "expression": ".*"},
    ])
    assert findings and findings[0].severity == "critical"


def test_analyse_flags_bare_tld():
    findings = urlfilter.analyse_rules([
        {"active": True, "action": 1, "regex": False, "expression": "*.tn/*"},
    ])
    assert findings and findings[0].severity == "critical"


def test_analyse_flags_search_engines():
    findings = urlfilter.analyse_rules([
        {"active": True, "action": 1, "regex": False, "expression": "google.com/*"},
    ])
    assert findings and findings[0].severity == "critical"


def test_analyse_flags_domain_wildcard_as_high():
    findings = urlfilter.analyse_rules([
        {"active": True, "action": 1, "regex": False, "expression": "*.medtech.tn/*"},
    ])
    assert findings and findings[0].severity == "high"


def test_analyse_ignores_block_and_inactive_rules():
    assert urlfilter.analyse_rules([
        {"active": True, "action": 0, "regex": True, "expression": ".*"},
        {"active": False, "action": 1, "regex": True, "expression": ".*"},
    ]) == []


def test_tight_rule_is_not_flagged():
    assert urlfilter.analyse_rules([
        {"active": True, "action": 1, "regex": False, "expression": "moodle.medtech.tn/mod/quiz/*"},
    ]) == []


# --------------------------------------------------------------------------
# Generated configurations
# --------------------------------------------------------------------------

def _spec(**kwargs) -> ExamSpec:
    defaults = dict(exam_name="Test Exam", quiz_url="https://moodle.medtech.tn/mod/quiz/view.php?id=1")
    defaults.update(kwargs)
    return ExamSpec(**defaults)


def test_generated_config_passes_its_own_audit():
    settings = build_settings(_spec(), generate_exam_passwords())
    result = audit(settings, byod=True)
    assert result.count("critical") == 0
    assert result.count("high") == 0, [f.title for f in result.sorted_findings]


def test_generated_config_sets_the_controls_that_matter():
    settings = build_settings(_spec(), generate_exam_passwords())
    assert settings["sendBrowserExamKey"] is True
    assert settings["URLFilterEnable"] is True
    assert settings["allowVirtualMachine"] is False
    assert settings["allowedDisplaysMaxNumber"] == 1
    assert settings["allowSwitchToApplications"] is False
    assert settings["examSessionReconfigureAllow"] is False
    assert settings["hashedAdminPassword"]
    assert settings["hashedQuitPassword"]
    assert settings["hashedAdminPassword"] != settings["hashedQuitPassword"]
    assert len(settings["examKeySalt"]) == 32
    assert settings["prohibitedProcesses"]


def test_generated_config_survives_a_file_roundtrip():
    settings = build_settings(_spec(), generate_exam_passwords())
    reloaded = sebfile.loads(sebfile.dumps(settings)).settings
    assert compute_config_key(reloaded) == compute_config_key(settings)


def test_profiles_differ_only_where_documented():
    pw = generate_exam_passwords()
    strict = build_settings(_spec(profile="byod_strict"), pw)
    balanced = build_settings(_spec(profile="byod_balanced"), pw)
    differing = {k for k in strict if strict[k] != balanced.get(k)} - {"examKeySalt"}
    assert differing == {"sebServicePolicy", "allowedDisplaysMaxNumber", "enableF5"}


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError):
        _spec(profile="nonsense")


def test_missing_url_is_rejected():
    with pytest.raises(ValueError):
        ExamSpec(exam_name="x", quiz_url="  ")


# --------------------------------------------------------------------------
# The auditor, against configurations that are actually broken
# --------------------------------------------------------------------------

def _titles(settings, **kwargs) -> set[str]:
    return {f.title for f in audit(settings, **kwargs).sorted_findings}


def test_audit_catches_missing_key_verification():
    settings = build_settings(_spec(), generate_exam_passwords())
    settings["sendBrowserExamKey"] = False
    assert "SEB is not sending its exam key" in _titles(settings)


def test_audit_catches_no_admin_password():
    settings = build_settings(_spec(), generate_exam_passwords())
    settings["hashedAdminPassword"] = ""
    result = audit(settings)
    assert result.count("critical") >= 1
    assert result.grade == "Not fit for use"


def test_audit_cracks_a_weak_quit_password():
    settings = build_settings(_spec(), generate_exam_passwords())
    settings["hashedQuitPassword"] = hash_password("medtech")
    assert "The quit password is guessable" in _titles(settings)


def test_audit_catches_reused_password():
    pw = generate_exam_passwords()
    settings = build_settings(_spec(), pw)
    settings["hashedQuitPassword"] = settings["hashedAdminPassword"]
    assert "The admin and quit passwords are the same" in _titles(settings)


def test_audit_catches_disabled_url_filter():
    settings = build_settings(_spec(), generate_exam_passwords())
    settings["URLFilterEnable"] = False
    assert "No URL filtering - SEB can browse anywhere" in _titles(settings)


def test_audit_catches_virtual_machine_and_second_screen():
    settings = build_settings(_spec(), generate_exam_passwords())
    settings["allowVirtualMachine"] = True
    settings["allowedDisplaysMaxNumber"] = 2
    titles = _titles(settings)
    assert "SEB is allowed to run inside a virtual machine" in titles
    assert "Up to 2 displays are permitted" in titles


def test_audit_catches_http_start_url():
    settings = build_settings(_spec(), generate_exam_passwords())
    settings["startURL"] = "http://moodle.medtech.tn/mod/quiz/view.php?id=1"
    assert "The exam is served over plain HTTP" in _titles(settings)


def test_audit_catches_empty_process_list():
    settings = build_settings(_spec(), generate_exam_passwords())
    settings["prohibitedProcesses"] = []
    titles = _titles(settings)
    assert "No remote-access software is blocked" in titles
    # Every essential category should be reported, not just the first.
    assert sum(1 for t in titles if t.startswith("No ")) >= 5


def test_audit_finding_wording_reads_as_prose():
    """Category labels are headings; findings must not lowercase them into prose."""
    settings = build_settings(_spec(), generate_exam_passwords())
    settings["prohibitedProcesses"] = []
    for finding in audit(settings).sorted_findings:
        if finding.key == "prohibitedProcesses":
            assert "(" not in finding.title, finding.title


def test_audit_catches_permitting_a_prohibited_tool():
    settings = build_settings(_spec(), generate_exam_passwords())
    settings["permittedProcesses"] = [{"active": True, "executable": "TeamViewer.exe"}]
    assert "A prohibited category of application is explicitly permitted" in _titles(settings)


def test_audit_catches_developer_console_and_address_bar():
    settings = build_settings(_spec(), generate_exam_passwords())
    settings["allowDeveloperConsole"] = True
    settings["browserWindowAllowAddressBar"] = True
    titles = _titles(settings)
    assert "The browser developer console is available" in titles
    assert "The address bar is visible and usable" in titles


def test_audit_catches_client_config_purpose():
    settings = build_settings(_spec(), generate_exam_passwords())
    settings["sebConfigPurpose"] = 1
    assert "This is a client configuration, not an exam configuration" in _titles(settings)


def test_audit_grades_a_wide_open_config_as_unusable():
    wide_open = {
        "startURL": "http://moodle.medtech.tn/quiz",
        "sendBrowserExamKey": False,
        "URLFilterEnable": False,
        "hashedAdminPassword": "",
        "hashedQuitPassword": "",
        "allowQuit": True,
        "allowVirtualMachine": True,
        "allowSwitchToApplications": True,
        "monitorProcesses": False,
    }
    result = audit(wide_open)
    assert result.grade == "Not fit for use"
    assert result.count("critical") >= 5


def test_audit_of_a_good_config_is_clean():
    settings = build_settings(_spec(), generate_exam_passwords())
    assert audit(settings, byod=True).grade == "Good"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
