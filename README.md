# QSMU_SEB — MedTech SEB Exam Kit

Generate hardened [Safe Exam Browser](https://safeexambrowser.org/) configurations for Moodle
quizzes, and audit the ones you already have.

Built for exams sat on **student-owned laptops** — the hard case, where the candidate
administers the machine, the lockdown is only a deterrent, and the server-side key check is the
one control that genuinely holds. The tool is designed around that fact rather than around it.

Developed and verified against **Safe Exam Browser 3.10.2** on Windows.

---

## Why this exists

A SEB configuration can look strict and enforce almost nothing. The failures are rarely exotic:

- The Config Key is never registered on the quiz, so Moodle performs no real verification.
- The allowlist permits `*.university.edu`, which quietly includes webmail, wikis and shared drives.
- No admin password is set, so any student can open the `.seb` file and read the entire exam policy.
- The quit password is `exam`, or last semester's.
- The prohibited-process list is SEB's short default, missing every current remote-access,
  phone-mirroring and desktop AI tool.
- A misspelled setting key is silently ignored by SEB — the config reads as locked down and isn't.

This tool closes those by construction, and reports honestly on what remains open.

---

## Running it as a teacher

No command line needed. Setup happens once per computer; after that each exam takes about two
minutes.

### Setup (once)

1. Install Python from [python.org](https://www.python.org/downloads/) — **tick "Add python.exe
   to PATH"** on the first screen of the installer.
2. Download this repository: the green **Code** button above → **Download ZIP** → extract it
   somewhere you can find again.
3. Double-click **`Start-SEB-Exam-Kit.bat`**. It checks for Python, installs the one component it
   needs, and opens the interface in your browser at `http://127.0.0.1:8733`.

Everything runs on your own machine. Nothing is uploaded anywhere. If the window closes instantly,
Python is not on PATH — reinstall it with that box ticked.

### For each exam

1. **Exam name** — e.g. `Anatomy S1 2026 — Session 1`
2. **Moodle quiz address** — copy it from your browser while looking at the quiz
3. Leave everything else on its default unless the paper needs file uploads or audio
4. Click **Generate exam configuration**

You get three things: two passwords **shown once on screen**, a `.seb` file to download, and a
printable exam pack.

> [!WARNING]
> **Save both passwords before leaving the page.** They are generated for that exam only and are
> stored nowhere. If you lose them, generate a new configuration — they cannot be recovered.
>
> The **quit password** goes to invigilators. The **settings password** stays with you: it is what
> stops a student opening the configuration file and reading the entire exam policy. Never read it
> aloud in the room.

### Set up the quiz in Moodle

1. Quiz → **Settings** → **Safe Exam Browser** section
2. Set **Require the use of Safe Exam Browser** to **Yes — Upload my own config**
3. Upload the generated `.seb` file and save
4. Leave the **Browser Exam Key** field empty unless you are deliberately pinning one exact SEB build
5. Let Moodle compute the Config Key itself — **do not paste one in**

> [!IMPORTANT]
> Moodle re-serialises an uploaded `.seb` before serving it to students, so a Config Key computed
> from your local copy will **not** match the file students receive. Pasting a locally computed key
> is the single most common reason an exam refuses every student on the day.

Avoid **Yes — Use SEB client config**: it performs no server-side verification of your settings,
removing the one control that still works on hardware you do not own.

### Test it before announcing the exam

Two checks, both required:

- Open the quiz in an **ordinary browser** → it must be **refused**
- Open it through **SEB using your configuration** → it must **load**

A configuration that has not passed both halves has not been tested.

### On the day

- Distribute the `.seb` file however you normally share materials — Moodle, email, or USB.
  Students double-click it and SEB launches straight into the exam.
- Give invigilators the **quit password only**.
- Print the last page of the exam pack. It is a room checklist: phone collection, second-monitor
  and earbud checks, and what to do when SEB fails on a student's machine.

---

## What it does

**Creates exam configurations.** Give it an exam name and the Moodle quiz address. It produces a
`.seb` file with ~70 settings chosen for exam integrity, a URL allowlist scoped to the Moodle
host, and 100+ blocked applications across remote access, screen sharing, virtual machines,
screen recording, phone mirroring, messaging and desktop AI assistants.

**Generates unique passwords per exam.** A settings password so students cannot open the
configuration and read the exam policy, and a separate quit password for invigilators. Random,
shown once, never reused between exams.

**Computes the Config Key** — the fingerprint Moodle uses to prove a student's SEB is running
your configuration and not one they assembled themselves.

**Produces a printable exam pack** — passwords, Moodle setup steps, what the configuration does
and does not enforce, and an invigilator sheet for the room.

**Audits existing configurations.** Point it at a `.seb` file, encrypted or not. It reports what
is actually enforced, cracks guessable passwords against a dictionary, flags over-broad
allowlists, and grades the result.

---

## Usage (from source)

For administrators and anyone working on the tool. Teachers should use the walkthrough above.

```bash
git clone https://github.com/TALELMN/QSMU_SEB.git
cd QSMU_SEB
python -m pip install -r requirements.txt
python -m sebkit ui                 # http://127.0.0.1:8733
```

### Command line

```bash
# Create a configuration
python -m sebkit create \
    --name "Anatomy S1 2026" \
    --url "https://moodle.example.edu/mod/quiz/view.php?id=42" \
    --quit-url "https://moodle.example.edu/course/view.php?id=7"

# Audit an existing one
python -m sebkit audit old-exam.seb --password "settings-password" --report audit.html

# Print the Config Key of a file
python -m sebkit key exam.seb
python -m sebkit key exam.seb --json    # the exact string being hashed
```

`audit` exits non-zero when it finds a critical issue, so it can gate a deployment script.

### Profiles

| Profile | Use for |
|---|---|
| `byod_strict` | Student laptops, maximum enforcement. **Default.** |
| `byod_balanced` | Student laptops, first deployment. Relaxes the three settings most likely to cause exam-day support calls — and the report names them. |
| `lab_managed` | Institution-managed lab machines. |

---

## What this cannot do

Worth being blunt, because the gap is where exams are actually lost.

SEB controls the machine it runs on, and on BYOD that machine belongs to the candidate. Outside
its reach entirely, at any configuration:

- **A second device.** A phone, tablet or second laptop. By a wide margin the most common method,
  and completely invisible to SEB.
- **Another person** in the room, or reachable by phone from outside it.
- **Capture hardware.** An HDMI splitter or capture card feeds the screen to a helper without the
  exam machine ever seeing it.
- **Paper notes.**
- **A prepared machine.** A student with administrator rights can stage software before SEB
  launches. VM and remote-access detection raise the effort; they do not make the machine
  trustworthy.

The process blocklist is enumeration: it stops the tools students actually have installed, which
is most of them, but a renamed binary gets through.

What closes that gap is invigilation, phone collection, seating, tight time limits, randomised
question banks, and questions that reward reasoning over recall. The generated exam pack includes
a room checklist covering these.

---

## How the settings were verified

SEB silently ignores unknown setting keys, so a configuration built from documentation alone can
read as strict and enforce nothing. Every key written by this tool was confirmed to exist in the
installed client by extracting the string literals from `SEBConfigTool.exe` (SEB 3.10.2) — 57
keys checked, all present.

The stored password hash casing was settled the same way: the only hex format literal in the
config tool's .NET user-string heap is the lowercase `{0:x2}`, so SEB writes lowercase.
`verify_hash` still compares case-insensitively, so files produced by other tools do not
false-alarm.

### One verification worth doing yourself

The Config Key implementation follows the published SEB specification and the test suite covers
its ordering, type encoding and exclusion rules — but it has not been diffed byte-for-byte
against SEB Config Tool's own output. Before a first real exam:

1. Open a generated `.seb` in `SEBConfigTool.exe`, using the settings password from the exam pack.
2. Read the **Config Key** on the Exam tab.
3. Compare with `python -m sebkit key yourfile.seb`.

They should be identical. If not, `--json` prints the exact string being hashed, which is what you
need to find the discrepancy. The recommended Moodle flow has Moodle compute the key itself, so
this is not load-bearing — but confirm it once.

---

## Project layout

```
sebkit/
  sebfile.py     .seb read/write — gzip layers, prefix headers, encryption
  rncryptor.py   RNCryptor v3 (AES-256-CBC + HMAC) for encrypted configs
  configkey.py   Config Key computation and request-hash reproduction
  profiles.py    the hardened profiles — every key verified against 3.10.2
  processes.py   the prohibited-application catalogue
  urlfilter.py   allowlist construction and over-breadth detection
  passwords.py   per-exam password generation and SEB-compatible hashing
  audit.py       the audit rules
  moodle.py      Moodle integration steps and verification notes
  report.py      the printable exam pack and audit report
web/             the local interface (standard library only)
tests/           51 tests
```

```bash
python -m pytest -q
```

---

## Requirements

Python 3.11+ and [`cryptography`](https://pypi.org/project/cryptography/). The interface uses the
standard library only, so it runs without administrator rights.

---

## Notes

Generated configurations and exam packs are written to `out/`, which is gitignored — exam packs
contain passwords in plain text and should never be committed.

This project is not affiliated with or endorsed by ETH Zürich, the Safe Exam Browser project, or
Moodle. Safe Exam Browser is developed by ETH Zürich and released under the Mozilla Public
License. This is an independent tool that produces configuration files for it.
