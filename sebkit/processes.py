"""
The prohibited-process catalogue.

SEB can refuse to start, or terminate the session, when it sees a named process
running. The default list shipped with SEB is short and dated; on student-owned
laptops it is the difference between a locked-down exam and a shared screen.

Entries are grouped so a teacher can reason about what they are switching on,
and so the generated report can say plainly what is and is not covered.

An honest caveat that belongs next to this list, not buried in a footnote:
process blocklists are enumeration. They stop the tools students actually have
installed, which is most of them, but a renamed binary or an unlisted tool gets
through. This raises the effort required; it does not make the machine trusted.
"""

from __future__ import annotations

from dataclasses import dataclass, field

OS_WINDOWS = 1
OS_MACOS = 0


@dataclass(frozen=True)
class ProcessRule:
    executable: str
    description: str
    original_name: str = ""
    strong_kill: bool = True

    def to_seb(self, *, active: bool = True, os: int = OS_WINDOWS) -> dict:
        """Render as a SEB prohibitedProcesses entry."""
        return {
            "active": active,
            "currentUser": True,
            "description": self.description,
            "executable": self.executable,
            "originalName": self.original_name or self.executable,
            "identifier": "",
            "os": os,
            "strongKill": self.strong_kill,
            "title": "",
            "user": "",
        }


@dataclass(frozen=True)
class Category:
    key: str
    label: str
    rationale: str
    # A short noun phrase that reads naturally mid-sentence in a finding,
    # e.g. "No remote-access software is blocked". The full label is a heading
    # and does not survive being lowercased into prose.
    short_label: str
    processes: tuple[ProcessRule, ...] = field(default=())
    # Categories a BYOD exam should always switch on.
    essential: bool = True


def _p(executable: str, description: str, original_name: str = "") -> ProcessRule:
    return ProcessRule(executable=executable, description=description, original_name=original_name)


REMOTE_ACCESS = Category(
    key="remote_access",
    short_label="remote-access",
    label="Remote access and remote control",
    rationale=(
        "Lets someone outside the room see the screen and drive the machine. "
        "The highest-impact category on student-owned hardware."
    ),
    processes=(
        _p("TeamViewer.exe", "TeamViewer remote control"),
        _p("TeamViewer_Service.exe", "TeamViewer background service"),
        _p("AnyDesk.exe", "AnyDesk remote control"),
        _p("rustdesk.exe", "RustDesk remote control"),
        _p("remoting_host.exe", "Chrome Remote Desktop host"),
        _p("mstsc.exe", "Windows Remote Desktop client"),
        _p("RdpSa.exe", "Windows Remote Desktop shadowing"),
        _p("vncserver.exe", "VNC server"),
        _p("winvnc.exe", "UltraVNC / RealVNC server"),
        _p("tvnserver.exe", "TightVNC server"),
        _p("vncviewer.exe", "VNC viewer"),
        _p("Radmin.exe", "Radmin remote control"),
        _p("rserver3.exe", "Radmin server"),
        _p("AmmyyAdmin.exe", "Ammyy Admin remote control"),
        _p("Supremo.exe", "Supremo remote control"),
        _p("SplashtopStreamer.exe", "Splashtop streamer"),
        _p("QuickAssist.exe", "Windows Quick Assist"),
        _p("parsecd.exe", "Parsec remote desktop"),
        _p("nxplayer.exe", "NoMachine remote desktop"),
        _p("LogMeIn.exe", "LogMeIn remote access"),
        _p("g2mcomm.exe", "GoToMyPC / GoToAssist"),
        _p("ScreenConnect.ClientService.exe", "ConnectWise ScreenConnect"),
        _p("DWRCC.exe", "DameWare remote control"),
        _p("AeroAdmin.exe", "AeroAdmin remote control"),
        _p("dwagent.exe", "DWService remote access"),
        _p("Sunlogin.exe", "Sunlogin remote control"),
        _p("sunloginclient.exe", "Sunlogin client"),
        _p("ToDesk.exe", "ToDesk remote control"),
    ),
)

SCREEN_SHARING = Category(
    key="screen_sharing",
    short_label="screen-sharing",
    label="Conferencing and screen sharing",
    rationale="Any of these can share the exam screen with a helper in real time.",
    processes=(
        _p("Zoom.exe", "Zoom meetings"),
        _p("Teams.exe", "Microsoft Teams"),
        _p("ms-teams.exe", "Microsoft Teams (new client)"),
        _p("Discord.exe", "Discord"),
        _p("Skype.exe", "Skype"),
        _p("webexmta.exe", "Cisco Webex"),
        _p("CiscoCollabHost.exe", "Cisco Webex host"),
        _p("slack.exe", "Slack"),
        _p("GoToMeeting.exe", "GoToMeeting"),
        _p("Jitsi Meet.exe", "Jitsi Meet"),
        _p("BlueJeans.exe", "BlueJeans"),
        _p("WhereBy.exe", "Whereby"),
    ),
)

VIRTUALISATION = Category(
    key="virtualisation",
    short_label="virtual-machine",
    label="Virtual machines and sandboxes",
    rationale=(
        "Running the exam inside a guest leaves the host free for lookups. "
        "Pair this with the allowVirtualMachine setting, which blocks the "
        "reverse case of SEB itself running inside a VM."
    ),
    processes=(
        _p("vmware.exe", "VMware Workstation"),
        _p("vmware-vmx.exe", "VMware virtual machine process"),
        _p("vmtoolsd.exe", "VMware guest tools"),
        _p("vmwaretray.exe", "VMware tray"),
        _p("VirtualBox.exe", "Oracle VirtualBox"),
        _p("VBoxSVC.exe", "VirtualBox service"),
        _p("VBoxTray.exe", "VirtualBox guest additions"),
        _p("vmconnect.exe", "Hyper-V virtual machine connection"),
        _p("qemu-system-x86_64.exe", "QEMU emulator"),
        _p("prl_client_app.exe", "Parallels Desktop"),
        _p("SandboxieRpcSs.exe", "Sandboxie"),
        _p("Docker Desktop.exe", "Docker Desktop"),
    ),
)

SCREEN_CAPTURE = Category(
    key="screen_capture",
    short_label="screen-recording",
    label="Screen recording and capture",
    rationale=(
        "Records the paper for circulation afterwards, and several of these "
        "double as live streaming tools."
    ),
    processes=(
        _p("obs64.exe", "OBS Studio"),
        _p("obs32.exe", "OBS Studio (32-bit)"),
        _p("Streamlabs OBS.exe", "Streamlabs"),
        _p("XSplit.Core.exe", "XSplit Broadcaster"),
        _p("Bandicam.exe", "Bandicam recorder"),
        _p("CamtasiaStudio.exe", "Camtasia"),
        _p("SnagitEditor.exe", "Snagit editor"),
        _p("Snagit32.exe", "Snagit capture"),
        _p("ShareX.exe", "ShareX"),
        _p("Greenshot.exe", "Greenshot"),
        _p("Lightshot.exe", "Lightshot"),
        _p("Screenpresso.exe", "Screenpresso"),
        _p("FlashBackRecorder.exe", "FlashBack recorder"),
        _p("Fraps.exe", "Fraps"),
        _p("NVIDIA Share.exe", "NVIDIA ShadowPlay"),
        _p("GameBar.exe", "Xbox Game Bar"),
        _p("GameBarFTServer.exe", "Xbox Game Bar capture"),
    ),
)

PHONE_MIRRORING = Category(
    key="phone_mirroring",
    short_label="phone-mirroring",
    label="Phone mirroring and second-screen bridges",
    rationale=(
        "Puts a phone's screen on the exam machine, or the exam machine's "
        "screen on a phone. Easy to overlook and widely installed."
    ),
    processes=(
        _p("scrcpy.exe", "scrcpy Android mirroring"),
        _p("Vysor.exe", "Vysor device mirroring"),
        _p("AirDroid.exe", "AirDroid"),
        _p("PhoneExperienceHost.exe", "Windows Phone Link"),
        _p("YourPhone.exe", "Windows Your Phone"),
        _p("Unison.exe", "Intel Unison"),
        _p("DroidCamApp.exe", "DroidCam virtual camera"),
        _p("iriunwebcam.exe", "Iriun virtual camera"),
        _p("EpocCam.exe", "EpocCam virtual camera"),
        _p("SamsungDeX.exe", "Samsung DeX"),
    ),
)

MESSAGING = Category(
    key="messaging",
    short_label="messaging",
    label="Messaging clients",
    rationale="A desktop messenger is a channel to a helper, with photo sending built in.",
    processes=(
        _p("WhatsApp.exe", "WhatsApp Desktop"),
        _p("Telegram.exe", "Telegram Desktop"),
        _p("Signal.exe", "Signal Desktop"),
        _p("Messenger.exe", "Facebook Messenger"),
        _p("Viber.exe", "Viber"),
        _p("WeChat.exe", "WeChat"),
        _p("Element.exe", "Element / Matrix"),
    ),
)

AI_ASSISTANTS = Category(
    key="ai_assistants",
    short_label="AI-assistant",
    label="AI assistants (desktop clients and local models)",
    rationale=(
        "Desktop AI clients answer exam questions directly, and local model "
        "runners keep working with the network switched off."
    ),
    processes=(
        _p("ChatGPT.exe", "OpenAI ChatGPT desktop"),
        _p("Claude.exe", "Claude desktop"),
        _p("Perplexity.exe", "Perplexity desktop"),
        _p("Copilot.exe", "Microsoft Copilot"),
        _p("ollama.exe", "Ollama local model runner"),
        _p("ollama app.exe", "Ollama desktop"),
        _p("LM Studio.exe", "LM Studio local models"),
        _p("gpt4all.exe", "GPT4All local models"),
        _p("jan.exe", "Jan local models"),
    ),
)

OTHER_BROWSERS = Category(
    key="other_browsers",
    short_label="alternative-browser",
    label="Other web browsers",
    rationale=(
        "A second browser beside SEB is an unfiltered window onto the internet. "
        "SEB hides them, but only terminating them removes the option."
    ),
    processes=(
        _p("chrome.exe", "Google Chrome"),
        _p("firefox.exe", "Mozilla Firefox"),
        _p("msedge.exe", "Microsoft Edge"),
        _p("opera.exe", "Opera"),
        _p("brave.exe", "Brave"),
        _p("vivaldi.exe", "Vivaldi"),
        _p("tor.exe", "Tor"),
        # Tor Browser ships its own firefox.exe, already covered by the entry above.
    ),
)

NOTES_AND_AUTOMATION = Category(
    key="notes_automation",
    short_label="note-taking and automation",
    label="Note tools and input automation",
    rationale=(
        "Note apps hold prepared crib sheets; macro tools can replay answers "
        "or defeat simple monitoring."
    ),
    essential=False,
    processes=(
        _p("ONENOTE.EXE", "Microsoft OneNote"),
        _p("Notion.exe", "Notion"),
        _p("Evernote.exe", "Evernote"),
        _p("Obsidian.exe", "Obsidian"),
        _p("anki.exe", "Anki flashcards"),
        _p("AutoHotkey.exe", "AutoHotkey"),
        _p("AutoHotkey64.exe", "AutoHotkey v2"),
        _p("AutoIt3.exe", "AutoIt"),
        _p("Ditto.exe", "Ditto clipboard manager"),
        _p("CopyQ.exe", "CopyQ clipboard manager"),
    ),
)

CATEGORIES: tuple[Category, ...] = (
    REMOTE_ACCESS,
    SCREEN_SHARING,
    VIRTUALISATION,
    SCREEN_CAPTURE,
    PHONE_MIRRORING,
    MESSAGING,
    AI_ASSISTANTS,
    OTHER_BROWSERS,
    NOTES_AND_AUTOMATION,
)

CATEGORIES_BY_KEY = {c.key: c for c in CATEGORIES}
ESSENTIAL_KEYS = tuple(c.key for c in CATEGORIES if c.essential)


def build_prohibited_processes(category_keys: list[str] | tuple[str, ...] | None = None) -> list[dict]:
    """Build the prohibitedProcesses array for the given categories."""
    keys = tuple(category_keys) if category_keys is not None else ESSENTIAL_KEYS
    seen: set[str] = set()
    entries: list[dict] = []
    for key in keys:
        category = CATEGORIES_BY_KEY.get(key)
        if category is None:
            raise KeyError(f"unknown process category: {key}")
        for rule in category.processes:
            marker = rule.executable.lower()
            if marker in seen:
                continue
            seen.add(marker)
            entries.append(rule.to_seb())
    return entries


def known_executables() -> set[str]:
    """Every executable named anywhere in the catalogue, lowercased."""
    return {r.executable.lower() for c in CATEGORIES for r in c.processes}
