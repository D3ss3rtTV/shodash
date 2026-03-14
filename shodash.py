"""
shodan-access-script.py  —  geo-radius OSINT, Shodan Lifetime API
─────────────────────────────────────────────────────────────────
Requires : pip install shodan rich requests
Setup    : shodan init <your-api-key>

Webcam tip: port-554 RTSP searches are unreliable on Shodan because
RTSP rarely exposes useful banner data on the initial connection.
Brand HTTP fingerprints (GoAhead, Hikvision-Webs, AXIS…) work FAR
better — those are what the IP Cameras category uses.
"""

import shodan
import requests
import sys
import re
import csv
import json
import time
from datetime import datetime
from pathlib import Path

try:
    from fpdf import FPDF
    _PDF_AVAILABLE = True
except ImportError:
    _PDF_AVAILABLE = False
from shodan.cli.helpers import get_api_key
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.columns import Columns
from rich import box
from rich.text import Text
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn

# ── Catppuccin Mocha ──────────────────────────────────────────────────────────
C = {
    "base":      "#1e1e2e", "mantle":    "#181825", "crust":     "#11111b",
    "surface0":  "#313244", "surface1":  "#45475a", "surface2":  "#585b70",
    "overlay0":  "#6c7086", "overlay1":  "#7f849c", "overlay2":  "#9399b2",
    "subtext0":  "#a6adc8", "subtext1":  "#bac2de", "text":      "#cdd6f4",
    "lavender":  "#b4befe", "blue":      "#89b4fa", "sapphire":  "#74c7ec",
    "sky":       "#89dceb", "teal":      "#94e2d5", "green":     "#a6e3a1",
    "yellow":    "#f9e2af", "peach":     "#fab387", "maroon":    "#eba0ac",
    "red":       "#f38ba8", "mauve":     "#cba6f7", "pink":      "#f5c2e7",
    "flamingo":  "#f2cdcd", "rosewater": "#f5e0dc",
}

console = Console()


class CIPrompt(Prompt):
    """Case-insensitive Prompt — lowercases input before validation."""
    def process_response(self, value: str) -> str:
        return super().process_response(value.strip().lower())

# ─────────────────────────────────────────────────────────────────────────────
# FILTER LIBRARY  —  the single source of truth for every search query.
#
# Each category has:
#   desc    short description shown in the browser
#   tip     shown when browsing that category — what to expect / what works
#   color   accent colour for the category
#   queries dict[label → (query_template, accent_color)]
#           {geo} is replaced at runtime with the geo:lat,lon,km string.
#
# api.count() is FREE (zero query credits).  Only api.search() costs credits.
# ─────────────────────────────────────────────────────────────────────────────
FILTER_LIBRARY: dict[str, dict] = {
    "IP Cameras": {
        "desc":  "Network cams, DVRs, NVRs — brand HTTP fingerprints",
        "tip": (
            "Why not RTSP?\n"
            "Shodan probes port 554 but RTSP rarely sends useful banner data on the\n"
            "raw TCP connect, so results are sparse and hard to act on.\n\n"
            "What actually works:\n"
            "• GoAhead webserver  →  ~40% of cheap OEM IP cameras use it\n"
            "• Hikvision-Webs     →  most reliable for DVR/NVR systems\n"
            "• AXIS Live View     →  high-quality commercial installs\n"
            "• Cross Web Server   →  another common OEM embedded server\n"
            "• mjpg-streamer      →  Raspberry Pi cams and 3-D printers\n"
            "• webcamXP/webcam7   →  Windows streaming software, still around\n\n"
            "Start with Hikvision + GoAhead — they give the most hits."
        ),
        "color": C["sky"],
        "queries": {
            "Hikvision DVR/NVR":      ("{geo} \"Hikvision-Webs\"",                  C["sky"]),
            "Axis Network Camera":    ("{geo} \"AXIS\" \"Live View\"",              C["sapphire"]),
            "Dahua Camera":           ("{geo} \"Dahua\"",                            C["sky"]),
            "GoAhead (OEM cams)":     ("{geo} \"GoAhead\" \"cameras\"",             C["teal"]),
            "Cross Web Server (OEM)": ("{geo} \"Cross Web Server\"",                C["sky"]),
            "Generic Network Camera": ("{geo} \"Network Camera\" \"Live View\"",    C["sky"]),
            "Foscam":                 ("{geo} \"Foscam\"",                           C["sky"]),
            "Vivotek":                ("{geo} \"Vivotek\"",                          C["sky"]),
            "D-Link IP Camera":       ("{geo} \"DCS-\"",                             C["sky"]),
            "GeoVision":              ("{geo} \"GeoVision\"",                        C["sky"]),
            "Amcrest / Swann":        ("{geo} \"Amcrest\" OR \"Swann\"",            C["sky"]),
            "ACTi":                   ("{geo} \"ACTi\"",                             C["sky"]),
            "Bosch IP Camera":        ("{geo} \"Bosch\"",                            C["sky"]),
            "Panasonic Network Cam":  ("{geo} \"Panasonic\" \"Network Camera\"",    C["sky"]),
            "Sony Network Camera":    ("{geo} \"Sony Network Camera\"",             C["sky"]),
            "webcamXP / webcam 7":    ("{geo} \"webcamXP\" OR \"webcam 7\"",        C["sky"]),
            "Android IP Webcam App":  ("{geo} \"IP Webcam Server\"",                C["sky"]),
            "mjpg-streamer (Pi/3D)":  ("{geo} \"mjpg-streamer\"",                   C["sky"]),
            "Blue Iris NVR":          ("{geo} \"Blue Iris\"",                        C["sky"]),
            "ZoneMinder":             ("{geo} \"ZoneMinder\"",                       C["sky"]),
            "iSpy / Agent DVR":       ("{geo} \"iSpy\"",                             C["sky"]),
            "Avtech":                 ("{geo} \"linux/2.x UPnP/1.0 Avtech/1.0\"",  C["sky"]),
            "RTSP (port 554)":        ("{geo} port:554 \"RTSP\"",                   C["sapphire"]),
        },
    },
    "Remote Access": {
        "desc":  "RDP, VNC, SSH, Telnet, VPN — exposed remote management",
        "tip": (
            "RDP (3389) is everywhere — residential, SMB, cloud VMs.\n"
            "VNC (5900) frequently has no password on home networks.\n"
            "Telnet (23) is plaintext and still surprisingly common on\n"
            "  embedded devices, older routers, and IoT gear.\n"
            "SSH (22) is noisy but useful for fingerprinting server orgs."
        ),
        "color": C["mauve"],
        "queries": {
            "RDP (3389)":        ("{geo} port:3389",                      C["mauve"]),
            "VNC (5900)":        ("{geo} port:5900 \"VNC\"",              C["mauve"]),
            "Telnet (23)":       ("{geo} port:23",                        C["maroon"]),
            "SSH (22)":          ("{geo} port:22",                        C["mauve"]),
            "FTP Anonymous":     ("{geo} \"220\" \"Anonymous\" port:21",  C["flamingo"]),
            "TeamViewer":        ("{geo} \"TeamViewer\"",                  C["mauve"]),
            "AnyDesk":           ("{geo} \"AnyDesk\"",                    C["mauve"]),
            "OpenVPN (1194)":    ("{geo} port:1194",                      C["lavender"]),
            "WireGuard (51820)": ("{geo} port:51820",                     C["lavender"]),
        },
    },
    "Industrial / ICS": {
        "desc":  "SCADA, PLCs, building automation — handle with care",
        "tip": (
            "BACnet (47808) is in almost every modern commercial building\n"
            "  — HVAC, lighting, access control all speak it.\n"
            "Modbus (502) is decades old and has zero authentication.\n"
            "EtherNet/IP (44818) is common in manufacturing.\n"
            "Siemens SIMATIC and Schneider show up in utilities & factories.\n\n"
            "These are real operational systems. Observe only."
        ),
        "color": C["red"],
        "queries": {
            "ICS / SCADA Generic":  ("{geo} \"Industrial Control System\"",  C["red"]),
            "BACnet (47808)":       ("{geo} port:47808",                     C["red"]),
            "Modbus (502)":         ("{geo} port:502",                       C["red"]),
            "DNP3 (20000)":         ("{geo} port:20000",                     C["red"]),
            "EtherNet/IP (44818)":  ("{geo} port:44818",                     C["red"]),
            "Schneider Electric":   ("{geo} \"Schneider\"",                  C["red"]),
            "Siemens SIMATIC":      ("{geo} \"SIMATIC\"",                    C["red"]),
            "UPS / Power Mgmt":     ("{geo} \"Network Management Card\"",    C["peach"]),
            "Solar Inverters":      ("{geo} \"SolarEdge\" OR \"Enphase\"",   C["yellow"]),
            "Building Dashboards":  ("{geo} \"Dashboard\" \"Login\"",        C["peach"]),
        },
    },
    "Smart Home & IoT": {
        "desc":  "Consumer smart devices — often default or no credentials",
        "tip": (
            "Home Assistant is surging — thousands of installs expose the UI.\n"
            "Shelly devices (smart relays/plugs) flood local networks.\n"
            "ESPHome powers tons of DIY sensors and automations.\n"
            "MQTT brokers (1883) are frequently wide open with no auth.\n"
            "UniFi controllers often have default 'ubnt/ubnt' credentials."
        ),
        "color": C["green"],
        "queries": {
            "Home Assistant":   ("{geo} \"Home Assistant\"",   C["green"]),
            "Sonos Speakers":   ("{geo} \"Sonos\"",            C["teal"]),
            "Philips Hue":      ("{geo} \"Philips hue\"",      C["yellow"]),
            "UniFi Controller": ("{geo} \"UniFi\"",            C["blue"]),
            "OpenWrt Router":   ("{geo} \"OpenWrt\"",          C["teal"]),
            "MQTT Broker":      ("{geo} port:1883 \"MQTT\"",   C["teal"]),
            "Shelly Devices":   ("{geo} \"Shelly\"",           C["green"]),
            "TP-Link Kasa":     ("{geo} \"TP-LINK\"",          C["yellow"]),
            "Wemo (Belkin)":    ("{geo} \"Wemo\"",             C["peach"]),
            "ESPHome":          ("{geo} \"ESPHome\"",          C["green"]),
        },
    },
    "Network Gear": {
        "desc":  "Routers, switches, APs — backbone of local networks",
        "tip": (
            "MikroTik is the #1 find — very common globally, often has\n"
            "  default 'admin' / no password on older firmware.\n"
            "Ubiquiti is everywhere in apartments and small businesses.\n"
            "pfSense/DD-WRT installations are usually intentional but\n"
            "  sometimes expose management interfaces publicly by mistake.\n"
            "Network printers (JetDirect) often have no auth at all."
        ),
        "color": C["sapphire"],
        "queries": {
            "MikroTik":         ("{geo} \"MikroTik\"",                  C["sapphire"]),
            "Ubiquiti":         ("{geo} \"Ubiquiti\"",                   C["sapphire"]),
            "Cisco IOS":        ("{geo} \"Cisco IOS\"",                  C["sapphire"]),
            "pfSense":          ("{geo} \"pfSense\"",                    C["sapphire"]),
            "DD-WRT":           ("{geo} \"DD-WRT\"",                     C["teal"]),
            "OpenWrt":          ("{geo} \"OpenWrt\"",                    C["teal"]),
            "Zyxel":            ("{geo} \"ZyXEL\"",                      C["sapphire"]),
            "Netgear":          ("{geo} \"NETGEAR\"",                    C["sapphire"]),
            "Fortinet":         ("{geo} \"Fortinet\"",                   C["sapphire"]),
            "Network Printers": ("{geo} \"JetDirect\" OR \"HP HTTP\"",  C["lavender"]),
        },
    },
    "Exposed Services": {
        "desc":  "Databases, dev tools, admin panels left open",
        "tip": (
            "MongoDB and Redis are the most common open databases — many\n"
            "  cloud instances spun up without auth.\n"
            "Grafana dashboards frequently have guest access enabled.\n"
            "Jupyter Notebooks are often completely open with code execution.\n"
            "Jenkins CI can expose full build pipelines and secrets.\n"
            "Portainer gives Docker management — finding it open is serious."
        ),
        "color": C["peach"],
        "queries": {
            "MongoDB":          ("{geo} product:\"MongoDB\"",        C["peach"]),
            "Elasticsearch":    ("{geo} product:\"Elasticsearch\"",  C["peach"]),
            "Redis":            ("{geo} product:\"Redis\"",          C["peach"]),
            "CouchDB":          ("{geo} \"CouchDB\"",                C["peach"]),
            "Grafana":          ("{geo} \"Grafana\"",                C["blue"]),
            "Kibana":           ("{geo} \"Kibana\"",                 C["blue"]),
            "Jenkins CI":       ("{geo} \"Jenkins\" \"Dashboard\"",  C["yellow"]),
            "Jupyter Notebook": ("{geo} \"Jupyter Notebook\"",       C["yellow"]),
            "Portainer":        ("{geo} \"Portainer\"",              C["blue"]),
            "phpMyAdmin":       ("{geo} \"phpMyAdmin\"",             C["blue"]),
            "Hadoop":           ("{geo} \"Hadoop\"",                 C["peach"]),
        },
    },
    "Communications": {
        "desc":  "VoIP, PBX, messaging infrastructure",
        "tip": (
            "SIP port 5060 is wide open on almost every business network.\n"
            "Asterisk is the most-deployed open-source PBX — very common.\n"
            "FreePBX is a popular web GUI on top of Asterisk.\n"
            "Open MQTT brokers let anyone publish/subscribe to IoT topics."
        ),
        "color": C["lavender"],
        "queries": {
            "VoIP / SIP (5060)": ("{geo} port:5060",         C["lavender"]),
            "Asterisk PBX":      ("{geo} \"Asterisk\"",       C["lavender"]),
            "FreePBX":           ("{geo} \"FreePBX\"",        C["lavender"]),
            "MQTT Broker":       ("{geo} port:1883 \"MQTT\"", C["teal"]),
        },
    },
    "Media & Fun": {
        "desc":  "Media servers, game servers — the fun stuff",
        "tip": (
            "Plex is the most commonly found open media server — people\n"
            "  accidentally expose it while port-forwarding for remote access.\n"
            "Jellyfin / Emby are the open-source alternatives, also common.\n"
            "Minecraft servers are usually intentional but fun to find locally.\n"
            "Steam game servers (27015) are plentiful near population centres."
        ),
        "color": C["pink"],
        "queries": {
            "Plex Media Server": ("{geo} \"Plex Media Server\"",            C["pink"]),
            "Emby / Jellyfin":   ("{geo} \"Emby Server\" OR \"Jellyfin\"",  C["pink"]),
            "Kodi":              ("{geo} \"Kodi\"",                          C["pink"]),
            "Minecraft":         ("{geo} port:25565 \"Minecraft\"",         C["green"]),
            "Steam Game Server": ("{geo} port:27015",                       C["green"]),
        },
    },
    "Misc / Curiosities": {
        "desc":  "Crypto nodes, privacy tools, and other weird finds",
        "tip": (
            "Pi-hole is surprisingly common to stumble on — people expose\n"
            "  the web UI without realising it's public.\n"
            "Bitcoin nodes (8333) are harmless to discover — they want peers.\n"
            "Tor exit nodes are public by design and listed in the directory.\n"
            "WireGuard/OpenVPN endpoints are often exposed intentionally."
        ),
        "color": C["rosewater"],
        "queries": {
            "Bitcoin Node":  ("{geo} port:8333",     C["yellow"]),
            "Pi-hole DNS":   ("{geo} \"Pi-hole\"",   C["rosewater"]),
            "Tor Exit Node": ("{geo} \"Tor exit\"",  C["overlay2"]),
            "WireGuard":     ("{geo} port:51820",    C["overlay2"]),
            "OpenVPN":       ("{geo} port:1194",     C["overlay2"]),
        },
    },
}

# Flat query dict built from library (for fetch/count/export helpers)
QUERIES: dict[str, tuple[str, str]] = {}
for _cat in FILTER_LIBRARY.values():
    QUERIES.update(_cat["queries"])  # type: ignore[arg-type]


# ── Session state  ────────────────────────────────────────────────────────────

_CONFIG_PATH = Path.home() / ".shodash" / "config.json"


def _save_config(session: "Session") -> None:
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "lat":       session.lat,
        "lon":       session.lon,
        "display":   session.display,
        "radius_mi": session.radius_mi,
        "radius_km": session.radius_km,
    }
    _CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load_config() -> dict | None:
    try:
        if _CONFIG_PATH.exists():
            return json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


class Session:
    """Holds location, query cart, and cached account info across the whole run."""
    def __init__(self) -> None:
        self.geo:          str | None = None
        self.lat:          str | None = None
        self.lon:          str | None = None
        self.display:      str | None = None
        self.radius_mi:    float | None = None
        self.radius_km:    int   | None = None
        self.cart:         dict[str, tuple[str, str]] = {}
        self.last_counts:  dict[str, int] = {}
        self.last_results: dict[str, list[dict]] = {}
        self.account_info: dict = {}
        self.api_key:      str  = ""

    @property
    def has_location(self) -> bool:
        return self.geo is not None

    def set_location(self, lat: str, lon: str, display: str,
                     radius_mi: float, radius_km: int) -> None:
        self.lat, self.lon, self.display = lat, lon, display
        self.radius_mi, self.radius_km   = radius_mi, radius_km
        self.geo = f"geo:{lat},{lon},{radius_km}"
        self.last_counts.clear()
        self.last_results.clear()
        _save_config(self)

    def location_line(self) -> str:
        if not self.has_location:
            return "no location set"
        return f"{self.display}  •  {self.radius_mi} mi / {self.radius_km} km"

    def cart_count(self) -> int:
        return len(self.cart)

    def clear_cart(self) -> None:
        self.cart.clear()

    def add_to_cart(self, label: str, entry: tuple[str, str]) -> None:
        self.cart[label] = entry

    def remove_from_cart(self, label: str) -> None:
        self.cart.pop(label, None)

    def total_estimated_results(self) -> int:
        """Sum of cached counts for items currently in cart. Returns 0 if no counts."""
        return sum(self.last_counts.get(k, 0) for k in self.cart if self.last_counts.get(k, 0) > 0)

    def credit_line(self) -> str:
        """Compact one-liner for the menu title."""
        info = self.account_info
        if not info:
            return f"[{C['overlay0']}]credits: ?[/]"
        plan = info.get("plan", "?")
        qc   = info.get("query_credits", "?")
        sc   = info.get("scan_credits", "?")
        qlim = info.get("usage_limits", {}).get("query_credits", 0)
        if isinstance(qc, int) and qlim > 0:
            ratio  = qc / qlim
            qcolor = C["green"] if ratio > 0.5 else C["yellow"] if ratio > 0.2 else C["red"]
        else:
            qcolor = C["text"]
        return (
            f"[{C['overlay1']}]plan[/] [{C['mauve']}]{plan}[/]  "
            f"[{C['overlay1']}]qc[/] [bold {qcolor}]{qc}[/]  "
            f"[{C['overlay1']}]sc[/] [{C['text']}]{sc}[/]"
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def miles_to_km(miles: float) -> int:
    return round(miles * 1.60934)


def parse_radius_input(raw: str) -> tuple[float, int]:
    """Accept '30', '30mi', '30 miles', '48km'. Returns (miles, km)."""
    raw = raw.strip().lower().replace(" ", "")
    m = re.match(r"^([0-9]+(?:\.[0-9]+)?)", raw)
    if not m:
        return 30.0, miles_to_km(30)
    num = float(m.group(1))
    if "km" in raw or raw.endswith("k"):
        return round(num / 1.60934, 1), int(num)
    return num, miles_to_km(num)


def banner() -> None:
    art = Text()
    art.append("  ███████╗██╗  ██╗ ██████╗ ██████╗  █████╗ ███████╗██╗  ██╗\n", style=f"bold {C['blue']}")
    art.append("  ██╔════╝██║  ██║██╔═══██╗██╔══██╗██╔══██╗██╔════╝██║  ██║\n", style=f"bold {C['sapphire']}")
    art.append("  ███████╗███████║██║   ██║██║  ██║███████║███████╗███████║\n",  style=f"bold {C['sky']}")
    art.append("  ╚════██║██╔══██║██║   ██║██║  ██║██╔══██║╚════██║██╔══██║\n", style=f"bold {C['teal']}")
    art.append("  ███████║██║  ██║╚██████╔╝██████╔╝██║  ██║███████║██║  ██║\n", style=f"bold {C['green']}")
    art.append("  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝\n", style=f"bold {C['yellow']}")
    art.append("         geo-radius OSINT  •  shodash  •  shodan lifetime tier\n", style=f"dim {C['overlay2']}")
    console.print(Panel(art, border_style=C["surface1"], padding=(0, 2)))


def fetch_account_info(api: shodan.Shodan) -> dict:
    """Fetch account info from Shodan. Returns empty dict on failure."""
    try:
        return api.info()
    except shodan.APIError:
        return {}


def _credit_bar(remaining: int, total: int, width: int = 22) -> tuple[str, str]:
    """Returns (bar_string, mocha_color)."""
    if total <= 0:
        return "░" * width, C["overlay0"]
    ratio  = max(0.0, min(1.0, remaining / total))
    filled = round(ratio * width)
    bar    = "█" * filled + "░" * (width - filled)
    color  = C["green"] if ratio > 0.5 else C["yellow"] if ratio > 0.2 else C["red"]
    return bar, color


PLAN_LABELS = {
    "oss":        "Open Source",
    "edu":        "Educational",
    "dev":        "Developer",
    "member":     "Member",
    "membership": "Membership",
    "freelancer": "Freelancer",
    "corporate":  "Corporate",
    "enterprise": "Enterprise",
    "free":       "Free",
    "small":      "Small Business",
}


def show_status(info: dict, key: str = "") -> None:
    """Rich account status panel — the real deal, not just credit numbers."""
    if not info:
        console.print(Panel(
            f"[{C['red']}]Could not retrieve account information.[/]",
            title=f"[{C['red']}]Account Status[/]", border_style=C["red"], expand=False,
        ))
        return

    plan_raw    = info.get("plan", "?")
    plan_label  = PLAN_LABELS.get(plan_raw, plan_raw.title())
    limits      = info.get("usage_limits", {})
    qc_rem      = info.get("query_credits", 0)
    qc_total    = limits.get("query_credits") or qc_rem or 0
    sc_rem      = info.get("scan_credits", 0)
    sc_total    = limits.get("scan_credits") or sc_rem or 0
    mon_ips     = info.get("monitored_ips")
    has_https   = info.get("https", False)
    unlocked    = info.get("unlocked", False)
    unlocked_l  = info.get("unlocked_left", 0)

    qbar, qcolor = _credit_bar(qc_rem, qc_total)
    sbar, scolor = _credit_bar(sc_rem, sc_total)

    qc_pct  = f"  {round(qc_rem / qc_total * 100)}% left" if qc_total > 0 else ""
    sc_pct  = f"  {round(sc_rem / sc_total * 100)}% left" if sc_total > 0 else ""

    tbl = Table(box=box.SIMPLE, show_header=False, pad_edge=False, padding=(0, 1))
    tbl.add_column(style=C["overlay1"], no_wrap=True, width=17)
    tbl.add_column()

    # Plan
    tbl.add_row(
        "plan",
        Text.from_markup(
            f"[bold {C['mauve']}]{plan_label}[/]  [{C['overlay0']}]({plan_raw})[/]"
        ),
    )
    tbl.add_row("", "")

    # Query credits with bar
    tbl.add_row(
        "query credits",
        Text.from_markup(
            f"[bold {qcolor}]{qc_rem:,}[/] [{C['overlay1']}]/ {qc_total:,}[/]  "
            f"[{qcolor}]{qbar}[/][{C['overlay1']}]{qc_pct}[/]"
        ),
    )

    # Scan credits with bar (skip bar if total is 0)
    sc_body = f"[bold {scolor}]{sc_rem:,}[/] [{C['overlay1']}]/ {sc_total:,}[/]"
    if sc_total > 0:
        sc_body += f"  [{scolor}]{sbar}[/][{C['overlay1']}]{sc_pct}[/]"
    tbl.add_row("scan credits", Text.from_markup(sc_body))

    tbl.add_row("", "")

    # Flags row
    yes = f"[bold {C['green']}]yes[/]"
    no  = f"[{C['overlay0']}]no[/]"
    tbl.add_row(
        "https / TLS",
        Text.from_markup(
            f"{yes if has_https else no}    "
            f"[{C['overlay1']}]unlocked[/] {yes if unlocked else no}    "
            f"[{C['overlay1']}]unlocked left[/] [{C['text']}]{unlocked_l}[/]"
        ),
    )

    # Monitored IPs
    mon_str = f"{mon_ips:,}" if isinstance(mon_ips, int) else "—"
    tbl.add_row("monitored IPs", Text(mon_str, style=C["text"]))

    # Masked API key
    if key:
        if len(key) > 8:
            masked = f"{key[:4]}{'·' * 16}{key[-4:]}"
        else:
            masked = "·" * len(key)
        tbl.add_row("api key", Text(masked, style=C["overlay0"]))

    console.print(Panel(
        tbl,
        title=f"[bold {C['mauve']}]Account Status[/]",
        border_style=C["surface1"],
    ))


def get_coords(city: str, state: str) -> tuple[str | None, str | None, str | None]:
    url = (
        "https://nominatim.openstreetmap.org/search"
        f"?city={requests.utils.quote(city)}"
        f"&state={requests.utils.quote(state)}&format=json"
    )
    try:
        r = requests.get(url, headers={"User-Agent": "ShodanGeoOSINT/4.0"}, timeout=8)
        data = r.json()
        if data:
            return data[0]["lat"], data[0]["lon"], data[0].get("display_name", f"{city}, {state}")
    except Exception:
        pass
    return None, None, None


def ask_location(session: Session) -> bool:
    """Prompt for city/state/radius. Updates session in place. Returns True on success."""
    city  = Prompt.ask(f"[{C['blue']}]City[/]").strip()
    state = Prompt.ask(f"[{C['blue']}]State[/] [{C['overlay1']}]name or 2-letter code[/]").strip()

    with Progress(SpinnerColumn(style=C["sapphire"]),
                  TextColumn(f"[{C['subtext0']}]resolving coordinates…"),
                  console=console, transient=True) as prog:
        prog.add_task("", total=None)
        lat, lon, display = get_coords(city, state)

    if not lat:
        console.print(f"[{C['red']}]Location not found.[/]")
        return False

    radius_raw = Prompt.ask(
        f"[{C['blue']}]Radius[/] [{C['overlay1']}]e.g. 30, 30mi, 50km[/]",
        default="30",
    )
    mi, km = parse_radius_input(radius_raw)
    session.set_location(lat, lon, display, mi, km)  # type: ignore[arg-type]

    console.print(Panel(
        f"[{C['text']}]{display}[/]\n"
        f"[{C['overlay1']}]coords  [/][{C['teal']}]{lat}, {lon}[/]\n"
        f"[{C['overlay1']}]radius  [/][{C['teal']}]{mi} mi  /  {km} km[/]",
        title=f"[{C['green']}]Target Area[/]", border_style=C["surface1"],
    ))
    return True


# ── Count preview (free) ──────────────────────────────────────────────────────

def count_queries(api: shodan.Shodan, geo: str,
                  query_map: dict[str, tuple[str, str]],
                  session: Session | None = None) -> dict[str, int]:
    counts: dict[str, int] = {}
    with Progress(SpinnerColumn(style=C["blue"]),
                  TextColumn(f"[{C['subtext0']}]counting — no credits used…"),
                  console=console, transient=True) as prog:
        prog.add_task("", total=None)
        for label, (tmpl, _) in query_map.items():
            # Use cached value if available and session is provided
            if session and label in session.last_counts:
                counts[label] = session.last_counts[label]
                continue

            try:
                val = api.count(tmpl.format(geo=geo))["total"]
                counts[label] = val
                if session:
                    session.last_counts[label] = val
            except shodan.APIError:
                counts[label] = -1
    return counts


# ── Fetch & display results ───────────────────────────────────────────────────

def fetch_results(api: shodan.Shodan, geo: str,
                  selected: list[str], limit: int) -> dict[str, list[dict]]:
    all_results: dict[str, list[dict]] = {}
    for label in selected:
        tmpl, color = QUERIES[label]
        console.print(Rule(f"[bold {color}]{label}[/]", style=C["surface1"]))
        try:
            with Progress(SpinnerColumn(style=color),
                          TextColumn(f"[{C['subtext0']}]querying…"),
                          console=console, transient=True) as prog:
                prog.add_task("", total=None)
                res = api.search(tmpl.format(geo=geo), limit=limit)

            matches = res["matches"]
            all_results[label] = matches

            if not matches:
                console.print(f"  [{C['overlay0']}]no results[/]\n")
                continue

            tbl = Table(box=box.SIMPLE_HEAD, border_style=C["surface0"],
                        header_style=f"bold {C['subtext1']}", show_edge=True)
            tbl.add_column("IP : Port",  style=f"bold {color}", no_wrap=True)
            tbl.add_column("Org",        style=C["text"],        max_width=28)
            tbl.add_column("Product",    style=C["yellow"],      max_width=20)
            tbl.add_column("Version",    style=C["subtext0"],    max_width=14)
            tbl.add_column("City",       style=C["teal"],        max_width=16)
            tbl.add_column("Hostnames",  style=C["sapphire"],    max_width=30)

            for r in matches:
                tbl.add_row(
                    f"{r['ip_str']}:{r['port']}",
                    r.get("org") or "—",
                    r.get("product") or "—",
                    r.get("version") or "—",
                    r.get("location", {}).get("city") or "—",
                    ", ".join(r.get("hostnames", [])[:2]) or "—",
                )
            console.print(tbl)
            console.print(f"  [{C['overlay1']}]showing {len(matches)} of {res['total']:,} total[/]\n")

        except shodan.APIError as e:
            console.print(f"  [{C['red']}]API error:[/] {e}\n")
            all_results[label] = []
    return all_results


# ── NVD CVE enrichment ────────────────────────────────────────────────────────

_NVD_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_SEVERITY_COLORS = {
    "CRITICAL": C["red"],
    "HIGH":     C["peach"],
    "MEDIUM":   C["yellow"],
    "LOW":      C["green"],
    "NONE":     C["overlay1"],
}

def fetch_cve_details(cve_id: str) -> dict:
    """Return {score, severity, description} from NVD, or {} on failure."""
    try:
        r = requests.get(_NVD_URL, params={"cveId": cve_id}, timeout=8)
        r.raise_for_status()
        vuln_list = r.json().get("vulnerabilities", [])
        if not vuln_list:
            return {}
        cve = vuln_list[0]["cve"]
        metrics = cve.get("metrics", {})
        score, severity = None, None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                m        = metrics[key][0]
                cvss     = m.get("cvssData", {})
                score    = cvss.get("baseScore")
                severity = (m.get("baseSeverity") or cvss.get("baseSeverity") or "").upper()
                break
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            ""
        )
        return {"score": score, "severity": severity, "description": desc}
    except Exception:
        return {}


# ── Export ────────────────────────────────────────────────────────────────────

_EXPORT_FIELDS = ["ip", "port", "category", "org", "product", "version", "city", "hostnames"]

def _export_rows(results: dict[str, list[dict]]) -> list[dict]:
    rows = []
    for label, matches in results.items():
        for r in matches:
            rows.append({
                "ip":        r.get("ip_str", ""),
                "port":      r.get("port", ""),
                "category":  label,
                "org":       r.get("org", ""),
                "product":   r.get("product", ""),
                "version":   r.get("version", ""),
                "city":      (r.get("location") or {}).get("city", ""),
                "hostnames": ", ".join(r.get("hostnames", [])[:3]),
            })
    return rows


def _save_csv(session: Session, results: dict[str, list[dict]]) -> Path:
    fname = datetime.now().strftime("shodan_%Y%m%d_%H%M%S.csv")
    path  = Path(fname)
    rows  = _export_rows(results)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_EXPORT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return path


def _save_json(session: Session, results: dict[str, list[dict]]) -> Path:
    fname = datetime.now().strftime("shodan_%Y%m%d_%H%M%S.json")
    path  = Path(fname)
    payload = {
        "generated":  datetime.now().isoformat(),
        "location":   session.display,
        "radius_mi":  session.radius_mi,
        "radius_km":  session.radius_km,
        "lat":        session.lat,
        "lon":        session.lon,
        "results":    {label: matches for label, matches in results.items()},
    }
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


def _save_txt(session: Session, counts: dict[str, int],
              results: dict[str, list[dict]]) -> Path:
    fname = datetime.now().strftime("shodan_%Y%m%d_%H%M%S.txt")
    path  = Path(fname)
    ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "SHODAN OSINT REPORT",
        "=" * 60,
        f"Generated : {ts}",
        f"Location  : {session.display}",
        f"Radius    : {session.radius_mi} mi / {session.radius_km} km",
        f"Coords    : {session.lat}, {session.lon}",
        "",
        "SUMMARY",
        "-" * 40,
    ]
    for label, matches in results.items():
        lines.append(f"  {label:<30} total={counts.get(label,0):>6,}  fetched={len(matches):>4}")
    lines += ["", "RESULTS", "-" * 40]
    for label, matches in results.items():
        if not matches:
            continue
        lines += [f"\n[{label}]"]
        col = f"{'IP:Port':<22} {'Org':<28} {'Product':<20} {'Version':<14} {'City':<16} Hostnames"
        lines += [col, "-" * len(col)]
        for r in matches:
            lines.append(
                f"{r['ip_str']+':'+str(r['port']):<22} "
                f"{(r.get('org') or ''):<28} "
                f"{(r.get('product') or ''):<20} "
                f"{(r.get('version') or ''):<14} "
                f"{((r.get('location') or {}).get('city') or ''):<16} "
                f"{', '.join(r.get('hostnames',[])[:2])}"
            )
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _ascii(s: str, maxlen: int = 0) -> str:
    """Strip non-latin-1 chars so fpdf2 doesn't choke, optionally truncate."""
    out = s.encode("latin-1", errors="replace").decode("latin-1")
    return out[:maxlen] if maxlen else out


def _save_pdf(session: Session, counts: dict[str, int],
              results: dict[str, list[dict]]) -> Path | None:
    if not _PDF_AVAILABLE:
        return None
    fname = datetime.now().strftime("shodan_%Y%m%d_%H%M%S.pdf")
    path  = Path(fname)
    ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.add_page()

    # ── Title ──
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Shodan OSINT Report")
    pdf.ln(12)

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, _ascii(f"Generated: {ts}    Location: {session.display}"))
    pdf.ln(7)
    pdf.cell(0, 6, _ascii(
        f"Radius: {session.radius_mi} mi / {session.radius_km} km    "
        f"Coords: {session.lat}, {session.lon}"
    ))
    pdf.ln(10)

    # ── Summary ──
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Summary")
    pdf.ln(9)
    pdf.set_font("Helvetica", "", 9)
    for label, matches in results.items():
        pdf.cell(0, 5, _ascii(
            f"  {label}  -  total: {counts.get(label, 0):,}  /  fetched: {len(matches)}"
        ))
        pdf.ln(6)
    pdf.ln(4)

    # ── Results tables ──
    col_w   = [40, 44, 30, 20, 26, 30]
    headers = ["IP:Port", "Org", "Product", "Version", "City", "Hostnames"]

    for label, matches in results.items():
        if not matches:
            continue

        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, _ascii(label))
        pdf.ln(9)

        # header row
        pdf.set_font("Helvetica", "B", 8)
        for w, h in zip(col_w, headers):
            pdf.cell(w, 6, h, border=1)
        pdf.ln()

        # data rows
        pdf.set_font("Helvetica", "", 8)
        for r in matches:
            vals = [
                _ascii(f"{r['ip_str']}:{r['port']}", 24),
                _ascii(r.get("org") or "", 32),
                _ascii(r.get("product") or "", 22),
                _ascii(r.get("version") or "", 14),
                _ascii((r.get("location") or {}).get("city") or "", 20),
                _ascii(", ".join(r.get("hostnames", [])[:2]), 28),
            ]
            for w, v in zip(col_w, vals):
                pdf.cell(w, 5, v, border=1)
            pdf.ln()
        pdf.ln(4)

    pdf.output(str(path))
    return path


def export_menu(session: Session, counts: dict[str, int],
                results: dict[str, list[dict]]) -> None:
    """Interactive export format picker."""
    menu = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    menu.add_column(style=C["blue"], width=4)
    menu.add_column(style=C["text"])
    menu.add_row("1", "Markdown  (.md)   — great for GitHub / Obsidian")
    menu.add_row("2", "CSV       (.csv)  — Excel, Google Sheets, pandas")
    menu.add_row("3", "JSON      (.json) — raw data, APIs, scripting")
    menu.add_row("4", "Plain TXT (.txt)  — universal, grep-friendly")
    if _PDF_AVAILABLE:
        menu.add_row("5", "PDF       (.pdf)  — reports, sharing")
    else:
        menu.add_row("5", f"[{C['overlay0']}]PDF       (.pdf)  — install fpdf2 to enable[/]")
    menu.add_row("b", "Back")
    console.print(Panel(menu, title=f"[{C['mauve']}]Export Format[/]",
                        border_style=C["surface1"], expand=False))

    choices = ["1", "2", "3", "4", "5", "b"]
    sel = CIPrompt.ask(f"[{C['blue']}]Format[/]", choices=choices, default="b")
    if sel == "b":
        return

    path: Path | None = None
    if sel == "1":
        save_markdown(session, counts, results)
        return
    elif sel == "2":
        path = _save_csv(session, results)
    elif sel == "3":
        path = _save_json(session, results)
    elif sel == "4":
        path = _save_txt(session, counts, results)
    elif sel == "5":
        if not _PDF_AVAILABLE:
            console.print(f"[{C['yellow']}]fpdf2 not installed. Run: pip install fpdf2[/]")
            return
        path = _save_pdf(session, counts, results)

    if path:
        console.print(Panel(f"[{C['green']}]{path.resolve()}[/]",
                            title=f"[{C['teal']}]Saved[/]",
                            border_style=C["surface1"], expand=False))


# ── Host deep-dive ────────────────────────────────────────────────────────────

def host_lookup(api: shodan.Shodan, ip: str | None = None) -> None:
    if not ip:
        ip = Prompt.ask(f"[{C['blue']}]IP address[/]").strip()
    if not ip:
        return
    try:
        with Progress(SpinnerColumn(style=C["mauve"]),
                      TextColumn(f"[{C['subtext0']}]fetching host…"),
                      console=console, transient=True) as prog:
            prog.add_task("", total=None)
            host = api.host(ip)

        panels = []

        it = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
        it.add_column(style=C["overlay1"], no_wrap=True)
        it.add_column(style=C["text"])
        for k, v in [
            ("IP",          host.get("ip_str", ip)),
            ("Org",         host.get("org") or "—"),
            ("ISP",         host.get("isp") or "—"),
            ("ASN",         host.get("asn") or "—"),
            ("Country",     host.get("country_name") or "—"),
            ("City",        host.get("city") or "—"),
            ("Hostnames",   ", ".join(host.get("hostnames", [])) or "—"),
            ("Tags",        ", ".join(host.get("tags", [])) or "—"),
            ("Last update", host.get("last_update") or "—"),
        ]:
            it.add_row(k, v)
        panels.append(Panel(it, title=f"[{C['blue']}]Info[/]", border_style=C["surface1"]))

        ports = sorted(host.get("ports", []))
        if ports:
            pt = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
            pt.add_column(style=f"bold {C['green']}")
            for p in ports:
                pt.add_row(str(p))
            panels.append(Panel(pt, title=f"[{C['green']}]Ports[/]", border_style=C["surface1"]))

        vulns = sorted(host.get("vulns", []))
        if vulns:
            vt = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
            vt.add_column(style=f"bold {C['red']}", no_wrap=True)    # CVE ID
            vt.add_column(style=C["text"],          no_wrap=True)    # score
            vt.add_column(style=C["text"],          no_wrap=True)    # severity
            vt.add_column(style=C["subtext0"],      max_width=48)    # description
            for v in vulns:
                vt.add_row(v, "…", "fetching", "")
            panels.append(Panel(vt, title=f"[{C['red']}]CVEs  (enriching…)[/]",
                                border_style=C["surface1"]))

        console.print(Columns(panels, equal=False, expand=False))

        # Enrich CVEs from NVD after the basic panels are shown
        if vulns:
            console.print(Rule(f"[bold {C['red']}]CVE Details[/]", style=C["surface1"]))
            et = Table(box=box.ROUNDED, border_style=C["surface1"],
                       header_style=f"bold {C['mauve']}")
            et.add_column("CVE",         style=f"bold {C['red']}",  no_wrap=True)
            et.add_column("Score",       style=C["text"],            no_wrap=True, justify="right")
            et.add_column("Severity",    no_wrap=True)
            et.add_column("Description", style=C["subtext0"],        max_width=60)
            with Progress(SpinnerColumn(style=C["red"]),
                          TextColumn(f"[{C['subtext0']}]fetching CVE details from NVD…"),
                          console=console, transient=True) as prog:
                prog.add_task("", total=None)
                details: list[tuple] = []
                for i, cve_id in enumerate(vulns):
                    if i > 0:
                        time.sleep(0.7)   # NVD rate-limit: ~5 req/30s without key
                    d = fetch_cve_details(cve_id)
                    score    = str(d.get("score", "—")) if d.get("score") is not None else "—"
                    severity = d.get("severity") or "—"
                    desc     = (d.get("description") or "—")[:200]
                    details.append((cve_id, score, severity, desc))
            for cve_id, score, severity, desc in details:
                sev_color = _SEVERITY_COLORS.get(severity, C["text"])
                et.add_row(cve_id, score,
                           f"[{sev_color}]{severity}[/]",
                           desc)
            console.print(et)

        for svc in host.get("data", []):
            proto   = svc.get("transport", "tcp").upper()
            prod    = svc.get("product") or ""
            ver     = svc.get("version") or ""
            snippet = (svc.get("data") or "").strip()[:400]
            title   = f"[{C['sky']}]{proto}:{svc['port']}[/]"
            if prod:  title += f"  [{C['yellow']}]{prod}[/]"
            if ver:   title += f" [{C['subtext0']}]{ver}[/]"
            if snippet:
                console.print(Panel(Text(snippet, style=C["subtext0"]),
                                    title=title, border_style=C["surface0"]))
    except shodan.APIError as e:
        console.print(f"[{C['red']}]Error:[/] {e}")


# ── DNS tools (all free) ──────────────────────────────────────────────────────

def dns_tools(api: shodan.Shodan) -> None:
    console.clear()
    banner()
    console.print(Rule(f"[bold {C['teal']}]DNS Tools  (free — no credits)[/]", style=C["surface1"]))

    while True:
        menu = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
        menu.add_column(style=C["blue"], width=4)
        menu.add_column(style=C["text"])
        menu.add_row("1", "Resolve hostname → IP")
        menu.add_row("2", "Reverse lookup  IP → hostnames")
        menu.add_row("3", "My public IP")
        menu.add_row("b", "Back")
        console.print(Panel(menu, title=f"[{C['teal']}]DNS[/]",
                            border_style=C["surface1"], expand=False))
        choice = CIPrompt.ask(f"[{C['blue']}]Select[/]",
                             choices=["1", "2", "3", "b"], default="b")
        if choice == "b":
            break

        if choice == "3":
            try:
                ip = api.tools.myip()
                if ip:
                    console.print(Panel(f"[{C['green']}]{ip}[/]",
                                        title=f"[{C['teal']}]Your Public IP[/]",
                                        border_style=C["surface1"], expand=False))
                else:
                    console.print(f"[{C['yellow']}]No IP returned from API.[/]")
            except (shodan.APIError, requests.exceptions.RequestException) as e:
                console.print(f"[{C['red']}]Error:[/] {e}")

        elif choice == "1":
            raw = Prompt.ask(f"[{C['blue']}]Hostname(s)[/] [{C['overlay1']}]comma-sep[/]").strip()
            hosts = [h.strip() for h in raw.split(",") if h.strip()]
            if hosts:
                try:
                    res = api._request('/dns/resolve', {'hostnames': ','.join(hosts)})
                    if not res:
                        console.print(f"[{C['yellow']}]No results found for these hostnames.[/]")
                        continue

                    tbl = Table(box=box.ROUNDED, border_style=C["surface1"],
                                header_style=f"bold {C['mauve']}")
                    tbl.add_column("Hostname", style=C["sky"])
                    tbl.add_column("IP", style=f"bold {C['green']}")
                    for h, ip in res.items():
                        tbl.add_row(str(h), str(ip) if ip else "—")
                    console.print(tbl)
                except (shodan.APIError, requests.exceptions.RequestException) as e:
                    console.print(f"[{C['red']}]Error:[/] {e}")

        elif choice == "2":
            raw = Prompt.ask(f"[{C['blue']}]IP(s)[/] [{C['overlay1']}]comma-sep[/]").strip()
            ips = [i.strip() for i in raw.split(",") if i.strip()]
            if ips:
                try:
                    res = api._request('/dns/reverse', {'ips': ','.join(ips)})
                    if not res:
                        console.print(f"[{C['yellow']}]No results found for these IPs.[/]")
                        continue

                    tbl = Table(box=box.ROUNDED, border_style=C["surface1"],
                                header_style=f"bold {C['mauve']}")
                    tbl.add_column("IP", style=f"bold {C['green']}")
                    tbl.add_column("Hostnames", style=C["sky"])
                    for ip, hs in res.items():
                        hostnames = ", ".join(hs) if (hs and isinstance(hs, list)) else "—"
                        tbl.add_row(str(ip), hostnames)
                    console.print(tbl)
                except (shodan.APIError, requests.exceptions.RequestException) as e:
                    console.print(f"[{C['red']}]Error:[/] {e}")


# ── Markdown export ───────────────────────────────────────────────────────────

def save_markdown(session: Session, counts: dict[str, int],
                  results: dict[str, list[dict]]) -> None:
    ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fname = datetime.now().strftime("shodan_%Y%m%d_%H%M%S.md")
    path  = Path(fname)

    lines = [
        "# Shodan OSINT Report", "",
        f"**Generated:** {ts}  ",
        f"**Location:** {session.display}  ",
        f"**Radius:** {session.radius_mi} mi / {session.radius_km} km  ",
        f"**Coordinates:** {session.lat}, {session.lon}  ",
        f"**Tool:** shodash — the TUI  ",
        "", "---", "", "## Summary", "",
        "| Category | Total | Fetched |",
        "|----------|-------|---------|",
    ]
    for label, matches in results.items():
        lines.append(f"| {label} | {counts.get(label, 0):,} | {len(matches)} |")

    lines += ["", "---", "", "## Results", ""]
    for label, matches in results.items():
        if not matches:
            continue
        lines += [f"### {label}", "",
                  "| IP:Port | Org | Product | Version | City | Hostnames |",
                  "|---------|-----|---------|---------|------|-----------|"]
        for r in matches:
            def esc(s: str) -> str: return (s or "—").replace("|", "\\|")
            lines.append(
                f"| `{r['ip_str']}:{r['port']}` "
                f"| {esc(r.get('org',''))} "
                f"| {esc(r.get('product',''))} "
                f"| {esc(r.get('version',''))} "
                f"| {esc((r.get('location') or {}).get('city',''))} "
                f"| {esc(', '.join(r.get('hostnames',[])[:3]))} |"
            )
        lines.append("")

    lines += ["---", "",
              "*Generated by shodash — the TUI. Data publicly indexed by Shodan.*"]
    path.write_text("\n".join(lines), encoding="utf-8")
    console.print(Panel(f"[{C['green']}]{path.resolve()}[/]",
                        title=f"[{C['teal']}]Saved[/]",
                        border_style=C["surface1"], expand=False))


# ── Filter Library ────────────────────────────────────────────────────────────

def _category_table(session: Session) -> None:
    """Print the category browser table."""
    tbl = Table(
        title=f"[bold {C['lavender']}]Filter Library[/]",
        box=box.ROUNDED, border_style=C["surface1"],
        header_style=f"bold {C['mauve']}",
    )
    tbl.add_column("#",        style=C["overlay1"], justify="right", width=4)
    tbl.add_column("Category", style=C["text"],     min_width=22)
    tbl.add_column("Desc",     style=C["subtext0"], min_width=38)
    tbl.add_column("Queries",  justify="right",     width=8)
    tbl.add_column("In Cart",  justify="right",     width=8)

    for i, (name, cat) in enumerate(FILTER_LIBRARY.items(), 1):
        color    = cat["color"]
        in_cart  = sum(1 for q in cat["queries"] if q in session.cart)
        cart_str = (Text(str(in_cart), style=f"bold {C['green']}") if in_cart
                    else Text("—", style=C["overlay0"]))
        tbl.add_row(
            str(i),
            Text(name, style=f"bold {color}"),
            cat["desc"],
            str(len(cat["queries"])),
            cart_str,
        )
    console.print(tbl)


def browse_category(api: shodan.Shodan, session: Session, cat_name: str) -> None:
    """Show queries in one category, let the user add/remove from cart."""
    cat     = FILTER_LIBRARY[cat_name]
    color   = cat["color"]
    queries = cat["queries"]  # dict[label → (tmpl, color)]

    # ── show tip ──
    console.clear()
    console.print(Panel(
        Text(cat["tip"], style=C["subtext0"]),
        title=f"[bold {color}]{cat_name}[/]  [{C['overlay1']}]tip[/]",
        border_style=C["surface1"],
    ))

    # ── count preview if location is set ──
    counts: dict[str, int] = {}
    if session.has_location:
        counts = count_queries(api, session.geo, queries, session=session)  # type: ignore[arg-type]

    # ── query table ──
    labels = list(queries.keys())

    def render_query_table() -> None:
        tbl = Table(
            box=box.ROUNDED, border_style=C["surface1"],
            header_style=f"bold {C['mauve']}", show_lines=False,
        )
        tbl.add_column("#",      style=C["overlay1"], justify="right", width=4)
        tbl.add_column("Query",  style=C["text"],     min_width=30)
        tbl.add_column("Total",  justify="right",     width=10)
        tbl.add_column("Cart",   justify="center",    width=6)
        for i, label in enumerate(labels, 1):
            _, qcolor = queries[label]
            cnt  = counts.get(label, -1)
            if not session.has_location:
                cnt_str = Text("—", style=C["overlay0"])
            elif cnt < 0:
                cnt_str = Text("err", style=C["overlay0"])
            elif cnt == 0:
                cnt_str = Text("0", style=C["overlay0"])
            else:
                cnt_str = Text(f"{cnt:,}", style=f"bold {qcolor}")
            in_cart = "✓" if label in session.cart else ""
            cart_style = f"bold {C['green']}" if in_cart else C["overlay0"]
            tbl.add_row(str(i), Text(label, style=qcolor), cnt_str,
                        Text(in_cart, style=cart_style))
        console.print(tbl)

    render_query_table()

    if not session.has_location:
        console.print(f"[{C['yellow']}]No location set — counts not available. "
                      f"Set location from the main menu.[/]")

    console.print(
        f"\n[{C['subtext0']}]"
        f"[bold {C['blue']}]numbers[/] to toggle (e.g. 1, 1-3, 5)  "
        f"[bold {C['blue']}]a[/] = add all  "
        f"[bold {C['blue']}]n[/] = remove all  "
        f"[bold {C['green']}]r[/] = run cart  "
        f"[bold {C['red']}]b[/] = back[/]"
    )

    while True:
        sel = CIPrompt.ask(f"[{C['blue']}]Toggle[/]", default="b").strip().lower()
        if sel == "b":
            break
        if sel == "r":
            if session.cart_count() > 0:
                console.clear()
                banner()
                run_cart(api, session)
                Prompt.ask(f"[{C['overlay1']}]Press enter to return[/]")
                # Re-render after returning from run
                console.clear()
                console.print(Panel(
                    Text(cat["tip"], style=C["subtext0"]),
                    title=f"[bold {color}]{cat_name}[/]  [{C['overlay1']}]tip[/]",
                    border_style=C["surface1"],
                ))
                render_query_table()
                continue
            else:
                console.print(f"[{C['red']}]Cart is empty.[/]")
                continue

        if sel == "a":
            for label, entry in queries.items():
                session.add_to_cart(label, entry)
        elif sel == "n":
            for label in list(queries.keys()):
                session.remove_from_cart(label)
        else:
            # Handle ranges (1-3) and comma lists (1,5,7)
            parts = [p.strip() for p in sel.split(",")]
            for part in parts:
                if "-" in part:
                    try:
                        start, end = map(int, part.split("-"))
                        indexes = range(start, end + 1)
                    except ValueError:
                        indexes = []
                elif part.isdigit():
                    indexes = [int(part)]
                else:
                    indexes = []
                
                for idx in indexes:
                    idx_0 = idx - 1
                    if 0 <= idx_0 < len(labels):
                        label = labels[idx_0]
                        if label in session.cart:
                            session.remove_from_cart(label)
                        else:
                            session.add_to_cart(label, queries[label])

        # re-render inline
        console.clear()
        console.print(Panel(
            Text(cat["tip"], style=C["subtext0"]),
            title=f"[bold {color}]{cat_name}[/]  [{C['overlay1']}]tip[/]",
            border_style=C["surface1"],
        ))
        render_query_table()
        console.print(
            f"\n[{C['subtext0']}]"
            f"[bold {C['blue']}]numbers[/] to toggle (e.g. 1-3, 5)  "
            f"[bold {C['blue']}]a[/] = add all  "
            f"[bold {C['blue']}]n[/] = remove all  "
            f"[bold {C['green']}]r[/] = run cart  "
            f"[bold {C['red']}]b[/] = back[/]"
        )


def view_cart(session: Session) -> None:
    if not session.cart:
        console.print(f"[{C['overlay0']}]Cart is empty.[/]")
        return
    tbl = Table(title=f"[bold {C['lavender']}]Cart ({session.cart_count()} queries)[/]",
                box=box.ROUNDED, border_style=C["surface1"],
                header_style=f"bold {C['mauve']}")
    tbl.add_column("#",        style=C["overlay1"], justify="right", width=4)
    tbl.add_column("Category", style=C["subtext0"], width=20)
    tbl.add_column("Query",    style=C["text"])
    for i, label in enumerate(session.cart, 1):
        # find which category this label belongs to
        cat_name = next(
            (cn for cn, cd in FILTER_LIBRARY.items() if label in cd["queries"]), "?"
        )
        _, qcolor = session.cart[label]
        tbl.add_row(str(i), cat_name, Text(label, style=qcolor))
    console.print(tbl)


def run_cart(api: shodan.Shodan, session: Session) -> None:
    """Ensure location is set, then run all cart queries."""
    if not session.cart:
        console.print(f"[{C['overlay0']}]Cart is empty — add queries first.[/]")
        return

    if not session.has_location:
        console.print(f"[{C['yellow']}]No location set. Enter one now.[/]")
        if not ask_location(session):
            return

    # Count preview for cart queries only
    console.print()
    cart_query_map = dict(session.cart)
    counts = count_queries(api, session.geo, cart_query_map, session=session)  # type: ignore[arg-type]

    tbl = Table(title=f"[bold {C['lavender']}]Cart Preview  (no credits)[/]",
                box=box.ROUNDED, border_style=C["surface1"],
                header_style=f"bold {C['mauve']}")
    tbl.add_column("#",      style=C["overlay1"], justify="right", width=4)
    tbl.add_column("Query",  style=C["text"])
    tbl.add_column("Total",  justify="right",     width=10)
    for i, label in enumerate(session.cart, 1):
        _, qcolor = session.cart[label]
        cnt = counts.get(label, -1)
        cnt_str = (Text("err", style=C["overlay0"]) if cnt < 0
                   else Text("—", style=C["overlay0"]) if cnt == 0
                   else Text(f"{cnt:,}", style=f"bold {qcolor}"))
        tbl.add_row(str(i), Text(label, style=qcolor), cnt_str)
    console.print(tbl)

    limit_raw = Prompt.ask(
        f"[{C['blue']}]Results per query[/] [{C['overlay1']}]1–100[/]", default="5"
    )
    try:
        limit = max(1, min(100, int(limit_raw)))
    except ValueError:
        limit = 5

    console.print()
    selected = list(session.cart.keys())
    results  = fetch_results(api, session.geo, selected, limit)  # type: ignore[arg-type]
    session.last_results = results
    session.last_counts  = counts
    info = fetch_account_info(api)
    session.account_info = info
    show_status(info)

    # Collect all unique IPs from this run's results
    all_result_ips = list(dict.fromkeys(
        r["ip_str"]
        for matches in results.values()
        for r in matches
    ))

    # Post-run options
    if any(results.values()):
        console.print()
        sc_rem = session.account_info.get("scan_credits", 0) or 0
        post = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
        post.add_column(style=C["blue"], width=4)
        post.add_column(style=C["text"])
        post.add_row("e", "Export results  (md / csv / json / txt / pdf)")
        post.add_row("h", "Deep-dive an IP from results")
        post.add_row("c", Text.from_markup(
            f"Scan these IPs  [{C['overlay1']}]({len(all_result_ips)} found, {sc_rem} scan credit(s) left)[/]"
        ))
        post.add_row("x", "Clear cart and continue")
        post.add_row("k", "Keep cart and continue")
        console.print(Panel(post, title=f"[{C['mauve']}]What next?[/]",
                            border_style=C["surface1"], expand=False))

        choice = CIPrompt.ask(f"[{C['blue']}]Select[/]",
                             choices=["e", "h", "c", "x", "k"], default="k")
        if choice == "e":
            export_menu(session, counts, results)
        elif choice == "h":
            if all_result_ips:
                ip_tbl = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
                ip_tbl.add_column(style=C["overlay1"], justify="right", width=4)
                ip_tbl.add_column(style=C["sky"])
                ip_tbl.add_column(style=C["overlay1"])
                for i, (r_ip, label) in enumerate(
                    ((r["ip_str"], label)
                     for label, matches in results.items()
                     for r in matches), 1
                ):
                    ip_tbl.add_row(str(i), r_ip, f"({label})")
                console.print(ip_tbl)
            host_lookup(api)
        elif choice == "c":
            scan_ips(api, session, prefill=all_result_ips)
        elif choice == "x":
            session.cart.clear()


def filter_library_menu(api: shodan.Shodan, session: Session) -> None:
    cat_names = list(FILTER_LIBRARY.keys())

    while True:
        console.clear()
        banner()
        _category_table(session)

        # Status bar
        loc_txt = (f"[{C['teal']}]{session.location_line()}[/]"
                   if session.has_location
                   else f"[{C['overlay0']}]no location set[/]")
        cart_txt = (f"[bold {C['green']}]{session.cart_count()} in cart[/]"
                    if session.cart_count()
                    else f"[{C['overlay0']}]cart empty[/]")
        console.print(
            f"  [{C['overlay1']}]location:[/] {loc_txt}    "
            f"[{C['overlay1']}]cart:[/] {cart_txt}\n"
        )

        valid_nums = [str(i) for i in range(1, len(cat_names) + 1)]
        actions    = ["r", "v", "x", "b"]
        console.print(
            f"[{C['subtext0']}]"
            f"[bold {C['blue']}]number[/] = browse category  "
            f"[bold {C['green']}]r[/] = run cart  "
            f"[bold {C['blue']}]v[/] = view cart  "
            f"[bold {C['red']}]x[/] = clear cart  "
            f"[bold {C['red']}]b[/] = back[/]"
        )
        sel = CIPrompt.ask(f"[{C['blue']}]Select[/]",
                          choices=valid_nums + actions, default="b")

        if sel == "b":
            break
        if sel == "x":
            session.cart.clear()
            continue
        if sel == "v":
            view_cart(session)
            Prompt.ask(f"[{C['overlay1']}]press enter[/]", default="")
            continue
        if sel == "r":
            console.clear()
            banner()
            run_cart(api, session)
            Prompt.ask(f"[{C['overlay1']}]press enter to return[/]", default="")
            continue

        # Browse a category
        browse_category(api, session, cat_names[int(sel) - 1])





# ── On-demand scan (uses scan credits) ───────────────────────────────────────

def scan_ips(api: shodan.Shodan, session: Session,
             prefill: list[str] | None = None) -> None:
    """Submit IPs for an on-demand Shodan rescan. Costs 1 scan credit per IP."""
    sc = session.account_info.get("scan_credits", 0)
    if not isinstance(sc, int):
        sc = 0

    color = C["green"] if sc > 20 else C["yellow"] if sc > 5 else C["red"]
    console.print(f"\n  [{C['overlay1']}]scan credits remaining:[/] [bold {color}]{sc}[/]")

    if sc == 0:
        console.print(f"[{C['red']}]No scan credits remaining this month.[/]")
        Prompt.ask(f"[{C['overlay1']}]Press enter[/]", default="")
        return

    if prefill:
        console.print(f"  [{C['subtext0']}]IPs from results:[/] {', '.join(prefill[:8])}"
                      + (f"  … +{len(prefill)-8} more" if len(prefill) > 8 else ""))
        raw = Prompt.ask(
            f"[{C['blue']}]IPs to scan[/] [{C['overlay1']}]enter to use all above, or comma-sep list[/]",
            default="",
        ).strip()
        ips = [ip.strip() for ip in raw.split(",") if ip.strip()] if raw else prefill
    else:
        raw = Prompt.ask(
            f"[{C['blue']}]IPs to scan[/] [{C['overlay1']}]comma-sep[/]"
        ).strip()
        ips = [ip.strip() for ip in raw.split(",") if ip.strip()]

    if not ips:
        return

    if len(ips) > sc:
        console.print(f"[{C['yellow']}]Capping to {sc} IPs (scan credit limit).[/]")
        ips = ips[:sc]

    console.print(
        f"\n  [{C['subtext0']}]Submitting [bold]{len(ips)}[/] IP(s) for on-demand scan. "
        f"Costs [bold {C['peach']}]{len(ips)}[/] scan credit(s).[/]"
    )
    if not Confirm.ask(f"[{C['yellow']}]Proceed?[/]"):
        return

    try:
        with Progress(SpinnerColumn(style=C["peach"]),
                      TextColumn(f"[{C['subtext0']}]submitting scan…"),
                      console=console, transient=True) as prog:
            prog.add_task("", total=None)
            result = api.scan(ips)

        scan_id      = result.get("id", "?")
        credits_left = result.get("credits_left", "?")
        count        = result.get("count", len(ips))

        tbl = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
        tbl.add_column(style=C["overlay1"], no_wrap=True)
        tbl.add_column(style=C["text"])
        tbl.add_row("Scan ID",      str(scan_id))
        tbl.add_row("IPs queued",   str(count))
        tbl.add_row("Credits left", str(credits_left))
        console.print(Panel(tbl, title=f"[{C['peach']}]Scan Submitted[/]",
                            border_style=C["surface1"], expand=False))

        session.account_info = fetch_account_info(api)

    except shodan.APIError as e:
        console.print(f"[{C['red']}]Scan error:[/] {e}")

    Prompt.ask(f"[{C['overlay1']}]Press enter[/]", default="")


# ── IP Monitor dashboard ───────────────────────────────────────────────────────

def monitor_dashboard(api: shodan.Shodan, session: Session) -> None:
    """Manage Shodan Monitor alerts — persistent watch on your IPs/CIDRs."""
    while True:
        console.clear()
        banner()
        console.print(Rule(f"[bold {C['blue']}]IP Monitor  [{C['overlay1']}]Shodan Alert — no query credits[/][/]",
                           style=C["surface1"]))

        # Refresh account info to get current monitored_ips count
        info      = session.account_info
        mon_used  = info.get("monitored_ips", 0) or 0
        limits    = info.get("usage_limits", {})
        mon_quota = limits.get("monitored_ips", 0) or 0
        sc_rem    = info.get("scan_credits", 0) or 0
        sc_total  = limits.get("scan_credits", 0) or sc_rem or 0

        # Quota bars
        quota_grid = Table.grid(padding=(0, 2))
        quota_grid.add_column(style=C["overlay1"], justify="right", no_wrap=True)
        quota_grid.add_column()

        if mon_quota:
            mbar, mcolor = _credit_bar(mon_quota - mon_used, mon_quota)
            quota_grid.add_row(
                "monitored IPs",
                Text.from_markup(
                    f"[bold {mcolor}]{mon_used}[/] [{C['overlay1']}]/ {mon_quota}  [{mcolor}]{mbar}[/][/]"
                ),
            )
        else:
            quota_grid.add_row("monitored IPs", Text(str(mon_used), style=C["text"]))

        sbar, scolor = _credit_bar(sc_rem, sc_total)
        sc_pct = f"  {round(sc_rem / sc_total * 100)}% left" if sc_total > 0 else ""
        quota_grid.add_row(
            "scan credits",
            Text.from_markup(
                f"[bold {scolor}]{sc_rem}[/] [{C['overlay1']}]/ {sc_total}[/]"
                + (f"  [{scolor}]{sbar}[/][{C['overlay1']}]{sc_pct}[/]" if sc_total > 0 else "")
            ),
        )
        console.print(Panel(quota_grid, title=f"[{C['mauve']}]Monthly Budget[/]",
                            border_style=C["surface1"], expand=False))

        # Fetch alerts
        try:
            with Progress(SpinnerColumn(style=C["blue"]),
                          TextColumn(f"[{C['subtext0']}]fetching monitors…"),
                          console=console, transient=True) as prog:
                prog.add_task("", total=None)
                _raw = api.alerts()
            # API returns None, a single dict, or a list depending on count
            if not _raw:
                alerts = []
            elif isinstance(_raw, dict):
                alerts = [_raw]
            else:
                alerts = list(_raw)
        except shodan.APIError as e:
            console.print(f"[{C['red']}]Could not fetch alerts: {e}[/]")
            alerts = []

        if alerts:
            tbl = Table(box=box.ROUNDED, border_style=C["surface1"],
                        header_style=f"bold {C['mauve']}")
            tbl.add_column("#",       style=C["overlay1"], justify="right", width=4)
            tbl.add_column("Name",    style=C["text"],     min_width=20)
            tbl.add_column("IP / CIDR", style=C["sky"],   min_width=18)
            tbl.add_column("IPs",     justify="right",     width=8)
            tbl.add_column("Created", style=C["subtext0"], width=12)

            for i, alert in enumerate(alerts, 1):
                filt  = alert.get("filters", {})
                ips   = filt.get("ip", [])
                if isinstance(ips, list):
                    ip_str = ", ".join(str(x) for x in ips[:3])
                    if len(ips) > 3:
                        ip_str += f" +{len(ips)-3}"
                else:
                    ip_str = str(ips)
                size  = alert.get("size", "—")
                ctime = (alert.get("created") or "")[:10] or "—"
                tbl.add_row(str(i), alert.get("name", "—"), ip_str,
                            str(size), ctime)
            console.print(tbl)
        else:
            console.print(
                f"\n  [{C['overlay0']}]No monitors active. "
                f"Use [bold {C['blue']}]a[/] to start watching an IP or CIDR.[/]\n"
            )

        # Action menu
        actions_tbl = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
        actions_tbl.add_column(style=C["blue"], width=4)
        actions_tbl.add_column(style=C["text"])
        actions_tbl.add_row("a", "Add IP / CIDR to monitor")
        if alerts:
            actions_tbl.add_row("d", "Delete a monitor")
            actions_tbl.add_row("v", "View monitor details")
        actions_tbl.add_row("c", f"Scan IPs now  [{C['overlay1']}]({sc_rem} credit(s) left)[/]")
        actions_tbl.add_row("r", "Refresh")
        actions_tbl.add_row("b", "Back")
        console.print(Panel(actions_tbl, title=f"[{C['blue']}]Monitor Actions[/]",
                            border_style=C["surface1"], expand=False))

        choices = ["a", "c", "r", "b"]
        if alerts:
            choices += ["d", "v"]
        sel = CIPrompt.ask(f"[{C['blue']}]Select[/]", choices=choices,
                          show_choices=False, default="b").strip().lower()

        if sel == "b":
            break

        elif sel == "r":
            session.account_info = fetch_account_info(api)

        elif sel == "a":
            name = Prompt.ask(f"[{C['blue']}]Monitor name[/]").strip()
            ip   = Prompt.ask(
                f"[{C['blue']}]IP or CIDR[/] [{C['overlay1']}]e.g. 1.2.3.4 or 1.2.3.0/24[/]"
            ).strip()
            if name and ip:
                try:
                    new_alert = api.create_alert(name, ip)
                    session.account_info = fetch_account_info(api)
                    console.print(
                        f"[{C['green']}]Monitor created — ID: {new_alert.get('id', '?')}[/]"
                    )
                except shodan.APIError as e:
                    console.print(f"[{C['red']}]Error: {e}[/]")
            Prompt.ask(f"[{C['overlay1']}]Press enter[/]", default="")

        elif sel == "d" and alerts:
            nums = [str(i) for i in range(1, len(alerts) + 1)]
            n    = CIPrompt.ask(f"[{C['blue']}]Delete #[/]", choices=nums)
            alert = alerts[int(n) - 1]
            if Confirm.ask(f"[{C['red']}]Delete monitor '{alert.get('name', '?')}'?[/]"):
                try:
                    api.delete_alert(alert["id"])
                    session.account_info = fetch_account_info(api)
                    console.print(f"[{C['green']}]Deleted.[/]")
                except shodan.APIError as e:
                    console.print(f"[{C['red']}]Error: {e}[/]")
            Prompt.ask(f"[{C['overlay1']}]Press enter[/]", default="")

        elif sel == "v" and alerts:
            nums = [str(i) for i in range(1, len(alerts) + 1)]
            n    = CIPrompt.ask(f"[{C['blue']}]View #[/]", choices=nums)
            alert = alerts[int(n) - 1]
            try:
                details = api.alerts(aid=alert["id"])
                # Normalize — single-alert call returns a dict directly
                if isinstance(details, list):
                    details = details[0] if details else {}
                det_tbl = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
                det_tbl.add_column(style=C["overlay1"], no_wrap=True, width=16)
                det_tbl.add_column(style=C["text"])
                for k, v in (details or {}).items():
                    if k == "triggers":
                        continue
                    det_tbl.add_row(str(k), str(v)[:80])
                console.print(Panel(det_tbl,
                                    title=f"[{C['sky']}]{alert.get('name', 'Alert')}[/]",
                                    border_style=C["surface1"]))
            except shodan.APIError as e:
                console.print(f"[{C['red']}]Error: {e}[/]")
            Prompt.ask(f"[{C['overlay1']}]Press enter[/]", default="")

        elif sel == "c":
            # Pull IPs from active alerts to pre-fill, or let user type them
            alert_ips: list[str] = []
            for alert in alerts:
                filt = alert.get("filters", {})
                raw_ips = filt.get("ip", [])
                if isinstance(raw_ips, list):
                    alert_ips.extend(str(x) for x in raw_ips)
                elif raw_ips:
                    alert_ips.append(str(raw_ips))
            scan_ips(api, session, prefill=alert_ips if alert_ips else None)


# ── Dashboard & New UI ────────────────────────────────────────────────────────

def render_dashboard(session: Session) -> None:
    console.clear()
    banner()

    # Top Row: Account & Location
    info     = session.account_info
    limits   = info.get("usage_limits", {})
    qc       = info.get("query_credits", 0) or 0
    sc       = info.get("scan_credits",  0) or 0
    qc_total = limits.get("query_credits", 0) or qc or 0
    sc_total = limits.get("scan_credits",  0) or sc or 0
    mon_used = info.get("monitored_ips",  0) or 0
    mon_max  = limits.get("monitored_ips", 0) or 0

    qbar, qcolor = _credit_bar(qc, qc_total)
    sbar, scolor = _credit_bar(sc, sc_total)

    # Account Panel
    acct_grid = Table.grid(padding=(0, 1))
    acct_grid.add_column(style=C["overlay1"], justify="right", no_wrap=True)
    acct_grid.add_column()
    acct_grid.add_row("Plan",    Text.from_markup(f"[bold {C['mauve']}]{str(info.get('plan','?')).title()}[/]"))
    acct_grid.add_row("Queries", Text.from_markup(
        f"[bold {qcolor}]{qc:,}[/][{C['overlay1']}]/{qc_total:,}[/] [{qcolor}]{qbar}[/]"
    ))
    acct_grid.add_row("Scans",   Text.from_markup(
        f"[bold {scolor}]{sc:,}[/][{C['overlay1']}]/{sc_total:,}[/] [{scolor}]{sbar}[/]"
    ))
    mon_str = f"{mon_used}" + (f"/{mon_max}" if mon_max else "")
    mon_color = C["green"] if mon_used < (mon_max or 999) else C["red"]
    acct_grid.add_row("Monitors", Text.from_markup(f"[bold {mon_color}]{mon_str}[/]  IPs watched"))

    # Location Panel
    loc_grid = Table.grid(padding=(0, 2))
    loc_grid.add_column(style=C["overlay1"], justify="right")
    loc_grid.add_column(style="bold")
    if session.has_location:
        loc_grid.add_row("Display", session.display)
        loc_grid.add_row("Coords",  f"{session.lat}, {session.lon}")
        loc_grid.add_row("Radius",  f"{session.radius_mi} mi / {session.radius_km} km")
    else:
        loc_grid.add_row("Status", f"[{C['yellow']}]No location set[/]")
        loc_grid.add_row("Action", "Press [bold blue]L[/] to set")

    # Cart Panel
    cart_grid = Table.grid(padding=(0, 2))
    cart_grid.add_column(style=C["overlay1"], justify="right")
    cart_grid.add_column(style="bold")
    count = session.cart_count()
    est = session.total_estimated_results()
    
    cart_grid.add_row("Queries", f"[{C['green']}]{count}[/]" if count else "0")
    if count > 0:
        cart_grid.add_row("Est. Results", f"[{C['blue']}]{est:,}[/]" if est > 0 else "—")
        cart_grid.add_row("Categories", str(len(set(FILTER_LIBRARY[k]["color"] for k in FILTER_LIBRARY if any(q in session.cart for q in FILTER_LIBRARY[k]["queries"])))))
    else:
        cart_grid.add_row("Status", f"[{C['overlay0']}]Empty[/]")

    # Combine into top dashboard
    dash = Table(box=box.ROUNDED, border_style=C["surface1"], expand=True, show_header=False, show_edge=True)
    dash.add_column("Account", ratio=3)
    dash.add_column("Location", ratio=4)
    dash.add_column("Cart", ratio=3)
    
    dash.add_row(
        Panel(acct_grid, title=f"[{C['mauve']}]Account[/]", border_style=C["surface0"]),
        Panel(loc_grid, title=f"[{C['teal']}]Target[/]", border_style=C["surface0"]),
        Panel(cart_grid, title=f"[{C['peach']}]Cart[/]", border_style=C["surface0"])
    )
    console.print(dash)

    # Hotkeys / Actions
    actions = Table(box=box.SIMPLE, show_header=False, pad_edge=False, expand=True)
    actions.add_column(justify="center")
    
    # Styled buttons
    def btn(key, label, color):
        return f"[bold {color}]{key}[/] {label}"

    row1 = [
        btn("B", "Browse Queries", C["blue"]),
        btn("L", "Set Location",   C["teal"]),
        btn("M", "IP Monitor",     C["sky"]),
        btn("H", "Host Lookup",    C["mauve"]),
        btn("D", "DNS Tools",      C["sapphire"]),
    ]
    if count > 0:
        row1.insert(1, btn("R", "Run Cart", C["green"]))
        row1.append(btn("X", "Clear Cart", C["red"]))

    row2 = [btn("Q", "Quit", C["overlay0"])]
    if session.last_results:
        row2.insert(0, btn("E", "Export Last Results", C["peach"]))

    actions.add_row("   ".join(row1))
    actions.add_row("   ".join(row2))
    
    console.print(Panel(actions, border_style=C["surface1"], padding=(1, 1)))


def dashboard_loop(api: shodan.Shodan, session: Session) -> None:
    while True:
        render_dashboard(session)
        
        # Valid choices depend on state
        choices = ["b", "l", "m", "h", "d", "q"]
        if session.cart_count() > 0:
            choices.extend(["r", "x"])
        if session.last_results:
            choices.append("e")

        sel = CIPrompt.ask(f"[{C['blue']}]Action[/]", choices=choices, show_choices=False).strip().lower()

        if sel == "q":
            break
        elif sel == "l":
            ask_location(session)
        elif sel == "m":
            monitor_dashboard(api, session)
        elif sel == "b":
            filter_library_menu(api, session)
        elif sel == "h":
            console.print(Rule(f"[bold {C['mauve']}]Host Lookup[/]", style=C["surface1"]))
            host_lookup(api)
            Prompt.ask(f"[{C['overlay1']}]Press enter to return[/]")
        elif sel == "d":
            dns_tools(api)
        elif sel == "r" and "r" in choices:
            console.clear()
            banner()
            run_cart(api, session)
            Prompt.ask(f"[{C['overlay1']}]Press enter to return[/]")
        elif sel == "x" and "x" in choices:
            if Confirm.ask(f"[{C['red']}]Clear all {session.cart_count()} items?[/]"):
                session.clear_cart()
        elif sel == "e" and session.last_results:
            export_menu(session, session.last_counts, session.last_results)

# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    # ── Stage 1: key file ─────────────────────────────────────────────────────
    key: str | None = None
    try:
        key = get_api_key()
    except Exception:
        pass

    if not key:
        console.clear()
        banner()
        console.print(Panel(
            f"[{C['red']}]No API key found on this machine.[/]\n\n"
            f"[{C['subtext0']}]Run this first:[/]\n"
            f"  [{C['green']}]shodan init <your-api-key>[/]\n\n"
            f"[{C['overlay1']}]Your key lives at[/] [{C['blue']}]~/.shodan/api_key[/]\n"
            f"[{C['overlay1']}]Get one at[/]       [{C['blue']}]https://account.shodan.io[/]",
            title=f"[bold {C['red']}]Not Initialized[/]",
            border_style=C["red"],
        ))
        sys.exit(1)

    # ── Stage 2: validate key against Shodan API ──────────────────────────────
    api = shodan.Shodan(key)
    try:
        account_info = api.info()
    except shodan.APIError as e:
        console.clear()
        banner()
        console.print(Panel(
            f"[{C['red']}]Shodan API error:[/] {e}\n\n"
            f"[{C['subtext0']}]Check your network connection and try again.[/]",
            title=f"[bold {C['red']}]API Unreachable[/]",
            border_style=C["red"],
        ))
        sys.exit(1)

    # ── Stage 3: start session ────────────────────────────────────────────────
    session = Session()
    session.account_info = account_info
    session.api_key      = key

    # ── Stage 4: restore last location if saved ───────────────────────────────
    cfg = _load_config()
    if cfg and cfg.get("lat") and cfg.get("display"):
        console.clear()
        banner()
        console.print(Panel(
            f"[{C['subtext0']}]Last session:[/] [{C['teal']}]{cfg['display']}[/]  "
            f"[{C['overlay1']}]•[/]  [{C['blue']}]{cfg.get('radius_mi')} mi / {cfg.get('radius_km')} km[/]",
            title=f"[{C['mauve']}]Saved Location[/]",
            border_style=C["surface1"], expand=False,
        ))
        if Confirm.ask(f"[{C['blue']}]Restore this location?[/]", default=True):
            # Assign fields directly to avoid triggering _save_config redundantly
            session.lat, session.lon, session.display = cfg["lat"], cfg["lon"], cfg["display"]
            session.radius_mi, session.radius_km      = cfg["radius_mi"], cfg["radius_km"]
            session.geo = f"geo:{cfg['lat']},{cfg['lon']},{cfg['radius_km']}"

    # Enter dashboard loop
    dashboard_loop(api, session)

    console.print(f"\n[{C['overlay1']}]bye.[/]\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(f"\n[{C['overlay1']}]bye.[/]\n")
        sys.exit(0)
