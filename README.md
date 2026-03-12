# SHODASH

```
 ███████╗██╗  ██╗ ██████╗ ██████╗  █████╗ ███████╗██╗  ██╗
 ██╔════╝██║  ██║██╔═══██╗██╔══██╗██╔══██╗██╔════╝██║  ██║
 ███████╗███████║██║   ██║██║  ██║███████║███████╗███████║
 ╚════██║██╔══██║██║   ██║██║  ██║██╔══██║╚════██║██╔══██║
 ███████║██║  ██║╚██████╔╝██████╔╝██║  ██║███████║██║  ██║
 ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
```

**geo-radius OSINT • built for the rest of us**

> You bought the Shodan lifetime membership. You monitored a couple IPs. Then you forgot about it.  
> **SHODASH fixes that.**

A Python terminal dashboard that puts your Shodan membership to actual use — searching for exposed devices, cameras, routers, IoT gear, industrial systems, and more within a geographic radius of any location. Built with `rich`, designed for the CLI, and credit-aware so you don't accidentally torch your 100 monthly query credits in one session.

---

## Features

- **Geo-radius search** — target any city or address, set a radius in miles, search within it
- **Filter Library** — 9 categories, 80+ pre-built queries covering cameras, remote access, ICS/SCADA, IoT, network gear, and more
- **Cart system** — preview result counts for free before spending a single credit, then run only what's worth it
- **Host Lookup** — deep-dive any IP at zero credit cost
- **DNS Tools** — built-in domain recon
- **Live account status** — query credits, scan credits, and plan info always visible
- **Built-in OSINT tips** — contextual guidance on what each query actually finds

---

## Requirements

- Python 3.8+
- A Shodan account with API access ([free tier works for basic use](https://account.shodan.io); the [$49 lifetime membership](https://account.shodan.io/billing) unlocks the full filter library and is occasionally on sale for $5)

---

## Installation

### 1. Clone the repo

```bash
git clone https://github.com/D3ss3rtTV/shodash.git
cd shodash
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Initialize Shodan with your API key

If you haven't already set up the Shodan CLI, do it now:

```bash
pip install shodan
shodan init YOUR_API_KEY_HERE
```

Get your API key from [account.shodan.io](https://account.shodan.io). You only need to do this once — SHODASH picks up the initialized key automatically.

### 4. Run it

```bash
python shodash.py
```

---

## Usage

### Main Menu

| Key | Action |
|-----|--------|
| `B` | Browse Filter Library |
| `L` | Set location and search radius |
| `H` | Host Lookup — free IP deep-dive, no credits |
| `D` | DNS Tools — domain recon |
| `Q` | Quit |

### Setting a Location

Press `L` and enter any city, address, or place name. SHODASH resolves it to coordinates and lets you set a radius in miles. Your location and radius stay active across all queries until you change them.

### Running Queries

1. Press `B` to open the Filter Library
2. Select a category
3. Browse queries — result counts are shown for free before you commit
4. Add queries to your cart
5. Press `R` to execute the cart and pull real results

### The Cart System

The cart exists to protect your monthly credits. Count queries (always free) show you how many results exist for each query before you decide to run it. Build a cart of queries worth running, then execute them all at once. No surprise credit burns.

---

## Credit Reference

| Action | Credits Used |
|--------|-------------|
| Count query (any filter) | **0** — always free |
| Search with filter (first page) | **1** |
| Each additional 100 results | **1** |
| IP host lookup | **0** — always free |
| DNS domain lookup | **1** |
| On-demand IP scan | **1 per IP** |

Shodan membership accounts receive **100 query credits + 100 scan credits** per month, resetting at the start of each billing cycle.

---

## Filter Library

| # | Category | Queries | What It Finds |
|---|----------|---------|---------------|
| 1 | IP Cameras | 23 | Network cams, DVRs, NVRs — brand-specific HTTP fingerprints |
| 2 | Remote Access | 9 | RDP, VNC, SSH, Telnet, VPN endpoints |
| 3 | Industrial / ICS | 10 | SCADA, PLCs, building automation systems |
| 4 | Smart Home & IoT | 10 | Home Assistant, UniFi, MQTT brokers, Shelly, TP-Link Kasa |
| 5 | Network Gear | 10 | Routers, switches, access points |
| 6 | Exposed Services | 11 | Databases, admin panels, dev tools left open |
| 7 | Communications | 4 | VoIP, PBX, messaging infrastructure |
| 8 | Media & Fun | 5 | Plex, game servers, media streamers |
| 9 | Misc / Curiosities | 5 | Crypto nodes, Tor, privacy tools, oddities |

---

## Ethical Use

SHODASH only queries data already indexed by Shodan from the public internet. It does not perform active scanning of any kind.

- **Do not attempt to access, log in to, or interact with any devices you find.** Viewing Shodan data is legal. Unauthorized access to devices is not.
- This tool is intended for security research, network awareness, and understanding public internet exposure.
- If you find your own devices in results, use that as a prompt to lock them down.

---

## Roadmap

- [ ] Export results to CSV / JSON
- [ ] Saved search profiles
- [ ] Host detail drill-down from results table
- [ ] Custom query builder with filter autocomplete
- [ ] Monitor mode — re-run saved cart on a schedule
- [ ] Additional OSINT source integrations

---

## Contributing

PRs welcome. If you have Shodan query fingerprints that work well for geo-radius searches, open an issue or submit them directly to the filter library.

---

## License

[GPL-3.0](LICENSE)
