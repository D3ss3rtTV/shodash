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

A Python terminal dashboard that puts your Shodan lifetime membership to actual use — searching for exposed devices, cameras, routers, IoT gear, industrial systems, and more within a geographic radius of any location you choose. Built with `rich`, designed for the CLI, and credit-aware so you don't burn your 100 monthly query credits on accident.

---

## What It Does

- 📍 **Geo-radius search** — set any city/location as your target and search within a custom mile/km radius
- 🗂 **Filter Library** — 9 curated categories (IP Cameras, Remote Access, ICS/SCADA, Smart Home & IoT, Network Gear, Exposed Services, Communications, Media & Fun, Misc/Curiosities) with 80+ pre-built queries
- 🛒 **Cart system** — preview result counts *before* spending credits, then run only what's worth it
- 💡 **Built-in OSINT tips** — contextual guidance on what each query finds and which ones actually work in the real world
- 🖥 **Host Lookup** — free IP deep-dives, no credits consumed
- 🌐 **DNS Tools** — domain recon built in
- 📊 **Live account status** — query credits, scan credits, plan info always visible on the dashboard
- ⚡ **Credit-smart** — count queries run free; credits only used when you pull real results

---

## Screenshots

> *(add your screenshots here)*

| Dashboard | Filter Library | Results |
|-----------|---------------|---------|
| ![dashboard]() | ![filters]() | ![results]() |

---

## Requirements

- Python 3.8+
- A **Shodan account** with a [lifetime membership](https://account.shodan.io/billing) ($49 one-time, occasionally on sale for $5)
- The official Shodan CLI/library **installed and initialized**

---

## ⚠️ Before You Run SHODASH

SHODASH uses the Shodan Python library under the hood. **You must install and initialize it first** or the tool will not work.

### Step 1 — Install the Shodan library

```bash
pip install shodan
```

### Step 2 — Initialize with your API key

Get your API key from [https://account.shodan.io](https://account.shodan.io) then run:

```bash
shodan init YOUR_API_KEY_HERE
```

You should see:

```
Successfully initialized
```

That's it. SHODASH will pick up your initialized key automatically. You only need to do this once.

> **Don't have a key yet?** Sign up at [shodan.io](https://shodan.io) and grab your API key from the account dashboard. A free account works for basic testing but the lifetime membership ($49 one-time) is what unlocks the full filter library and API access.

---

## Installation

```bash
git clone https://github.com/yourusername/shodash.git
cd shodash
pip install -r requirements.txt
python shodash.py
```

---

## Usage

On launch, SHODASH checks that Shodan is installed and your API key is initialized. If either is missing, it walks you through the fix.

### Main Menu

```
B  Browse Queries    — open the Filter Library
L  Set Location      — set your geo-radius target
H  Host Lookup       — deep-dive a specific IP (free, no credits)
D  DNS Tools         — domain recon
Q  Quit
```

### Setting Your Location

Hit `L` and enter any city, address, or place name. SHODASH resolves it to coordinates and lets you set a search radius in miles. Your location and radius stay active across all queries until you change them.

### Browsing & Running Queries

1. Hit `B` to open the Filter Library
2. Pick a category by number
3. Browse the queries — SHODASH counts results for free first so you can see what's out there
4. Add interesting ones to your cart
5. Hit `R` to run the cart and pull real results

### The Cart System

The cart exists to protect your 100 monthly query credits. Count queries (free) show you how many results exist before you commit. You build a cart of queries worth running, then execute them all at once. No surprise credit burns.

---

## Credit Usage Reference

| Action | Credits Used |
|--------|-------------|
| Count query (any filter) | **0** — always free |
| Search with filter (page 1) | **1** |
| Each additional 100 results | **1** |
| IP host lookup | **0** — always free |
| DNS domain lookup | **1** |
| On-demand IP scan | **1 per IP** |

Your membership gives you **100 query credits + 100 scan credits** per month, resetting at the start of each month.

---

## Filter Library Categories

| # | Category | What It Finds |
|---|----------|--------------|
| 1 | **IP Cameras** | Network cams, DVRs, NVRs — 23 brand-specific HTTP fingerprints |
| 2 | **Remote Access** | RDP, VNC, SSH, Telnet, VPN — exposed remote management (9 queries) |
| 3 | **Industrial / ICS** | SCADA, PLCs, building automation — handle with care (10 queries) |
| 4 | **Smart Home & IoT** | Home Assistant, UniFi, MQTT brokers, Shelly, TP-Link Kasa (10 queries) |
| 5 | **Network Gear** | Routers, switches, APs — backbone of local networks (10 queries) |
| 6 | **Exposed Services** | Databases, dev tools, admin panels left open (11 queries) |
| 7 | **Communications** | VoIP, PBX, messaging infrastructure (4 queries) |
| 8 | **Media & Fun** | Plex, game servers, media streamers (5 queries) |
| 9 | **Misc / Curiosities** | Crypto nodes, Tor, privacy tools, weird stuff (5 queries) |

---

## Ethical Use

SHODASH only queries data that Shodan has already indexed from the public internet — it does not perform any active scanning on its own. Everything you see in results is already publicly exposed.

That said:

- **Do not attempt to access, log in to, or interact with any devices you find.** Viewing Shodan data is legal; unauthorized access to devices is not.
- This tool is intended for **security research, network awareness, and understanding your local internet exposure.**
- If you find your own devices exposed, use that as a prompt to lock them down.

---

## Roadmap

- [ ] Export results to CSV / JSON
- [ ] Saved search profiles
- [ ] Host detail drill-down view from results table
- [ ] Custom query builder with filter autocomplete
- [ ] Monitor mode — re-run saved cart on a schedule
- [ ] Integration with other API keys and OSINT sources

---

## Contributing

PRs welcome. If you have good Shodan query fingerprints that work well for geo-radius searches, open an issue or submit them to the filter library.

---

## License

MIT

---

*Built because too many people paid $49 (or $5 during the sale) for a Shodan membership and never used it past the first week.*
