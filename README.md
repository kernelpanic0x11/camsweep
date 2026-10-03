# CamSweep · CAMERA guide

Find discoverable devices on your attached IPv4 network and understand camera clues.
By [@kernel.panic.0x11](https://www.instagram.com/kernel.panic.0x11/).

**Here from the CAMERA reel? [Download the guide + Python kit](https://github.com/kernelpanic0x11/camsweep/raw/refs/heads/main/camera-guide.zip).**
Extract the ZIP and open `guide.html` in your browser. It works offline and includes
setup, result explanations, the real Blink test, limitations, and troubleshooting.

## Quick start

Use a network you own or have permission to assess. Guest WiFi access does not itself
grant permission to scan. Requires Python 3.10+ and OS network utilities; no pip
packages, root, or special adapter. Run from the extracted folder:

```sh
# macOS / Linux
python3 --version
python3 camsweep.py --hide-mac
```

```powershell
# Windows
py -3 --version
py -3 camsweep.py --hide-mac
```

The script detects your interface and subnet, sends ping and selected TCP probes,
and reads the neighbor cache. It does not access camera feeds or attempt passwords.
macOS was live-tested October 1, 2026. Windows/Linux parsing have fixture coverage;
those platforms were not live-tested in that session.

## Read the results

| Result | Meaning |
| --- | --- |
| Responding | Response evidence, newly resolved neighbor, or this computer |
| Cached/unconfirmed | Cache entry without current response confirmation |
| CAMERA CLUE | Camera-brand or streaming/DVR-port match; a hub can match |
| CHECK | Shared-use port or smart-home maker; identify the device |
| No camera clue | No matching clue, not proof a device is camera-free |

**A clean scan cannot prove a room is camera-free.** Sleeping cameras, guest isolation,
separate networks, cellular cameras, and memory-card-only cameras can defeat visibility.
An open TCP port does not authenticate a service as a camera.

## What our test actually showed

On October 1, 2026, Grant's home Blink Sync Module was flagged by brand without open
camera ports. His battery camera responded while its official-app Live View was open,
then went quiet after it closed. It appeared as Amazon Technologies with a CHECK result.
A later scan took 23.6 seconds and listed 10 responding and 5 cached/unconfirmed entries.
That is one observed run, not a performance or completeness guarantee.

The reel's TV/laptop/camera visuals are illustrative. These observations do not establish
a hidden-camera discovery at an Airbnb. The kit contains no private device labels or
captured home-network reports.

## Options and privacy

```sh
python3 camsweep.py --help
python3 camsweep.py --timeout 0.6
python3 camsweep.py --json report.json
```

JSON retains IP and MAC addresses. `--hide-mac` only hides terminal MACs; IPs remain.
Keep reports private and redact screenshots. Optional `--subnet` must be inside the
detected LAN; ranges larger than /20 are rejected. A VPN can affect interface selection.

## Verify and test

`SHA256SUMS` inside the ZIP covers the other bundled files.
The scanner tests use synthetic fixtures and mocks:

```sh
python3 -m unittest discover -s . -p test_camsweep.py -v
```

Packaged October 2, 2026. The full [offline reader](guide.html) accompanies the script.
