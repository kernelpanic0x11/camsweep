CAMERA — CamSweep field guide

Extract the entire ZIP into a folder. Open guide.html in your browser.
Requires Python 3.10+ and the operating system network utilities.
No pip packages, USB WiFi adapter, or administrator/root access required.

Open Terminal (macOS/Linux) or PowerShell (Windows) in this folder.
macOS/Linux:
  python3 --version
  python3 camsweep.py --help
  python3 camsweep.py --hide-mac
Windows:
  py -3 --version
  py -3 camsweep.py --help
  py -3 camsweep.py --hide-mac

Run only on a network you own or have permission to assess.
Joining guest WiFi does not itself grant permission to scan it.
The script sends ping and TCP probes; it is not passive radio detection.
It does not open video feeds or attempt passwords.

Optional: python3 camsweep.py --json report.json
Reports contain IP and MAC addresses. Keep them private.
--hide-mac hides terminal MACs only, not JSON or IP addresses.

CAMERA CLUE is a lead, not proof. Cached/unconfirmed is not proof of liveness.
A clean scan cannot rule out a camera. Read guide.html for limitations.
macOS live-tested October 1, 2026. Windows/Linux have parsing fixture coverage,
not a live validation in the recorded session.

Creator: @kernel.panic.0x11
Packaged October 2, 2026. No private device labels or captures included.
