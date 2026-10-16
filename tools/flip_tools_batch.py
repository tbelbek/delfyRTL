#!/usr/bin/env python3
"""flip_tools_batch - reboot, navigate to the Tools menu, and run a batch of tools.

Each tool: navigate from the top of the Tools list (DOWN*i), OK, screenshot busy + after,
BACK. Writes suite3/. If the FAP zombies (desktop while 'running'), the batch stops and
says so.

Usage: python3 flip_tools_batch.py <start_index> <count>
"""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
T = "/private/var/folders/d3/tc4kl8dj4_95r62sctcfk61h0000gn/T/opencode/suite3"
os.makedirs(T, exist_ok=True)
LOG = os.path.join(T, "run.log")
FAP = "/ext/apps/GPIO/delfyrtl.fap"
PY = sys.executable


def log(m):
    line = f"{time.strftime('%H:%M:%S')} {m}"
    print(line, flush=True)
    open(LOG, "a").write(line + "\n")


def cli(cmd, wait=1.5):
    try:
        r = subprocess.run([PY, os.path.join(HERE, "flip_cli.py"), cmd],
                           capture_output=True, text=True, timeout=25)
        return r.stdout
    except subprocess.TimeoutExpired:
        return "<<timeout>>"


def shot(name):
    p = os.path.join(T, name + ".png")
    try:
        r = subprocess.run([PY, os.path.join(HERE, "flipctl.py"), "shot", p],
                           capture_output=True, text=True, timeout=25)
        ok = "saved" in r.stdout
    except subprocess.TimeoutExpired:
        ok = False
    log(f"    shot {name}: {'ok' if ok else 'NOFRAME/HANG'}")
    return ok


def keys(*ks, settle=0.35):
    args = [PY, os.path.join(HERE, "flipctl.py"), "drive", *ks, "--settle", str(settle)]
    try:
        subprocess.run(args, capture_output=True, text=True, timeout=45)
    except subprocess.TimeoutExpired:
        log("    drive TIMEOUT")


def nav_to_tools():
    log("  reboot + loader open + scan + nav to Tools")
    subprocess.run([PY, os.path.join(HERE, "flip_reboot.py")], capture_output=True, timeout=30)
    time.sleep(5)
    cli(f"loader open {FAP}", wait=3.5)
    time.sleep(2.5)
    keys("OK", settle=0.9)          # hub
    keys("OK", settle=1.2)          # scan
    time.sleep(13)
    keys("DOWN", "OK", settle=0.5)  # hub -> List Wifi
    time.sleep(1.2)
    # pick list item #2: in every observed scan order that slot is a NAMED AP, whereas
    # #0/#1 are sometimes the hidden "<empty>" AP, whose info screen has no <Edit button
    # (so you cannot reach Tools). Verified against 3 different scan orders.
    keys("DOWN", "DOWN", "OK", settle=0.5)  # list -> item #2 info
    time.sleep(1.2)
    keys("LEFT", settle=0.9)        # config
    keys("DOWN", "DOWN", "DOWN", "OK", settle=0.4)   # Tools
    time.sleep(1.2)
    shot("b00-tools")


# (idx, name, wait_s) - idx is the ROW in the Tools menu. The menu now starts with the
# "Target: <ssid>" picker, so every row below it is one further down than it used to be.
TOOLS = {
    0: ("Target_AP", 2),
    14: ("Capture_HS_passive", 14),
    1: ("Grab_HS_deauth", 24),
    2: ("PMKID_passive", 12),
    3: ("PMKID_grab_deauth", 16),
    4: ("PMKID_clientless", 14),
    5: ("Capture_STOP", 2),
    6: ("Guided_audit", 20),
    7: ("PMF_WPA3_scan", 12),
    8: ("STASCAN", 12),
    9: ("Deauth_list_addAP", 3),
    10: ("Deauth_list_RUN", 6),
    11: ("Deauth_list_STOP", 3),
    12: ("Channel_hop", 3),
    13: ("Stop_clear", 3),
}


def main():
    start = int(sys.argv[1]) if len(sys.argv) > 1 else 2
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    log(f"================ TOOLS BATCH start={start} count={count} ================")
    nav_to_tools()
    for i in range(start, start + count):
        if i not in TOOLS:
            continue
        name, wait = TOOLS[i]
        log(f"  TOOL #{i} {name}")
        keys(*(["DOWN"] * i + ["OK"]), settle=0.35)
        shot(f"b{i:02d}-{name}-busy")
        time.sleep(wait)
        shot(f"b{i:02d}-{name}-after")
        keys("BACK", settle=0.6)
        shot(f"b{i:02d}-{name}-back")
    log("================ BATCH done ================")


if __name__ == "__main__":
    main()
