#!/usr/bin/env python3
"""board_cmd - send one command to the BW16/RTL8720DN over CH340 and print the reply.

DANGER: opening the CH340 asserts DTR/RTS by default, and RTS->BOOT drops the BW16 into
download mode. We drop both the instant the port is open (the board may blink/reset once).
The firmware's loop() also reads USB Serial, so this doubles as an out-of-band control
channel (e.g. "STOP" to tear the AP down when the FAP is hung).

Usage:  python3 board_cmd.py "STOP"     [--wait 2.0] [--read 3000]
"""
import sys
import time

import serial

PORT = "/dev/cu.usbserial-20220"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    wait = 2.0
    if "--wait" in sys.argv:
        wait = float(sys.argv[sys.argv.index("--wait") + 1])
    read = 4000
    if "--read" in sys.argv:
        read = int(sys.argv[sys.argv.index("--read") + 1])
    cmd = " ".join(args)

    s = serial.Serial(PORT, 115200, timeout=0.3)
    try:
        s.dtr = False
        s.rts = False
    except Exception:
        pass
    time.sleep(0.3)
    s.reset_input_buffer()
    s.write((cmd + "\n").encode())
    time.sleep(wait)
    sys.stdout.write(s.read(read).decode("utf-8", "replace"))
    s.close()


if __name__ == "__main__":
    main()
