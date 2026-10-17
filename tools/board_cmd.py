#!/usr/bin/env python3
"""board_cmd - send one command to the BW16/RTL8720DN over CH340 and print the reply.

DANGER: opening the CH340 asserts DTR/RTS by default, and RTS->BOOT drops the BW16 into
download mode. We drop both the instant the port is open (the board may blink/reset once).
The firmware's loop() also reads USB Serial, so this doubles as an out-of-band control
channel (e.g. "STOP" to tear the AP down when the FAP is hung).

Usage:  python3 board_cmd.py "STOP"     [--wait 2.0] [--read 3000]

TRAP (cost a whole false diagnosis): the flag *values* used to leak into the command.
The old parser only dropped args that started with "--", so
    board_cmd.py "APSTART DELFYAP" --wait 14 --read 8000
sent "APSTART DELFYAP 14 8000" and the firmware created an AP with the SSID
"DELFYAP 14 8000" - the AP was beaconing all along, we just scanned the wrong name and
concluded "the AP never comes up". Consume each flag's value explicitly (below).
"""
import sys
import time

import serial

PORT = "/dev/cu.usbserial-20220"

# Flags whose *next* argument is their value and must never reach the board.
VALUE_FLAGS = {"--wait": float, "--read": int}


def parse_args(argv):
    """Split argv into (command, wait, read), consuming flag values explicitly."""
    cmd_parts = []
    wait = 2.0
    read = 4000
    i = 0
    while i < len(argv):
        a = argv[i]
        conv = VALUE_FLAGS.get(a)
        if conv is not None:
            if i + 1 >= len(argv):
                raise SystemExit(f"board_cmd: {a} needs a value")
            v = conv(argv[i + 1])
            if a == "--wait":
                wait = v
            else:
                read = v
            i += 2
            continue
        cmd_parts.append(a)
        i += 1
    return " ".join(cmd_parts), wait, read


def main():
    cmd, wait, read = parse_args(sys.argv[1:])

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
