#!/usr/bin/env python3
"""Audit the FAP for the "touch the active view from its own dispatch" crash class.

Three real crashes in this project had the same root cause: mutating the view/submenu that is
currently dispatching an event, from inside that dispatch. Concretely:

  1. view_set_input_callback() on the widget view crashed because the widget had no context
     (view_set_context was never called) -> NULL deref in the callback.
  2. Rebuilding the submenu from inside its own item callback left it walking a freed model and
     crashed on the next key.
  3. Installing/clearing the KARMA input callback in scene on_enter/on_exit crashed because
     on_exit runs inside the view's own input dispatch.

The safe shapes are: build/modify views in scene `on_enter` (or a build helper called from there
or from `on_event`), and let UART-thread handlers post custom events instead of pushing scenes.

Usage: python3 fap_view_check.py [path-to-delfyrtl.c]
"""
import re
import sys
from collections import Counter

FN = re.compile(r"^(?:static\s+)?(?:void|bool|int|uint32_t)\s+([A-Za-z_][\w]*)\s*\(")
TOUCH = re.compile(r"(submenu_reset|widget_reset|view_dispatcher_switch_to_view)\s*\(")
SCENE = re.compile(r"(scene_manager_next_scene|scene_manager_previous_scene)\s*\(")

# Functions that legitimately touch a view outside a scene transition.
KNOWN_OK = {
    "delfyRTL_custom_callback",   # GUI thread, between frames (view dispatcher callback)
    "animation_timer_callback",   # pre-existing RickRoll animation (timer thread), verified on hw
}


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "../flipper-app/delfyrtl.c"
    src = open(path, encoding="utf-8", errors="replace").read().splitlines()

    fn = None
    touches, scenes = [], []
    in_uart = False
    for i, line in enumerate(src, 1):
        m = FN.match(line)
        if m:
            fn = m.group(1)
            in_uart = fn == "uart_process_line"
        if fn and TOUCH.search(line):
            touches.append((i, fn, TOUCH.search(line).group(1)))
        if fn and in_uart and SCENE.search(line):
            scenes.append((i, fn, SCENE.search(line).group(1)))

    problems = 0
    print("=== view touched inside a callback? ===")
    for lineno, name, kind in touches:
        if (name.endswith("_cb") or name.endswith("_callback") or name.endswith("call_back")) \
                and name not in KNOWN_OK:
            print(f"  RISK  line {lineno}: {kind} called from {name} (inside a callback)")
            problems += 1
    if not problems:
        print("  clean (only the known-safe callbacks touch a view)")

    print("=== scene pushed straight from uart_process_line? ===")
    if scenes:
        for lineno, name, kind in scenes:
            print(f"  RISK  line {lineno}: {kind} in {name} (UART worker thread)")
        problems += len(scenes)
    else:
        print("  clean (handlers post custom events instead)")

    print()
    print("=== where views are built (should be on_enter / build helpers / on_event) ===")
    for (name, kind), n in sorted(Counter((f, k) for _, f, k in touches).items()):
        print(f"  {name:44s} {kind:24s} x{n}")

    print()
    print(f"{len(touches)} view-touch call sites, {problems} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
