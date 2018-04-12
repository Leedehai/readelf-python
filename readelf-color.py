#!/usr/bin/env python
# Author: Leedehai

import subprocess
import sys

READELF = "/usr/bin/readelf"

NON_COLOR = "\x1b[0m"
TITLE_COLOR = "\x1b[1;38;5;207m"
ZERO_BYTE_COLOR = "\x1b[2;37m"

ZERO_BYTE_STR = ZERO_BYTE_COLOR + "0000" + NON_COLOR

args = [READELF] + sys.argv[1:]

if len(args) == 0 or "-v" in args or "--version" in args or "--help" in args:
    print("Mounted with a colorizer that is not a part of GNU binutils ('which readelf' for more info.)")

try:
    lines = subprocess.check_output(args).splitlines()
except:
    sys.exit(0)

for (i, line) in enumerate(lines):
    color = TITLE_COLOR if len(line) > 0 and line[-1] == ":" else NON_COLOR
    line = line.replace("0000", ZERO_BYTE_STR) if color is not TITLE_COLOR else line
    print(color + line + NON_COLOR)
