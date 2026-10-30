# SPDX-FileCopyrightText: 2026 Henry Cuevas
# SPDX-License-Identifier: Apache-2.0
#
# README recording of Demo A. Prints recorded results; it does not start the stack.
# Regenerate (from the repository root):
#   tests/demoa/run.sh > /tmp/demoa-run.out
#   python3 -I assets/readme/demo-extract.py var/demoa /tmp/demoa-run.out assets/readme/demo-capture.json
#   docker run --rm -v "$PWD":/vhs -w /vhs ghcr.io/charmbracelet/vhs:v0.10.0 assets/readme/demo.tape
# The capture step copies the real run's output; demo-replay.py only prints it.

Output assets/readme/demo.gif

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 16
Set Width 1000
Set Height 1000
Set Padding 28
Set LineHeight 1.15
Set Framerate 12
Set TypingSpeed 35ms
Set CursorBlink false
Set Theme { "name": "nodkey", "black": "#0E1116", "red": "#E5534B", "green": "#57AB5A", "yellow": "#C69026", "blue": "#539BF5", "magenta": "#B083F0", "cyan": "#39C5CF", "white": "#E6E6E6", "brightBlack": "#636E7B", "brightRed": "#FF938A", "brightGreen": "#6BC46D", "brightYellow": "#DAAA3F", "brightBlue": "#6CB6FF", "brightMagenta": "#DCBDFB", "brightCyan": "#56D4DD", "brightWhite": "#F2F2F2", "background": "#0E1116", "foreground": "#E6E6E6", "selection": "#2D333B", "cursor": "#E6E6E6" }

# The command is typed while hidden so that the first frame already shows it and the first
# output line (the first frame is what still-image previews display).
Hide
Type "export PS1='$ ' && clear"
Enter
Type "python3 -I assets/readme/demo-replay.py"
Enter
Show
Sleep 18s
