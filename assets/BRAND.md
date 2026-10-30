# Nodkey brand assets

Direction: **Boundary**. The identity is drawn like an engineering drawing. In the wordmark, the `k`
is cut by a vertical slot so the stem never touches the arms: computation on one side, authority on
the other. The mark is that `k` on its own. In the hero, the only graphic element is one ultramarine
rule, the trust boundary, with the properties of each side written next to it.

The labels in the hero and the diagram describe the system as documented in
[ARCHITECTURE.md](../docs/ARCHITECTURE.md) and
[ADR-0011](../docs/decisions/0011-propose-confirm-execute.md). If the architecture changes, update the
labels; do not keep a label that is no longer true.

## Files

| File | What it is | How it is made |
|---|---|---|
| `brand/nodkey-wordmark.svg` | Wordmark, ink on light backgrounds | Schibsted Grotesk outlined to paths |
| `brand/nodkey-wordmark-dark.svg` | Wordmark for dark backgrounds | Same paths, light fill |
| `brand/nodkey-mark.svg` | Mark (the cut `k`), 64 x 64 | Taken from the wordmark `k` |
| `brand/nodkey-mark-dark.svg` | Mark for dark backgrounds | Same path, light fill |
| `icon/nodkey-icon-1024.svg` | Icon: the mark on paper, 1024 x 1024 | Mark scaled 12x and centred, 128 px margin |
| `icon/nodkey-icon-1024.png` | PNG of the icon | Headless Chrome screenshot of the SVG |
| `readme/hero-light.png`, `readme/hero-dark.png` | README hero, 1600 x 560 | Headless Chrome screenshots of `src/hero-light.html`, `src/hero-dark.html` |
| `readme/diagram-light.svg`, `readme/diagram-dark.svg` | README flow diagram, 1600 x 680; text outlined to paths | Same six steps and labels as the earlier README Mermaid diagram |
| `readme/diagram-light.png`, `readme/diagram-dark.png` | PNG fallbacks of the diagram | Headless Chrome screenshots of the SVGs |
| `social/social-preview.png` | Repository social preview, 1280 x 640 | Headless Chrome screenshot of `src/social-preview.html` |
| `src/*.html` | Editable sources of the hero and the social preview | Hand-written |
| `readme/demo.gif` | README recording | [VHS](https://github.com/charmbracelet/vhs) (MIT) in the pinned image `ghcr.io/charmbracelet/vhs:v0.10.0`, from `readme/demo.tape` |
| `readme/demo.tape` | VHS script for the recording | Hand-written |
| `readme/demo-capture.json` | Selected results of one real Demo A run, copied verbatim | `readme/demo-extract.py` from `var/demoa/` and the stdout of `tests/demoa/run.sh` |
| `readme/demo-extract.py` | Copies the selected results out of a finished run | Hand-written |
| `readme/demo-replay.py` | Prints `demo-capture.json`; the recording shows its output | Hand-written |

The SVG files contain only paths, so they render the same everywhere without fonts. The script that
outlined the wordmark and the diagram text is not in this repository; to change the wordmark or the
diagram, edit the SVGs directly or outline new text with a font tool of your choice.

## Wordmark and mark

- The wordmark is lower case: `nodkey`. In running text, write the name as **Nodkey**.
- Use the light files (`nodkey-wordmark.svg`, `nodkey-mark.svg`) on paper `#F5F4F0` or white, and the
  `-dark` files on `#0F1114` or similar dark backgrounds.
- Do not close the slot in the `k`, recolour the wordmark in the accent, add effects (shadow, outline,
  gradient), stretch it, or set the name in another typeface as a replacement for the wordmark.
- Use the mark where the wordmark would be too small to read, for example an avatar or a favicon.
- Minimum size: wordmark 16 px tall; mark 16 px.

### Clear space

- Wordmark: keep free space around it at least equal to the height of its `o` (the x-height).
- Mark and icon: keep at least 1/8 of the mark's width free on every side. The icon file already
  includes a 128 px margin on 1024 px.

## Palette

Contrast ratios use the WCAG 2.x relative-luminance formula. AAA for normal text needs 7:1, AA needs
4.5:1.

| Role | Light theme | Ratio on paper | Dark theme | Ratio on background |
|---|---|---|---|---|
| Background | paper `#F5F4F0` | | `#0F1114` | |
| Text (ink) | `#14161A` | 16.46:1 (AAA) | `#ECEBE6` | 15.84:1 (AAA) |
| Accent, the boundary rule and its labels | ultramarine `#2438C8` | 7.71:1 (AAA) | `#8B9BFF` | 7.41:1 (AAA) |
| Muted text | `#5B5F67` | 5.82:1 (AA) | `#9599A1` | 6.62:1 (AA) |

Use the accent for one meaning only: the trust boundary (the key-holding side). Do not use it for
decoration or emphasis.

The diagram adds a few neutral tones (box fills `#FFFFFF` and `#ECEBE6` in light, `#16191D` and
`#14171B` in dark; lines `#C9C8C3` in dark, 11.29:1 on `#0F1114`).

The README recording (`demo.gif`) uses its own terminal palette, set in `readme/demo.tape`:
background `#0E1116`, text `#E6E6E6`, secondary text `#969EA8`, executed `#57AB5A`, denied or rejected
`#E5534B`, executed through a stated limit `#C69026`.

## Typography and licences

| Use | Font | Settings | Licence |
|---|---|---|---|
| Wordmark, hero headline | [Schibsted Grotesk](https://github.com/schibsted/schibsted-grotesk) | Weight 600, lower case in the wordmark | SIL Open Font License 1.1 |
| Labels, diagram labels, recording | [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono) | Weights 400 and 500; labels in capitals with wide tracking | SIL Open Font License 1.1 |

Neither font declares a Reserved Font Name. The wordmark and the diagram text are outlined to paths,
and the PNGs are rendered images, so **no font file is shipped in this repository**. If a font file is
ever committed, its `OFL.txt` must be committed next to it.

The images are covered by the repository licence (see `LICENSE` and `NOTICE`). Using the name or the
mark to imply endorsement is not covered by that licence (Apache-2.0, section 6). No trademark search
has been done for the name or the mark.

## Regenerating

### Hero, social preview and icon

The HTML sources load the fonts from `assets/src/fonts/`, which is not part of the repository.
Download the variable fonts `SchibstedGrotesk[wght].ttf` (from `ofl/schibstedgrotesk/`) and
`JetBrainsMono[wght].ttf` (from `ofl/jetbrainsmono/`) in
[github.com/google/fonts](https://github.com/google/fonts) into `assets/src/fonts/`. Then, from the
repository root, run Google Chrome headless (`chrome` below stands for the Chrome binary, for example
`/Applications/Google Chrome.app/Contents/MacOS/Google Chrome` on macOS):

```sh
shot() { chrome --headless=new --hide-scrollbars --allow-file-access-from-files \
  --force-device-scale-factor=1 --window-size="$1" --screenshot="$2" "$3"; }
shot 1600,560 assets/readme/hero-light.png assets/src/hero-light.html
shot 1600,560 assets/readme/hero-dark.png assets/src/hero-dark.html
shot 1280,640 assets/social/social-preview.png assets/src/social-preview.html
shot 1024,1024 assets/icon/nodkey-icon-1024.png assets/icon/nodkey-icon-1024.svg
shot 1600,680 assets/readme/diagram-light.png assets/readme/diagram-light.svg
shot 1600,680 assets/readme/diagram-dark.png assets/readme/diagram-dark.svg
```

Delete `assets/src/fonts/` afterwards.

### Recording

From the repository root, with Docker running:

```sh
tests/demoa/run.sh > /tmp/demoa-run.out
python3 -I assets/readme/demo-extract.py var/demoa /tmp/demoa-run.out assets/readme/demo-capture.json
docker run --rm -v "$PWD":/vhs -w /vhs ghcr.io/charmbracelet/vhs:v0.10.0 assets/readme/demo.tape
```

The recording does not run the stack itself. It prints results recorded from a run, because the full
run (two fresh stacks and the conformance rows) takes minutes. `demo-replay.py` adds only headings and
a one-word reading of each status; every argument, status, error and harness row comes from the run.
`tests/demoa/run.sh` exits with status 2 (NOT TESTED rows); that is expected. Update the run date in
the README caption when the capture changes.
