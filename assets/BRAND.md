# Nodkey README and social assets

There is no logo. The name is set as text, and the README opens with a recording of real Demo A
results. The background research is in
[docs/research/design-research.md](../docs/research/design-research.md) (direction A).

## Files

| File | What it is | How it is made |
|---|---|---|
| `readme/demo.gif` | README recording | [VHS](https://github.com/charmbracelet/vhs) (MIT) in the pinned image `ghcr.io/charmbracelet/vhs:v0.10.0`, from `readme/demo.tape` |
| `readme/demo.tape` | VHS script for the recording | Hand-written |
| `readme/demo-capture.json` | Selected results of one real Demo A run, copied verbatim | `readme/demo-extract.py` from `var/demoa/` and the stdout of `tests/demoa/run.sh` |
| `readme/demo-extract.py` | Copies the selected results out of a finished run | Hand-written |
| `readme/demo-replay.py` | Prints `demo-capture.json`; the recording shows its output | Hand-written |
| `social/social-preview.png` | Repository social preview, 1280 x 640 | Headless Chrome screenshot of `social/social-preview.html` |
| `social/social-preview.html` | Source of the social preview | Hand-written |

The recording does not run the stack itself. It prints results recorded from a run, because the full
run (two fresh stacks and the conformance rows) takes minutes. `demo-replay.py` adds only headings and
a one-word reading of each status; every argument, status, error and harness row comes from the run.

## Regenerating

From the repository root, with Docker running:

```sh
tests/demoa/run.sh > /tmp/demoa-run.out
python3 -I assets/readme/demo-extract.py var/demoa /tmp/demoa-run.out assets/readme/demo-capture.json
docker run --rm -v "$PWD":/vhs -w /vhs ghcr.io/charmbracelet/vhs:v0.10.0 assets/readme/demo.tape
```

`tests/demoa/run.sh` exits with status 2 (NOT TESTED rows); that is expected. Update the run date in
the README caption when the capture changes.

Social preview: copy `JetBrainsMono-Regular.ttf` and `JetBrainsMono-Bold.ttf` next to
`social/social-preview.html` (for example from `/usr/share/fonts/jetbrains-mono/` in the VHS image,
with `docker create`, `docker cp` and `docker rm -v`), then run Google Chrome headless (`chrome` below stands for the Chrome binary, for
example `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome` on macOS):

```sh
chrome --headless=new --hide-scrollbars --allow-file-access-from-files \
  --force-device-scale-factor=1 --window-size=1280,640 \
  --screenshot=assets/social/social-preview.png assets/social/social-preview.html
```

Delete the copied font files afterwards; they are not part of the repository.

## Palette

| Role | Hex |
|---|---|
| Background | `#0E1116` |
| Text | `#E6E6E6` |
| Secondary text | `#9DA5B0` (social preview), `#969EA8` (recording) |
| Executed | `#57AB5A` |
| Denied or rejected | `#E5534B` |
| Executed through a stated limit | `#C69026` |

## Typography and licence

JetBrains Mono (SIL Open Font License 1.1) is used to render the recording and the social preview. No
font file is shipped in this repository. The images are covered by the repository licence (see
`LICENSE` and `NOTICE`). Using the name to imply endorsement is not covered by that licence
(Apache-2.0, section 6).
