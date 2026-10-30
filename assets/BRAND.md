# Nodkey brand assets

## Concept

The mark is a key whose bow (the handle) is a filled disc with a checkmark cut out of it. The check is
the "nod": the human approval that the project turns into authority. The blade and its two teeth are
plain rounded strokes. The mark is built from one circle, one check stroke, and three line strokes on
a 64-unit grid, so it stays recognisable at small sizes and works in one colour (the check is a
transparent cut-out, not a second colour).

The palette uses a dark navy ink for structure and text and a single warm accent for the approval
step. The accent appears only on the bow and on the "nod" step of the schematic. It is the one
coloured element, and it marks the step where a human approves.

## Files

| File | Use |
|---|---|
| `brand/nodkey-mark.svg` | Mark alone, for light backgrounds (Ink blade, Brass bow) |
| `brand/nodkey-wordmark.svg` | Mark and wordmark, for light backgrounds |
| `brand/nodkey-wordmark-dark.svg` | Mark and wordmark, for dark backgrounds (Mist text, Amber bow) |
| `icon/nodkey-icon-1024.svg`, `.png` | App icon / avatar: Ink rounded tile, Mist blade, Amber bow. Use this, not the bare mark, at 16 to 32 px |
| `readme/hero-light.png`, `hero-dark.png` | README hero, 1600 x 560 |
| `social/social-preview.png` | Repository social preview, 1280 x 640 |

The PNGs were rendered from hand-written SVG with headless Google Chrome at device scale factor 1.

## Palette

| Name | Hex | Role |
|---|---|---|
| Ink | `#0F1B2A` | Text and mark blade on light backgrounds; icon tile |
| Paper | `#F5F7FA` | Light background |
| Slate | `#4A5868` | Secondary text on light backgrounds |
| Rule | `#C9D2DC` | Hairlines and outlines on light backgrounds (decorative only) |
| Night | `#0D1520` | Dark background |
| Mist | `#E8EDF3` | Text and mark blade on dark backgrounds |
| Fog | `#9AA8B8` | Secondary text on dark backgrounds |
| Night rule | `#2A3747` | Hairlines and outlines on dark backgrounds (decorative only) |
| Amber | `#D99A2B` | Accent on dark backgrounds (bow, "nod" step) |
| Brass | `#B87A14` | Accent on light backgrounds (bow, "nod" step) |

Contrast ratios (WCAG 2.x relative luminance formula, computed for this file):

| Pair | Ratio | Meets |
|---|---|---|
| Ink on Paper | 16.16:1 | AA text |
| Slate on Paper | 6.78:1 | AA text |
| Mist on Night | 15.58:1 | AA text |
| Fog on Night | 7.57:1 | AA text |
| Amber on Night | 7.52:1 | 3:1 non-text graphics |
| Brass on Paper | 3.36:1 | 3:1 non-text graphics, not text |
| Amber on Paper | 2.27:1 | Does not meet 3:1; do not use Amber on light backgrounds |

Do not set text in Amber or Brass on light backgrounds. Rule and Night rule are below 3:1 and are
used only for decorative lines that carry no information.

## Clear space and minimum size

- Keep clear space around the mark of at least the bow radius (15 of 64 grid units)
  on every side. For the wordmark, keep the same clear space measured at the
  mark's size.
- The bare mark is wide and gets small inside a square. At 16 to 32 px use the app icon instead.
- Minimum wordmark height: 24 px.
- Do not rotate, recolour outside the palette, add effects, or separate the check from the bow.

## Typography and licence

No font files are used or shipped. The wordmark "nodkey", the tagline, and the labels in the hero and
social images are hand-drawn monoline glyphs (circles, arcs, and straight strokes) written directly
as SVG paths for these assets. No third-party typeface licence applies.

These assets are part of the repository and are covered by its licence (see `LICENSE` and `NOTICE`).
Using the name and mark to imply endorsement is not covered by that licence (Apache-2.0, section 6).
