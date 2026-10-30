# README header and social preview: design research

Point-in-time note (2026-10-30). Research only; no assets implemented. Ranks as an agent research
note in the source-of-truth hierarchy. Facts below come from the READMEs/pages fetched on this date
(links in each row); judgements are marked as such.

## 1. What admired repos put at the top

| Repo | Logo treatment | One-liner (verbatim) | Hero visual | Badges / density |
|---|---|---|---|---|
| [astral-sh/uv](https://github.com/astral-sh/uv) | None; plain `# uv` | "An extremely fast Python package and project manager, written in Rust." | Benchmark bar chart (light/dark `<picture>`), captioned "Installing Trio's dependencies with a warm cache." | 3 small badges; then a plain bullet list |
| [astral-sh/ruff](https://github.com/astral-sh/ruff) | None; `# Ruff` | "An extremely fast Python linter and code formatter, written in Rust." | Benchmark chart, caption "Linting the CPython codebase from scratch." | 6 badges, then Docs / Playground links |
| [oven-sh/bun](https://github.com/oven-sh/bun) | Mascot logo, centred | "Bun is an all-in-one toolkit for JavaScript and TypeScript apps." | None; code blocks with real commands | 3 badges, link row |
| [tauri-apps/tauri](https://github.com/tauri-apps/tauri) | Full-width splash image | "a framework for building tiny, blazingly fast binaries for all major operating systems" | Splash only | 8 badges (heavy) |
| [zed-industries/zed](https://github.com/zed-industries/zed) | None; `# Zed` | "a high-performance, multiplayer code editor from the creators of Atom and Tree-sitter." | None | 2 badges; 48-line README |
| [charmbracelet/gum](https://github.com/charmbracelet/gum) | Illustrated product image | "A tool for glamorous shell scripts." | VHS terminal GIF; "The above example is running from a single shell script (source)." | 3 badges |
| [charmbracelet/vhs](https://github.com/charmbracelet/vhs) | Wordmark image, light/dark | "Write terminal GIFs as code for integration testing and demoing your CLI tools." | Terminal GIF, with link to the `.tape` that produced it | 3 badges |
| [biomejs/biome](https://github.com/biomejs/biome) | Logo + slogan banner, light/dark SVG | "Toolchain of the web" (in banner) | Banner only | 5 badges, palette-matched colour (`60a5fa`) |
| [supabase/supabase](https://github.com/supabase/supabase) | Wordmark, light/dark | "Supabase is the Postgres development platform." | Real dashboard screenshot | Checklist of features |
| [tailscale/tailscale](https://github.com/tailscale/tailscale) | None | "Private WireGuard® networks made easy" | None | 0 badges; purely factual |
| [ratatui/ratatui](https://github.com/ratatui/ratatui) | Release-header image | "a Rust crate for cooking up terminal user interfaces (TUIs)" | Header image; then working code | 8 badges + 9 links (dense) |
| [sigstore/cosign](https://github.com/sigstore/cosign) | Horizontal colour logo, 300 px | "Signing OCI containers (and other artifacts) using Sigstore!"; "Cosign aims to make signatures **invisible infrastructure**." | None | 4 trust badges (Scorecard, CII) |
| [hashicorp/vault](https://github.com/hashicorp/vault) | Logo below links | "Vault is a tool for securely accessing secrets." | None | CI + enterprise badge |
| [gravitational/teleport](https://github.com/gravitational/teleport) | None at top | "Teleport provides connectivity, authentication, access controls and audit for infrastructure." | Platform image after the bullets | 4 badges |
| [BurntSushi/ripgrep](https://github.com/BurntSushi/ripgrep), [sharkdp/bat](https://github.com/sharkdp/bat) | ripgrep none; bat a small SVG wordmark | "A *cat(1)* clone with syntax highlighting and Git integration." | Real terminal screenshots; ripgrep a timing table with exact hardware | 3 badges each |

Landing pages (fetched as text only, so visuals were not observable): [zed.dev](https://zed.dev)
"Your last next editor" + an editor-UI mockup; [astral.sh](https://astral.sh) "Next-gen Python tooling";
[goteleport.com](https://goteleport.com) "Unified Identity Securing Classic & AI Infrastructure";
[tailscale.com](https://tailscale.com) "The best secure connectivity platform for the AI era";
[vercel.com](https://vercel.com) "Agentic Infrastructure". Linear (linear.app) returned only "Loading…"
to the fetcher and is **not assessed**.

## 2. Patterns (judgement, drawn from the table)

What makes them feel crafted:
1. **The one-liner is a category noun plus one differentiator.** "Python linter… written in Rust";
   "cat(1) clone with syntax highlighting". It says what the thing *is*, not how it makes you feel.
2. **The visual is evidence, not decoration.** A benchmark on a named workload (uv, ruff), a real
   terminal run (gum, vhs, bat, ripgrep), a real UI screenshot (supabase). Each carries a caption that
   names exactly what is shown and often links to the source that reproduces it.
3. **Restraint.** Strongest examples (uv, zed, tailscale, ripgrep) have no logo at the top at all;
   the name in `# H1` is the brand. Logos, when used, are small (cosign 300 px, bat inline).
4. **Light/dark variants done properly** (`<picture>` or `#gh-dark-mode-only`), and badge colours
   matched to the palette (biome).
5. **The README leads into a command within one screen** (bun, gum, vhs, ratatui).

What reads as generic / AI-generated (the current hero hits several):
- **Icon-in-circle → arrow → icon-in-circle pipelines** with one-word labels ("propose → nod →
  execute"). They restate the tagline instead of showing anything true about the system.
- **Stock glyphs as logo** (checkmark, key, shield, lock, sparkle); a checkmark badge is the default
  "approved" metaphor of every template.
- **Pun taglines that need the name to decode** ("Your nod is the key."). None of the studied repos
  leads with wordplay; personality, where present (bun, gum, ratatui "cooking up"), sits *inside* a
  descriptive sentence.
- Rounded geometric display type with wide tracking, soft grey-blue background, one warm accent:
  the default look of generated brand sheets.
- Gradient blobs, glows, isometric illustrations, "AI era" phrasing (note even the big vendors'
  landing heroes above have converged on this, which is a reason to avoid it, not copy it).
- Large splash banners with no information (tauri style) and badge walls.

## 3. Three directions

Constraint common to all: no invented numbers or badges (owner directive); keep "research
prototype" visible; every visual must be reproducible from the repo and captioned with its source.

### A. "The run" — a real terminal recording of Demo A (recommended)

- **Concept:** do what gum/vhs/bat/ripgrep do: show the product working. Nodkey's claim is
  behavioural, so the hero is evidence of behaviour.
- **Hero:** a VHS ([charmbracelet/vhs](https://github.com/charmbracelet/vhs), MIT) recording,
  ~20 s, 1200×640, of a trimmed Demo A run. Script a `docs/demo/demoa.tape` that runs a short,
  hero-specific mode of `tests/demoa/run.sh` against an already-built stack (build time is
  unmeasured, so do not record the build). Show 5–6 rows only, taken from real output
  (QUICKSTART.md "Selected scenario rows"): S2 €20.00 refund inside the mandate → executes;
  S3 €5,000.00 refund on another customer's order → denied, nothing runs; S6 email to
  `x@evil.example` → rejected; S8 message containing card data → **executes (stated limit R-A2)**;
  then the real summary line. Showing S8 is the differentiator: an honest security tool that shows
  its own failure mode in the hero. A still frame (last frame, via
  [charmbracelet/freeze](https://github.com/charmbracelet/freeze), MIT, or a PNG export) is the
  fallback for contexts without GIF. Caption beneath: "Demo A: a scripted prompt-injected agent
  against a fresh stack. Source: `docs/demo/demoa.tape`." Optionally a second, smaller still of the
  real confirmation page (S3) next to it.
- **Logo:** none at top. `# Nodkey` as plain H1, like uv/zed.
- **Palette:** the terminal theme is the palette. Near-black `#0E1116` background, off-white
  `#E6E6E6` text, one semantic pair: denied `#E5534B`, executed `#57AB5A`, limit rows amber
  `#C69026`. Light README variant: the same recording (terminals read fine on white); no light
  re-theme needed.
- **Type:** JetBrains Mono (OFL-1.1) in the recording; GitHub's own type everywhere else.
- **Social preview (1280×640, GitHub's recommended size):** the final frame of the recording
  cropped to the table, with "Nodkey" and the one-liner set in JetBrains Mono top-left. No icons.
- **Why not slop:** it cannot be generated without the software existing; every pixel is checkable
  against a script in the repo.
- **Risk:** the recording must be regenerated when output format changes; pin it in CI or a make
  target and treat it as a test artefact.

### B. Typographic only — wordmark, sentence, invariant

- **Concept:** the zed/tailscale/ripgrep register. Confidence through absence.
- **Hero:** no image in the README at all. `# Nodkey`, the one-liner, then the invariant set as a
  plain blockquote. If a header image is wanted for parity in dark/light, it is pure type: "nodkey"
  in IBM Plex Mono Medium (OFL-1.1), lower-case, tight tracking (−1 %), left-aligned, and beneath it
  in IBM Plex Serif Italic (OFL-1.1) "Compromise of computation must not imply compromise of
  authority." Nothing else.
- **Logo:** wordmark only. One typographic detail allowed, not a glyph: the `k` in a second colour,
  or a hairline rule between `nod` and `key` (the boundary). Test it at 16 px before adopting.
- **Palette:** two colours. Ink `#111111` on paper `#FAFAF7` (light); `#ECECEC` on `#0D0D0D`
  (dark). Optional single accent, oxide red `#B4442C`, used only for the hairline.
- **Social preview:** the same composition at 1280×640, wordmark 120 px, invariant 36 px, generous
  left margin, "research prototype · Apache-2.0" small bottom-left.
- **Why not slop:** no metaphor icons; it relies on a real sentence the project actually defends.
  Cheapest to produce and to keep accurate.
- **Risk:** low recall; depends on the one-liner being strong.

### C. One diagram of the authority boundary

- **Concept:** replace the "three bubbles" with the single fact that is Nodkey's architecture: the
  workload is on the wrong side of a wall and holds nothing. Closer to a technical figure in a paper
  than a marketing graphic.
- **Hero:** an SVG (hand-authored, light and dark files), monochrome line drawing, 1600×560. A
  vertical double rule splits it. Left box: "workload (app or agent)", annotated in small mono:
  `credentials: none` / `network: none` / `can: propose`. Right side: "broker" (holds provider
  credentials) → "provider"; above it "authority" (signing key, no network) fed by "human approves
  exact values". The only crossing of the rule is a single labelled line: `proposal` going right,
  and a dashed `single-use grant` arriving at the broker from the authority. One red mark: an
  attempted direct line from workload to provider ending at the rule with "no route" (true per
  test N-01..N-07). All labels must match ARCHITECTURE.md terminology exactly; get the diagram
  reviewed against the spec so the hero does not over-claim (it is simplified; say so in the
  caption and link ARCHITECTURE.md, as the current mermaid section already does).
- **Logo:** wordmark only, in the diagram's top-left, Inter Display SemiBold (OFL-1.1).
- **Palette:** ink + paper as in B, one alert red `#C8372D` for the blocked path only.
- **Type:** Inter for labels, JetBrains Mono for the annotations.
- **Social preview:** the diagram cropped to the boundary with the wordmark and one-liner.
- **Why not slop:** every element is a real component with a real property; no glyph icons, no
  arrows that do not correspond to a call path.
- **Risk:** diagrams drift from the code; one that is wrong in the hero is worse than none.

## 4. One-liners

Plain, descriptive:
1. "Nodkey lets AI agents and apps propose payments, refunds, and messages; nothing runs until a person approves that exact action."
2. "Human approval for the actions your AI agent takes, enforced outside the agent."
3. "A broker that executes an agent's payments and messages only with a single-use grant from a human approval."
4. "Keep credentials out of your AI agent. It proposes; a separate broker executes what you approve."
5. "Action-level approval for AI agents and apps, with the keys held somewhere the agent cannot reach."
6. "An open-source authority boundary between AI agents and the systems they can change."

With some personality (still literal):
7. "Your agent can be prompt-injected. Your refunds shouldn't be."
8. "Taking over the agent gets you proposals, not payments." (adapted from the README's own "yields proposals, not authority")
9. "The agent asks. You approve the exact action. The broker, not the agent, holds the keys."
10. "Compromise of computation must not imply compromise of authority." (the invariant; best as the second line, not the first)

Avoid: "Your nod is the key.", "for the AI era", "secure by design", "trust layer", "guardrails".

Recommendation (judgement): Direction A with one-liner 1 or 2 as the README sentence and 7 or 8 as
the social-preview line; Direction B as the fallback until the recording exists.
