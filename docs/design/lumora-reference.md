# Recreate this site as a single HTML file: Lumora — Design & Engineering Studio

You are an expert creative front-end developer. Produce a **single self-contained `index.html`** that reproduces the project below **exactly** — same layout, sections, visuals, motion, and interaction. Pure HTML/CSS/JS in one file: no build step, no framework, no bundler. Use ES modules with a CDN importmap for the one library actually used (Lenis smooth-scroll). Hardcode every value given here as a fixed constant. All the CSS below lives in one `<style>` block in `<head>`; the JS in one `<script type="module">` block before `</body>`. The spring / text-reveal animations from the original (react-spring + spring-text-engine) must be reproduced with **plain JS** — a tiny rAF spring helper and/or CSS transitions — achieving the same feel.

## What it is

A single-page, light-palette landing site for **"Lumora — Independent Design & Engineering Studio"**. The page is built on a rem-based adaptive grid (the root font-size scales with the viewport), uses Google **Onest** as the only typeface, and reads as near-white surfaces (`#ffffff` page, `#f1f0ee` light fills) punctuated by deep near-black ink cards (`#0a0a0a`) and a single burnt-orange accent (`#b15f2c`). It opens with a **full-screen dark intro loader** that counts `000 → 100` and slides up; only then do the above-the-fold reveals play. The hero is a **full-bleed before/after photo with a "liquid" cursor-reveal** (moving the pointer paints a soft brush trail of a second image over the first), with a giant `LUMORA` watermark, a line-by-line headline, a carousel card, and a partner grid. Below: an About statement, a four-pill "We / Build / → / Better" band, a 4-card Portfolio on black cards, a 4-row Services list with hover-fill rows, a black Stats panel with scroll-driven count-up numbers, and a black footer with a CTA, link columns and a watermark. A header (Menu button + live local clock) overlays the hero; the Menu opens a full-screen dark overlay; every "Contact / Let's Talk / Start a project" CTA opens a **request modal** (stubbed submit). All smooth-scrolling is driven by **Lenis**.

Sections in DOM order: **PageLoader** → **Header** (fixed overlay) → `main`{ **Hero** → **About** → **CreateBand** → **Portfolio** → **Services** → **Stats** } → **Footer** → **NavMenu** (overlay) → **RequestModal** (overlay).

## Page shell & libraries

### `<head>`

```html
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Lumora — Independent Design & Engineering Studio</title>
<meta name="description" content="Lumora is an independent studio crafting brands, products, and the systems that connect them — bold ideas, shipped with quiet precision." />
<meta name="theme-color" content="#0a0a0a" />
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Onest:wght@400;500;600;700&display=swap" rel="stylesheet">
```

### Importmap + module entry (before `</body>`)

```html
<script type="importmap">
{ "imports": { "lenis": "https://unpkg.com/lenis@1.3.23/dist/lenis.mjs" } }
</script>
<script type="module"> /* all JS below */ </script>
```

Lenis import + raf loop (the original instantiates Lenis with smoothWheel and runs a manual raf loop; it also resets scroll to top on load):

```js
import Lenis from 'lenis';
window.scrollTo(0, 0);
const lenis = new Lenis({ smoothWheel: true });
function raf(t){ lenis.raf(t); requestAnimationFrame(raf); }
requestAnimationFrame(raf);
```

**Scroll lock model.** A single boolean `scrollEnabled` gates everything. When something needs to lock scroll (loader, nav overlay, request modal) call a `stopScroll()` that does `lenis.stop()` and sets `html { position:relative; overflow:hidden; height:100% }`; `startScroll()` does `lenis.start()` and removes those three inline styles. The loader stops scroll on mount and starts it when its exit finishes.

**`scrollTo(id)` helper.** Smooth-scroll to an element by id: temporarily disable scroll-state, then after `50ms` `window.scrollTo({ top: <element top + pageYOffset>, behavior: 'smooth' })`, re-enable after `100ms`. Used by the logo, nav links (non-contact), and the hero "View Work" button.

### Global CSS reset / base

```css
*{ box-sizing:border-box; margin:0; padding:0 }
html{ font-size:16px; -webkit-font-smoothing:antialiased }
body{ background:#ffffff; color:#111111; font-family:'Onest',sans-serif; overflow-x:hidden }
a{ color:inherit; text-decoration:none }
button{ font:inherit; color:inherit; background:none; border:none; cursor:pointer }
ul{ list-style:none }
img{ display:block }
.sr-only{ position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0 }
:focus-visible{ outline:2px solid #b15f2c; outline-offset:2px }
@media (prefers-reduced-motion: reduce){ *{ animation:none !important; transition:none !important } }
```

### The rem-based adaptive grid (CRITICAL — bake exactly)

The whole layout is sized in **rem**; the root font-size scales with the viewport so the design stays proportional. The design base is `FONT_BASE = 16px`. Reproduce the original's media queries verbatim (each = `16 * 100 / baseWidth` vw):

```css
@media (max-width:1920px){ html{ font-size:0.833333vw } }   /* base 1920 */
@media (max-width:1440px){ html{ font-size:1.111111vw } }   /* base 1440 */
@media (max-width:1024px){ html{ font-size:1.5625vw } }     /* base 1024 */
@media (max-width:640px){  html{ font-size:4.444444vw } }   /* base 360  */
```

**Scale-UP above 1920px** (runtime JS, mirrors the original `AdaptiveGrid`): on load + resize, set `html.style.fontSize` to an interpolated value so the layout keeps growing on large displays. Formula with damping `coef = 0.6666`:

```js
function applyAdaptiveGrid(){
  const FONT_BASE = 16, baseWidth = 1920, coef = 0.6666;
  const w = window.innerWidth;
  const widthReduction = ((baseWidth - w) / baseWidth) * 100;   // negative when w > baseWidth
  const size = FONT_BASE - (FONT_BASE * (widthReduction * coef)) / 100;
  if (size > FONT_BASE) document.documentElement.style.fontSize = size + 'px';
  else document.documentElement.style.removeProperty('font-size'); // let media queries drive
}
applyAdaptiveGrid(); addEventListener('resize', applyAdaptiveGrid);
```

Because everything is rem-based, **all sizes below are given in rem/px exactly as Tailwind emitted them** (Tailwind's default scale: `text-sm`=0.875rem, `text-base`=1rem, `text-lg`=1.125rem, `text-xl`=1.25rem, `text-2xl`=1.5rem, `text-3xl`=1.875rem, `text-4xl`=2.25rem, `text-5xl`=3rem, `text-6xl`=3.75rem, `text-7xl`=4.5rem; spacing unit `0.25rem`; `gap-3`=0.75rem etc.). Keep them in rem so the adaptive grid works.

### Shared spring helper (replace react-spring)

Implement one tiny critically-ish-damped spring stepper used for entrance reveals and hovers. react-spring configs are given as `{ tension, friction }`; map them to a stiffness/damping rAF integrator (mass = 1): `accel = tension*(target - x) - friction*v`, integrate at `dt≈1/60`, settle when `|target-x|<0.001 && |v|<0.001`. For entrance reveals you can instead use CSS transitions with the equivalent feel:

- `{ tension:210, friction:26 }` ≈ `cubic-bezier(.22,1,.36,1)` ~0.7s
- `{ tension:200, friction:24 }` / `{180,26}` ≈ `cubic-bezier(.16,1,.3,1)` ~0.8s
- `{ tension:320, friction:18 }` (hovers) ≈ snappy ~0.35s `cubic-bezier(.2,.8,.2,1)`

Either approach is acceptable as long as motion reads springy. Hovers are pointer-driven and disabled on touch (the original disables `Hover` on mobile).

### Text reveal helper (replace spring-text-engine)

Two reveal modes are used; both play **once** when the element scrolls into view (IntersectionObserver, `mode:"once"`), gated additionally on the intro loader being finished for hero text.

- **Line reveal** (`overflow` clip): split the heading into lines (wrap each line in a `span` with `overflow:hidden`; inner span translates `Y 100% → 0%` and `opacity 0 → 1`). Per-line stagger when given (`lineStagger`). Spring/curve ≈ `duration 900ms, easeOutCubic` → `cubic-bezier(0.215,0.61,0.355,1)`.
- **Word reveal** (About statement): split into words; each word `translateY(24px→0)` + `opacity(0→1)`, stagger `35ms` per word, `duration 700ms, easeOutQuart` → `cubic-bezier(0.165,0.84,0.44,1)`.

For simplicity you may split by spaces and treat visual "lines" as the natural wrap; the important part is the staggered slide-up-from-clip feel.

## Fixed palette & tokens (bake these in)

```
--background:#ffffff   --foreground:#111111
--ink:#0a0a0a          (black cards / pills / overlays)
--muted:#8d8d8d        --subtle:#b6b6b6
--line:#e6e5e2         (hairline borders)
--surface:#f1f0ee      --surface-2:#e3e2df
--accent:#b15f2c       --accent-from:#cf8047   --accent-to:#97501f
--hero-from:#ecebe9    --hero-to:#c9c9c9   (hero section bg = hero-to #c9c9c9)
```
Radii: `--radius-pill:9999px`, `--radius-card:2rem`, `--radius-card-sm:1.25rem`, `--radius-control:0.875rem`.
Watermark size: `--text-watermark:13rem`.
Page shell max-width: `--container-shell:88rem` (use `max-width:88rem; margin-inline:auto` for `.shell`).
Font weights used: 400/500/600/700.

### SVG assets to inline (sized `1em`, `fill`/`stroke` = `currentColor`)

- **LogoMark** (brand 4-point spark), `viewBox="0 0 48 48"`, filled:
  `M24 2c2.2 13.8 7.9 19.6 22 22-14.1 2.4-19.8 8.2-22 22-2.2-13.8-7.9-19.6-22-22 14.1-2.4 19.8-8.2 22-22Z`
- **ArrowRight** `viewBox 0 0 24 24` stroke 2 round: `M5 12h14M13 6l6 6-6 6`
- **ArrowUpRight** stroke 2 round: `M7 17 17 7M8 7h9v9`
- **Star** filled: `M12 2.5l2.9 5.88 6.49.94-4.7 4.58 1.11 6.46L12 17.9l-5.8 3.05 1.1-6.46-4.69-4.58 6.49-.94L12 2.5z`
- **Globe** stroke 1.4: `<circle cx=12 cy=12 r=9.25/>` + `M12 2.75c2.6 2.3 4 5.8 4 9.25s-1.4 6.95-4 9.25c-2.6-2.3-4-5.8-4-9.25s1.4-6.95 4-9.25zM2.75 12h18.5`
- **X / close** stroke 2 round: `M4 4l16 16M20 4 4 20`
- **CircleDot** stroke 1.6: `<circle cx12 cy12 r9/>` + filled `<circle cx12 cy12 r3.2/>`
- **Grid / menu** (three lines) stroke 2 round: `M4 6h16M4 12h16M4 18h16`

---

## The loader / reveal (PageLoader)

A fixed full-screen panel on top of everything from first paint. `position:fixed; inset:0; z-index:120; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:2rem; background:#0a0a0a; color:#fff; border-radius:0 0 2rem 2rem` (rounded bottom corners — `rounded-b-card`).

- Locks scroll on mount (`stopScroll()`).
- **Center content** (`gap:1.25rem`, centered text, `opacity 1`): a row `font-weight:600; font-size:1.5rem` (sm: 1.875rem) reading `[LogoMark, 1.875rem, color:#cf8047] Lumora`; below it a `max-width:24ch; font-size:0.875rem; color:rgba(255,255,255,.55)` paragraph: **"Bold ideas, shipped with quiet precision."**
- **Progress block** `width:min(22rem,72vw); gap:0.75rem`: a `height:1px` track `background:rgba(255,255,255,.15)` with an inner fill `height:100%; background:#cf8047; width:<progress>%; transition:width .1s ease-out`. Below it a row `justify-content:space-between; font-size:0.75rem; font-weight:500; text-transform:uppercase; letter-spacing:.05em; color:rgba(255,255,255,.45)` → left `Loading`, right a tabular-nums counter `color:rgba(255,255,255,.8)` showing the number **zero-padded to 3 digits** (`000`…`100`).
- **Count animation:** drive progress `0 → 100` over `FILL_MS = 1300ms`, eased with **easeInOutCubic** (`t<.5 ? 4t³ : 1-((-2t+2)³)/2`), `progress = round(ease(t)*100)`.
- **Exit:** when the count reaches 100, slide the whole panel up: `transform: translateY(0%) → translateY(-100%)` with spring feel `{tension:220,friction:30}` (~`cubic-bezier(.22,1,.36,1)`, ~0.7s); simultaneously fade the center content `opacity 1→0, translateY 0→-12px`. When the slide finishes: set the global **intro `ready` flag true**, `startScroll()`, and remove the loader from the DOM. All hero reveals are gated on `ready` (they only begin after the loader has left).

---

## Layout & sections (in order)

A `.shell` wrapper = `max-width:88rem; margin-inline:auto`. Default horizontal padding `px-5`=1.25rem, `sm:px-8`=2rem (sm breakpoint = 640px). `lg` = 1024px.

### A skip link (first focusable)

`<a href="#main">Skip to content</a>` — visually hidden until focused, then `position:fixed; left:1rem; top:1rem; z-index:60; border-radius:.875rem; background:#0a0a0a; padding:.5rem 1rem; font-size:.875rem; color:#fff`.

---

### 1) Header (fixed overlay, entrance gated on `ready`)

`position:absolute; inset-inline:0; top:0; z-index:50`. Entrance: `opacity 0→1, translateY(-14px→0)`, spring `{210,26}`, delay `150ms` after `ready`.

Inner: `.shell` flex row, `align-items:center; justify-content:space-between; gap:1.5rem; padding:1.25rem` (sm: `2rem 2rem` → `py-6 px-8`).

- **Left — brand button** (`onClick → scrollTo('home')`): a hover-spring `span` (`scale 1→1.04`, `{320,18}`) `display:flex; align-items:center; gap:.5rem; font-size:1.125rem; font-weight:600; letter-spacing:-.01em` → `[LogoMark 1.25rem color:#b15f2c] Lumora`.
- **Center — primary nav** (`display:none` below `lg`, then `flex`): `ul` `gap:2rem; font-size:.875rem; font-weight:500`. Items (each a button; hover lifts the label `translateY(0→-2px)` + `opacity .8→1`, `{320,22}`): **Home** (current, `aria-current=page`), **Work**, **Services** (with a `▾` dropdown caret, `font-size:.75rem opacity:.6`), **Studio**, **Careers**, **Contact**. Click routing: `Home→#home`, `Work→#works`, `Services→#services`, `Studio→#about`, `Careers→#careers`, `Contact→opens request modal`. Non-contact links call `scrollTo(id)`.
- **Right — clock chip + Menu**:
  - Clock chip (`display:none` below `md`=768px, then `flex`): `border:1px solid rgba(230,229,226,.8); background:rgba(255,255,255,.4); backdrop-filter:blur(4px); border-radius:.875rem; padding:.5rem .75rem; gap:.75rem; font-size:.75rem; color:rgba(17,17,17,.7)`. Contents: muted label **"Local time"** (`color:rgba(17,17,17,.45)`), then a `min-width:3.5rem; tabular-nums; font-weight:500; color:#111` **live time** (e.g. `9:41am`), a `•` separator (`color:rgba(17,17,17,.3)`), then a `font-weight:500` **live date** (e.g. `12 March, 2025`).
  - **Live clock JS:** update every 1s. Time = `H:MM` + lowercase meridiem, no leading zero on hour (`hours%12||12`, minutes padded to 2). Date = `D Month, YYYY` (full month name). Until first tick, show fallbacks `9:41am` / `12 March, 2025`.
  - Menu button (`onClick → open NavMenu`): `border:1px solid rgba(230,229,226,.8); background:rgba(255,255,255,.4); backdrop-filter:blur(4px); border-radius:.875rem; hover bg:rgba(255,255,255,.7)`. Inner hover-spring span (`scale 1→1.05`): `padding:.5rem 1rem; font-size:.75rem; font-weight:500; text-transform:uppercase; letter-spacing:.05em` → `[GridIcon .875rem] Menu` (the word "Menu" hidden below `sm`).

---

### 2) Hero (`#home`) — full-bleed before/after liquid reveal

`section#home`: `position:relative; isolation:isolate; overflow:hidden; border-radius:0 0 2rem 2rem; background:#c9c9c9` (hero-to).

**A) LiquidReveal full-bleed background** (`position:absolute; inset:0; z-index:0`). This is the signature effect — reproduce its mechanics exactly:

- A positioned container holds: (1) a `<img>` of the **before** image, `object-fit:cover`, `position:absolute; inset:0; width/height:100%` — always visible, the LCP image; (2) a `<canvas aria-hidden>` `position:absolute; inset:0; width/height:100%; pointer-events:none` that paints the **after** image along the cursor trail.
- **IMPORTANT image mapping (preserve exactly):** `beforeSrc = .../hero/after.jpg` (the always-shown base image) and `afterSrc = .../hero/before.jpg` (the brush-revealed image). I.e. the file named `after.jpg` is shown by default and the file named `before.jpg` is painted on the cursor trail. Do not swap them.
- **Params:** `brushRadius = 143` (CSS px), `decay = 0.016` per frame, `dpr = min(devicePixelRatio, 2)`.
- **Canvas sizing:** size the main canvas to the container rect × dpr; keep CSS size = rect size. On resize (ResizeObserver on the container) re-measure. Build an offscreen **cover** canvas at canvas resolution and draw the `after` image into it with `object-fit:cover` math (scale to fill, center). `radius = brushRadius*dpr`; a **brush** offscreen canvas is `diameter = ceil(radius*2)` square.
- **Pointer trail:** listen to `pointermove` on `window`. Convert client coords to canvas space (×dpr). Ignore points more than `radius` outside the canvas (and reset `last`). Interpolate between the last point and the new point: `step = max(radius*0.3, 1)`, `n = min(ceil(dist/step), 60)` intermediate points pushed into a `points` array.
- **Per-frame tick (rAF):**
  - If there are queued points → `idle = 0`; else increment `idle` and bail once `idle > 120`.
  - Compute `fade = drawing ? decay : min(decay + idle*0.004, 0.5)`. Apply `globalCompositeOperation:'destination-out'; fillStyle = rgba(0,0,0,fade); fillRect(full)` so the existing trail decays.
  - If drawing: for each queued point **stamp** it, then clear the queue. If idle reaches 120 frames: `clearRect(full)` (hard clear so no residue lingers).
  - **stamp(x,y):** on the brush canvas, clear, `source-over`, draw a radial gradient centered (`addColorStop 0 → rgba(255,255,255,1)`, `0.55 → rgba(255,255,255,.82)`, `1 → rgba(255,255,255,0)`), fill the square. Then `source-in`, draw the matching region of the **cover** canvas (`drawImage(cover, x-c,y-c,diam,diam, 0,0,diam,diam)`) so only the after-pixels under the soft brush remain. Finally on the main canvas `source-over`, `drawImage(brush, x-c, y-c)`.
  - Honor `prefers-reduced-motion: reduce` → skip the canvas entirely, leave only the static base image.

**B) Legibility vignette** `position:absolute; inset:0; z-index:1; pointer-events:none; background:linear-gradient(to bottom, rgba(255,255,255,.35), transparent, rgba(255,255,255,.35))`.

**C) Brand watermark** (`pointer-events:none; position:absolute; inset-inline:0; bottom:7rem; z-index:1; text-align:center; user-select:none; font-weight:700; line-height:1; font-size:13rem; color:rgba(255,255,255,.4)`) text **LUMORA**. Reveal (gated on `ready`): `opacity 0→0.4, translateY(20px→0)`, `{120,30}`, delay `300ms`.

**D) Content grid** `.shell` `position:relative; z-index:20; display:flex; flex-direction:column; gap:2rem; padding:7rem 1.25rem 5rem` (sm px 2rem; lg: `display:grid; min-height:100lvh; grid-template-columns:repeat(12,1fr); gap:2.5rem; padding:9rem 2rem 7rem`).

- **Left column** (`lg:grid-column: span 7`), `display:flex; flex-direction:column; gap:1.75rem`:
  - **Eyebrow** (reveal `opacity/translateY(10px)`, delay 200ms): a `font-size:.875rem; font-weight:500; color:rgba(17,17,17,.7); display:inline-flex; align-items:center; gap:.5rem` with a leading `0.375rem` dot (`background:rgba(17,17,17,.5); border-radius:9999px`) → **"Independent Studio"**.
  - **H1** (line reveal, gated on `ready`, delay 250ms, `lineStagger 120ms`, easeOutCubic 900ms, `overflow` clip): `max-width:18ch; font-size:2.25rem; font-weight:600; line-height:.98; letter-spacing:-.02em` (sm 3rem, md 3.75rem). Lines: **"Bold ideas,"** / **"shipped with"** / **"quiet precision"**.
  - **Rating row** (reveal, delay 650ms): `display:flex; align-items:center; gap:.75rem`. A `color:#b15f2c` span with **5** Star icons (`font-size:1rem`), then `font-size:.875rem; font-weight:500; color:rgba(17,17,17,.7)` text **"200+ brands shipped"**.
  - **CTA row** (reveal, delay 750ms): `display:flex; flex-wrap:wrap; gap:.75rem`. Two pill buttons: **"Let's Talk"** (variant `dark`, with arrow → opens request modal) and **"View Work"** (variant `outline` → `scrollTo('works')`).
- **Right column** (`lg:span 5`), `display:flex; flex-direction:column; align-items:flex-start; gap:2rem` (lg: `align-items:flex-end`):
  - **HeroCard** (carousel) — reveal `opacity/translateY(16px) scale(.96→1)`, `{200,24}`, delay 400ms. Card: `width:100%; max-width:24rem (lg width:19rem); border-radius:1.25rem; background:rgba(255,255,255,.7); padding:.5rem; box-shadow: sm; box-shadow ring 1px rgba(230,229,226,.7); backdrop-filter:blur(12px)`. Inside a clickable row (`display:flex; gap:.5rem; cursor:pointer; border-radius:.875rem`):
    - Left tile: `aspect-ratio:1; width:6rem; display:grid; place-items:center; border-radius:.875rem; background:#0a0a0a; font-size:1.875rem; color:#fff` containing a `LogoMark` in `color:#cf8047`.
    - Right panel: `flex:1; border-radius:.875rem; background:rgba(241,240,238,.7); padding:.75rem; display:flex; flex-direction:column; justify-content:space-between`. Top = a `position:relative; min-height:3.25rem` slot showing the active item: a `font-size:.65rem; font-weight:500; uppercase; letter-spacing:.05em; color:rgba(17,17,17,.45)` **caption** over a `max-width:8rem; font-size:.875rem; font-weight:500; line-height:1.35` **title**. Items (cycle): `{caption:"Conversion design", title:"Crafted to convert."}`, `{caption:"Engineering", title:"Built to scale."}`, `{caption:"Brand systems", title:"Designed to last."}`. Bottom row: dots on the left (`h:1px*`… actually 3 dashes `height:.25rem; border-radius:9999px`; active = `width:1rem; background:rgba(17,17,17,.7)`, inactive = `width:.375rem; background:rgba(17,17,17,.2)`, `transition:all .3s`) and prev/next buttons on the right (`size:1.75rem; display:grid; place-items:center; border-radius:9999px; background:#fff; color:rgba(17,17,17,.7); ring 1px #e6e5e2; hover color:#111`, prev = ArrowRight rotated 180°, next = ArrowRight). **Behavior:** clicking the card or Next advances; Prev goes back; wraps around `(i+step+n)%n`. Swap animation: outgoing item fades/slides `translateY(±14px)`, incoming enters from `translateY(∓14px) → 0`, `{300,28}`.
  - **Partners** (reveal `translateY(14px)`, `{200,24}`, delay 550ms): `width:100%; max-width:24rem (lg 19rem)`. A label `margin-bottom:.75rem; font-size:.75rem; font-weight:500; color:rgba(17,17,17,.45); text-align:left` (lg right) **"Trusted by"**. Then a `display:grid; grid-template-columns:repeat(4,1fr); column-gap:1rem; row-gap:.75rem` list; each item is a hover-spring span (`translateY(0→-2px)`, `opacity .7→1`, `{320,20}`) `display:flex; align-items:center; gap:.375rem; font-size:.75rem; color:rgba(17,17,17,.7)` → `[CircleDot .875rem color:rgba(17,17,17,.4)] <name>`. Names: **Kaido, Northpeak, Vellum, Orbit, Brightline, Cobalt, Mesa**.

**E) Bottom status bar** (reveal opacity only, delay 900ms): `.shell` `display:flex; align-items:center; justify-content:space-between; gap:.75rem; border-top:1px solid rgba(17,17,17,.1); padding:1.25rem; font-size:.75rem; font-weight:500; text-transform:uppercase; letter-spacing:.025em; color:rgba(17,17,17,.6)` (sm px 2rem). Left **"Working since 2014"**; center **"Remote-first, worldwide"** (hidden below sm); right `inline-flex; gap:.5rem` **"Scroll to explore"** + a `↓`.

---

### 3) About (`#about`)

`section#about` `background:#fff`. `.shell` `display:grid; grid-template-columns:1fr; align-items:center; gap:3rem; padding:5rem 1.25rem` (sm px 2rem; lg: `grid-template-columns:1fr 1fr; padding-block:7rem`).

- **Left — globe block** `position:relative; min-height:14rem` (lg 20rem): a big background `Globe` icon `position:absolute; left:-1rem; top:50%; transform:translateY(-50%); font-size:12rem; color:rgba(17,17,17,.1)` (sm 16rem, lg `left:-1.5rem; 20rem`). Eyebrow **"The Studio"** (`position:relative`). Bottom-left a reveal block (`translateY(12px)`) `display:flex; align-items:center; gap:.75rem; font-size:.875rem; color:rgba(17,17,17,.7)` → `[Globe 1.5rem color:#111] <span max-width:14rem>` **"A distributed team building across every time zone."**
- **Right — statement** `display:flex; flex-direction:column; gap:2.5rem`:
  - **H2** (word reveal, `wordStagger 35ms`, easeOutQuart 700ms, `translateY 24px`): `font-size:1.5rem; font-weight:500; line-height:1.35; letter-spacing:-.01em` (sm 1.875rem). Text: **"We partner with ambitious teams to ship "** then in `color:#8d8d8d`: **"digital products, brand systems, and the strategy that holds them together."**
  - **Footer row** (reveal `translateY(12px)`, delay 200ms): `display:flex; flex-wrap:wrap; align-items:flex-end; justify-content:space-between; gap:1.5rem; border-top:1px solid #e6e5e2; padding-top:1.5rem`. Left: a `font-size:.875rem; color:rgba(17,17,17,.45)` label **"Find us online"** above a `display:flex; gap:.5rem` row of 3 social chips (`size:2.25rem; display:grid; place-items:center; border-radius:9999px; font-size:.875rem`; each inner icon hover-springs `scale 1→1.18`, `{320,16}`): **X / Twitter** = `background:#b15f2c; color:#fff` with the X icon; **Behance** and **Dribbble** = `background:#f1f0ee; color:rgba(17,17,17,.7)` with a CircleDot icon. Right: a pill button **"About Us"** (variant `outline`, withArrow, href `#about`).

---

### 4) CreateBand ("We Build → Better")

`section` `background:#fff`. `ul` `.shell` `display:flex; flex-direction:column; gap:.75rem; padding:2.5rem 1.25rem` (sm: `flex-direction:row; gap:1rem; px 2rem`). Four `li flex:1`, each a reveal (`translateY(28px)`, `{200,22}`, delay `index*120ms`) wrapping a hover-spring tile (`scale 1→1.03`, `{300,18}`) `display:grid; place-items:center; height:6rem; border-radius:9999px; font-size:1.875rem; font-weight:500` (sm: `height:10rem; font-size:2.25rem`). Words/variants:
1. **"We"** — variant `light`: `background:#f1f0ee; color:#111`.
2. **"Build"** — variant `accent`: `background:linear-gradient(to bottom right,#cf8047,#97501f); color:#fff`.
3. (arrow) — variant `dark`: `background:#0a0a0a; color:#fff`, content = ArrowRight icon `font-size:2.25rem` (sm 3rem).
4. **"Better"** — variant `ghost`: `background:rgba(241,240,238,.6); color:rgba(17,17,17,.35)`.

---

### 5) Portfolio (`#works`)

`section#works` `background:#fff`. `.shell` `padding:2.5rem 1.25rem 5rem` (sm px 2rem; lg pb 7rem).

- **Eyebrow** (reveal, centered): an Eyebrow with extra `border:1px solid #e6e5e2; border-radius:9999px; padding:.375rem 1rem` → **"Portfolio"**.
- **H2** (line reveal, easeOutCubic 900ms, delay 120ms, `overflow`, centered, `width:fit-content`): `font-size:2.25rem; font-weight:600; letter-spacing:-.02em` (sm 3rem) → **"Selected Work"**.
- **Cards** `display:grid; grid-template-columns:1fr; gap:1.5rem` (md=768px: 2 cols). Each card is a reveal `li` (`translateY(48px)`, `{180,26}`, delay `index*90ms`) wrapping a link → hover-spring `article` (`translateY(0→-8px) scale(1→1.012)`, `{260,22}`): `position:relative; min-height:22rem; overflow:hidden; border-radius:2rem; background:#0a0a0a; padding:1.5rem; color:#fff; box-shadow ring 1px rgba(255,255,255,.05)` (sm `min-height:26rem; padding:2rem`).
  - Top meta row `display:flex; justify-content:space-between; font-size:.75rem; text-transform:uppercase; letter-spacing:.025em; color:rgba(255,255,255,.45)`: left `<category> — <year>`; right a hover-spring badge **triggered by the whole card** (`rotate 0→45deg, scale 1→1.08`, `{280,18}`) `size:2.75rem; display:grid; place-items:center; border-radius:9999px; background:rgba(255,255,255,.1); color:#fff; ring 1px rgba(255,255,255,.15)` containing ArrowUpRight.
  - Centered watermark: `position:absolute; inset:0; display:grid; place-items:center; pointer-events:none` → `[LogoMark font-size:4.5rem color:rgba(255,255,255,.9)]` with a tiny `® font-size:.75rem color:rgba(255,255,255,.6)`.
  - Bottom block `position:absolute; inset-inline:1.5rem; bottom:1.5rem` (sm 2rem): `h3 font-size:1.5rem; font-weight:500; letter-spacing:-.01em` (sm 1.875rem) = name; `p margin-top:.5rem; max-width:28rem; font-size:.875rem; color:rgba(255,255,255,.55)` = description; then a `margin-top:1.25rem; display:flex; flex-wrap:wrap; gap:.5rem` of tag chips (`display:inline-flex; border:1px solid rgba(255,255,255,.25); color:#fff; border-radius:9999px; padding:.5rem 1rem; font-size:.875rem`).
  - **Items:**
    1. **Aster Labs** — Branding — 2025 — "A complete identity and go-to-market system for a fast-moving research startup." — tags: Branding, Strategy, Design.
    2. **Nova Finance** — Product — 2024 — "A finance platform reimagined — clear data, calm interfaces, and effortless flows." — tags: Product Design, Web App, QA.
    3. **Helio Studio** — Identity — 2023 — "A bold visual identity and art direction system built to scale across every surface." — tags: Brand Identity, Art Direction.
    4. **Pulse Health** — Mobile — 2023 — "A wellness app grounded in research, shipped end to end from concept to release." — tags: Mobile App, UX Research, Development.

---

### 6) Services (`#services`)

`section#services` `background:#fff`. `.shell` `padding:5rem 1.25rem` (sm px 2rem; lg py 7rem).

- **Eyebrow** (reveal) **"Services"**.
- **H2** (line reveal, easeOutCubic 900ms, delay 120ms, overflow): `margin:1.25rem 0 3rem; max-width:16ch; font-size:2.25rem; font-weight:600; letter-spacing:-.02em` (sm `margin-bottom:3.5rem; font-size:3rem`) → **"What we do best"**.
- **Rows** `ul`. Each row is a reveal `li` (`translateY(24px)`, `{200,24}`, delay `index*80ms`) `border-top:1px solid #e6e5e2` (first row no top border) wrapping a link → a **hover-spring row** that fills on hover: `from { background:rgba(241,240,238,0); padding-left:1.5rem; padding-right:1.5rem }` → `to { background:rgba(241,240,238,1); padding-left:2rem; padding-right:1.25rem }`, `{240,26}`; base `display:flex; align-items:center; gap:1rem; border-radius:1.25rem; padding-block:1.5rem` (sm `gap:1.5rem; padding-block:2rem`). Cells: index `width:1.75rem; font-size:.875rem; font-weight:500; color:rgba(17,17,17,.4)` (sm `width:2.5rem`); `h3 flex:1; font-size:1.5rem; font-weight:500; letter-spacing:-.01em` (sm 1.875rem, md 2.25rem) = title; a description `p` (hidden below lg) `max-width:20rem; font-size:.875rem; color:rgba(17,17,17,.55)`; a trailing badge — hover-spring **triggered by the row** (`translateX 0→5px`, `{300,18}`) `size:2.5rem; display:grid; place-items:center; border-radius:9999px; background:#0a0a0a; color:#fff` (sm `size:3rem`) with ArrowUpRight.
  - **01 Software Development** — "Scalable web & mobile products built to last."
  - **02 Product Design** — "Interfaces that feel effortless and look sharp."
  - **03 Quality Assurance** — "Rigorous testing for flawless, confident releases."
  - **04 Consulting** — "Strategy and direction for ambitious teams."

---

### 7) Stats (black panel, scroll count-up)

`section` `background:#fff`. `.shell` `padding:0 1.25rem 5rem` (sm px 2rem; lg pb 7rem). Inside, a reveal panel (`translateY(40px) scale(.99→1)`, `{180,26}`): `border-radius:2rem; background:#0a0a0a; padding:3rem 1.5rem; color:#fff` (sm `padding:4rem 2rem`, md `padding-inline:4rem`).

- **Eyebrow** tone `light` (`color:rgba(255,255,255,.7)`, dot `rgba(255,255,255,.6)`) **"By the numbers"**.
- **H2** (line reveal, easeOutCubic 900ms, delay 120ms, overflow): `margin-top:1rem; max-width:20ch; font-size:1.875rem; font-weight:500; letter-spacing:-.01em` (md 2.25rem) → **"Proof in the work, not the words."**
- **Grid** `margin-top:3.5rem; display:grid; grid-template-columns:repeat(2,1fr); column-gap:2rem; row-gap:3rem` (lg 4 cols). Each stat is a reveal `li` (`translateY(20px)`, `{200,24}`, delay `index*90ms`): a `font-size:3rem; font-weight:600; letter-spacing:-.02em` number (sm 3.75rem, md 4.5rem) followed by `<suffix>`, then `margin-top:.75rem; font-size:.875rem; color:rgba(255,255,255,.55)` label.
  - **Count-up:** drive each number with a scroll-progress trigger from **`start:"top bottom"` → `end:"center center"`** (progress 0 when the element's top hits viewport bottom, 1 when its center hits viewport center); display `round(progress * value)`. Throttle ~30ms.
  - Stats: **150+** "Projects delivered", **98%** "Client retention", **12** "Years of craft" (no suffix), **40+** "Team members".

---

### 8) Footer (black, CTA + columns + watermark)

`footer` `position:relative; overflow:hidden; border-radius:2rem 2rem 0 0; background:#0a0a0a; color:#fff`. Inner `.shell` `position:relative; z-index:10; padding:5rem 1.25rem 2.5rem` (sm px 2rem; lg pt 6rem).

- **CTA row** `display:flex; flex-direction:column; gap:2rem; border-bottom:1px solid rgba(255,255,255,.1); padding-bottom:4rem` (lg: `flex-direction:row; align-items:flex-end; justify-content:space-between`):
  - **H2** (line reveal, `lineStagger 100ms`, easeOutCubic 900ms, overflow): `max-width:16ch; font-size:2.25rem; font-weight:600; letter-spacing:-.02em` (sm 3rem, md 3.75rem) → **"Have a project in mind? Let's get to work."**
  - Pill button **"Start a project"** (variant `light`, withArrow, arrow `up-right` → opens request modal).
- **Columns** `display:grid; grid-template-columns:1fr; gap:3rem; padding-block:4rem` (md 2 cols, lg 4 cols):
  - Brand col: `[LogoMark 1.25rem] Lumora` (`font-size:1.125rem; font-weight:600`) over `max-width:20rem; font-size:.875rem; color:rgba(255,255,255,.55)` tagline **"An independent studio crafting brands, products, and the systems that connect them."**
  - **Company:** About (#about), Careers (#careers), Partners (#partners), Contact (#contact).
  - **Services:** Development (#development), Design (#design), Quality Assurance (#qa), Consulting (#consulting).
  - **Social:** X / Twitter, Behance, Dribbble, LinkedIn.
  - Column titles: `font-size:.75rem; text-transform:uppercase; letter-spacing:.025em; color:rgba(255,255,255,.4)`. Links: `font-size:.875rem`, each an **AnimatedLink** = hover-spring span (`translateX 0→4px, opacity .65→1`, `{320,22}`).
- **Legal bar** `display:flex; flex-direction:column; align-items:center; justify-content:space-between; gap:1rem; border-top:1px solid rgba(255,255,255,.1); padding-top:2rem; font-size:.75rem; color:rgba(255,255,255,.45)` (sm row): left **"© 2025 Lumora Studio. All rights reserved."**; right a `gap:1.5rem` row of AnimatedLinks (`translateX 0→3px, opacity .7→1`) **Privacy** (#privacy), **Terms** (#terms).
- **Watermark** `position:absolute; inset-inline:0; bottom:-1.5rem; z-index:0; text-align:center; pointer-events:none; user-select:none; font-weight:700; line-height:1; font-size:13rem; color:rgba(255,255,255,.05)` → **LUMORA**.

---

### 9) NavMenu (full-screen overlay)

Opened by the header Menu button (and not present until opened). `position:fixed; inset:0; z-index:115; display:flex; flex-direction:column; background:#0a0a0a; color:#fff`. Open/close = fade `opacity 0↔1`, `{280,32}`. On open: `stopScroll()`, listen for `Escape` to close; on close: `startScroll()`.

- **Top bar** `.shell` `display:flex; align-items:center; justify-content:space-between; padding:1.25rem` (sm `1.5rem 2rem`): left `[LogoMark 1.25rem color:#cf8047] Lumora` (`font-size:1.125rem; font-weight:600`); right a **Close** button `display:inline-flex; gap:.5rem; border:1px solid rgba(255,255,255,.15); border-radius:.875rem; padding:.5rem 1rem; font-size:.75rem; font-weight:500; text-transform:uppercase; letter-spacing:.05em; color:rgba(255,255,255,.7); hover border:rgba(255,255,255,.4) color:#fff` → `[X .875rem] Close`.
- **Nav** `.shell` `flex:1; display:flex; flex-direction:column; justify-content:center`. `ul gap:.25rem`. Each item a full-width button (`display:flex; gap:1rem; padding-block:.5rem; text-align:left; font-size:2.25rem; font-weight:600; letter-spacing:-.02em`, sm 3.75rem) that **staggers in** on open: `transition:all .5s ease-out; transition-delay:<index*45 + 80>ms`; entered state = `translateY(0) opacity 1`, initial = `translateY(1rem) opacity 0`. Each contains a small index `0<n>` (`font-size:1rem; font-weight:400; color:rgba(255,255,255,.3)`, group-hover → `color:#cf8047`) and the label (`color:rgba(255,255,255,.7)`, group-hover → `#fff`, `transition .3s`). Items: **Home, Work, Services, Studio, Careers, Contact** (same routing as header; Contact opens the request modal; clicking any item closes the menu first).
- **Bottom bar** `.shell` `display:flex; flex-direction:column; gap:.75rem; border-top:1px solid rgba(255,255,255,.1); padding:1.5rem 1.25rem; font-size:.75rem; text-transform:uppercase; letter-spacing:.025em; color:rgba(255,255,255,.45)` (sm row, justify-between, px 2rem): left **"Local time — <live time>"** (fallback just "Local time"); right a button **"Start a project →"** (`color:rgba(255,255,255,.7); hover underline + #fff`) → closes menu + opens request modal.

---

### 10) RequestModal (stubbed submit)

Opened by any "Contact / Let's Talk / Start a project / Send request" CTA. Backdrop: `position:fixed; inset:0; z-index:110; display:flex; align-items:flex-end; justify-content:center; padding:1rem; background:rgba(17,17,17,.3); backdrop-filter:blur(16px)` (sm `align-items:center`), `role=dialog aria-modal=true`. Click the backdrop to close; `Escape` closes; on open `stopScroll()`, on close `startScroll()`. Enter/exit: panel `opacity 0↔1` + `translateY(28px → 0 → 18px)`, `{260,30}`.

Panel: `position:relative; width:100%; max-width:32rem; overflow:hidden; border-radius:2rem; background:#fff; padding:1.5rem; box-shadow:2xl; ring 1px #e6e5e2` (sm padding 2rem). `stopPropagation` on panel click. Top-right Close button `position:absolute; right:1rem; top:1rem; size:2.25rem; display:grid; place-items:center; border-radius:9999px; background:#f1f0ee; color:rgba(17,17,17,.6); hover bg:#e3e2df color:#111` with X icon.

**Default (form) state:**
- Heading block `margin-bottom:1.5rem; gap:.375rem`: a `inline-flex; gap:.5rem; font-size:.875rem; font-weight:500; color:rgba(17,17,17,.6)` row with a `.375rem` accent dot (`background:#b15f2c`) + **"Start a project"**; then `h2 font-size:1.5rem; font-weight:600; letter-spacing:-.01em` (sm 1.875rem) → **"Tell us what you're building."**
- Form `display:flex; flex-direction:column; gap:1rem`. Three fields, each a `label` with a `font-size:.75rem; font-weight:500; uppercase; letter-spacing:.025em; color:rgba(17,17,17,.5)` caption above the control. Controls: `width:100%; border:1px solid #e6e5e2; background:rgba(241,240,238,.5); border-radius:.875rem; padding:.75rem 1rem; font-size:.875rem; outline:none; transition; focus → border:rgba(17,17,17,.3) background:#fff`.
  - **Name** (text, required, placeholder "Your name")
  - **Email** (email, required, placeholder "you@company.com")
  - **Project** (textarea, 4 rows, required, `resize:none`, placeholder "A few words about your project, timeline, and budget.")
- Bottom row `margin-top:.5rem; display:flex; align-items:center; justify-content:space-between; gap:1rem`: a `font-size:.75rem; color:rgba(17,17,17,.45)` note **"We reply within one business day."** and a pill button **"Send request"** (variant `dark`, withArrow, arrow `up-right`, `type=submit`; while submitting label = "Sending…").
- **Submit is a no-op/stub:** prevent default, briefly show "Sending…", then switch to the **success** state (no network call).

**Success state** (centered, `padding-block:2rem; gap:1rem`): a `size:3.5rem; display:grid; place-items:center; border-radius:9999px; background:#0a0a0a; color:#cf8047; font-size:1.5rem` LogoMark badge; `h2 font-size:1.5rem; font-weight:600` **"Request received"**; `max-width:32ch; font-size:.875rem; color:rgba(17,17,17,.6)` **"Thanks for reaching out — we'll get back to you within one business day."**; a pill button **"Close"** (variant `dark`) that closes the modal. Reset the form ~300ms after the modal closes.

---

## Shared component recipes

**PillButton** — `inline-block`, wraps a hover-spring scale (`scale 1→1.04`, `{320,18}`, triggered by the root). Inner pill = `inline-flex; align-items:center; gap:.75rem; border-radius:9999px; font-size:.875rem; font-weight:500`. Variants: `dark` = `background:#0a0a0a; color:#fff`; `light` = `background:#f1f0ee; color:#111`; `outline` = `border:1px solid #e6e5e2; background:transparent; color:#111`. Padding: with arrow = `.375rem .375rem .375rem 1.5rem` (`py-1.5 pl-6 pr-1.5`); without arrow = `.875rem 1.75rem` (`py-3.5 px-7`). With arrow: append a `size:2.25rem; display:grid; place-items:center; border-radius:9999px; font-size:1rem` badge (dark variant badge = `background:#fff; color:#0a0a0a`; other variants = `background:#0a0a0a; color:#fff`) whose icon hover-springs (triggered by the button root): `right` arrow shifts `translate(3px,0)`, `up-right` arrow shifts `translate(2px,-2px)`, `{320,18}`. Icon = ArrowRight or ArrowUpRight per `arrow`.

**Eyebrow** — `inline-flex; align-items:center; gap:.5rem; font-size:.875rem; font-weight:500`. Leading `.375rem` round dot. `dark` tone: text `rgba(17,17,17,.7)`, dot `rgba(17,17,17,.5)`. `light` tone: text `rgba(255,255,255,.7)`, dot `rgba(255,255,255,.6)`.

**TagChip** — `inline-flex; border:1px solid; border-radius:9999px; padding:.5rem 1rem; font-size:.875rem`. `light` tone (on dark cards) = `border:rgba(255,255,255,.25); color:#fff`.

**AnimatedLink** — `inline-flex` link wrapping a hover-spring span (default `translateX 0→4px, opacity .65→1`, `{320,22}`; footer legal links override to `translateX 0→3px, opacity .7→1`).

**Hover behavior note** — all hover springs are disabled on touch/mobile (no pointer:hover). On desktop they spring to the `to` state on `mouseenter` and back to `from` on `mouseleave` (a few are triggered by a parent element rather than self — noted inline above).

---

## Assets

`ASSET_BASE_URL = https://api.getlayers.ai/storage/v1/object/public/public/assets/lumora-e8b711fc68`

Load these from the public bucket (NOT relative paths):

| Original path | Full URL | Role in hero |
|---|---|---|
| `/assets/hero/before.jpg` | `https://api.getlayers.ai/storage/v1/object/public/public/assets/lumora-e8b711fc68/hero/before.jpg` | painted on cursor trail (`afterSrc`) |
| `/assets/hero/after.jpg` | `https://api.getlayers.ai/storage/v1/object/public/public/assets/lumora-e8b711fc68/hero/after.jpg` | always-shown base image (`beforeSrc`) |

**Mapping note (preserve exactly):** in the LiquidReveal, `beforeSrc` (the always-visible base / LCP image) = `.../hero/after.jpg`, and `afterSrc` (the brush-revealed image) = `.../hero/before.jpg`. The file named `after.jpg` shows by default; the file named `before.jpg` is revealed under the cursor. Do not swap which file sits on which layer.

---

## Fixed parameters (bake these in)

- **Colors:** `#ffffff #111111 #0a0a0a #8d8d8d #b6b6b6 #e6e5e2 #f1f0ee #e3e2df #b15f2c #cf8047 #97501f #ecebe9 #c9c9c9`. theme-color `#0a0a0a`.
- **Font:** Google **Onest**, weights 400/500/600/700. Fallback `sans-serif`.
- **Radii:** pill `9999px`, card `2rem`, card-sm `1.25rem`, control `.875rem`. Watermark font-size `13rem`. Shell max-width `88rem`.
- **Breakpoints:** sm `640px`, md `768px`, lg `1024px`; adaptive-grid base widths `1920/1440/1024/360`, scale-up base `1920`, coef `0.6666`, FONT_BASE `16`.
- **Loader:** `FILL_MS = 1300ms`, easeInOutCubic count, counter zero-padded to 3 digits, exit slide `translateY 0→-100%` `{220,30}`, content fade `{260,26}`, progress track `1px`, fill `#cf8047`.
- **LiquidReveal:** `brushRadius 143`, `decay 0.016`, dpr `min(dpr,2)`, fadeFrames `120`, idle fade ramp `+idle*0.004` capped `0.5`, brush gradient stops `1 / 0.82 / 0` at `0 / 0.55 / 1`, step `max(radius*0.3,1)`, max interp points `60`.
- **Reveal easings:** lines `easeOutCubic`≈`cubic-bezier(.215,.61,.355,1)` 900ms; words `easeOutQuart`≈`cubic-bezier(.165,.84,.44,1)` 700ms (`wordStagger 35`); hero line `lineStagger 120`, footer CTA `lineStagger 100`.
- **Entrance delays (ms after `ready`):** header 150, hero eyebrow 200, hero H1 250, hero card 400, partners 550, rating 650, CTAs 750, status bar 900, watermark 300. CreateBand `index*120`, Portfolio cards `index*90`, Services rows `index*80`, Stats `index*90`.
- **Spring configs (tension/friction):** header `210/26`; hovers (logo/menu/badges/pills) `320/18`; nav-item & link lifts `320/22`; social icon `320/16`; partner `320/20`; create tile `300/18`; service row fill `240/26`, service arrow `300/18`; portfolio card `260/22` + badge `280/18`; portfolio reveal `180/26`; create/partners/heroCard/stats-item reveal `200/24`; stats panel `180/26`; hero card carousel `300/28`; nav overlay fade `280/32`; modal `260/30`.
- **Stats count-up trigger:** `start "top bottom"`, `end "center center"`, value = `round(progress*target)`, throttle ~30ms.
- **Clock:** updates every 1s; time `H:MMam/pm` (no leading hour zero, minutes padded), date `D Month, YYYY`; fallback `9:41am` / `12 March, 2025`.
- **Copy / labels (verbatim):** brand "Lumora"; loader tagline "Bold ideas, shipped with quiet precision."; status bar "Local time" / time / date; nav Home/Work/Services/Studio/Careers/Contact; hero eyebrow "Independent Studio", watermark "LUMORA", heading "Bold ideas," / "shipped with" / "quiet precision", rating "200+ brands shipped", CTAs "Let's Talk" / "View Work", card items + partners + hero footer ("Working since 2014" / "Remote-first, worldwide" / "Scroll to explore") as listed; About all copy as listed; CreateBand We/Build/→/Better; Portfolio "Portfolio" / "Selected Work" + 4 items; Services "Services" / "What we do best" + 4 rows; Stats "By the numbers" / "Proof in the work, not the words." + 4 stats; Footer CTA "Have a project in mind? Let's get to work." + "Start a project", tagline, 3 link columns, legal "© 2025 Lumora Studio. All rights reserved." + Privacy/Terms; modal "Start a project" / "Tell us what you're building." / fields / "We reply within one business day." / "Send request" / success "Request received" / "Thanks for reaching out — we'll get back to you within one business day."
---
NOTE (added by the project owner, not part of the original prompt):
Corrected 2026-11-09: an earlier version of this note said the text above
was cut off mid-hero. It is not. Every section through the RequestModal,
the component recipes and the fixed parameters are present.
For ProvenanceX, take the structure from this reference: Onest typeface,
rem/spacing scale, radii, hairline borders, frosted header/control chips,
pill buttons and component shapes. Do not rebuild the landing page.
The owner's Phase 8 decisions in CLAUDE.md override this reference where
they differ: dark theme with the palette remapped, no gradients, a fixed
16px root, AA-contrast text colours, 150-250 ms motion and an 8px grid.
Where this reference is silent, extend it in the same style.
