---
description: Holistic brand identity workflow — audits the app's purpose, reinvents or refines its visual identity, generates all creative assets, and applies end-to-end design polish
---

# /generate-brand-identity

Transform a Nuxt 4 app from functional skeleton into a visually stunning, emotionally resonant product with a unified brand identity. This is not a checklist — it is a creative brief. Study the app, understand its soul, and craft something beautiful.

> **Your mandate:** Every decision — color, type, radius, shadow, animation — should feel _intentional_, as though a senior brand designer spent a week on it. Generic is failure. Boring is unacceptable.

> **Autonomy:** You are the creative director. **Do not ask the user any questions.** Analyze the app, make every creative decision yourself, execute the full pipeline, and present the finished result. This is _your_ project — own it.

## Phase 1: Discovery & Creative Direction

Before touching a single file, **immerse yourself** in the project.

1. **Read the codebase.** Scan the app's pages, components, layouts, server routes, and `nuxt.config.ts`. Understand what kind of product this is — a dashboard? a marketplace? a creative tool? a consumer app?
2. **Identify the audience.** Who will use this? Developers? Consumers? Enterprise buyers? Teenagers? The answer changes everything.
3. **Establish the emotional register.** Every great brand evokes a specific feeling. Determine the mood:
   - _Trustworthy & professional_ → deep blues, clean type, generous whitespace
   - _Playful & energetic_ → saturated gradients, rounded corners, bouncy animations
   - _Luxurious & minimal_ → muted palette, tight leading, editorial type
   - _Bold & technical_ → monospace accents, neon highlights, dark UI
   - _Warm & approachable_ → earth tones, soft shadows, organic shapes
4. **Lock in a creative direction.** Decide on:
   - **Primary Color** — a Nuxt UI / Tailwind color name (e.g., `indigo`, `amber`, `rose`, `cyan`). Pick the one that best fits the brand.
   - **Neutral Color** — the complementary gray scale (`slate`, `zinc`, `stone`, `neutral`).
   - **Typography** — a Display font for headings and a Sans font for body. Pull from Google Fonts. Pick the best pairing — geometric sans for tech, humanist sans for warmth, slab serif for authority.
   - **Visual Language** — glassmorphism vs. flat, light vs. dark mode bias, illustration vs. photography, sharp corners vs. rounded, dense vs. airy.
   - **Signature Motif** — one distinctive visual element that makes the brand memorable: a gradient direction, a specific border radius, an accent pattern, a unique icon style.

**Proceed immediately.** Do not wait for approval — trust your analysis and move to Phase 2.

## Phase 2: Configure Theme & Typography

Apply the approved direction to the Nuxt 4 configuration:

### 2a. Set Nuxt UI Colors

Create or update `apps/<app-name>/app/app.config.ts`:

```ts
export default defineAppConfig({
  ui: {
    colors: {
      primary: '<chosen-primary>',
      neutral: '<chosen-neutral>',
    },
  },
});
```

### 2b. Set Tailwind v4 Theme Overrides

Create or update `apps/<app-name>/app/assets/css/main.css`:

```css
@import 'tailwindcss';
@import '@nuxt/ui';

@theme {
  --font-sans: '<Body Font>', system-ui, sans-serif;
  --font-display: '<Display Font>', system-ui, sans-serif;

  /* Shape language — tune these to the brand personality */
  --radius-card: 1.5rem;
  --radius-button: 9999px; /* pill buttons for playful; 0.5rem for professional */
}
```

> _Note: `@nuxt/fonts` auto-resolves Google Fonts referenced in CSS._

### 2c. Dark Mode & Color Fine-Tuning

If the brand leans dark-first, ensure the dark palette feels intentional — not just Tailwind's default inversion. Consider overriding specific semantic tokens for backgrounds, borders, and text.

## Phase 3: Generate Visual Assets

Use the `generate_image` tool to create **bespoke, high-fidelity imagery** — not clipart, not stock, not placeholder.

### 3a. Logo / App Icon

Generate a distinctive logo that embodies the brand:

```
Prompt guidance: "A [style] app icon for [APP]. [Describe the concept].
[Color palette]. No text. No device frame. Square aspect ratio, suitable for a favicon."
```

- Save to `apps/<app-name>/public/favicon.svg` (or convert a generated PNG to SVG).
- The logo should work at 16×16 _and_ 180×180. Test both mentally before finalizing.

### 3b. Hero / Auth Background (if applicable)

Generate an atmospheric background for the landing page, login screen, or hero section:

```
Prompt guidance: "Abstract [mood] background. [Color palette], subtle [texture/gradient/pattern].
Widescreen, cinematic. No text, no UI elements."
```

- Save to `apps/<app-name>/public/images/hero-bg.webp`.

### 3c. Content & Feature Imagery (if applicable)

If the app has empty states, onboarding flows, or feature sections, generate real imagery instead of leaving placeholders:

- Illustrations for empty states
- Feature screenshots or conceptual images for marketing pages
- Avatar sets for social apps
- Save to `apps/<app-name>/public/images/`.

## Phase 4: Generate Favicons & Web Manifest

Run the favicon generator using the logo from Phase 3:

```bash
pnpm generate:favicons -- \
  --target=apps/<app-name>/public \
  --name="<Display Name>" \
  --short-name="<Short Name>" \
  --color="<primary-hex>" \
  --bg="<background-hex>"
```

This produces:

| Asset                  | Size    |
| ---------------------- | ------- |
| `apple-touch-icon.png` | 180×180 |
| `favicon-32x32.png`    | 32×32   |
| `favicon-16x16.png`    | 16×16   |
| `favicon.ico`          | 32×32   |
| `site.webmanifest`     | JSON    |

### Update Schema.org (if applicable)

If the app has `schemaOrg.identity.logo` in `nuxt.config.ts`, update it:

```ts
schemaOrg: {
  identity: {
    logo: '/favicon.svg',
  }
}
```

## Phase 5: Holistic Design Polish

This is where the brand comes alive. Don't just configure — **design**.

### 5a. Surface Treatment

Apply the brand's visual language to key surfaces:

- **Glass & Depth:** Use `.glass`, `.glass-card`, `.shadow-card`, `.shadow-elevated` on navbars, auth cards, modals — but only if the brand calls for it. Not every app should be glassmorphic.
- **Backgrounds:** The main `app.vue` or `layouts/default.vue` should set the stage. Consider gradient backgrounds, subtle patterns, or atmospheric imagery.
- **Cards & Containers:** Ensure every card, panel, and container uses the brand's radius and shadow language consistently.

### 5b. Motion & Micro-animation

An interface that moves with purpose feels premium:

- **Entrances:** `.animate-count-in`, fade-ups, scale-ins on page load and route transitions.
- **Interactions:** `.transition-base` on hover states. Buttons that respond. Cards that lift.
- **Data:** Number counters, skeleton loaders, progress bars that animate smoothly.
- **Restraint:** Motion should enhance, never distract. If an animation makes you notice the animation instead of the content, remove it.

### 5c. Typography Hierarchy

Verify that the type system creates clear visual hierarchy:

- `h1` should command attention
- Body text should be effortlessly readable
- Captions and metadata should recede without disappearing
- Check line heights, letter spacing, and font weights across both modes

### 5d. Dark Mode Audit

Switch to dark mode and verify:

- Backgrounds have depth (not flat `#000`)
- Text contrast meets WCAG standards
- Borders are subtle but visible
- Colored elements remain vibrant without being harsh

## Phase 6: Visual Verification

1. Start the dev server: `pnpm run dev --filter <app-name>`
2. Open the app in a browser — **take screenshots** for the user.
3. Verify:
   - Favicon appears in browser tab
   - Apple Touch Icon loads (`/apple-touch-icon.png` → 200)
   - Typography renders with the chosen fonts (no FOUT/FOIT)
   - Color system works in both light and dark modes
   - Animations are smooth and purposeful
   - Layout feels intentional on both desktop and mobile widths
4. Present the finished result to the user with screenshots and a brief summary of the creative choices you made and _why_.

## Prerequisites

- `sharp` must be installed: `pnpm add -wD sharp` (already in `onlyBuiltDependencies`)

## Quick Reference: Favicon Generator Options

| Option         | Default                           | Description                     |
| -------------- | --------------------------------- | ------------------------------- |
| `--target`     | `layers/narduk-nuxt-layer/public` | Output directory                |
| `--source`     | `<target>/favicon.svg`            | Source SVG path                 |
| `--name`       | `Nuxt 4 App`                      | Full name in webmanifest        |
| `--short-name` | First 12 chars of `--name`        | Short name in webmanifest       |
| `--color`      | `#10b981`                         | Theme color in webmanifest      |
| `--bg`         | `#0B1120`                         | Background color in webmanifest |
