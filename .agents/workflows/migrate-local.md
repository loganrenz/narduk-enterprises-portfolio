---
description: Migrate a flat Nuxt 4 app into the monorepo when both the template and source already exist locally (e.g. both in ~/new-code)
---

# Migrate Local App to Monorepo (In-Place)

> **Scope:** This is the optimized migration path for when `narduk-nuxt-template` and the source app **both already exist** on the local filesystem. Unlike `/migrate-to-monorepo` (which clones from GitHub into `/tmp`), this workflow copies the template scaffold directly from the local monorepo, avoids temp directories, and works in-place in `~/new-code/`.

// turbo-all

## Quick Checklist (TL;DR)

- [ ] **Phase 0:** Copy local template → init → verify `pnpm run dev`
- [ ] **Phase 1:** Audit source files (layer-provided vs app-specific vs junk)
- [ ] **Phase 2:** Copy app files → merge CSS → merge app.vue → copy server code
- [ ] **Phase 3:** Slim configs (nuxt.config, package.json, wrangler, eslint)
- [ ] **Phase 4:** Clean up examples + junk
- [ ] **Phase 5:** Install → quality → dev → seed DB → commit
- [ ] **Phase 6:** Run `/check-*` audit workflows
- [ ] **Phase 7:** Archive old repo → set Git remote → push

## Prerequisites

> [!NOTE]
> The template was renamed from `nuxt-v4-template` to `narduk-nuxt-template`. If the source app has references to the old name (in `package.json`, `AGENTS.md`, configs, etc.), they should be updated to the new name during migration.

1. **Template exists locally.** Confirm `~/new-code/narduk-nuxt-template` (or wherever the golden template lives) is up-to-date. Pull if needed:
   ```bash
   cd ~/new-code/narduk-nuxt-template && git pull
   ```
2. **Source is Nuxt 4.** It must have `nuxt.config.ts` with `future: { compatibilityVersion: 4 }`. If not, STOP.
3. **Names decided.** Know the `<source>` directory name, the new `<project-name>`, the `<display-name>`, and the `<site-url>`.

---

## 🚨 Layer Issue Escalation Protocol

> **This rule applies to EVERY phase.** If you hit an issue **caused by the layer** (`layers/narduk-nuxt-layer/`), not the app:

1. STOP migration work.
2. Document the error, layer files involved, and why it's the layer's fault.
3. Output the bug report template (see `/migrate-to-monorepo` for the full template).
4. Wait for user confirmation before resuming.

---

## Phase 0: Scaffold from Local Template

**No GitHub clone. No `/tmp`. Copy directly from the local template.**

1. **Copy the template into the new project directory:**

   ```bash
   cp -R ~/new-code/narduk-nuxt-template ~/new-code/<project-name>
   cd ~/new-code/<project-name>
   rm -rf .git node_modules .nuxt .output .turbo .wrangler apps/*/node_modules apps/*/.nuxt apps/*/.output layers/*/node_modules layers/*/.nuxt packages/*/node_modules packages/*/dist playwright-report test-results
   git init && git add . && git commit -m "chore: scaffold from narduk-nuxt-template"
   ```

2. **Run init.ts:**

   ```bash
   pnpm install
   pnpm init -- --name="<project-name>" --display="<Display Name>" --url="https://<domain>"
   ```

3. **Verify scaffold compiles:**
   ```bash
   pnpm run dev
   ```
   Kill once it starts. If it fails, fix before proceeding.

> [!TIP]
> Since you copied from a local template that was already `pnpm install`'d, the lockfile is correct. `pnpm install` will be fast (mostly linking).

---

## Phase 1: Inventory the Source App

Before moving ANY files, audit the source app (`~/new-code/<source>`) to categorize every file. This phase is identical to `/migrate-to-monorepo` Phase 1.

### 1a. Layer-Provided Files (DO NOT COPY)

These exist in `layers/narduk-nuxt-layer/` — duplicating them causes conflicts:

- `composables/useSeo.ts`, `composables/useSchemaOrg.ts`
- `components/OgImage/*`
- `plugins/gtag.client.ts`, `plugins/posthog.client.ts`, `plugins/csrf.client.ts`, `plugins/fetch.client.ts`
- `server/utils/` (auth, admin, database, google, kv, r2, rateLimit)
- `server/middleware/csrf.ts`, `server/middleware/d1.ts`
- `server/api/health.get.ts`, `server/api/indexnow/*`

### 1b. App-Specific Files (MOVE to `apps/web/`)

- `app/pages/**`, `app/components/**` (non-layer), `app/composables/**` (non-layer)
- `app/layouts/**`, `app/middleware/**`
- `app/assets/css/main.css` — only app-specific styles (see Phase 2)
- `app/app.vue` — merge, don't overwrite
- `app/error.vue`, `app/app.config.ts`
- `content/**`, `content.config.ts`
- `server/api/**` (app-specific routes)
- `server/routes/**` (app-specific)
- `server/database/schema.ts` (app-specific tables)
- `public/**`, `drizzle/**`, `scripts/**`
- Any standalone tools (e.g. `scraper/`)

### 1c. Junk (DELETE)

- `.env*`, `.dev.vars`, ESLint plugin dirs, `.cursor/`, reports, lock files — all superseded.

---

## Phase 2: Move App-Specific Files

Copy from the **sibling directory** — no clone needed:

```bash
cd ~/new-code/<project-name>
SOURCE=~/new-code/<source>

mkdir -p apps/web/app/{components,composables,plugins,types,middleware,layouts}
mkdir -p apps/web/server/{api,utils,routes}

# Pages, components, layouts, composables, middleware, types
cp -R $SOURCE/app/pages/* apps/web/app/pages/ 2>/dev/null || true
cp -R $SOURCE/app/components/* apps/web/app/components/ 2>/dev/null || true
cp -R $SOURCE/app/layouts/* apps/web/app/layouts/ 2>/dev/null || true
cp -R $SOURCE/app/composables/* apps/web/app/composables/ 2>/dev/null || true
cp -R $SOURCE/app/middleware/* apps/web/app/middleware/ 2>/dev/null || true
cp -R $SOURCE/app/types/* apps/web/app/types/ 2>/dev/null || true

# Static assets, content, scraper, drizzle
cp -R $SOURCE/public/* apps/web/public/ 2>/dev/null || true
[ -d $SOURCE/content ] && cp -R $SOURCE/content apps/web/content
[ -d $SOURCE/scraper ] && cp -R $SOURCE/scraper apps/web/scraper

# Server
cp -R $SOURCE/server/api/* apps/web/server/api/ 2>/dev/null || true
[ -d $SOURCE/server/routes ] && cp -R $SOURCE/server/routes/* apps/web/server/routes/ 2>/dev/null || true
cp $SOURCE/drizzle/*.sql apps/web/drizzle/ 2>/dev/null || true
```

Then **immediately delete layer-provided files** that were copied (see 1a list).

### CSS Merge

Compare `$SOURCE/app/assets/css/main.css` with `layers/narduk-nuxt-layer/app/assets/css/main.css`. **Delete overlap** (tailwind/nuxt-ui imports, `@theme` base tokens, `.glass`, body/heading font rules, page transitions, form layouts). **Keep only** app-specific theme tokens, component styles, animations, and scrollbar rules. Write the result to `apps/web/app/assets/css/main.css`.

### app.vue Merge

The template's canonical structure is:

```vue
<template>
  <UApp>
    <NuxtLayout>
      <NuxtPage />
    </NuxtLayout>
  </UApp>
</template>
```

Copy any `<script setup>` logic (SEO meta, providers) and `<style>` blocks from the source. **Do NOT remove UApp/NuxtLayout/NuxtPage.**

### Schema Merge

Read `$SOURCE/server/database/schema.ts`. Merge app-specific tables into `apps/web/server/database/schema.ts`, which already re-exports from the layer.

---

## Phase 3: Rewrite Configuration

### nuxt.config.ts

Must be **slim**. Delete everything the layer handles:

- `modules` array, `devtools`, `ui`, `colorMode`, `compatibilityDate`
- `nitro.preset`, `nitro.esbuild`, `nitro.externals`
- `image.provider`, `ogImage.defaults`

**Keep only:** `extends`, `css`, `runtimeConfig`, `site`, `schemaOrg.identity`, `image.cloudflare.baseURL`, `sitemap`, `robots`, `app.head`, `app.pageTransition`.

### package.json

Remove all layer-provided deps. Keep only strictly app-specific packages (e.g. `cheerio`, `drizzle-orm`).

### eslint.config.mjs

Replace with:

```js
// @ts-check
import withNuxt from './.nuxt/eslint.config.mjs';
import { sharedConfigs } from '@narduk/eslint-config';
export default withNuxt(...sharedConfigs);
```

### wrangler.json

Update `d1_databases` and add any `r2_buckets` from the source app.

---

## Phase 4: Clean Up

```bash
# Remove example apps (keep web only, remove example-* and showcase)
rm -rf apps/example-* apps/showcase
# Junk
find apps/web -name ".DS_Store" -delete
find apps/web -name "*.bak" -delete
```

Update `playwright.config.ts` to remove example project entries. Update root `package.json` scripts to remove example-specific commands.

---

## Phase 5: Verification

```bash
cd ~/new-code/<project-name>
pnpm install
rm -rf apps/web/.nuxt apps/web/.output
pnpm run quality    # Lint + typecheck — must pass
pnpm run dev        # Verify app starts, pages render
```

Seed DB if applicable:

```bash
pnpm --filter web run db:migrate
pnpm --filter web run db:seed
```

Commit:

```bash
git add . && git commit -m "feat: migrate <source> to monorepo architecture"
```

### Troubleshooting

| Error                                           | Fix                                                                 |
| ----------------------------------------------- | ------------------------------------------------------------------- |
| `D1_ERROR: no such table`                       | `pnpm --filter web run db:migrate && pnpm --filter web run db:seed` |
| `Duplicated auto-import: X`                     | Delete app-level file (layer takes priority)                        |
| `PostCSS: @import must precede all other rules` | Move `@import` to top of CSS, or use `app.head.link`                |
| `Cannot find module '@narduk-enterprises/...'`           | `pnpm install` from repo root                                       |
| `No D1 database binding`                        | Add `d1_databases` to `wrangler.json`                               |

---

## Phase 6: Post-Migration Audits

Run `/check-layer-health`, `/check-architecture`, `/check-ui-styling`, `/check-seo-compliance`, `/check-ssr-hydration-safety`, `/audit-repo-hygiene`.

---

## Phase 7: Finalize

1. **Archive the old repo:**

   ```bash
   mkdir -p ~/old-code/graveyard
   mv ~/new-code/<source> ~/old-code/graveyard/
   ```

2. **Set up git remote and push:**

   ```bash
   cd ~/new-code/<project-name>
   git remote add origin https://github.com/narduk-enterprises/<project-name>.git
   git branch -M main
   git push -u origin main --force
   ```

3. **Final quality:**
   ```bash
   pnpm run quality
   ```

---

## When to Use This vs `/migrate-to-monorepo`

| Scenario                                              | Workflow                                    |
| ----------------------------------------------------- | ------------------------------------------- |
| Template and source both in `~/new-code/` or `~/code` | **`/migrate-local`** (this one)             |
| Source is on a remote server or another machine       | `/migrate-to-monorepo` (clones from GitHub) |
| Starting a brand-new project (no source app)          | Just clone + run `init.ts` directly         |
