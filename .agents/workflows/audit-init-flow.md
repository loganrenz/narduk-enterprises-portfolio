---
description: Audit the init.ts setup flow for stale references, missing replacements, broken cross-refs, and agent-facing documentation gaps
---

This workflow audits the `tools/init.ts` initialization pipeline and ALL files it touches. Run after modifying `init.ts`, adding new apps, renaming the template, or changing the layer's identity. Report findings grouped by severity.

## Prerequisites

Read these files first to understand the replacement pipeline:

- `tools/init.ts` — the REPLACEMENTS array and all 9 steps
- `AGENTS.md` — the Initialization Routine and Production Cleanup recipes
- `CONTRIBUTING.md` — contributor onboarding instructions

---

## 1. Verify the REPLACEMENTS array covers all boilerplate strings

Search for every hardcoded template-specific string in code files. Each match MUST be covered by a pattern in the REPLACEMENTS array or have an explicit reason for exclusion.

// turbo
`grep -rn "narduk-nuxt-template" --include="*.ts" --include="*.vue" --include="*.json" --include="*.mjs" --include="*.yaml" --include="*.yml" . | grep -v node_modules | grep -v .nuxt | grep -v .output | grep -v tools/init.ts | grep -v tools/validate.ts | grep -v .git/`

// turbo
`grep -rn "Nuxt 4 Demo\|Nuxt 4 Template" --include="*.ts" --include="*.vue" --include="*.json" --include="*.mjs" . | grep -v node_modules | grep -v .nuxt | grep -v .output | grep -v tools/init.ts`

// turbo
`grep -rn "narduk-nuxt-template\.workers\.dev" --include="*.ts" --include="*.vue" --include="*.json" . | grep -v node_modules | grep -v .nuxt | grep -v tools/init.ts`

For each match, verify:

- It appears in code that `walkDir` will reach (not inside `node_modules/`, `.git/`, `.nuxt/`, etc.)
- The file is NOT excluded by the skip conditions (`.md` files, `tools/init.ts`, binary extensions)
- A REPLACEMENTS regex covers it

**Exceptions (expected matches):**

- `tools/validate.ts` — uses `narduk-nuxt-template` in validation logic (checking if init has run)
- Layer `package.json` `name` field — protected by the `isLayerPkg` guard
- Layer component prop defaults (e.g., `OgImageDefault.takumi.vue`) — these are runtime fallbacks in the shared layer, overridden by props passed from consuming apps

Flag as 🔴 **Critical** if any code-file reference is NOT covered by REPLACEMENTS.

---

## 2. Verify the targeted .md replacement step

The `.md` replacement step in `init.ts` processes markdown files separately. Verify:

// turbo
`grep -rn "narduk-nuxt-template" --include="*.md" . | grep -v node_modules | grep -v .nuxt | grep -v .git/ | grep -v AGENTS.md`

For each match:

- **SHOULD be replaced** → CONTRIBUTING.md, example READMEs (Doppler project names, clone URLs)
- **MUST NOT be replaced** → AGENTS.md files (clone/push safety warnings), root README.md (overwritten by init), layer READMEs (reference `@narduk-enterprises/narduk-nuxt-template-layer` published identity), `.agents/workflows/` files (instructional references)

Verify the `mdFiles` filter in `init.ts` correctly includes/excludes each category:

- `!f.endsWith('AGENTS.md')` — skips AGENTS.md files ✓
- `f !== path.join(ROOT_DIR, 'README.md')` — skips root README ✓
- `!f.includes(layers)` — skips layer .md files ✓
- `!f.includes(.agents)` — skips workflow .md files ✓

Flag as 🔴 **Critical** if a replacement would corrupt the layer's package identity.

---

## 3. Verify init.ts self-exclusion safety

After modifications to init.ts, ensure the script won't replace its own regex patterns:

// turbo
`grep -c "tools/init.ts" tools/init.ts`

Check:

- The main loop has `if (file.endsWith('tools/init.ts')) continue`
- The REPLACEMENTS regexes use literal strings, not variables — so they survive self-exclusion

Flag as 🔴 **Critical** if init.ts would modify itself during replacement.

---

## 4. Verify GitHub Actions workflows match actual app directories

// turbo
`ls -d apps/*/`

Cross-reference with:

- `.github/workflows/deploy-showcase.yml` — matrix must list ONLY apps that exist
- `.github/workflows/ci.yml` — must run against all workspace packages
- `playwright.config.ts` — projects must reference existing `tests/e2e/` directories

// turbo
`for app in $(grep -oP "example-\w+" .github/workflows/deploy-showcase.yml | sort -u); do [ -d "apps/$app" ] && echo "✅ apps/$app exists" || echo "❌ apps/$app MISSING"; done`

// turbo
`for proj in $(grep -oP "testDir: 'apps/[^']+'" playwright.config.ts | sed "s/testDir: '//;s/'//"); do [ -d "$proj" ] && echo "✅ $proj exists" || echo "❌ $proj MISSING"; done`

Flag as 🟠 **High** if any workflow references a non-existent app.

---

## 5. Verify wrangler.json consistency across apps

Every app with a `wrangler.json` must have:

- A `name` field that matches the expected pattern (`<app-name>` or `<app-name>-<suffix>`)
- A `d1_databases` entry with `database_name` matching `<app-name>-<suffix>-db`
- `database_id` as either a real UUID or `REPLACE_VIA_PNPM_SETUP` (pre-init only)

// turbo
`for f in apps/*/wrangler.json; do echo "=== $f ===" && jq '{name: .name, db_name: .d1_databases[0].database_name, db_id: .d1_databases[0].database_id}' "$f" 2>/dev/null; done`

Flag as 🟠 **High** if any `database_id` is `REPLACE_VIA_PNPM_SETUP` in a non-template repo (means init wasn't run).

---

## 6. Verify nuxt.config.ts metadata is replaceable

Check that `apps/web/nuxt.config.ts` build-time metadata fields are covered by REPLACEMENTS:

// turbo
`grep -n "site\.\|schemaOrg\.\|appName\|appUrl" apps/web/nuxt.config.ts`

Verify:

- `site.name` — contains a REPLACEMENTS target (e.g., `Nuxt 4 Demo`)
- `site.description` — contains a REPLACEMENTS target (the template-specific description)
- `schemaOrg.identity.name` — contains a REPLACEMENTS target
- `runtimeConfig.public.appName` fallback — contains a REPLACEMENTS target
- All `SITE_URL || '...'` fallbacks — contain the `workers.dev` URL replacement target

Flag as 🟡 **Medium** if any SEO-critical field uses a string not in REPLACEMENTS.

---

## 7. Verify package.json scripts are consistent

// turbo
`grep "db:migrate\|db:seed\|db:ready" package.json apps/*/package.json`

Check:

- Root `package.json` has a `db:migrate` script that delegates to `apps/web`
- Each app's `db:migrate` / `db:seed` commands reference the correct database name
- Database names in scripts match `wrangler.json` `database_name` values

Flag as 🟡 **Medium** if any script references a wrong database name.

---

## 8. Verify documentation consistency

Check that key docs match the current state of the codebase:

- **AGENTS.md Production Cleanup recipe** — lists the correct example app directories to delete
  // turbo
  `grep -A5 "Delete example apps" AGENTS.md`

- **AGENTS.md Initialization Routine** — step numbers match `init.ts` (currently 9 steps)
  // turbo
  `grep "Step [0-9]" tools/init.ts | tail -1`

- **CONTRIBUTING.md** — `pnpm run` commands (never `npm run`), Doppler project name references
  // turbo
  `grep -n "npm run\b" CONTRIBUTING.md | grep -v pnpm || echo "No bare npm run (pass)"`

- **Layer AGENTS.md** — layout references, provided files list
  // turbo
  `grep "layouts/" layers/narduk-nuxt-layer/AGENTS.md`

Flag as 🟡 **Medium** for stale docs, 🟠 **High** if they'd mislead an agent into wrong Doppler project.

---

## 9. Verify Doppler + CI integration

- `ci.yml` must have Doppler CLI installation and secrets injection (guarded by `secrets.DOPPLER_TOKEN`)
- `deploy.yml` must inject `DOPPLER_TOKEN` for production builds
- `deploy-showcase.yml` must inject `DOPPLER_TOKEN`
- Root `build` script wraps with `doppler run --` — CI should use `pnpm -r build` directly

// turbo
`grep -l "DOPPLER_TOKEN\|doppler" .github/workflows/*.yml`

Flag as 🟡 **Medium** if any deploy workflow lacks Doppler integration.

---

## 10. Verify favicon and public asset pipeline

- `apps/web/public/` should have `favicon.svg` (source) + generated assets if init has run
- Layer's `public/` provides fallback assets (`apple-touch-icon.png`, `favicon-32x32.png`, etc.)
- Init Step 8/9 generates app-specific favicons from source SVG

// turbo
`echo "=== apps/web/public/ ===" && ls apps/web/public/ && echo "" && echo "=== layer public/ ===" && ls layers/narduk-nuxt-layer/public/`

Flag as 🟡 **Medium** if `apps/web/public/` only has `favicon.svg` and `favicon.ico` (init Step 8 wasn't run or failed).

---

## 11. Compile and present findings

Group all findings into severity tiers:

- 🔴 **Critical** — Missing REPLACEMENTS coverage, self-corruption risk, layer identity corruption
- 🟠 **High** — Workflow/app directory mismatches, stale wrangler.json placeholders, misleading Doppler refs
- 🟡 **Medium** — SEO metadata gaps, stale docs, favicon pipeline incomplete, `npm run` references
- 🟢 **Low** — Informational observations, nice-to-have improvements

Present as a table with:
| Severity | File | Issue | Recommended Fix |
|----------|------|-------|-----------------|

Ask the user for approval before making any changes.
