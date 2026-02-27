---
description: Audit pages for SEO compliance (useSeo, Schema.org, OG images)
---

This workflow ensures every page uses the template's standardized SEO composables instead of bare Nuxt primitives.

1. **Check for pages missing `useSeo()`**
   - Every page in `app/pages/` must call `useSeo()` for consistent title, description, and OG image generation.
     // turbo
     `for f in $(find app/pages -name "*.vue"); do grep -L "useSeo(" "$f"; done | head -20 || echo "All pages use useSeo (pass)"`
   - If a page uses bare `useSeoMeta(` or `useHead(` instead of the wrapper, flag it for refactoring.
     // turbo
     `grep -rn "useSeoMeta\|useHead(" app/pages/ | grep -v "useSeo" || echo "No bare useSeoMeta/useHead found (pass)"`

2. **Check for missing Schema.org markup**
   - Every public page should call one of the Schema.org composables: `useWebPageSchema`, `useArticleSchema`, `useProductSchema`, etc.
     // turbo
     `for f in $(find app/pages -name "*.vue"); do grep -L "Schema(" "$f"; done | head -20 || echo "All pages have Schema.org (pass)"`

3. **Verify OG image templates exist**
   - At least one component must exist in `app/components/OgImage/` to generate dynamic social sharing images.
     // turbo
     `ls app/components/OgImage/*.vue 2>/dev/null || echo "WARNING: No OG image templates found in app/components/OgImage/"`

4. **Verify `nuxt.config.ts` SEO configuration**
   - Ensure the `site` block has `url`, `name`, `description`, and `defaultLocale` set.
   - Ensure `ogImage.defaults.component` points to a valid OG image component.
   - Ensure `schemaOrg.identity` is configured with the correct organization or person type.
