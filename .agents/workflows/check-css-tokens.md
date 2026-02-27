---
description: Audit Tailwind v4 CSS import order, token usage, and deprecated patterns
---

This workflow enforces Tailwind CSS v4 and Nuxt UI 4 styling standards. Incorrect import order is the #1 cause of completely unstyled Nuxt UI components.

1. **Verify `main.css` import order**
   - The import order MUST be: (1) Google Fonts `@import url(...)`, (2) `@import 'tailwindcss'`, (3) `@import '@nuxt/ui'`. Getting this wrong causes all Nuxt UI components to render unstyled.
     // turbo
     `head -10 app/assets/css/main.css`
   - Manually verify the order matches the required sequence above.

2. **Check for legacy Tailwind/PostCSS config files**
   - Tailwind v4 uses the Vite plugin. Legacy config files interfere with Nuxt UI 4's built-in integration and must be deleted.
     // turbo
     `ls tailwind.config.* postcss.config.* 2>/dev/null || echo "No legacy config files found (pass)"`

3. **Check for `@apply` in scoped styles**
   - Using `@apply` inside `<style scoped>` (especially with `:deep()`) triggers `Cannot apply unknown utility class` errors during SSR. Use CSS variables instead (e.g., `var(--color-neutral-100)`).
     // turbo
     `grep -rn "@apply" app/components/ app/pages/ app/layouts/ 2>/dev/null || echo "No @apply usage found (pass)"`
   - If found in `<style scoped>` blocks, refactor to use Tailwind utility classes inline or CSS variables.

4. **Check for deprecated Tailwind v3 class names**
   - These classes were renamed in Tailwind v4 and will silently fail:
     - `flex-shrink-0` → `shrink-0`
     - `flex-grow-0` → `grow-0`
     - `bg-gradient-to-r` → `bg-linear-to-r`
       // turbo
       `grep -rn "flex-shrink-\|flex-grow-\|bg-gradient-to-" app/ 2>/dev/null || echo "No deprecated TW3 classes found (pass)"`

5. **Check for hardcoded color values**
   - Templates should use Nuxt UI design tokens (`primary`, `neutral`, etc.) and Tailwind theme colors, not hardcoded hex/rgb values in templates.
     // turbo
     `grep -rn "color: #\|color: rgb\|bg-\[#" app/components/ app/pages/ 2>/dev/null | head -15 || echo "No hardcoded colors found (pass)"`
   - A few exceptions are acceptable (e.g., `theme-color` meta tag), but component styling should always use tokens.
