---
description: Audit architectural separation of concerns — Thin Components, Thick Composables, Thin Stores
---

This workflow enforces a clean service-layer architecture.

**ESLint (run first):** Module-scope `ref()` in composables/utils is flagged by `atx/no-module-scope-ref`. Inline types in stores by `atx/no-inline-types-in-stores`. Raw fetch in stores by `nuxt-guardrails/no-raw-fetch-in-stores`. Run `pnpm run lint` before manual checks below. View components should contain minimal logic, complex logic belongs in composables, and stores should be thin (delegating to services and types).

1. **Check component size and logic (Thin Components)**
   - Components in `app/components/` and `app/pages/` should ideally be under 150 lines.
   - Large `setup` blocks with extensive data fetching, state mutation, or complex conditional logic should be extracted to `app/composables/`.
     // turbo
     `find app/components app/pages -name "*.vue" 2>/dev/null | xargs wc -l | awk '$1 > 150 {print}' || echo "No oversized components found (pass)"`

2. **Verify component responsibilities**
   - Components should ONLY subscribe to composables (e.g., `const { user, login } = useAuth()`), pass state down as props, and emit events up.
   - Look for inline `fetch` calls, complex `try/catch` mutation blocks, or multi-step logic inside bounds like `@click`. These belong in composables.

3. **Check composable payload size (Thick Composables)**
   - Composables returning more than 5-7 refs/functions might need to be split into domain-specific composables to prevent "god objects".
   - Composables over 400 lines should be split into smaller units.
     // turbo
     `find app/composables -name "*.ts" 2>/dev/null | xargs wc -l | awk '$1 > 400 {print}' || echo "No oversized composables found (pass)"`

4. **Verify Store/State Isolation and Leaks**
   - Global reactive state MUST use `useState()` (Nuxt) or Pinia stores.
   - Do not use global `ref()` variables defined outside of a composable context or at module scope. Module-scope refs leak state across SSR requests.
     // turbo
     `grep -rn "^const .* = ref(" app/composables/ app/utils/ 2>/dev/null | grep -v "export function\|defineStore\|setup" | head -10 || echo "No module-scope ref leaks found (pass)"`

5. **Check for inline type definitions in stores (Thin Stores)**
   - Interfaces and type aliases defined inside store files should be extracted to `app/types/`. This makes types reusable across composables.
     // turbo
     `grep -rn "^export interface\|^export type\|^interface \|^type " app/stores/ 2>/dev/null || echo "No inline types in stores (pass)"`

6. **Check for raw fetch calls in stores**
   - Stores should delegate API calls to `app/services/*-api.ts` modules or use `useAppFetch()`. Direct `$fetch` or `useFetch` calls inside stores couple data management to transport logic.
     // turbo
     `grep -rn "\$fetch\|useFetch(" app/stores/ 2>/dev/null | grep -v "useAppFetch\|FetchFn\|fetchFn\|type " || echo "No raw fetch in stores (pass)"`

7. **Check for oversized stores**
   - Stores over 300 lines are candidates for decomposition: extract types, extract API calls to services, extract calculations to composables.
     // turbo
     `find app/stores -name "*.ts" 2>/dev/null | xargs wc -l | awk '$1 > 300 {print}' || echo "No oversized stores found (pass)"`
