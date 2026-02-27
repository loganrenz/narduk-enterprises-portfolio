---
description: Audit Thin Store decomposition — types, services, and composable extraction
---

This workflow enforces the Thin Store decomposition roadmap: types belong in `app/types/`, API calls belong in `app/services/`, and complex logic belongs in composables. Derived from stonx-app-2026's mature service-layer architecture.

1. **Check for inline type definitions in stores**
   - Interfaces and type aliases defined inside store files should be extracted to `app/types/`. This keeps stores focused on state management and makes types reusable across composables.
     // turbo
     `grep -rn "^export interface\|^export type\|^interface \|^type " app/stores/ 2>/dev/null || echo "No inline types in stores (pass)"`
   - Re-exporting types from `app/types/` is acceptable (e.g., `export type { Game } from '~/types/game'`).

2. **Check for raw fetch calls in stores**
   - Stores should delegate API calls to `app/services/*-api.ts` modules or use `useAppFetch()`. Direct `$fetch` or `useFetch` calls inside stores couple data management to transport logic.
     // turbo
     `grep -rn "\$fetch\|useFetch(" app/stores/ 2>/dev/null | grep -v "useAppFetch\|FetchFn\|fetchFn\|type " || echo "No raw fetch in stores (pass)"`

3. **Check for oversized stores**
   - Stores over 300 lines are candidates for the Thin Store decomposition: extract types (Phase 1), extract API calls to services (Phase 2), extract calculations to composables (Phase 3), extract permissions (Phase 4), extract actions (Phase 5).
     // turbo
     `find app/stores -name "*.ts" | xargs wc -l 2>/dev/null | awk '$1 > 300 {print}' || echo "No oversized stores found (pass)"`

4. **Check for oversized composables**
   - Composables over 400 lines should be split into domain-specific composables. A single "god composable" returning 10+ refs/functions is a code smell.
     // turbo
     `find app/composables -name "*.ts" | xargs wc -l 2>/dev/null | awk '$1 > 400 {print}' || echo "No oversized composables found (pass)"`

5. **Check for bare `ref()` at module scope**
   - Global reactive state MUST use `useState()` (Nuxt) or Pinia stores, never a bare `ref()` declared at module scope outside a composable. Module-scope refs leak state across SSR requests.
     // turbo
     `grep -rn "^const .* = ref(" app/composables/ app/utils/ 2>/dev/null | grep -v "export function\|defineStore\|setup" | head -10 || echo "No module-scope ref leaks found (pass)"`
   - Review output manually: refs inside `export function use*()` are safe; refs outside any function body are not.
