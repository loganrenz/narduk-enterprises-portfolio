---
description: Comprehensive SSR and Hydration safety audit — window access, isHydrated pattern, ClientOnly logic
---

This workflow performs a deep SSR and hydration safety audit. It ensures the application safely executes on the server without crashing and prevents common client-hydration mismatches.

**ESLint (run first):** `nuxt-guardrails/no-ssr-dom-access` flags unguarded `window`/`document`; `nuxt-guardrails/no-raw-fetch` flags raw `$fetch`. `vue-official/no-composable-dom-access-without-client-guard` covers composables. Store serialization is enforced by `nuxt-guardrails/no-non-serializable-store-state`. Hydration-sensitive components (UNavigationMenu, UColorMode*) are enforced by `atx/require-client-only-hydration-sensitive`. Run `pnpm run lint` before manual checks below.

1. **Check for `window` or `document` usage in setup**
   - Any access to `window` or `document` directly in `<script setup>` outside of lifecycle hooks (like `onMounted`) will cause SSR crashes.
   - **Enforced by:** `nuxt-guardrails/no-ssr-dom-access`
   - Optional manual check:
     // turbo
     `grep -rn "window\." app/ 2>/dev/null | grep -v "onMounted" || echo "No unsafe window access found (pass)"`

2. **Verify data fetching patterns**
   - Ensure API calls during SSR are made using `useAsyncData` or `useFetch`. Raw `$fetch` calls in the setup block without wrapping them will execute twice (server and client), causing hydration mismatches.
   - **Enforced by:** `nuxt-guardrails/no-raw-fetch`
   - Optional manual check:
     // turbo
     `grep -rn "const .* = await \$fetch" app/ 2>/dev/null || echo "No unsafe raw $fetch found (pass)"`

3. **Check for `isHydrated` pattern in Pinia stores and components**
   - Complex client-only state or stores that hold live/dynamic data (prices, WebSockets) must implement an `isHydrated` guard. This prevents live calculations from running on stale SSR-serialized data or mismatches from browser APIs.
     // turbo
     `grep -rn "isHydrated\|markHydrated" app/stores/ app/components/ 2>/dev/null || echo "No isHydrated pattern found — verify if stores/components hold live data"`

4. **Check `ClientOnly` wrapping for hydration-sensitive components**
   - `UNavigationMenu`, color mode toggles, and any component depending on `localStorage` or `matchMedia` must be wrapped in `<ClientOnly>` to prevent SSR/client mismatch flicker.
     // turbo
     `grep -rn "UNavigationMenu\|UColorModeButton\|UColorModeSelect" app/ 2>/dev/null | grep -v "ClientOnly" | head -10 || echo "All hydration-sensitive components properly wrapped (pass)"`

5. **Check for DOM nesting violations**
   - Invalid HTML nesting (e.g., `<div>` inside `<p>`, `<a>` inside `<a>`, block elements inside inline elements) causes Vue's hydration to fail silently, producing visual corruption.
     // turbo
     `grep -rn "<p>" app/components/ app/pages/ 2>/dev/null | grep -v "\.ts$" | head -20`
   - Review output manually: look for `<p>` tags containing `<div>`, `<UCard>`, or other block-level elements. Refactor `<p>` to `<div>` if it wraps block content.

6. **Check for non-serializable state in stores**
   - `Map`, `Set`, `Date`, and class instances cannot be serialized for SSR hydration. Store state must use plain objects (`Record<>`) and arrays. Use `shallowRef` + `skipHydrate` for unavoidable complex types.
     // turbo
     `grep -rn "ref<Map\|ref<Set\|new Map()\|new Set()" app/stores/ 2>/dev/null || echo "No non-serializable store state found (pass)"`

7. **Check `#fallback` slot structural symmetry**
   - When using `<ClientOnly>` or `<Suspense>`, the `#fallback` skeleton must match the hydrated DOM structure (same container type and spacing). Mismatched fallback structures cause layout shift and hydration warnings.
     // turbo
     `grep -rn "#fallback\|v-slot:fallback" app/ 2>/dev/null | head -10 || echo "No fallback slots found — verify ClientOnly usage"`

8. **Verify Teleports coverage**
   - If `Teleport` or `<UTooltip>`/`<UModal>` are used, make sure there are no scoped CSS hazards preventing them from rendering styles correctly (Tailwind `@theme` utility usage is preferred).
