---
description: Deep hydration safety audit — isHydrated pattern, ClientOnly wrapping, DOM nesting
---

This workflow performs a deep hydration safety audit beyond basic SSR checks. It enforces the `isHydrated` guarding pattern, `ClientOnly` wrapping requirements, and structural DOM safety from stonx-app-2026.

1. **Check for `isHydrated` pattern in Pinia stores**
   - Stores that hold live/dynamic data (prices, WebSocket state, real-time calculations) must implement `isHydrated` + `markHydrated()`. This prevents live calculations from running on stale SSR-serialized data before the client has taken over.
     // turbo
     `grep -rn "isHydrated\|markHydrated" app/stores/ 2>/dev/null || echo "No isHydrated pattern found — verify if stores hold live data"`
   - If any store manages real-time or frequently-updating data, it MUST gate live computations behind `isHydrated.value`.

2. **Check `ClientOnly` wrapping for hydration-sensitive components**
   - `UNavigationMenu`, color mode toggles, and any component depending on `localStorage` or `matchMedia` must be wrapped in `<ClientOnly>` to prevent SSR/client mismatch flicker.
     // turbo
     `grep -rn "UNavigationMenu\|UColorModeButton\|UColorModeSelect" app/ 2>/dev/null | grep -v "ClientOnly" | head -10 || echo "All hydration-sensitive components properly wrapped (pass)"`
   - Review output manually: these components are safe only if they appear inside a `<ClientOnly>` wrapper in their parent template.

3. **Check for DOM nesting violations**
   - Invalid HTML nesting (e.g., `<div>` inside `<p>`, `<a>` inside `<a>`, block elements inside inline elements) causes Vue's hydration to fail silently, producing visual corruption.
     // turbo
     `grep -rn "<p>" app/components/ app/pages/ 2>/dev/null | grep -v ".ts" | head -20`
   - Review output manually: look for `<p>` tags containing `<div>`, `<UCard>`, or other block-level elements. Refactor `<p>` to `<div>` if it wraps block content.

4. **Check for non-serializable state in stores**
   - `Map`, `Set`, `Date`, and class instances cannot be serialized for SSR hydration. Store state must use plain objects (`Record<>`) and arrays. Use `shallowRef` + `skipHydrate` for unavoidable complex types.
     // turbo
     `grep -rn "ref<Map\|ref<Set\|new Map()\|new Set()" app/stores/ 2>/dev/null || echo "No non-serializable store state found (pass)"`
   - If found, verify they are wrapped with `shallowRef` and excluded from SSR serialization.

5. **Check `#fallback` slot structural symmetry**
   - When using `<ClientOnly>` or `<Suspense>`, the `#fallback` skeleton must match the hydrated DOM structure (same container type and spacing). Mismatched fallback structures cause layout shift and hydration warnings.
     // turbo
     `grep -rn "#fallback\|v-slot:fallback" app/ 2>/dev/null | head -10 || echo "No fallback slots found — verify ClientOnly usage"`
   - Review output manually: ensure fallback content uses the same wrapper elements as the actual content.
