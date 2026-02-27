---
description: Audit data fetching for waterfalls, raw $fetch, and N+1 queries
---

This workflow catches API waterfall anti-patterns, unsafe data fetching, and N+1 query risks derived from stonx-app-2026's data-bundling standards.

1. **Check for raw `$fetch` in page/component setup**
   - All data fetching in `<script setup>` must use `useAsyncData` or `useFetch`, never bare `await $fetch`. Raw `$fetch` executes on both server and client, causing double-fetches and hydration mismatches.
     // turbo
     `grep -rn "await \$fetch\|const .* = \$fetch" app/pages/ app/components/ 2>/dev/null || echo "No unsafe raw \$fetch found (pass)"`

2. **Check for sequential await waterfalls**
   - Multiple independent `await` calls on separate lines should be parallelized with `Promise.all`. Look for patterns like `await fetchA(); await fetchB();` where B doesn't depend on A.
     // turbo
     `grep -rn -A1 "await fetch\|await use" app/composables/ app/stores/ 2>/dev/null | grep -B1 "await " | head -30`
   - Review output manually — consecutive `await` lines on independent resources are waterfall candidates.

3. **Check for N+1 queries in server API**
   - The `.map(async` pattern inside API handlers usually indicates an N+1 query. Use batched `.in('id', ids)` queries instead.
     // turbo
     `grep -rn "\.map(async" server/api/ 2>/dev/null || echo "No N+1 map(async) patterns found (pass)"`

4. **Check stores use `useAppFetch()` or `useRequestFetch()`**
   - Store fetch actions must use `useAppFetch()` (or accept a `fetchFn` parameter for SSR) to ensure proper cookie/auth proxying during server-side rendering.
     // turbo
     `grep -rn "\$fetch\|useFetch\b" app/stores/ 2>/dev/null | grep -v "useAppFetch\|useRequestFetch\|FetchFn" || echo "All stores use safe fetch pattern (pass)"`

5. **Check for SSR hang risks**
   - `useAsyncData` with `lazy: false` combined with `watch` in `app.vue` or global middleware can cause infinite SSR loops.
     // turbo
     `grep -rn -A5 "useAsyncData" app/app.vue app/middleware/*.global.* 2>/dev/null | grep "lazy: false" || echo "No SSR hang risk patterns found (pass)"`
