---
description: Audit plugin naming, lifecycle safety, and analytics patterns
---

This workflow enforces safe Nuxt plugin naming conventions and lifecycle patterns derived from stonx-app-2026.

1. **Verify plugin file suffixes**
   - Plugins that access `window`, `document`, or browser-only APIs MUST use the `.client.ts` suffix. Server-only plugins MUST use `.server.ts`. Incorrect suffixes cause SSR crashes or client-side errors.
     // turbo
     `for f in $(find app/plugins -name "*.ts" ! -name "*.client.ts" ! -name "*.server.ts"); do grep -l "window\.\|document\.\|localStorage\|sessionStorage\|navigator\." "$f" 2>/dev/null; done || echo "No unsafe plugin suffixes found (pass)"`

2. **Check for correct analytics capture pattern**
   - Analytics plugins (PostHog, GA4) should disable auto-capture and use manual `$pageview` events on `router.afterEach` with `nextTick`. This ensures accurate SPA route tracking.
     // turbo
     `grep -rn "capture_pageview\|auto_capture\|autocapture" app/plugins/ 2>/dev/null || echo "No analytics auto-capture config found — verify manually"`

3. **Check for `process.env.NODE_ENV` in server code**
   - Server-side code should use `import.meta.dev` (the Vite/Nitro standard) instead of `process.env.NODE_ENV`. The latter is unreliable in Cloudflare Workers.
     // turbo
     `grep -rn "process.env.NODE_ENV" server/ app/ 2>/dev/null || echo "No process.env.NODE_ENV found (pass)"`

4. **Check for blocking Nitro plugin initialization**
   - Server plugins (`defineNitroPlugin`) must not perform heavy async work (like establishing database connections or WebSocket pools) synchronously at startup. This blocks Nitro's ready signal and causes proxy timeouts on Fly.io/Cloudflare.
     // turbo
     `grep -rn -A3 "defineNitroPlugin" server/plugins/ 2>/dev/null | head -20`
   - Review output manually: ensure heavy async is in `nitroApp.hooks.hook('ready', ...)` or `onReady`, not in the top-level plugin body.

5. **Verify graceful no-op when keys are missing**
   - All analytics/third-party plugins should check for empty API keys and return early without errors. This allows dev mode to run without any Doppler configuration.
     // turbo
     `grep -rn "posthogPublicKey\|gaMeasurementId" app/plugins/ 2>/dev/null | head -10`
   - Verify that each plugin has a guard like `if (!key) return` before initialization.
