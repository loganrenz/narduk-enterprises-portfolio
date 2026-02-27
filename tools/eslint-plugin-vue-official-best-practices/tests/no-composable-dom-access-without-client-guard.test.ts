/**
 * Tests for no-composable-dom-access-without-client-guard rule
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/no-composable-dom-access-without-client-guard'

const ruleTester = new RuleTester({
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
})

ruleTester.run('no-composable-dom-access-without-client-guard', rule, {
  valid: [
    {
      code: `
        export function useWindow() {
          if (import.meta.client) {
            window.something = true
          }
        }
      `,
      filename: 'composables/useWindow.ts',
    },
    {
      code: `
        export function useWindow() {
          onMounted(() => {
            window.something = true
          })
        }
      `,
      filename: 'composables/useWindow.ts',
    },
  ],
  invalid: [
    {
      code: `
        export function useWindow() {
          window.something = true
        }
      `,
      filename: 'composables/useWindow.ts',
      errors: [
        {
          messageId: 'noClientGuard',
        },
      ],
    },
  ],
})
