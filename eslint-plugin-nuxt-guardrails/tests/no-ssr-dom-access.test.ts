/**
 * Tests for no-ssr-dom-access rule
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/no-ssr-dom-access'

const ruleTester = new RuleTester({
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
})

ruleTester.run('no-ssr-dom-access', rule, {
  valid: [
    {
      code: 'if (import.meta.client) { window.location.href = "/" }',
    },
    {
      code: 'onMounted(() => { document.title = "Test" })',
    },
    {
      code: 'if (import.meta.client) { localStorage.setItem("key", "value") }',
    },
  ],
  invalid: [
    {
      code: 'window.location.href = "/"',
      errors: [
        {
          messageId: 'unguardedDomAccess',
          data: { type: 'window' },
        },
      ],
    },
    {
      code: 'document.title = "Test"',
      errors: [
        {
          messageId: 'unguardedDomAccess',
          data: { type: 'document' },
        },
      ],
    },
    {
      code: 'localStorage.setItem("key", "value")',
      errors: [
        {
          messageId: 'unguardedDomAccess',
          data: { type: 'localStorage' },
        },
      ],
    },
  ],
})
