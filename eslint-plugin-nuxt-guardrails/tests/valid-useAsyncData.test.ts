/**
 * Tests for valid-useAsyncData rule
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/valid-useAsyncData'

const ruleTester = new RuleTester({
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
})

ruleTester.run('valid-useAsyncData', rule, {
  valid: [
    {
      code: "useAsyncData('key', () => fetch('/api'))",
    },
    {
      code: "useAsyncData('key', async () => { return await fetch('/api') })",
    },
    {
      code: 'useAsyncData(key, () => fetch("/api"))',
      options: [{ requireStableAsyncDataKeys: false }],
    },
  ],
  invalid: [
    {
      code: 'useAsyncData()',
      errors: [
        {
          messageId: 'missingKey',
        },
      ],
    },
    {
      code: "useAsyncData('key')",
      errors: [
        {
          messageId: 'missingCallback',
        },
      ],
    },
    {
      code: 'useAsyncData(key, () => fetch("/api"))',
      errors: [
        {
          messageId: 'keyNotLiteral',
        },
      ],
    },
  ],
})
