/**
 * Tests for valid-useFetch rule
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/valid-useFetch'

const ruleTester = new RuleTester({
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
})

ruleTester.run('valid-useFetch', rule, {
  valid: [
    {
      code: "useFetch('/api/data')",
    },
    {
      code: 'useFetch(() => `/api/${id}`)',
    },
    {
      code: "useFetch('/api/data', { server: true })",
    },
  ],
  invalid: [
    {
      code: 'useFetch()',
      errors: [
        {
          messageId: 'missingUrl',
        },
      ],
    },
  ],
})
