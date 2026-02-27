/**
 * Tests for prefer-import-meta-client rule
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/prefer-import-meta-client'

const ruleTester = new RuleTester({
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
})

ruleTester.run('prefer-import-meta-client', rule, {
  valid: [
    {
      code: 'if (import.meta.client) { console.log("client") }',
    },
    {
      code: 'if (import.meta.server) { console.log("server") }',
    },
    {
      code: 'if (process.client) { }',
      options: [{ allowProcessClientServer: true }],
    },
  ],
  invalid: [
    {
      code: 'if (process.client) { }',
      errors: [
        {
          messageId: 'preferImportMetaClient',
        },
      ],
      output: 'if (import.meta.client) { }',
    },
    {
      code: 'if (process.server) { }',
      errors: [
        {
          messageId: 'preferImportMetaServer',
        },
      ],
      output: 'if (import.meta.server) { }',
    },
  ],
})
