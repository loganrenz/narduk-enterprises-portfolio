/**
 * Tests for app-structure-consistency rule
 * Note: This rule checks file system, so tests are limited
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/app-structure-consistency'

const ruleTester = new RuleTester({
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
})

ruleTester.run('app-structure-consistency', rule, {
  valid: [
    {
      code: 'export default {}',
      options: [{ projectStyle: 'legacy' }],
    },
    {
      code: 'export default {}',
      options: [{ projectStyle: 'mixed' }],
    },
  ],
  invalid: [
    // Note: Actual file system checks would require mocking
    // These tests verify the rule structure
  ],
})
