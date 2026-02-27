/**
 * Tests for pinia-require-defineStore-id rule
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/pinia-require-defineStore-id'

const ruleTester = new RuleTester({
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
})

ruleTester.run('pinia-require-defineStore-id', rule, {
  valid: [
    {
      code: `import { defineStore } from 'pinia'
export const useStore = defineStore('store-id', () => {
  return {}
})`,
    },
    {
      code: `import { defineStore } from 'pinia'
export const useStore = defineStore('my-store', {
  state: () => ({}),
})`,
    },
  ],
  invalid: [
    {
      code: `import { defineStore } from 'pinia'
export const useStore = defineStore()`,
      errors: [
        {
          messageId: 'requireStoreId',
        },
      ],
    },
    {
      code: `import { defineStore } from 'pinia'
const id = 'store-id'
export const useStore = defineStore(id, () => {})`,
      errors: [
        {
          messageId: 'requireStoreId',
        },
      ],
    },
  ],
})
