/**
 * Tests for pinia-no-direct-state-mutation-outside-actions rule
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/pinia-no-direct-state-mutation-outside-actions'

const ruleTester = new RuleTester({
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
})

ruleTester.run('pinia-no-direct-state-mutation-outside-actions', rule, {
  valid: [
    {
      code: `
        import { defineStore } from 'pinia'
        export const useStore = defineStore('store', () => {
          const count = ref(0)
          function increment() {
            count.value++
          }
          return { count, increment }
        })
      `,
    },
  ],
  invalid: [
    {
      code: `
        const store = useCounterStore()
        store.$state.count = 1
      `,
      errors: [
        {
          messageId: 'noDirectMutation',
        },
      ],
    },
  ],
})
