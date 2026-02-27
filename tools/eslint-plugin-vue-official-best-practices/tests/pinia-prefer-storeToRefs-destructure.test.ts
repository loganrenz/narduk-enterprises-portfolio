/**
 * Tests for pinia-prefer-storeToRefs-destructure rule
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/pinia-prefer-storeToRefs-destructure'

const ruleTester = new RuleTester({
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
})

ruleTester.run('pinia-prefer-storeToRefs-destructure', rule, {
  valid: [
    {
      code: `
        const store = useCounterStore()
        const { count } = storeToRefs(store)
      `,
    },
    {
      code: `
        const { init } = useNotifications()
      `,
    },
  ],
  invalid: [
    {
      code: `
        const { count } = useCounterStore()
      `,
      errors: [
        {
          messageId: 'preferStoreToRefs',
        },
      ],
    },
  ],
})
