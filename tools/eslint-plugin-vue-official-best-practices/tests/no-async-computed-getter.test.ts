/**
 * Tests for no-async-computed-getter rule
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/no-async-computed-getter'
import vueParser from 'vue-eslint-parser'

const ruleTester = new RuleTester({
  parser: vueParser,
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
})

ruleTester.run('no-async-computed-getter', rule, {
  valid: [
    {
      code: `
        <script setup>
        const count = computed(() => 1 + 1)
        </script>
      `,
    },
    {
      code: `
        <script setup>
        const doubled = computed(() => {
          return count.value * 2
        })
        </script>
      `,
    },
  ],
  invalid: [
    {
      code: `
        <script setup>
        const data = computed(async () => {
          const res = await fetch('/api')
          return res.json()
        })
        </script>
      `,
      errors: [
        {
          messageId: 'noAsyncComputed',
        },
      ],
    },
  ],
})
