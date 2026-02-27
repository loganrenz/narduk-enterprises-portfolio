/**
 * Tests for prefer-shallow-watch rule
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/prefer-shallow-watch'
import vueParser from 'vue-eslint-parser'

const ruleTester = new RuleTester({
  parser: vueParser,
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
})

ruleTester.run('prefer-shallow-watch', rule, {
  valid: [
    {
      code: `
        <script setup>
        watch(state, () => {})
        </script>
      `,
    },
    {
      code: `
        <script setup>
        /* vue-official allow-deep-watch */
        watch(state, () => {}, { deep: true })
        </script>
      `,
    },
  ],
  invalid: [
    {
      code: `
        <script setup>
        watch(state, () => {}, { deep: true })
        </script>
      `,
      errors: [
        {
          messageId: 'preferShallowWatch',
        },
      ],
    },
  ],
})
