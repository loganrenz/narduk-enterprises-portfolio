/**
 * Tests for no-legacy-fetch-hook rule
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/no-legacy-fetch-hook'
import vueParser from 'vue-eslint-parser'

const ruleTester = new RuleTester({
  parser: vueParser,
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
})

ruleTester.run('no-legacy-fetch-hook', rule, {
  valid: [
    {
      code: `
        <script setup>
        const { data } = await useFetch('/api')
        </script>
      `,
    },
  ],
  invalid: [
    {
      code: `
        <script>
        export default {
          async fetch() {
            return { data: {} }
          }
        }
        </script>
      `,
      errors: [
        {
          messageId: 'legacyFetch',
        },
      ],
    },
  ],
})
