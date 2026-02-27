/**
 * Tests for no-legacy-head rule
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/no-legacy-head'
import vueParser from 'vue-eslint-parser'

const ruleTester = new RuleTester({
  parser: vueParser,
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
})

ruleTester.run('no-legacy-head', rule, {
  valid: [
    {
      code: `
        <script setup>
        useHead({ title: 'Test' })
        </script>
      `,
    },
    {
      code: `
        <script>
        export default {
          data() {
            return {}
          }
        }
        </script>
      `,
    },
  ],
  invalid: [
    {
      code: `
        <script>
        export default {
          head() {
            return { title: 'Test' }
          }
        }
        </script>
      `,
      errors: [
        {
          messageId: 'legacyHeadMethod',
        },
      ],
    },
    {
      code: `
        <script>
        export default {
          head: {
            title: 'Test'
          }
        }
        </script>
      `,
      errors: [
        {
          messageId: 'legacyHeadOption',
        },
      ],
    },
  ],
})
