/**
 * Tests for require-script-setup rule
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/require-script-setup'
import vueParser from 'vue-eslint-parser'

const ruleTester = new RuleTester({
  parser: vueParser,
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
})

ruleTester.run('require-script-setup', rule, {
  valid: [
    {
      code: `
        <script setup>
        const count = ref(0)
        </script>
      `,
    },
    {
      code: `
        <script setup lang="ts">
        const props = defineProps<{ name: string }>()
        </script>
      `,
    },
    {
      code: `
        <script>
        export default {
          name: 'MyComponent',
        }
        </script>
      `,
      options: [{ allowOptionsApi: true }],
    },
  ],
  invalid: [
    {
      code: `
        <script>
        export default {
          data() {
            return { count: 0 }
          },
          methods: {
            increment() {
              this.count++
            }
          }
        }
        </script>
      `,
      options: [{ allowOptionsApi: false }],
      errors: [
        {
          messageId: 'preferScriptSetup',
        },
      ],
    },
  ],
})
