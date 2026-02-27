/**
 * Tests for prefer-typed-defineprops rule
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/prefer-typed-defineprops'
import vueParser from 'vue-eslint-parser'
import tsParser from '@typescript-eslint/parser'

const ruleTester = new RuleTester({
  parser: vueParser,
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
    parser: tsParser,
  },
})

ruleTester.run('prefer-typed-defineprops', rule, {
  valid: [
    {
      code: `
        <script setup lang="ts">
        const props = defineProps<{ name: string }>()
        </script>
      `,
    },
    {
      code: `
        <script setup lang="ts">
        const props = withDefaults(defineProps<{ name: string }>(), { name: 'default' })
        </script>
      `,
    },
  ],
  invalid: [
    {
      code: `
        <script setup lang="ts">
        const props = defineProps({ name: String })
        </script>
      `,
      errors: [
        {
          messageId: 'preferTypedProps',
        },
      ],
    },
  ],
})
