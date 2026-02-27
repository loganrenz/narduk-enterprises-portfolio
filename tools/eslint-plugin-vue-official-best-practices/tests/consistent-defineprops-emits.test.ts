/**
 * Tests for consistent-defineprops-emits rule
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/consistent-defineprops-emits'
import vueParser from 'vue-eslint-parser'

const ruleTester = new RuleTester({
  parser: vueParser,
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
})

ruleTester.run('consistent-defineprops-emits', rule, {
  valid: [
    {
      code: `
        <script setup>
        const props = defineProps<{ name: string }>()
        const emit = defineEmits<{ change: [value: string] }>()
        </script>
      `,
    },
  ],
  invalid: [
    {
      code: `
        <script setup>
        const props1 = defineProps<{ name: string }>()
        const props2 = defineProps<{ age: number }>()
        </script>
      `,
      errors: [
        {
          messageId: 'multipleDefineProps',
        },
      ],
    },
    {
      code: `
        <script setup>
        if (true) {
          const props = defineProps<{ name: string }>()
        }
        </script>
      `,
      errors: [
        {
          messageId: 'notTopLevel',
        },
      ],
    },
  ],
})
