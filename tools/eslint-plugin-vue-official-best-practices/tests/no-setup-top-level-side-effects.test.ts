/**
 * Tests for no-setup-top-level-side-effects rule
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/no-setup-top-level-side-effects'
import vueParser from 'vue-eslint-parser'

const ruleTester = new RuleTester({
  parser: vueParser,
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
})

ruleTester.run('no-setup-top-level-side-effects', rule, {
  valid: [
    {
      code: `
        <script setup>
        const { data } = await useFetch('/api')
        </script>
      `,
    },
    {
      code: `
        <script setup>
        onMounted(() => {
          window.addEventListener('resize', handleResize)
        })
        </script>
      `,
    },
    {
      code: `
        <script setup>
        if (import.meta.client) {
          window.something = true
        }
        </script>
      `,
    },
  ],
  invalid: [
    {
      code: `
        <script setup>
        fetch('/api')
        </script>
      `,
      errors: [
        {
          messageId: 'useNuxtComposable',
        },
      ],
    },
    {
      code: `
        <script setup>
        setInterval(() => {}, 1000)
        </script>
      `,
      errors: [
        {
          messageId: 'noTopLevelSideEffect',
        },
      ],
    },
    {
      code: `
        <script setup>
        window.something = true
        </script>
      `,
      errors: [
        {
          messageId: 'noTopLevelSideEffect',
        },
      ],
    },
  ],
})
