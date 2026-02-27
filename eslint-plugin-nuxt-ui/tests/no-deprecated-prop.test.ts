/**
 * Tests for no-deprecated-prop rule
 */

import { RuleTester } from '@typescript-eslint/rule-tester'
import rule from '../src/rules/no-deprecated-prop'
import vueParser from 'vue-eslint-parser'

const ruleTester = new RuleTester({
  languageOptions: {
    parser: vueParser,
    parserOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
    },
  },
})

ruleTester.run('nuxt-ui/no-deprecated-prop', rule, {
  valid: [
    // Valid prop usage
    {
      code: '<template><UButton variant="solid">Click</UButton></template>',
    },
    // Component with non-deprecated props
    {
      code: '<template><UModal v-model:open="isOpen">Content</UModal></template>',
    },
    // Kebab-case component names
    {
      code: '<template><u-button variant="solid">Click</u-button></template>',
    },
  ],
  invalid: [
    // Deprecated prop without replacement
    {
      code: '<template><UButton oldProp="value">Click</UButton></template>',
      errors: [
        {
          messageId: 'deprecatedProp',
        },
      ],
    },
  ],
})
