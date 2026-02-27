/**
 * Tests for require-valid-variant-values rule
 */

import { RuleTester } from '@typescript-eslint/rule-tester'
import rule from '../src/rules/require-valid-variant-values'
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

ruleTester.run('nuxt-ui/require-valid-variant-values', rule, {
  valid: [
    // Valid variant value
    {
      code: '<template><UButton variant="solid">Click</UButton></template>',
    },
    // Valid color value
    {
      code: '<template><UButton color="primary">Click</UButton></template>',
    },
    // Kebab-case prop names
    {
      code: '<template><UButton variant="outline">Click</UButton></template>',
    },
    // Dynamic values (should not be checked)
    {
      code: '<template><UButton :variant="dynamicVariant">Click</UButton></template>',
    },
    // Expression values (should not be checked)
    {
      code: '<template><UButton :variant="isActive ? \'solid\' : \'outline\'">Click</UButton></template>',
    },
  ],
  invalid: [
    // Invalid variant value (not in allowed values)
    {
      code: '<template><UButton variant="invalidValue">Click</UButton></template>',
      errors: [
        {
          messageId: 'invalidVariant',
        },
      ],
    },
    // Invalid color value
    {
      code: '<template><UButton color="invalidColor">Click</UButton></template>',
      errors: [
        {
          messageId: 'invalidVariant',
        },
      ],
    },
  ],
})
