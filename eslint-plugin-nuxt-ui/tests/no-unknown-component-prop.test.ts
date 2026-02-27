/**
 * Tests for no-unknown-component-prop rule
 */

import { RuleTester } from '@typescript-eslint/rule-tester'
import rule from '../src/rules/no-unknown-component-prop'
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

ruleTester.run('nuxt-ui/no-unknown-component-prop', rule, {
  valid: [
    {
      code: '<template><UButton variant="solid">Click</UButton></template>',
    },
    {
      code: '<template><u-button variant="solid">Click</u-button></template>',
    },
  ],
  invalid: [
    {
      code: '<template><UButton unknownProp="value">Click</UButton></template>',
      errors: [
        {
          messageId: 'unknownProp',
          data: {
            propName: 'unknownProp',
            componentName: 'UButton',
            componentSlug: 'button',
          },
        },
      ],
    },
  ],
})
