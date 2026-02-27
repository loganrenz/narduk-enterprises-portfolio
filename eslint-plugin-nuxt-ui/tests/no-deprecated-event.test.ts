/**
 * Tests for no-deprecated-event rule
 */

import { RuleTester } from '@typescript-eslint/rule-tester'
import rule from '../src/rules/no-deprecated-event'
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

ruleTester.run('nuxt-ui/no-deprecated-event', rule, {
  valid: [
    // Standard DOM event
    {
      code: '<template><UButton @click="handleClick">Click</UButton></template>',
    },
    // v-model update event
    {
      code: '<template><UModal @update:open="handleOpen">Content</UModal></template>',
    },
    // Standard DOM events (focus, blur, etc.)
    {
      code: '<template><UInput @focus="onFocus" @blur="onBlur" @input="onInput">Content</UInput></template>',
    },
    // Kebab-case component with standard events
    {
      code: '<template><u-button @click="handleClick">Click</u-button></template>',
    },
  ],
  invalid: [
    // Unknown event (not in spec or standard DOM events)
    {
      code: '<template><UButton @unknownEvent="handler">Click</UButton></template>',
      errors: [
        {
          messageId: 'unknownEvent',
        },
      ],
    },
  ],
})
