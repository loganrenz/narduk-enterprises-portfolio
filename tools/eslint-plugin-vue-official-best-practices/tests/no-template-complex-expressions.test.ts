/**
 * Tests for no-template-complex-expressions rule
 */

import { RuleTester } from 'eslint'
import rule from '../src/rules/no-template-complex-expressions'
import vueParser from 'vue-eslint-parser'

const ruleTester = new RuleTester({
  parser: vueParser,
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
})

ruleTester.run('no-template-complex-expressions', rule, {
  valid: [
    {
      code: `
        <template>
          <div>{{ count }}</div>
        </template>
      `,
    },
    {
      code: `
        <template>
          <div>{{ formatPrice(price) }}</div>
        </template>
      `,
    },
  ],
  invalid: [
    {
      code: `
        <template>
          <div>{{ a ? b ? c : d : e }}</div>
        </template>
      `,
      errors: [
        {
          messageId: 'complexExpression',
        },
      ],
    },
  ],
})
