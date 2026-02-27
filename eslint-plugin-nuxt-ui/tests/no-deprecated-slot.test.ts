/**
 * Tests for no-deprecated-slot rule
 */

import { RuleTester } from '@typescript-eslint/rule-tester'
import rule from '../src/rules/no-deprecated-slot'
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

ruleTester.run('nuxt-ui/no-deprecated-slot', rule, {
  valid: [
    // Valid slot usage with default slot
    {
      code: '<template><UButton><template #default>Click</template></UButton></template>',
    },
    // Valid named slot
    {
      code: '<template><UModal><template #header>Title</template></UModal></template>',
    },
    // Dynamic slots (UTable)
    {
      code: '<template><UTable><template #name-cell>Cell</template></UTable></template>',
    },
    // Dynamic slots (UTabs)
    {
      code: '<template><UTabs><template #customTab>Tab</template></UTabs></template>',
    },
    // Fallback slot (UAvatar)
    {
      code: '<template><UAvatar><template #fallback>?</template></UAvatar></template>',
    },
  ],
  invalid: [
    // Unknown slot (not dynamic pattern)
    {
      code: '<template><UButton><template #unknownSlot>Content</template></UButton></template>',
      errors: [
        {
          messageId: 'unknownSlot',
        },
      ],
    },
  ],
})
