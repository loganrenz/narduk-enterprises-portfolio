/**
 * Rule: nuxt-guardrails/no-legacy-fetch-hook
 * 
 * Detects Nuxt 2 fetch() hook and guides toward useFetch/useAsyncData
 */

import type { RuleContext, RuleListener } from 'eslint'
import { getApiSpec } from '../utils/spec-loader'

export default {
  meta: {
    type: 'problem',
    docs: {
      description: 'disallow legacy Nuxt 2 fetch() hook',
      category: 'Best Practices',
      recommended: true,
    },
    schema: [],
    messages: {
      legacyFetch: 'Use useFetch() or useAsyncData() instead of fetch() hook. See: {{docUrl}}',
    },
  },
  create(context: RuleContext<string, any[]>): RuleListener {
    const parserServices = context.parserServices as any
    
    if (!parserServices || !parserServices.defineTemplateBodyVisitor) {
      return {}
    }
    
    const useFetchSpec = getApiSpec('useFetch')
    const useAsyncDataSpec = getApiSpec('useAsyncData')
    const docUrl = useFetchSpec?.docUrl || useAsyncDataSpec?.docUrl || 'https://nuxt.com/docs/api/composables/use-fetch'
    
    return parserServices.defineTemplateBodyVisitor(
      {},
      {
        // Check for fetch() method in Options API
        'MethodDefinition[key.name="fetch"]'(node: any) {
          context.report({
            node,
            messageId: 'legacyFetch',
            data: { docUrl },
          })
        },
      }
    )
  },
}
