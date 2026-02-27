/**
 * Rule: nuxt-guardrails/no-legacy-head
 * 
 * Detects Vue Options API head() method or head: {} option
 * and guides toward useHead() composable
 */

import type { AST } from 'vue-eslint-parser'
import type { RuleContext, RuleListener } from 'eslint'
import { getApiSpec } from '../utils/spec-loader'

export default {
  meta: {
    type: 'problem',
    docs: {
      description: 'disallow legacy Options API head() method or head option',
      category: 'Best Practices',
      recommended: true,
    },
    fixable: 'code',
    schema: [],
    messages: {
      legacyHeadMethod: 'Use useHead() composable instead of head() method. See: {{docUrl}}',
      legacyHeadOption: 'Use useHead() composable instead of head option. See: {{docUrl}}',
    },
  },
  create(context: RuleContext<string, any[]>): RuleListener {
    const parserServices = context.parserServices as any
    
    // Only process Vue files
    if (!parserServices || !parserServices.defineTemplateBodyVisitor) {
      return {}
    }
    
    const useHeadSpec = getApiSpec('useHead')
    const docUrl = useHeadSpec?.docUrl || 'https://nuxt.com/docs/api/composables/use-head'
    
    return parserServices.defineTemplateBodyVisitor(
      {},
      {
        // Check script block for Options API patterns
        'Program:exit'(node: AST.ESLintProgram) {
          // Find export default with Options API
          for (const statement of node.body) {
            if (
              statement.type === 'ExportDefaultDeclaration' &&
              statement.declaration &&
              statement.declaration.type === 'ObjectExpression'
            ) {
              const obj = statement.declaration
              
              // Check for head: {} option
              for (const prop of obj.properties) {
                if (
                  prop.type === 'Property' &&
                  prop.key &&
                  ((prop.key.type === 'Identifier' && prop.key.name === 'head') ||
                   (prop.key.type === 'Literal' && prop.key.value === 'head'))
                ) {
                  context.report({
                    node: prop,
                    messageId: 'legacyHeadOption',
                    data: { docUrl },
                    fix(fixer) {
                      // Only autofix if it's a simple literal object
                      if (
                        prop.value &&
                        prop.value.type === 'ObjectExpression' &&
                        prop.value.properties.length > 0
                      ) {
                        const firstProp = prop.value.properties[0]
                        if (
                          firstProp.type === 'Property' &&
                          firstProp.key &&
                          firstProp.key.type === 'Identifier' &&
                          (firstProp.key.name === 'title' || firstProp.key.name === 'description') &&
                          firstProp.value &&
                          firstProp.value.type === 'Literal'
                        ) {
                          const key = firstProp.key.name
                          const value = firstProp.value.value
                          const useHeadCall = `useHead({ ${key}: '${value}' })`
                          return fixer.replaceText(prop, useHeadCall)
                        }
                      }
                      return null
                    },
                  })
                }
              }
            }
          }
        },
        
        // Check for head() method
        'MethodDefinition[key.name="head"]'(node: any) {
          context.report({
            node,
            messageId: 'legacyHeadMethod',
            data: { docUrl },
          })
        },
      }
    )
  },
}
