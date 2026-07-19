import { buildRadarSnapshot, evaluateAlertRule, validateAlertRule, validateExecutionPolicy } from './launch-intelligence.mjs'
import { createLaunchSourceRegistry } from './source-adapters.mjs'

export function createLaunchRadar({ scout, policy = {}, alertRules = [] }) {
  const sources = createLaunchSourceRegistry()
  const rules = alertRules.map(validateAlertRule)
  const executionPolicy = validateExecutionPolicy(policy)

  function snapshot(query = {}) {
    const result = buildRadarSnapshot(scout, query, executionPolicy)
    return { ...result, policy: executionPolicy }
  }

  return Object.freeze({
    sources: () => ({ generatedAt: new Date().toISOString(), sources: sources.list() }),
    snapshot,
    alerts: (query = {}) => {
      const current = snapshot({ ...query, limit: 500 })
      const matches = []
      for (const candidate of current.candidates) {
        for (const rule of rules) {
          const result = evaluateAlertRule(candidate, rule)
          if (result.matched) matches.push({ candidateId: candidate.id, ruleId: rule.id, actions: rule.actions, candidate })
        }
      }
      const rawLimit = Number(query.limit ?? 100)
      const limit = Number.isSafeInteger(rawLimit) ? Math.max(1, Math.min(500, rawLimit)) : 100
      return { generatedAt: current.generatedAt, policy: executionPolicy, rules: rules.length, matches: matches.slice(0, limit) }
    }
  })
}
