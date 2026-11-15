import { createTpError } from "./envelope.mjs";

export function validateSubGoalDag(subGoals = []) {
  if (!Array.isArray(subGoals)) {
    return { ok: false, error: createTpError("TP-GOAL002", "sub_goals must be an array.") };
  }
  if (subGoals.length === 0) {
    return { ok: true, topologicalOrder: [], waves: [] };
  }

  const ids = new Set();
  for (const sg of subGoals) {
    if (!sg || typeof sg.sub_goal_id !== "string" || sg.sub_goal_id.length === 0 || !Array.isArray(sg.depends_on)) {
      return { ok: false, error: createTpError("TP-GOAL002", "Invalid SubGoalReference entry.") };
    }
    if (ids.has(sg.sub_goal_id)) {
      return { ok: false, error: createTpError("TP-GOAL002", `Duplicate sub_goal_id "${sg.sub_goal_id}".`) };
    }
    ids.add(sg.sub_goal_id);
  }

  const inDegree = new Map();
  const dependents = new Map();
  for (const sg of subGoals) {
    inDegree.set(sg.sub_goal_id, 0);
    dependents.set(sg.sub_goal_id, []);
  }

  for (const sg of subGoals) {
    for (const dep of sg.depends_on) {
      if (!ids.has(dep) || dep === sg.sub_goal_id) {
        return { ok: false, error: createTpError("TP-GOAL002", `Invalid or self dependency "${dep}".`) };
      }
      inDegree.set(sg.sub_goal_id, inDegree.get(sg.sub_goal_id) + 1);
      dependents.get(dep).push(sg.sub_goal_id);
    }
  }

  const topologicalOrder = [];
  const waves = [];
  let ready = [...inDegree.entries()]
    .filter(([, deg]) => deg === 0)
    .map(([id]) => id);

  while (ready.length > 0) {
    waves.push(ready);
    const nextReady = [];
    for (const id of ready) {
      topologicalOrder.push(id);
      for (const child of dependents.get(id)) {
        const nextDeg = inDegree.get(child) - 1;
        inDegree.set(child, nextDeg);
        if (nextDeg === 0) nextReady.push(child);
      }
    }
    ready = nextReady;
  }

  if (topologicalOrder.length !== subGoals.length) {
    return { ok: false, error: createTpError("TP-GOAL002", "Cyclic dependency detected in sub_goals DAG.") };
  }
  return { ok: true, topologicalOrder, waves };
}

function validateOutputAgainstSchema(output, schema) {
  if (!schema || typeof schema !== "object") return true;
  if (schema.type === "object") {
    if (!output || typeof output !== "object" || Array.isArray(output)) return false;
    if (Array.isArray(schema.required)) {
      for (const reqKey of schema.required) {
        if (!(reqKey in output) || output[reqKey] === undefined) return false;
      }
    }
    if (schema.properties && typeof schema.properties === "object") {
      for (const [prop, propSchema] of Object.entries(schema.properties)) {
        if (output[prop] !== undefined && propSchema && typeof propSchema.type === "string") {
          const val = output[prop];
          if (propSchema.type === "array" && !Array.isArray(val)) return false;
          if (propSchema.type === "object" && (typeof val !== "object" || val === null || Array.isArray(val))) return false;
          if (["string", "number", "boolean"].includes(propSchema.type) && typeof val !== propSchema.type) {
            return false;
          }
        }
      }
    }
  }
  return true;
}

export class GoalStateMachine {
  constructor(sharedContextManager = null, { maxNegotiationRounds = 10 } = {}) {
    this.sharedContextManager = sharedContextManager;
    this.maxNegotiationRounds = maxNegotiationRounds;
    this.goals = new Map();
    this.rounds = new Map();
    this.subGoalStatuses = new Map();
  }

  getGoal(goalId) {
    return this.goals.get(goalId) ?? null;
  }

  proposeGoal(goal, nowIso = new Date().toISOString()) {
    if (!goal || typeof goal.goal_id !== "string" || typeof goal.context_ref !== "string") {
      return { ok: false, error: createTpError("TP-GOAL001", "Goal requires goal_id and context_ref.") };
    }
    if (this.sharedContextManager) {
      const ctx = this.sharedContextManager.getContext(goal.context_ref);
      if (!ctx || ctx.lifecycle.state !== "active") {
        return { ok: false, error: createTpError("TP-GOAL003", "Goal requires an active SharedContext.") };
      }
      if (ctx.lifecycle.expiration && Date.parse(nowIso) >= Date.parse(ctx.lifecycle.expiration)) {
        return { ok: false, error: createTpError("TP-GOAL003", "Referenced SharedContext is expired.") };
      }
    }
    const dagCheck = validateSubGoalDag(goal.sub_goals ?? []);
    if (!dagCheck.ok) return dagCheck;

    const stored = { ...structuredClone(goal), status: "proposed" };
    this.goals.set(goal.goal_id, stored);
    this.rounds.set(goal.goal_id, 0);
    const sgMap = new Map();
    for (const sg of stored.sub_goals ?? []) sgMap.set(sg.sub_goal_id, "proposed");
    this.subGoalStatuses.set(goal.goal_id, sgMap);
    return { ok: true, goal: stored, waves: dagCheck.waves };
  }

  counterPropose(goalId, patch = {}) {
    const goal = this.goals.get(goalId);
    if (!goal || !["proposed", "negotiating"].includes(goal.status)) {
      return { ok: false, error: createTpError("TP-GOAL001", "Goal cannot be counter-proposed in current state.") };
    }
    const nextRound = (this.rounds.get(goalId) ?? 0) + 1;
    if (nextRound > this.maxNegotiationRounds) {
      goal.status = "rejected";
      return {
        ok: false,
        error: createTpError("TP-GOAL005", `Exceeded max negotiation rounds (${this.maxNegotiationRounds}).`)
      };
    }
    if (patch.sub_goals) {
      const dagCheck = validateSubGoalDag(patch.sub_goals);
      if (!dagCheck.ok) return dagCheck;
      goal.sub_goals = structuredClone(patch.sub_goals);
    }
    if (patch.constraints) goal.constraints = structuredClone(patch.constraints);
    if (patch.parameters) goal.parameters = structuredClone(patch.parameters);
    this.rounds.set(goalId, nextRound);
    goal.status = "negotiating";
    return { ok: true, round: nextRound, goal };
  }

  acceptGoal(goalId) {
    const goal = this.goals.get(goalId);
    if (!goal || !["proposed", "negotiating"].includes(goal.status)) {
      return { ok: false, error: createTpError("TP-GOAL001", "Cannot accept Goal from current state.") };
    }
    goal.status = "accepted";
    return { ok: true, goal };
  }

  rejectGoal(goalId, reason = "Rejected by peer Fay") {
    const goal = this.goals.get(goalId);
    if (!goal || !["proposed", "negotiating"].includes(goal.status)) {
      return { ok: false, error: createTpError("TP-GOAL001", "Cannot reject Goal from current state.") };
    }
    goal.status = "rejected";
    goal.result = {
      goal_id: goalId,
      status: "failed",
      error: { error_code: "TP-GOAL001", error_message: reason }
    };
    return { ok: true, goal };
  }

  startExecution(goalId) {
    const goal = this.goals.get(goalId);
    if (!goal || goal.status !== "accepted") {
      return { ok: false, error: createTpError("TP-GOAL001", "Goal must be accepted before execution.") };
    }
    goal.status = "in_progress";
    return { ok: true, goal };
  }

  completeGoal(goalId, output) {
    const goal = this.goals.get(goalId);
    if (!goal || !["accepted", "in_progress"].includes(goal.status)) {
      return { ok: false, error: createTpError("TP-GOAL001", "Goal is not in execution.") };
    }
    if (!validateOutputAgainstSchema(output, goal.description?.output_schema)) {
      return { ok: false, error: createTpError("TP-GOAL004", "Goal output failed output_schema validation.") };
    }
    goal.status = "completed";
    goal.result = { goal_id: goalId, status: "completed", output: structuredClone(output) };
    return { ok: true, goal };
  }

  cancelGoal(goalId) {
    const goal = this.goals.get(goalId);
    if (!goal) return { ok: false, error: createTpError("TP-GOAL001", `Unknown Goal "${goalId}".`) };
    goal.status = "cancelled";
    return { ok: true, goal };
  }

  propagateSubGoalFailure(goalId, failedSubGoalId) {
    const goal = this.goals.get(goalId);
    if (!goal) return { ok: false, error: createTpError("TP-GOAL001", `Unknown Goal "${goalId}".`) };
    const sgMap = this.subGoalStatuses.get(goalId);
    if (!sgMap || !sgMap.has(failedSubGoalId)) {
      return { ok: false, error: createTpError("TP-GOAL011", `Unknown sub_goal_id "${failedSubGoalId}".`) };
    }
    sgMap.set(failedSubGoalId, "failed");
    const cancelledSubGoals = [];
    const queue = [failedSubGoalId];
    const visited = new Set([failedSubGoalId]);
    while (queue.length > 0) {
      const curr = queue.shift();
      for (const sg of goal.sub_goals ?? []) {
        if (sg.depends_on.includes(curr) && !visited.has(sg.sub_goal_id)) {
          visited.add(sg.sub_goal_id);
          sgMap.set(sg.sub_goal_id, "cancelled");
          cancelledSubGoals.push(sg.sub_goal_id);
          queue.push(sg.sub_goal_id);
        }
      }
    }
    return { ok: true, cancelledSubGoals };
  }
}

export function computeRetryDelayMs(retryPolicy, attemptIndex) {
  if (!retryPolicy) return 0;
  if (retryPolicy.backoff_strategy === "exponential") {
    return retryPolicy.initial_delay_ms * 2 ** attemptIndex;
  }
  return retryPolicy.initial_delay_ms;
}

export class ConsultationManager {
  constructor({ maxChainDepth = 5 } = {}) {
    this.maxChainDepth = maxChainDepth;
    this.consultations = new Map();
  }

  registerConsultation(request) {
    if (
      !request ||
      typeof request.consultation_id !== "string" ||
      typeof request.query_type !== "string" ||
      !request.required_info_schema ||
      !request.authorization_scope ||
      !Array.isArray(request.authorization_scope.required_permissions)
    ) {
      return { ok: false, error: createTpError("TP-GOAL021", "Malformed ConsultationRequest.") };
    }

    const needsPrimeDelegation = request.authorization_scope.required_permissions.some(
      (p) => p === "prime_delegated" || p.startsWith("prime_delegated:")
    );
    if (needsPrimeDelegation) {
      const pd = request.authorization_scope.prime_delegation;
      if (
        !pd ||
        typeof pd.human_prime_id !== "string" ||
        pd.human_prime_id.length === 0 ||
        typeof pd.fp_authorization_ref !== "string" ||
        pd.fp_authorization_ref.length === 0
      ) {
        return {
          ok: false,
          error: createTpError("TP-ID003", "PrimeDelegation with human_prime_id and fp_authorization_ref is required.")
        };
      }
    }

    let depth = 1;
    if (request.chained_from) {
      const visited = new Set([request.consultation_id]);
      let currId = request.chained_from;
      while (currId) {
        if (visited.has(currId)) {
          return { ok: false, error: createTpError("TP-GOAL020", "Cyclic consultation chain.") };
        }
        visited.add(currId);
        const parent = this.consultations.get(currId);
        if (!parent) {
          return { ok: false, error: createTpError("TP-GOAL020", `Unknown chained_from "${currId}".`) };
        }
        depth += 1;
        if (depth > this.maxChainDepth) {
          return {
            ok: false,
            error: createTpError("TP-GOAL020", `Consultation chain depth (${depth}) exceeds ${this.maxChainDepth}.`)
          };
        }
        currId = parent.chained_from;
      }
    }

    this.consultations.set(request.consultation_id, structuredClone(request));
    return { ok: true, depth };
  }
}
