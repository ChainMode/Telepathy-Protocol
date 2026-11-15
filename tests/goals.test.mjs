import test from "node:test";
import assert from "node:assert/strict";
import {
  validateSubGoalDag,
  GoalStateMachine,
  ConsultationManager,
  computeRetryDelayMs
} from "../src/goals.mjs";
import { SharedContextManager } from "../src/shared-context.mjs";
import {
  ALICE_FAY_ID,
  BOB_FAY_ID,
  makeAliceIdentity,
  makeBobIdentity
} from "./_fixtures.mjs";

test("validateSubGoalDag accepts valid acyclic DAGs, computes topological waves, and rejects cycles with TP-GOAL002", () => {
  const validDag = [
    { sub_goal_id: "sg_flights", depends_on: [] },
    { sub_goal_id: "sg_hotels", depends_on: ["sg_flights"] },
    { sub_goal_id: "sg_rail_pass", depends_on: ["sg_flights"] },
    { sub_goal_id: "sg_summary", depends_on: ["sg_hotels", "sg_rail_pass"] }
  ];
  const res = validateSubGoalDag(validDag);
  assert.equal(res.ok, true);
  assert.deepEqual(res.waves, [
    ["sg_flights"],
    ["sg_hotels", "sg_rail_pass"],
    ["sg_summary"]
  ]);

  const cyclicDag = [
    { sub_goal_id: "sg_a", depends_on: ["sg_c"] },
    { sub_goal_id: "sg_b", depends_on: ["sg_a"] },
    { sub_goal_id: "sg_c", depends_on: ["sg_b"] }
  ];
  const cycRes = validateSubGoalDag(cyclicDag);
  assert.equal(cycRes.ok, false);
  assert.equal(cycRes.error.error_code, "TP-GOAL002");
});

test("GoalStateMachine enforces active context (TP-GOAL003), bilateral negotiation <= 10 rounds (TP-GOAL005), output schema check, and cascading sub-goal cancel", () => {
  const ctxMgr = new SharedContextManager();
  ctxMgr.createContext({
    contextId: "ctx_goal_01",
    participants: [makeAliceIdentity(), makeBobIdentity()],
    mode: "collaborative_space",
    nowIso: "2026-11-16T00:00:00Z"
  });
  // Before activation -> TP-GOAL003
  const gsm = new GoalStateMachine(ctxMgr);
  const baseGoal = {
    goal_id: "goal_trip_01",
    goal_type: "execute",
    description: {
      summary: "Generate Kyoto 3-day itinerary",
      output_schema: {
        type: "object",
        required: ["days", "estimated_cost_cny"],
        properties: {
          days: { type: "array" },
          estimated_cost_cny: { type: "number" }
        }
      }
    },
    parameters: {
      schema_ref: "https://ifay.ai/schemas/trip-params.json",
      values: { city: "Kyoto", nights: 2 }
    },
    constraints: [{ constraint_type: "priority", value: "high", required: true }],
    sub_goals: [
      { sub_goal_id: "sg_transport", depends_on: [] },
      { sub_goal_id: "sg_lodging", depends_on: ["sg_transport"] }
    ],
    context_ref: "ctx_goal_01",
    status: "proposed"
  };

  const inactiveAttempt = gsm.proposeGoal(baseGoal, "2026-11-16T00:00:01Z");
  assert.equal(inactiveAttempt.ok, false);
  assert.equal(inactiveAttempt.error.error_code, "TP-GOAL003");

  ctxMgr.activateContext("ctx_goal_01", "2026-11-16T00:00:02Z");
  assert.equal(gsm.proposeGoal(baseGoal, "2026-11-16T00:00:03Z").ok, true);

  // Counter-propose 2 rounds then accept
  assert.equal(gsm.counterPropose("goal_trip_01", { constraints: [] }).ok, true);
  assert.equal(gsm.getGoal("goal_trip_01").status, "negotiating");
  assert.equal(gsm.acceptGoal("goal_trip_01").ok, true);
  assert.equal(gsm.startExecution("goal_trip_01").ok, true);

  // Output missing required field fails with TP-GOAL004
  const badOutput = gsm.completeGoal("goal_trip_01", { days: ["Day 1"] });
  assert.equal(badOutput.ok, false);
  assert.equal(badOutput.error.error_code, "TP-GOAL004");

  const goodOutput = gsm.completeGoal("goal_trip_01", { days: ["Day 1", "Day 2", "Day 3"], estimated_cost_cny: 4200 });
  assert.equal(goodOutput.ok, true);
  assert.equal(gsm.getGoal("goal_trip_01").status, "completed");

  // Exceeding 10 counter-proposals fails with TP-GOAL005
  const loopGoal = { ...baseGoal, goal_id: "goal_loop_02" };
  assert.equal(gsm.proposeGoal(loopGoal, "2026-11-16T00:01:00Z").ok, true);
  for (let i = 1; i <= 10; i++) {
    assert.equal(gsm.counterPropose("goal_loop_02", { round: i }).ok, true);
  }
  const round11 = gsm.counterPropose("goal_loop_02", { round: 11 });
  assert.equal(round11.ok, false);
  assert.equal(round11.error.error_code, "TP-GOAL005");

  // Sub-goal failure cascades cancellation to dependent sub-goals
  const cascade = gsm.propagateSubGoalFailure("goal_trip_01", "sg_transport");
  assert.equal(cascade.ok, true);
  assert.deepEqual(cascade.cancelledSubGoals, ["sg_lodging"]);
});

test("ConsultationManager enforces PrimeDelegation fp_authorization_ref, max 5 chain hops (TP-GOAL020), and backoff timing", () => {
  const cm = new ConsultationManager();

  // Missing prime_delegation when prime_delegated permission requested -> TP-ID003
  const missingDelegation = cm.registerConsultation({
    consultation_id: "cons_unauth",
    query_type: "calendar_availability",
    required_info_schema: { type: "object" },
    authorization_scope: {
      required_permissions: ["prime_delegated:calendar.read"]
    }
  });
  assert.equal(missingDelegation.ok, false);
  assert.equal(missingDelegation.error.error_code, "TP-ID003");

  // Build valid 5-hop chain (depth 1..5), then 6th hop fails with TP-GOAL020
  let prevId = undefined;
  for (let hop = 1; hop <= 5; hop++) {
    const id = `cons_hop_${hop}`;
    const res = cm.registerConsultation({
      consultation_id: id,
      query_type: "availability_check",
      required_info_schema: { type: "object" },
      authorization_scope: {
        required_permissions: ["prime_delegated:calendar.read"],
        prime_delegation: {
          human_prime_id: "prime_alice_001",
          delegated_permissions: ["prime_delegated:calendar.read"],
          fp_authorization_ref: "fp_mandate_alice_2026_01"
        }
      },
      chained_from: prevId
    });
    assert.equal(res.ok, true);
    assert.equal(res.depth, hop);
    prevId = id;
  }

  const hop6 = cm.registerConsultation({
    consultation_id: "cons_hop_6",
    query_type: "availability_check",
    required_info_schema: { type: "object" },
    authorization_scope: {
      required_permissions: ["public"]
    },
    chained_from: prevId
  });
  assert.equal(hop6.ok, false);
  assert.equal(hop6.error.error_code, "TP-GOAL020");

  assert.equal(
    computeRetryDelayMs({ max_retries: 3, backoff_strategy: "exponential", initial_delay_ms: 250 }, 2),
    1000
  );
  assert.equal(
    computeRetryDelayMs({ max_retries: 3, backoff_strategy: "fixed", initial_delay_ms: 250 }, 2),
    250
  );
});
