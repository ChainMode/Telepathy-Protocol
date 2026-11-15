export const SEED_ALICE_HEX = "0101010101010101010101010101010101010101010101010101010101010101";
export const SEED_BOB_HEX = "0202020202020202020202020202020202020202020202020202020202020202";
export const SEED_X25519_ALICE_HEX = "1111111111111111111111111111111111111111111111111111111111111111";
export const SEED_X25519_BOB_HEX = "2222222222222222222222222222222222222222222222222222222222222222";

export const ALICE_FAY_ID = "ifay_alice234567abcdef";
export const BOB_FAY_ID = "cofay_bobservice234567ab";
export const CAROL_FAY_ID = "ifay_carol234567abcdef";

export function makeAliceIdentity(publicKeyB64 = "YWxpY2UtcHVibGljLWtleS1iNjQ=") {
  return {
    fay_id: ALICE_FAY_ID,
    fay_type: "iFay",
    human_prime_id: "prime_alice_001",
    fp_authorization_ref: "fp_mandate_alice_2026_01",
    did: {
      method: "did:key",
      value: `did:key:z6MkAlice${publicKeyB64.slice(0, 12)}`,
      proof: {
        type: "Ed25519Signature2020",
        created: "2026-11-16T00:00:00Z",
        verification_method: "did:key:z6MkAlice#key-1",
        proof_value: publicKeyB64
      }
    }
  };
}

export function makeBobIdentity(publicKeyB64 = "Ym9iLXB1YmxpYy1rZXktYjY0") {
  return {
    fay_id: BOB_FAY_ID,
    fay_type: "coFay",
    fp_authorization_ref: "fp_mandate_bob_org_2026_01",
    did: {
      method: "did:web",
      value: "did:web:travel.example.org",
      proof: {
        type: "Ed25519Signature2020",
        created: "2026-11-16T00:00:00Z",
        verification_method: "did:web:travel.example.org#key-1",
        proof_value: publicKeyB64
      }
    }
  };
}

export function makeProfile(identity, ontologies = [], extra = {}) {
  return {
    identity,
    capabilities: [
      {
        capability_id: "cap_itinerary_plan",
        name: "ItineraryPlanner",
        version: "1.0.0",
        input_schema: { type: "object", required: ["destination"], properties: { destination: { type: "string" } } },
        output_schema: { type: "object", required: ["plan"], properties: { plan: { type: "array" } } },
        access_level: "authorized"
      }
    ],
    supported_ontologies: ontologies,
    supported_crypto_suites: ["Ed25519", "ML-DSA-65"],
    sharing_willingness: {
      shareable_resource_types: ["memory_fragment", "view_state", "environment_context"],
      preferred_mode: "collaborative_space",
      max_concurrent_contexts: 4
    },
    status: {
      availability: "online",
      current_contexts: 0,
      last_active: "2026-11-16T00:00:00Z"
    },
    prime_authorization: {
      fp_authorization_ref: identity.fp_authorization_ref || "fp_mandate_default_01",
      authorized_resource_types: ["memory_fragment", "view_state", "environment_context"],
      authorized_operations: ["read", "write", "consult"],
      max_sharing_duration: "PT2H",
      restrictions: [
        {
          restriction_type: "no_medical_records",
          description: "Exclude clinical records from shared contexts."
        }
      ]
    },
    conformance_level: "tp_full",
    ...extra
  };
}
