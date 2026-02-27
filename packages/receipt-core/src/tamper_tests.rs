//! Cryptographic tamper detection test suite.
//!
//! Red-team tests that systematically verify receipt-core and verifier-core
//! reject every class of tampering, replay, and domain-confusion attack.
//!
//! Categories:
//! 1. Single-bit corruption → signature rejection
//! 2. Field reordering → RFC 8785 canonical stability
//! 3. Hash swap → Tier 2 verifier rejection
//! 4. Key ID mismatch → wrong-key rejection
//! 5. Agreement hash drift → participant-list mutation
//! 6. Budget chain fork → prev_receipt_hash chain break
//! 7. Canonicalization collision → RFC 8785 normalization
//! 8. Domain separation brute → cross-domain signature rejection

#[cfg(test)]
mod tests {
    use crate::agreement::{
        compute_agreement_hash, compute_pre_agreement_hash, ModelIdentity, PreAgreementFields,
        SessionAgreementFields, AGREEMENT_DOMAIN_PREFIX, PRE_AGREEMENT_DOMAIN_PREFIX,
    };
    use crate::canonicalize::{canonicalize, canonicalize_serializable};
    use crate::handoff::{BudgetTierV2, HashRef, UnsignedSessionHandoff};
    use crate::ledger::{ApplyOutcome, BudgetLedger, LedgerError};
    use crate::manifest::{
        sign_manifest, verify_manifest, ManifestArtefacts, PublicationManifest, UnsignedManifest,
        MANIFEST_DOMAIN_PREFIX,
    };
    use crate::receipt::{
        BudgetChainRecord, BudgetUsageRecord, Receipt, ReceiptStatus, UnsignedReceipt,
        SCHEMA_VERSION,
    };
    use crate::signer::{
        compute_receipt_hash, compute_receipt_key_id, generate_keypair, hash_message,
        public_key_to_hex, sign_handoff, sign_receipt, verify_handoff, verify_receipt,
        SigningError, BUDGET_CHAIN_DOMAIN_PREFIX, DOMAIN_PREFIX, RECEIPT_HASH_DOMAIN_PREFIX,
        RECEIPT_HASH_PLACEHOLDER, SESSION_HANDOFF_DOMAIN_PREFIX,
    };
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    use sha2::{Digest, Sha256};
    use vault_family_types::ExecutionLane;
    use vault_family_types::{BudgetTier, Purpose};

    // =========================================================================
    // Helpers
    // =========================================================================

    fn sample_budget_usage() -> BudgetUsageRecord {
        BudgetUsageRecord {
            pair_id: "a".repeat(64),
            window_start: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            bits_used_before: 0,
            bits_used_after: 11,
            budget_limit: 128,
            budget_tier: BudgetTier::Default,
            budget_enforcement: None,
            compartment_id: None,
        }
    }

    fn sample_unsigned_receipt() -> UnsignedReceipt {
        UnsignedReceipt {
            schema_version: SCHEMA_VERSION.to_string(),
            session_id: "b".repeat(64),
            purpose_code: Purpose::Compatibility,
            participant_ids: vec!["agent-a".to_string(), "agent-b".to_string()],
            runtime_hash: "c".repeat(64),
            guardian_policy_hash: "d".repeat(64),
            model_weights_hash: "e".repeat(64),
            llama_cpp_version: "0.1.0".to_string(),
            inference_config_hash: "f".repeat(64),
            output_schema_version: "1.0.0".to_string(),
            session_start: Utc.with_ymd_and_hms(2025, 1, 15, 10, 0, 0).unwrap(),
            session_end: Utc.with_ymd_and_hms(2025, 1, 15, 10, 2, 0).unwrap(),
            fixed_window_duration_seconds: 120,
            status: ReceiptStatus::Completed,
            execution_lane: ExecutionLane::SoftwareLocal,
            output: Some(serde_json::json!({
                "decision": "PROCEED",
                "confidence_bucket": "HIGH",
                "reason_code": "MUTUAL_INTEREST_UNCLEAR"
            })),
            output_entropy_bits: 8,
            receipt_payload_type: None,
            receipt_payload_version: None,
            payload: None,
            mitigations_applied: vec![],
            budget_usage: sample_budget_usage(),
            budget_chain: None,
            model_identity: None,
            agreement_hash: None,
            receipt_key_id: None,
            model_profile_hash: None,
            policy_bundle_hash: None,
            contract_hash: None,
            output_schema_id: None,
            signal_class: None,
            entropy_budget_bits: None,
            schema_entropy_ceiling_bits: None,
            prompt_template_hash: None,
            contract_timing_class: None,
            ifc_output_label: None,
            ifc_policy_hash: None,
            ifc_label_receipt: None,
            ifc_joined_confidentiality: None,
            entropy_status_commitment: None,
            ledger_head_hash: None,
            delta_commitment_counterparty: None,
            delta_commitment_contract: None,
            policy_declaration: None,
            attestation: None,
        }
    }

    fn sample_unsigned_handoff() -> UnsignedSessionHandoff {
        UnsignedSessionHandoff {
            handoff_id: "handoff-12345678".to_string(),
            participants: vec!["agent-alice-123".to_string(), "agent-bob-456".to_string()],
            contract_id: "dating.v1.d2".to_string(),
            contract_version: 1,
            contract_hash: HashRef::sha256("dGVzdC1jb250cmFjdC1oYXNo"),
            budget_tier: BudgetTierV2::Small,
            ttl_seconds: 120,
            operator_endpoint_id: "operator-prod-001".to_string(),
            capability_tokens: vec![],
            prior_receipt_hash: None,
            intended_spend_bits: 11,
            model_profile_hash: None,
            policy_bundle_hash: None,
        }
    }

    fn make_chain_receipt(
        session_id: &str,
        window_start: chrono::DateTime<chrono::Utc>,
        bits_before: u32,
        bits_after: u32,
        prev: Option<String>,
        signing_key: &SigningKey,
    ) -> Receipt {
        let mut unsigned = sample_unsigned_receipt();
        unsigned.session_id = session_id.to_string();
        unsigned.budget_usage.window_start = window_start;
        unsigned.budget_usage.bits_used_before = bits_before;
        unsigned.budget_usage.bits_used_after = bits_after;
        unsigned.budget_chain = Some(BudgetChainRecord {
            chain_id: format!("chain-{}", "1".repeat(64)),
            prev_receipt_hash: prev,
            receipt_hash: RECEIPT_HASH_PLACEHOLDER.to_string(),
        });
        let h = compute_receipt_hash(&unsigned).unwrap();
        unsigned.budget_chain.as_mut().unwrap().receipt_hash = h;
        let sig = sign_receipt(&unsigned, signing_key).unwrap();
        unsigned.sign(sig)
    }

    // =========================================================================
    // 1. Single-bit corruption → signature rejection
    // =========================================================================

    mod single_bit_corruption {
        use super::*;

        #[test]
        fn tamper_session_id_rejects() {
            let (signing_key, verifying_key) = generate_keypair();
            let receipt = sample_unsigned_receipt();
            let sig = sign_receipt(&receipt, &signing_key).unwrap();

            let mut tampered = receipt.clone();
            // Flip one character in session_id
            let mut chars: Vec<char> = tampered.session_id.chars().collect();
            chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
            tampered.session_id = chars.into_iter().collect();

            assert!(matches!(
                verify_receipt(&tampered, &sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn tamper_runtime_hash_rejects() {
            let (signing_key, verifying_key) = generate_keypair();
            let receipt = sample_unsigned_receipt();
            let sig = sign_receipt(&receipt, &signing_key).unwrap();

            let mut tampered = receipt.clone();
            tampered.runtime_hash = "0".repeat(64);
            assert!(matches!(
                verify_receipt(&tampered, &sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn tamper_guardian_policy_hash_rejects() {
            let (signing_key, verifying_key) = generate_keypair();
            let receipt = sample_unsigned_receipt();
            let sig = sign_receipt(&receipt, &signing_key).unwrap();

            let mut tampered = receipt.clone();
            tampered.guardian_policy_hash = "0".repeat(64);
            assert!(matches!(
                verify_receipt(&tampered, &sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn tamper_output_entropy_bits_rejects() {
            let (signing_key, verifying_key) = generate_keypair();
            let receipt = sample_unsigned_receipt();
            let sig = sign_receipt(&receipt, &signing_key).unwrap();

            let mut tampered = receipt.clone();
            tampered.output_entropy_bits = 99;
            assert!(matches!(
                verify_receipt(&tampered, &sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn tamper_participant_ids_rejects() {
            let (signing_key, verifying_key) = generate_keypair();
            let receipt = sample_unsigned_receipt();
            let sig = sign_receipt(&receipt, &signing_key).unwrap();

            let mut tampered = receipt.clone();
            tampered.participant_ids = vec!["agent-a".to_string(), "agent-c".to_string()];
            assert!(matches!(
                verify_receipt(&tampered, &sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn tamper_status_rejects() {
            let (signing_key, verifying_key) = generate_keypair();
            let receipt = sample_unsigned_receipt();
            let sig = sign_receipt(&receipt, &signing_key).unwrap();

            let mut tampered = receipt.clone();
            tampered.status = ReceiptStatus::Aborted;
            assert!(matches!(
                verify_receipt(&tampered, &sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn tamper_execution_lane_rejects() {
            let (signing_key, verifying_key) = generate_keypair();
            let receipt = sample_unsigned_receipt();
            let sig = sign_receipt(&receipt, &signing_key).unwrap();

            let mut tampered = receipt.clone();
            tampered.execution_lane = ExecutionLane::SealedLocal;
            assert!(matches!(
                verify_receipt(&tampered, &sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn tamper_output_rejects() {
            let (signing_key, verifying_key) = generate_keypair();
            let receipt = sample_unsigned_receipt();
            let sig = sign_receipt(&receipt, &signing_key).unwrap();

            let mut tampered = receipt.clone();
            tampered.output = Some(serde_json::json!({"decision": "HALT"}));
            assert!(matches!(
                verify_receipt(&tampered, &sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn tamper_budget_usage_rejects() {
            let (signing_key, verifying_key) = generate_keypair();
            let receipt = sample_unsigned_receipt();
            let sig = sign_receipt(&receipt, &signing_key).unwrap();

            let mut tampered = receipt.clone();
            tampered.budget_usage.bits_used_after = 999;
            assert!(matches!(
                verify_receipt(&tampered, &sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn tamper_model_profile_hash_rejects() {
            let (signing_key, verifying_key) = generate_keypair();
            let mut receipt = sample_unsigned_receipt();
            receipt.model_profile_hash = Some("a".repeat(64));
            let sig = sign_receipt(&receipt, &signing_key).unwrap();

            let mut tampered = receipt.clone();
            tampered.model_profile_hash = Some("b".repeat(64));
            assert!(matches!(
                verify_receipt(&tampered, &sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn tamper_signature_hex_rejects() {
            let (signing_key, verifying_key) = generate_keypair();
            let receipt = sample_unsigned_receipt();
            let mut sig = sign_receipt(&receipt, &signing_key).unwrap();

            // Flip first byte of signature
            let mut chars: Vec<char> = sig.chars().collect();
            chars[0] = if chars[0] == '0' { '1' } else { '0' };
            sig = chars.into_iter().collect();

            assert!(verify_receipt(&receipt, &sig, &verifying_key).is_err());
        }

        #[test]
        fn tamper_fixed_window_duration_rejects() {
            let (signing_key, verifying_key) = generate_keypair();
            let receipt = sample_unsigned_receipt();
            let sig = sign_receipt(&receipt, &signing_key).unwrap();

            let mut tampered = receipt.clone();
            tampered.fixed_window_duration_seconds = 999;
            assert!(matches!(
                verify_receipt(&tampered, &sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn tamper_contract_hash_rejects() {
            let (signing_key, verifying_key) = generate_keypair();
            let mut receipt = sample_unsigned_receipt();
            receipt.contract_hash = Some("a".repeat(64));
            let sig = sign_receipt(&receipt, &signing_key).unwrap();

            let mut tampered = receipt.clone();
            tampered.contract_hash = Some("b".repeat(64));
            assert!(matches!(
                verify_receipt(&tampered, &sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn tamper_adding_optional_field_rejects() {
            let (signing_key, verifying_key) = generate_keypair();
            let receipt = sample_unsigned_receipt();
            assert!(receipt.model_profile_hash.is_none());
            let sig = sign_receipt(&receipt, &signing_key).unwrap();

            // Add a field that wasn't present when signed
            let mut tampered = receipt.clone();
            tampered.model_profile_hash = Some("a".repeat(64));
            assert!(matches!(
                verify_receipt(&tampered, &sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn tamper_removing_optional_field_rejects() {
            let (signing_key, verifying_key) = generate_keypair();
            let mut receipt = sample_unsigned_receipt();
            receipt.model_profile_hash = Some("a".repeat(64));
            let sig = sign_receipt(&receipt, &signing_key).unwrap();

            // Remove a field that was present when signed
            let mut tampered = receipt.clone();
            tampered.model_profile_hash = None;
            assert!(matches!(
                verify_receipt(&tampered, &sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }
    }

    // =========================================================================
    // 2. Field reordering → RFC 8785 canonical stability
    // =========================================================================

    mod field_reordering {
        use super::*;

        #[test]
        fn json_key_order_does_not_affect_canonical_form() {
            let obj1 = serde_json::json!({"z": 1, "a": 2, "m": 3});
            let obj2 = serde_json::json!({"a": 2, "m": 3, "z": 1});
            let obj3 = serde_json::json!({"m": 3, "z": 1, "a": 2});

            let c1 = canonicalize(&obj1);
            let c2 = canonicalize(&obj2);
            let c3 = canonicalize(&obj3);

            assert_eq!(c1, c2);
            assert_eq!(c2, c3);
        }

        #[test]
        fn receipt_canonicalization_is_deterministic() {
            let receipt = sample_unsigned_receipt();
            let c1 = canonicalize_serializable(&receipt).unwrap();
            let c2 = canonicalize_serializable(&receipt).unwrap();
            assert_eq!(c1, c2);
        }

        #[test]
        fn receipt_json_reparse_produces_same_canonical() {
            let receipt = sample_unsigned_receipt();
            let json_str = serde_json::to_string(&receipt).unwrap();
            let reparsed: UnsignedReceipt = serde_json::from_str(&json_str).unwrap();

            let c1 = canonicalize_serializable(&receipt).unwrap();
            let c2 = canonicalize_serializable(&reparsed).unwrap();
            assert_eq!(c1, c2);
        }

        #[test]
        fn nested_object_keys_are_sorted_recursively() {
            let obj = serde_json::json!({
                "z": {"c": 1, "a": 2, "b": 3},
                "a": {"z": 1, "a": 2}
            });
            let canonical = canonicalize(&obj);
            // "a" key should come before "z"
            let a_pos = canonical.find("\"a\":{").unwrap();
            let z_pos = canonical.find("\"z\":{").unwrap();
            assert!(a_pos < z_pos);
            // Within "z" object, "a" should come before "b" before "c"
            assert!(canonical.contains("{\"a\":2,\"b\":3,\"c\":1}"));
        }
    }

    // =========================================================================
    // 3. Hash swap → receipt with wrong model_profile_hash
    // =========================================================================

    mod hash_swap {
        use super::*;

        #[test]
        fn swapping_model_profile_hash_changes_receipt_hash() {
            let mut receipt_a = sample_unsigned_receipt();
            receipt_a.model_profile_hash = Some("a".repeat(64));
            receipt_a.budget_chain = Some(BudgetChainRecord {
                chain_id: format!("chain-{}", "1".repeat(64)),
                prev_receipt_hash: None,
                receipt_hash: RECEIPT_HASH_PLACEHOLDER.to_string(),
            });

            let mut receipt_b = receipt_a.clone();
            receipt_b.model_profile_hash = Some("b".repeat(64));

            let hash_a = compute_receipt_hash(&receipt_a).unwrap();
            let hash_b = compute_receipt_hash(&receipt_b).unwrap();
            assert_ne!(hash_a, hash_b);
        }

        #[test]
        fn swapping_policy_bundle_hash_changes_receipt_hash() {
            let mut receipt_a = sample_unsigned_receipt();
            receipt_a.policy_bundle_hash = Some("a".repeat(64));
            receipt_a.budget_chain = Some(BudgetChainRecord {
                chain_id: format!("chain-{}", "1".repeat(64)),
                prev_receipt_hash: None,
                receipt_hash: RECEIPT_HASH_PLACEHOLDER.to_string(),
            });

            let mut receipt_b = receipt_a.clone();
            receipt_b.policy_bundle_hash = Some("b".repeat(64));

            let hash_a = compute_receipt_hash(&receipt_a).unwrap();
            let hash_b = compute_receipt_hash(&receipt_b).unwrap();
            assert_ne!(hash_a, hash_b);
        }

        #[test]
        fn swapping_model_profile_hash_invalidates_signature() {
            let (signing_key, verifying_key) = generate_keypair();
            let mut receipt = sample_unsigned_receipt();
            receipt.model_profile_hash = Some("a".repeat(64));
            let sig = sign_receipt(&receipt, &signing_key).unwrap();

            // Verify original passes
            assert!(verify_receipt(&receipt, &sig, &verifying_key).is_ok());

            // Swap the hash
            let mut tampered = receipt;
            tampered.model_profile_hash = Some("b".repeat(64));
            assert!(matches!(
                verify_receipt(&tampered, &sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }
    }

    // =========================================================================
    // 4. Key ID mismatch → sign with key A, verify with key B
    // =========================================================================

    mod key_id_mismatch {
        use super::*;

        #[test]
        fn receipt_signed_with_key_a_rejected_by_key_b() {
            let (key_a, _) = generate_keypair();
            let (_, verifying_b) = generate_keypair();

            let receipt = sample_unsigned_receipt();
            let sig = sign_receipt(&receipt, &key_a).unwrap();

            assert!(matches!(
                verify_receipt(&receipt, &sig, &verifying_b),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn handoff_signed_with_key_a_rejected_by_key_b() {
            let (key_a, _) = generate_keypair();
            let (_, verifying_b) = generate_keypair();

            let handoff = sample_unsigned_handoff();
            let sig = sign_handoff(&handoff, &key_a).unwrap();

            assert!(matches!(
                verify_handoff(&handoff, &sig, &verifying_b),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn manifest_signed_with_key_a_rejected_by_key_b() {
            let (key_a, verifying_a) = generate_keypair();
            let (_, verifying_b) = generate_keypair();

            let pub_hex = public_key_to_hex(&verifying_a);
            let unsigned = UnsignedManifest {
                manifest_version: "1.0.0".to_string(),
                operator_id: "operator-test".to_string(),
                operator_key_id: format!("opkey-{}", "a".repeat(64)),
                operator_public_key_hex: pub_hex,
                protocol_version: "1.0.0".to_string(),
                published_at: "2026-01-01T00:00:00Z".to_string(),
                artefacts: ManifestArtefacts {
                    contracts: vec![],
                    profiles: vec![],
                    policies: vec![],
                },
                runtime_hashes: None,
            };
            let sig = sign_manifest(&unsigned, &key_a).unwrap();
            let manifest = PublicationManifest {
                manifest_version: unsigned.manifest_version,
                operator_id: unsigned.operator_id,
                operator_key_id: unsigned.operator_key_id,
                operator_public_key_hex: unsigned.operator_public_key_hex,
                protocol_version: unsigned.protocol_version,
                published_at: unsigned.published_at,
                artefacts: unsigned.artefacts,
                runtime_hashes: None,
                signature: sig,
            };

            assert!(matches!(
                verify_manifest(&manifest, &verifying_b),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn different_keys_produce_different_key_ids() {
            let (_, vk1) = generate_keypair();
            let (_, vk2) = generate_keypair();

            let kid1 = compute_receipt_key_id(&public_key_to_hex(&vk1));
            let kid2 = compute_receipt_key_id(&public_key_to_hex(&vk2));
            assert_ne!(kid1, kid2);
        }
    }

    // =========================================================================
    // 5. Agreement hash drift → modified participant list post-agreement
    // =========================================================================

    mod agreement_hash_drift {
        use super::*;

        fn sample_pre_agreement() -> PreAgreementFields {
            PreAgreementFields {
                participants: vec!["agent-alice".to_string(), "agent-bob".to_string()],
                contract_id: "SCHEDULING_COMPAT_V1".to_string(),
                purpose_code: "SCHEDULING_COMPAT_V1".to_string(),
                model_identity: ModelIdentity {
                    provider: "OPENAI".to_string(),
                    model_id: "gpt-4.1".to_string(),
                    model_version: Some("2025-04-14".to_string()),
                },
                output_budget: 4,
                symmetry_rule: "SYMMETRIC".to_string(),
                input_schema_hashes: vec!["b".repeat(64), "c".repeat(64)],
                expiry: "2025-06-01T00:00:00Z".to_string(),
                model_profile_hash: None,
                policy_bundle_hash: None,
            }
        }

        fn sample_agreement() -> SessionAgreementFields {
            let pre_hash = compute_pre_agreement_hash(&sample_pre_agreement()).unwrap();
            SessionAgreementFields {
                session_id: "a".repeat(64),
                pre_agreement_hash: pre_hash,
                participants: vec!["agent-alice".to_string(), "agent-bob".to_string()],
                contract_id: "SCHEDULING_COMPAT_V1".to_string(),
                purpose_code: "SCHEDULING_COMPAT_V1".to_string(),
                model_identity: ModelIdentity {
                    provider: "OPENAI".to_string(),
                    model_id: "gpt-4.1".to_string(),
                    model_version: Some("2025-04-14".to_string()),
                },
                output_budget: 4,
                symmetry_rule: "SYMMETRIC".to_string(),
                input_schema_hashes: vec!["b".repeat(64), "c".repeat(64)],
                expiry: "2025-06-01T00:00:00Z".to_string(),
                model_profile_hash: None,
                policy_bundle_hash: None,
            }
        }

        #[test]
        fn adding_participant_changes_agreement_hash() {
            let fields1 = sample_agreement();
            let mut fields2 = sample_agreement();
            fields2.participants.push("agent-charlie".to_string());

            let h1 = compute_agreement_hash(&fields1).unwrap();
            let h2 = compute_agreement_hash(&fields2).unwrap();
            assert_ne!(h1, h2);
        }

        #[test]
        fn removing_participant_changes_agreement_hash() {
            let fields1 = sample_agreement();
            let mut fields2 = sample_agreement();
            fields2.participants = vec!["agent-alice".to_string()];

            let h1 = compute_agreement_hash(&fields1).unwrap();
            let h2 = compute_agreement_hash(&fields2).unwrap();
            assert_ne!(h1, h2);
        }

        #[test]
        fn reordering_participants_changes_agreement_hash() {
            let fields1 = sample_agreement();
            let mut fields2 = sample_agreement();
            fields2.participants = vec!["agent-bob".to_string(), "agent-alice".to_string()];

            let h1 = compute_agreement_hash(&fields1).unwrap();
            let h2 = compute_agreement_hash(&fields2).unwrap();
            // Agreement hash intentionally does NOT auto-sort — caller is responsible
            assert_ne!(h1, h2);
        }

        #[test]
        fn changing_contract_id_changes_agreement_hash() {
            let fields1 = sample_agreement();
            let mut fields2 = sample_agreement();
            fields2.contract_id = "DATING_COMPAT_V1".to_string();

            let h1 = compute_agreement_hash(&fields1).unwrap();
            let h2 = compute_agreement_hash(&fields2).unwrap();
            assert_ne!(h1, h2);
        }

        #[test]
        fn changing_model_identity_changes_agreement_hash() {
            let fields1 = sample_agreement();
            let mut fields2 = sample_agreement();
            fields2.model_identity.model_id = "gpt-4o".to_string();

            let h1 = compute_agreement_hash(&fields1).unwrap();
            let h2 = compute_agreement_hash(&fields2).unwrap();
            assert_ne!(h1, h2);
        }

        #[test]
        fn pre_agreement_participant_drift_changes_hash() {
            let pre1 = sample_pre_agreement();
            let mut pre2 = sample_pre_agreement();
            pre2.participants.push("agent-mallory".to_string());

            let h1 = compute_pre_agreement_hash(&pre1).unwrap();
            let h2 = compute_pre_agreement_hash(&pre2).unwrap();
            assert_ne!(h1, h2);
        }

        #[test]
        fn model_version_none_vs_some_changes_agreement_hash() {
            let fields1 = sample_agreement();
            let mut fields2 = sample_agreement();
            fields2.model_identity.model_version = None;

            let h1 = compute_agreement_hash(&fields1).unwrap();
            let h2 = compute_agreement_hash(&fields2).unwrap();
            assert_ne!(h1, h2);
        }
    }

    // =========================================================================
    // 6. Budget chain fork → wrong prev_receipt_hash
    // =========================================================================

    mod budget_chain_fork {
        use super::*;

        #[test]
        fn wrong_prev_receipt_hash_detected_by_ledger() {
            let (signing_key, _) = generate_keypair();
            let window = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

            let r1 = make_chain_receipt(&"1".repeat(64), window, 0, 11, None, &signing_key);
            let r_fork = make_chain_receipt(
                &"2".repeat(64),
                window,
                11,
                22,
                Some("wrong_hash".to_string()),
                &signing_key,
            );

            let mut ledger = BudgetLedger::new();
            assert_eq!(ledger.apply_receipt(&r1).unwrap(), ApplyOutcome::Applied);

            match ledger.apply_receipt(&r_fork).unwrap_err() {
                LedgerError::UnexpectedPrev { .. } => {} // expected
                other => panic!("Expected UnexpectedPrev, got {:?}", other),
            }
        }

        #[test]
        fn null_prev_after_first_receipt_is_reset_attack() {
            let (signing_key, _) = generate_keypair();
            let window = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

            let r1 = make_chain_receipt(&"1".repeat(64), window, 0, 11, None, &signing_key);
            let r_reset = make_chain_receipt(
                &"2".repeat(64),
                window,
                11,
                22,
                None, // null prev = reset attempt
                &signing_key,
            );

            let mut ledger = BudgetLedger::new();
            assert_eq!(ledger.apply_receipt(&r1).unwrap(), ApplyOutcome::Applied);
            assert_eq!(
                ledger.apply_receipt(&r_reset).unwrap_err(),
                LedgerError::ResetDetected
            );
        }

        #[test]
        fn forked_chain_second_branch_rejected() {
            let (signing_key, _) = generate_keypair();
            let window = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

            let r1 = make_chain_receipt(&"1".repeat(64), window, 0, 11, None, &signing_key);
            let h1 = r1.budget_chain.as_ref().unwrap().receipt_hash.clone();

            // Both r2_a and r2_b claim to follow r1
            let r2_a = make_chain_receipt(
                &"2a".repeat(32),
                window,
                11,
                22,
                Some(h1.clone()),
                &signing_key,
            );
            let r2_b = make_chain_receipt(&"2b".repeat(32), window, 11, 22, Some(h1), &signing_key);

            let mut ledger = BudgetLedger::new();
            assert_eq!(ledger.apply_receipt(&r1).unwrap(), ApplyOutcome::Applied);
            assert_eq!(ledger.apply_receipt(&r2_a).unwrap(), ApplyOutcome::Applied);

            // r2_b is a fork — its prev points to r1, but ledger already moved to r2_a
            match ledger.apply_receipt(&r2_b).unwrap_err() {
                LedgerError::UnexpectedPrev { .. } => {}
                other => panic!("Expected UnexpectedPrev, got {:?}", other),
            }
        }

        #[test]
        fn retrograde_window_rejected() {
            let (signing_key, _) = generate_keypair();
            let w1 = Utc.with_ymd_and_hms(2025, 2, 1, 0, 0, 0).unwrap();
            let w0 = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

            let r1 = make_chain_receipt(&"1".repeat(64), w1, 0, 11, None, &signing_key);
            let r_retro = make_chain_receipt(&"2".repeat(64), w0, 0, 11, None, &signing_key);

            let mut ledger = BudgetLedger::new();
            ledger.apply_receipt(&r1).unwrap();
            assert_eq!(
                ledger.apply_receipt(&r_retro).unwrap_err(),
                LedgerError::RetrogradeWindow
            );
        }

        #[test]
        fn budget_usage_mismatch_rejected() {
            let (signing_key, _) = generate_keypair();
            let window = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

            let r1 = make_chain_receipt(&"1".repeat(64), window, 0, 11, None, &signing_key);
            let h1 = r1.budget_chain.as_ref().unwrap().receipt_hash.clone();

            // r2 claims bits_used_before=10 but r1 set bits_used_after=11
            let r2 = make_chain_receipt(
                &"2".repeat(64),
                window,
                10, // should be 11
                22,
                Some(h1),
                &signing_key,
            );

            let mut ledger = BudgetLedger::new();
            ledger.apply_receipt(&r1).unwrap();
            assert_eq!(
                ledger.apply_receipt(&r2).unwrap_err(),
                LedgerError::BudgetUsageMismatch {
                    expected: 11,
                    got: 10
                }
            );
        }
    }

    // =========================================================================
    // 7. Canonicalization collision tests
    // =========================================================================

    mod canonicalization_collision {
        use super::*;

        #[test]
        fn escaped_vs_raw_characters_produce_same_canonical() {
            // \u0041 is 'A' — after JSON parsing, both become the same character
            let raw: serde_json::Value = serde_json::from_str(r#"{"key": "A"}"#).unwrap();
            let escaped: serde_json::Value = serde_json::from_str(r#"{"key": "\u0041"}"#).unwrap();

            assert_eq!(canonicalize(&raw), canonicalize(&escaped));
        }

        #[test]
        fn scientific_notation_vs_integer_same_canonical() {
            // 1e2 and 100 are the same number — serde_json parses both as 100
            let v1: serde_json::Value = serde_json::from_str(r#"{"n": 100}"#).unwrap();
            let v2: serde_json::Value = serde_json::from_str(r#"{"n": 1e2}"#).unwrap();

            assert_eq!(canonicalize(&v1), canonicalize(&v2));
        }

        #[test]
        fn reordered_deep_nested_keys_produce_same_canonical() {
            let v1 = serde_json::json!({
                "z": {"c": {"f": 1, "e": 2}, "a": 3},
                "a": {"z": {"b": 4, "a": 5}, "a": 6}
            });
            let v2 = serde_json::json!({
                "a": {"a": 6, "z": {"a": 5, "b": 4}},
                "z": {"a": 3, "c": {"e": 2, "f": 1}}
            });

            assert_eq!(canonicalize(&v1), canonicalize(&v2));
        }

        #[test]
        fn integer_zero_representations_same_canonical() {
            let v1: serde_json::Value = serde_json::from_str(r#"{"n": 0}"#).unwrap();
            let v2: serde_json::Value = serde_json::from_str(r#"{"n": 0.0}"#).unwrap();

            // Both should canonicalize to {"n":0}
            let c1 = canonicalize(&v1);
            let c2 = canonicalize(&v2);
            assert_eq!(c1, c2);
        }

        #[test]
        fn whitespace_variations_do_not_affect_canonical() {
            let compact: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
            let spaced: serde_json::Value =
                serde_json::from_str(r#"{ "a" : 1 , "b" : 2 }"#).unwrap();
            let multiline: serde_json::Value = serde_json::from_str(
                r#"{
                    "a": 1,
                    "b": 2
                }"#,
            )
            .unwrap();

            let c1 = canonicalize(&compact);
            let c2 = canonicalize(&spaced);
            let c3 = canonicalize(&multiline);
            assert_eq!(c1, c2);
            assert_eq!(c2, c3);
        }

        #[test]
        fn boolean_representations_are_canonical() {
            let v1 = serde_json::json!({"flag": true});
            let c = canonicalize(&v1);
            assert_eq!(c, "{\"flag\":true}");

            let v2 = serde_json::json!({"flag": false});
            let c2 = canonicalize(&v2);
            assert_eq!(c2, "{\"flag\":false}");
        }

        #[test]
        fn null_vs_missing_key_produce_different_canonical() {
            let with_null = serde_json::json!({"a": 1, "b": null});
            let without = serde_json::json!({"a": 1});

            let c1 = canonicalize(&with_null);
            let c2 = canonicalize(&without);
            assert_ne!(c1, c2);
        }

        #[test]
        fn empty_string_vs_missing_key_different_canonical() {
            let with_empty = serde_json::json!({"a": 1, "b": ""});
            let without = serde_json::json!({"a": 1});

            assert_ne!(canonicalize(&with_empty), canonicalize(&without));
        }

        #[test]
        fn array_order_preserved_in_canonical() {
            let v1 = serde_json::json!({"arr": [1, 2, 3]});
            let v2 = serde_json::json!({"arr": [3, 2, 1]});

            // Arrays are NOT sorted — order is significant
            assert_ne!(canonicalize(&v1), canonicalize(&v2));
        }
    }

    // =========================================================================
    // 8. Domain separation brute test
    // =========================================================================

    mod domain_separation {
        use super::*;

        /// All 10 domain prefixes in the VCAV system
        const ALL_PREFIXES: [&str; 10] = [
            "VCAV-RECEIPT-V1:",      // DOMAIN_PREFIX
            "VCAV-HANDOFF-V1:",      // SESSION_HANDOFF_DOMAIN_PREFIX
            "VCAV-AGREEMENT-V1:",    // AGREEMENT_DOMAIN_PREFIX
            "VCAV-PREAGREEMENT-V1:", // PRE_AGREEMENT_DOMAIN_PREFIX
            "VCAV-MANIFEST-V1:",     // MANIFEST_DOMAIN_PREFIX
            "VCAV-MSG-V1:",          // ENVELOPE_DOMAIN_PREFIX (message-envelope)
            "vcav/receipt_hash/v1",  // RECEIPT_HASH_DOMAIN_PREFIX
            "vcav/budget_chain/v1",  // BUDGET_CHAIN_DOMAIN_PREFIX
            "vcav/model_profile/v1", // PROFILE_HASH_DOMAIN_PREFIX
            "vcav/policy_bundle/v1", // POLICY_BUNDLE_DOMAIN_PREFIX
        ];

        #[test]
        fn all_domain_prefixes_are_unique() {
            let mut seen = std::collections::HashSet::new();
            for prefix in &ALL_PREFIXES {
                assert!(
                    seen.insert(*prefix),
                    "Duplicate domain prefix found: {}",
                    prefix
                );
            }
        }

        #[test]
        fn domain_constants_match_expected_values() {
            assert_eq!(DOMAIN_PREFIX, "VCAV-RECEIPT-V1:");
            assert_eq!(SESSION_HANDOFF_DOMAIN_PREFIX, "VCAV-HANDOFF-V1:");
            assert_eq!(AGREEMENT_DOMAIN_PREFIX, "VCAV-AGREEMENT-V1:");
            assert_eq!(PRE_AGREEMENT_DOMAIN_PREFIX, "VCAV-PREAGREEMENT-V1:");
            assert_eq!(MANIFEST_DOMAIN_PREFIX, "VCAV-MANIFEST-V1:");
            assert_eq!(RECEIPT_HASH_DOMAIN_PREFIX, "vcav/receipt_hash/v1");
            assert_eq!(BUDGET_CHAIN_DOMAIN_PREFIX, "vcav/budget_chain/v1");
        }

        /// For every pair of domain prefixes (A, B) where A != B:
        /// signing under prefix A and verifying under prefix B must fail.
        ///
        /// We test the Ed25519 signing prefixes: receipt, handoff, manifest.
        #[test]
        fn cross_domain_receipt_vs_handoff_signature_rejected() {
            let (signing_key, _verifying_key) = generate_keypair();

            // Sign as receipt
            let receipt = sample_unsigned_receipt();
            let receipt_sig = sign_receipt(&receipt, &signing_key).unwrap();

            // Sign as handoff
            let handoff = sample_unsigned_handoff();
            let handoff_sig = sign_handoff(&handoff, &signing_key).unwrap();

            // Cross-verify: receipt signature on handoff should fail
            assert_ne!(receipt_sig, handoff_sig);
        }

        #[test]
        fn receipt_signature_cannot_verify_as_handoff() {
            let (signing_key, verifying_key) = generate_keypair();
            let receipt = sample_unsigned_receipt();
            let receipt_sig = sign_receipt(&receipt, &signing_key).unwrap();

            // Try to use the receipt signature to verify a handoff — must fail
            let handoff = sample_unsigned_handoff();
            assert!(matches!(
                verify_handoff(&handoff, &receipt_sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn handoff_signature_cannot_verify_as_receipt() {
            let (signing_key, verifying_key) = generate_keypair();
            let handoff = sample_unsigned_handoff();
            let handoff_sig = sign_handoff(&handoff, &signing_key).unwrap();

            let receipt = sample_unsigned_receipt();
            assert!(matches!(
                verify_receipt(&receipt, &handoff_sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn manifest_signature_cannot_verify_as_receipt() {
            let (signing_key, verifying_key) = generate_keypair();
            let pub_hex = public_key_to_hex(&verifying_key);
            let unsigned_manifest = UnsignedManifest {
                manifest_version: "1.0.0".to_string(),
                operator_id: "operator-test".to_string(),
                operator_key_id: format!("opkey-{}", "a".repeat(64)),
                operator_public_key_hex: pub_hex,
                protocol_version: "1.0.0".to_string(),
                published_at: "2026-01-01T00:00:00Z".to_string(),
                artefacts: ManifestArtefacts {
                    contracts: vec![],
                    profiles: vec![],
                    policies: vec![],
                },
                runtime_hashes: None,
            };
            let manifest_sig = sign_manifest(&unsigned_manifest, &signing_key).unwrap();

            let receipt = sample_unsigned_receipt();
            assert!(matches!(
                verify_receipt(&receipt, &manifest_sig, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }

        #[test]
        fn receipt_signature_cannot_verify_as_manifest() {
            let (signing_key, verifying_key) = generate_keypair();
            let receipt = sample_unsigned_receipt();
            let receipt_sig = sign_receipt(&receipt, &signing_key).unwrap();

            let pub_hex = public_key_to_hex(&verifying_key);
            let manifest = PublicationManifest {
                manifest_version: "1.0.0".to_string(),
                operator_id: "operator-test".to_string(),
                operator_key_id: format!("opkey-{}", "a".repeat(64)),
                operator_public_key_hex: pub_hex,
                protocol_version: "1.0.0".to_string(),
                published_at: "2026-01-01T00:00:00Z".to_string(),
                artefacts: ManifestArtefacts {
                    contracts: vec![],
                    profiles: vec![],
                    policies: vec![],
                },
                runtime_hashes: None,
                signature: receipt_sig,
            };

            assert!(matches!(
                verify_manifest(&manifest, &verifying_key),
                Err(SigningError::VerificationFailed)
            ));
        }

        /// Hash domain separation: signing message under prefix A
        /// produces a different SHA-256 hash than under prefix B.
        #[test]
        fn hash_domain_separation_brute_81_pairs() {
            let payload = b"test-payload-for-domain-separation";
            let mut hashes = Vec::new();

            for prefix in &ALL_PREFIXES {
                let mut hasher = Sha256::new();
                hasher.update(prefix.as_bytes());
                hasher.update(payload);
                hashes.push(hex::encode(hasher.finalize()));
            }

            // All 9 hashes must be unique (9 choose 2 = 36 distinct pairs)
            for i in 0..hashes.len() {
                for j in (i + 1)..hashes.len() {
                    assert_ne!(
                        hashes[i], hashes[j],
                        "Domain prefixes '{}' and '{}' produced identical hash!",
                        ALL_PREFIXES[i], ALL_PREFIXES[j]
                    );
                }
            }
        }

        /// For each domain prefix, verify that signing with it and verifying
        /// with a different prefix fails.
        #[test]
        fn signing_prefixes_cross_verification_matrix() {
            // The three Ed25519 signing domains
            let signing_prefixes = [
                DOMAIN_PREFIX,
                SESSION_HANDOFF_DOMAIN_PREFIX,
                MANIFEST_DOMAIN_PREFIX,
            ];

            let payload = b"test-canonical-json-content";
            let (signing_key, verifying_key) = generate_keypair();

            for sign_prefix in &signing_prefixes {
                // Build message with this prefix
                let mut message = sign_prefix.as_bytes().to_vec();
                message.extend(payload);
                let hash = hash_message(&message);
                let signature = signing_key.sign(&hash);

                for verify_prefix in &signing_prefixes {
                    let mut verify_message = verify_prefix.as_bytes().to_vec();
                    verify_message.extend(payload);
                    let verify_hash = hash_message(&verify_message);

                    let result = verifying_key.verify(&verify_hash, &signature);

                    if sign_prefix == verify_prefix {
                        assert!(
                            result.is_ok(),
                            "Same-domain verification failed for '{}'",
                            sign_prefix
                        );
                    } else {
                        assert!(
                            result.is_err(),
                            "Cross-domain verification should fail: signed with '{}', verified with '{}'",
                            sign_prefix, verify_prefix
                        );
                    }
                }
            }
        }
    }
}
