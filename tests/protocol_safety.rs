use std::collections::BTreeSet;
use vess_bench::{crypto::*, ledger::*, protocol::*};

#[test]
fn strict_target_budget_and_population_guard() {
    let mut request = Request {
        old_root: [0; 32],
        nonce: 1,
        recipients: [1, 2].into(),
        target: [1; 32],
        target_t: 8,
        target_rho: 5,
        eligible: 8,
        mode: Mode::Difference,
    };
    assert!(target_check(&request, 1).is_err());
    request.target_rho = 4;
    assert!(target_check(&request, 1).is_ok());
    request.eligible = 7;
    assert!(target_check(&request, 1).is_err());
}
#[test]
fn snapshot_does_not_spend_source_difference_budget() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = Ledger::create(
        temp.path(),
        Policy {
            source: [9; 32],
            source_t: 4,
            delta: 1,
            incoming: [1, 2].into(),
            rho_out: 0,
        },
    )
    .unwrap();
    let request = Request {
        old_root: ledger.root().unwrap(),
        nonce: 1,
        recipients: [3, 4].into(),
        target: [2; 32],
        target_t: 8,
        target_rho: 1,
        eligible: 8,
        mode: Mode::Snapshot,
    };
    assert!(ledger.reserve(request).unwrap().reserved.is_empty());
    let request = Request {
        old_root: ledger.root().unwrap(),
        nonce: 2,
        recipients: [3].into(),
        target: [3; 32],
        target_t: 8,
        target_rho: 1,
        eligible: 8,
        mode: Mode::Difference,
    };
    assert!(ledger.reserve(request).is_err());
}
#[test]
fn certificate_requires_distinct_signers_and_correct_digest() {
    let mut random = rng(82, "certificate", 0);
    let keys: Vec<_> = (0..4).map(|_| nonzero(&mut random)).collect();
    let pks: Vec<_> = keys.iter().map(|s| s * g()).collect();
    let signatures: Vec<_> = (0..3)
        .map(|i| ((i + 1) as u64, sign(keys[i], &[7; 32], &mut random)))
        .collect();
    let mut certificate = Certificate {
        digest: [7; 32],
        signatures,
    };
    assert!(verify_certificate(&certificate, &pks, 3));
    certificate.signatures[2] = certificate.signatures[1].clone();
    assert!(!verify_certificate(&certificate, &pks, 3));
    certificate.digest = [8; 32];
    assert!(!verify_certificate(&certificate, &pks, 3));
}
#[test]
fn plaintext_bound_batch_rejects_weight_cancellation() {
    let mut random = rng(91, "batch", 0);
    let state = init(
        Params {
            n: 7,
            k: 3,
            f: 2,
            t: 8,
        },
        0,
        &mut random,
    )
    .unwrap();
    let ids = [1, 2, 3];
    let mut parts: Vec<_> = state.rows[..3].iter().map(|p| eval(p, Fr::ONE)).collect();
    let original = combine(&ids.into_iter().zip(parts.clone()).collect::<Vec<_>>()).unwrap();
    parts[0].v += Fr::ONE;
    parts[1].v += Fr::ONE;
    assert_eq!(
        original,
        combine(&ids.into_iter().zip(parts.clone()).collect::<Vec<_>>()).unwrap()
    );
    assert!(!batch_verify(
        b"issuance",
        &ids,
        &parts,
        &state.vectors[..3],
        Fr::ONE
    ));
}
#[test]
fn staged_update_cannot_be_applied_under_another_commit() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("participant.bin");
    let mut random = rng(7, "stage", 0);
    let src = init(
        Params {
            n: 4,
            k: 2,
            f: 1,
            t: 3,
        },
        0,
        &mut random,
    )
    .unwrap();
    let dst = generate(&src, 2, &mut random).unwrap();
    let mut p = Participant {
        id: 1,
        epoch: 0,
        share: src.share(1),
        staged: None,
        applied: BTreeSet::new(),
    };
    p.stage(
        Staged {
            nonce: 9,
            target: 1,
            token: dst.share(1).minus(src.share(1)),
            target_public: dst.public,
        },
        &path,
    )
    .unwrap();
    assert!(p.apply(10, 1, &path).is_err());
    assert!(p.apply(9, 2, &path).is_err());
    assert_eq!(p.share, src.share(1));
    p.abort(&path).unwrap();
    let recovered = Participant::load(&path).unwrap();
    assert!(recovered.staged.is_none());
    assert_eq!(recovered.epoch, 0);
}
#[test]
fn blob_root_limbs_and_record_field_positions_are_authenticated() {
    let root = [255u8; 32];
    let payload = vec![171u8; 800];
    let bundle = vess_bench::chain::blob_bundle(root, &payload).unwrap();
    assert_eq!(&bundle.bytes[16..32], &root[..16]);
    assert_eq!(&bundle.bytes[48..64], &root[16..]);
    let openings = vess_bench::experiments::anchors::fields(&bundle, payload.len()).unwrap();
    assert_eq!(openings.len(), 26 * 192);
    use c_kzg::{ethereum_kzg_settings, Bytes32, Bytes48};
    let p = &openings[..192];
    let mut bad_y = p[64..96].to_vec();
    bad_y[31] ^= 1;
    assert!(!ethereum_kzg_settings(0)
        .verify_kzg_proof(
            &Bytes48::from_bytes(&p[96..144]).unwrap(),
            &Bytes32::from_bytes(&p[32..64]).unwrap(),
            &Bytes32::from_bytes(&bad_y).unwrap(),
            &Bytes48::from_bytes(&p[144..192]).unwrap()
        )
        .unwrap());
}

#[test]
fn e2e_first_blob_field_authenticates_full_field_native_root() {
    use c_kzg::{ethereum_kzg_settings, Bytes32, Bytes48};
    use vess_bench::chain::{field_blob_bundle, field_hash, word};
    let root = field_hash(b"VESS-MERKLE-v1 test input");
    let payload = vec![171u8; 800];
    let bundle = field_blob_bundle(root, &payload).unwrap();
    assert_eq!(&bundle.bytes[..32], &root);
    assert_eq!(&bundle.bytes[33..64], &payload[..31]);
    assert_eq!(&bundle.bytes[65..96], &payload[31..62]);
    assert!(bundle.point_proofs[1].is_empty());
    let p = &bundle.point_proofs[0];
    assert_eq!(p.len(), 192);
    assert_eq!(&p[..32], &bundle.versioned);
    assert_eq!(&p[32..64], &word(1));
    assert_eq!(&p[64..96], &root);
    assert!(ethereum_kzg_settings(0)
        .verify_kzg_proof(
            &Bytes48::from_bytes(&p[96..144]).unwrap(),
            &Bytes32::from_bytes(&p[32..64]).unwrap(),
            &Bytes32::from_bytes(&root).unwrap(),
            &Bytes48::from_bytes(&p[144..192]).unwrap()
        )
        .unwrap());
    let mut wrong_root = root;
    wrong_root[31] ^= 1;
    assert!(!ethereum_kzg_settings(0)
        .verify_kzg_proof(
            &Bytes48::from_bytes(&p[96..144]).unwrap(),
            &Bytes32::from_bytes(&p[32..64]).unwrap(),
            &Bytes32::from_bytes(&wrong_root).unwrap(),
            &Bytes48::from_bytes(&p[144..192]).unwrap()
        )
        .unwrap());
    assert!(field_blob_bundle([255; 32], &payload).is_err());
}

#[test]
fn multipart_field_payload_roundtrips_boundaries_and_rejects_corruption() {
    use vess_bench::chain::{field_hash, field_payload, FieldPublication, FIELD_PAYLOAD_BYTES};
    let root = field_hash(b"multipart fixture");
    for size in [1, FIELD_PAYLOAD_BYTES, FIELD_PAYLOAD_BYTES + 1] {
        let payload: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
        let publication = FieldPublication::new(root, &payload).unwrap();
        let mut bytes = publication
            .blobs
            .iter()
            .map(|b| b.bytes.clone())
            .collect::<Vec<_>>();
        assert_eq!(field_payload(root, &bytes, size).unwrap(), payload);
        assert_eq!(publication.physical_bytes(), bytes.len() * 131072);
        if bytes.len() > 1 {
            bytes.swap(0, 1);
            assert!(field_payload(root, &bytes, size).is_err());
            bytes.swap(0, 1);
            let last = bytes.pop().unwrap();
            assert!(field_payload(root, &bytes, size).is_err());
            bytes.push(last);
        }
        bytes[0][32] = 1;
        assert!(field_payload(root, &bytes, size).is_err());
        bytes[0][32] = 0;
        bytes[0][31] ^= 1;
        assert!(field_payload(root, &bytes, size).is_err());
    }
    assert!(FieldPublication::new(root, &[]).is_err());
}

#[test]
fn field_merkle_domain_and_path_canonicality_are_enforced() {
    use vess_bench::chain::{bn::Tree, field_hash, field_member, field_parent};
    let a = field_hash(b"VESS-RECORD-v1 left");
    let b = field_hash(b"VESS-VECTOR-v1 right");
    let tree = Tree::new_field(vec![a, b]);
    assert_eq!(tree.root(), field_parent(a, b));
    assert!(field_member(tree.root(), a, 0, &tree.proof(0)));
    assert!(!field_member(tree.root(), a, 1, &tree.proof(0)));
    assert!(!field_member(tree.root(), a, 2, &tree.proof(0)));
    let mut malformed = b;
    malformed[0] = 1;
    assert!(!field_member(tree.root(), a, 0, &[malformed]));
    assert_ne!(
        field_hash(b"VESS-RECORD-v1 same"),
        field_hash(b"VESS-VECTOR-v1 same")
    );
}

#[test]
fn invalid_pop_has_no_public_decryption_witness() {
    assert!(vess_bench::chain::bn::fixture(7182, 8, 8, "bad_pop")
        .dp
        .is_empty());
    assert_eq!(
        vess_bench::chain::bn::fixture(7182, 8, 8, "honest")
            .dp
            .len(),
        4
    );
}
