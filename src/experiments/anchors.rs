use super::*;
use crate::{
    chain::{self, Arg, Devnet},
    crypto::*,
    protocol::*,
};
use num_bigint::BigUint;
use num_traits::One;
pub fn fields(bundle: &chain::BlobBundle, payload_len: usize) -> Result<Vec<u8>> {
    use c_kzg::{ethereum_kzg_settings, Blob, Bytes32, Bytes48};
    let modulus = BigUint::parse_bytes(
        b"52435875175126190479447740508185965837690552500527637822603658699938581184513",
        10,
    )
    .unwrap();
    let exponent = (&modulus - BigUint::one()) / BigUint::from(4096u32);
    let omega = BigUint::from(7u32).modpow(&exponent, &modulus);
    let settings = ethereum_kzg_settings(0);
    let blob = Blob::from_bytes(&bundle.bytes)?;
    let commitment = Bytes48::from_bytes(&bundle.commitment)?;
    let mut joined = Vec::new();
    for slot in 2..2 + payload_len.div_ceil(31) {
        let reversed = (slot as u16).reverse_bits() >> 4;
        let number = omega
            .modpow(&BigUint::from(reversed), &modulus)
            .to_bytes_be();
        let mut z = [0; 32];
        z[32 - number.len()..].copy_from_slice(&number);
        let (proof, y) = settings.compute_kzg_proof(&blob, &Bytes32::from_bytes(&z)?)?;
        let proof = proof.to_bytes();
        ensure!(
            y.as_ref() == &bundle.bytes[slot * 32..(slot + 1) * 32],
            "slot ordering"
        );
        ensure!(
            settings.verify_kzg_proof(&commitment, &Bytes32::from_bytes(&z)?, &y, &proof)?,
            "field verification"
        );
        joined.extend(bundle.versioned);
        joined.extend(z);
        joined.extend(y.as_ref());
        joined.extend(&bundle.commitment);
        joined.extend(proof.as_ref());
    }
    Ok(joined)
}
pub fn run(c: &Config, r: &mut Recorder, d: &mut Devnet) -> Result<()> {
    for trial in 0..c.evm_repeats {
        let f = chain::bn::fixture(c.seed + 707070 + trial as u64, 16, 16, "honest");
        let bundle = chain::blob_bundle(f.record_tree.root(), &f.rec.concat())?;
        let data = chain::calldata(
            "anchorBlob(bytes32,bytes32,bytes32,uint256,uint256)",
            &[
                Arg::Word(f.record_tree.root()),
                Arg::Word(f.src_tree.root()),
                Arg::Word(f.tgt_tree.root()),
                Arg::Word(chain::word(16)),
                Arg::Word(chain::word(16)),
            ],
        );
        let rc = d.blob_send(data, &bundle, "fieldwise-anchor")?;
        ensure!(chain::hex_u64(&rc["status"])? == 1, "fieldwise anchor");
        let start = Instant::now();
        let proofs = fields(&bundle, 800)?;
        r.sample(
            "B17",
            "fieldwise_kzg_generate_verify",
            trial,
            "measured_component",
            ns(start),
            json!({"proofs":26,"proof_bytes":proofs.len(),"record_bytes":800}),
        )?;
        let args = [
            Arg::Bytes(proofs),
            Arg::Word(chain::keccak(&f.rec.concat())),
            Arg::Word(chain::word(800)),
        ];
        let data = chain::calldata("fieldOpenings(bytes,bytes32,uint256)", &args);
        let len = data.len();
        let to = d.verifier.clone();
        let start = Instant::now();
        let rc = d.send(Some(&to), data, 0, 0, "fieldwise-kzg")?;
        ensure!(chain::hex_u64(&rc["status"])? == 1, "fieldwise KZG");
        r.sample("B17","fieldwise_kzg_contract",trial,"measured_devnet_receipt",ns(start),json!({"gas":chain::hex_u64(&rc["gasUsed"])?,"calldata_bytes":len,"fields":26,"transaction_hash":rc["transactionHash"]}))?;
        let args = [
            Arg::Bytes(bundle.point_proofs[0].clone()),
            Arg::Bytes(bundle.point_proofs[1].clone()),
        ];
        let data = chain::calldata("rootOpening(bytes,bytes)", &args);
        let len = data.len();
        let start = Instant::now();
        let rc = d.send(Some(&to), data, 0, 0, "root-kzg")?;
        ensure!(chain::hex_u64(&rc["status"])? == 1, "root KZG");
        r.sample("B17","root_kzg_contract",trial,"measured_devnet_receipt",ns(start),json!({"gas":chain::hex_u64(&rc["gasUsed"])?,"calldata_bytes":len,"fields":2,"transaction_hash":rc["transactionHash"],"membership":"single record leaf; general membership measured in bisection"}))?;
    }
    // Encode real public objects, including both retained dealer vectors and aggregate vectors.
    for &t in &c.evm_thresholds {
        let mut random = rng(c.seed, "full-publication", t as u64);
        let src = init(
            Params {
                n: 4,
                k: 2,
                f: 1,
                t,
            },
            0,
            &mut random,
        )?;
        let dst = generate(&src, t, &mut random)?;
        let sk = nonzero(&mut random);
        let keys: Vec<_> = (0..4).map(|_| nonzero(&mut random)).collect();
        let records: Vec<_> = (0..3)
            .map(|j| {
                make_record(
                    &src,
                    &dst,
                    j,
                    1,
                    1,
                    Mode::Difference,
                    sk * g(),
                    keys[j],
                    Fr::ZERO,
                    &mut random,
                )
            })
            .collect();
        let header = enc(&(src.digest(), dst.digest(), 1u64, t as u64, 0u64));
        let registry = enc(&(1..=t as u64).collect::<Vec<_>>());
        let certificate = enc(&(1..=3)
            .map(|id| (id, sign(keys[id - 1], &header, &mut random)))
            .collect::<Vec<_>>());
        let aggregate = enc(&(&src.public, &dst.public));
        let dealers = enc(&(&src.vectors, &dst.vectors));
        let record_bytes = enc(&records);
        let trees: Vec<_> = src
            .vectors
            .iter()
            .chain(&dst.vectors)
            .map(|v| {
                let values: Vec<_> = v.iter().map(enc).collect();
                let tree = crate::storage::Merkle::new(&values);
                (tree.root(), tree.proof(0))
            })
            .collect();
        let treebytes = enc(&trees);
        let pool = enc(&(
            &aggregate,
            &dealers,
            &record_bytes,
            &header,
            &registry,
            &certificate,
            &treebytes,
        ));
        let root = hash(&[&pool]);
        let start = Instant::now();
        let bundles: Vec<_> = pool
            .chunks(4094 * 31)
            .map(|b| chain::blob_bundle(root, b))
            .collect::<Result<_>>()?;
        let packing_ns = ns(start);
        let mut gas = 0;
        let mut blobgas = 0;
        let mut txs = 0;
        let mut block_numbers = BTreeSet::new();
        let start = Instant::now();
        for batch in bundles.chunks(9) {
            let data = chain::calldata(
                "anchorBlobs(bytes32,uint256)",
                &[Arg::Word(root), Arg::Word(chain::word(batch.len() as u64))],
            );
            let receipt =
                d.blobs_send(data, &batch.iter().collect::<Vec<_>>(), "full-epoch-blobs")?;
            ensure!(
                chain::hex_u64(&receipt["status"])? == 1,
                "whole publication"
            );
            gas += chain::hex_u64(&receipt["gasUsed"])?;
            blobgas += chain::hex_u64(&receipt["blobGasUsed"])?;
            txs += 1;
            block_numbers.insert(chain::hex_u64(&receipt["blockNumber"])?);
        }
        r.sample("B19","full_publication_pool",0,"measured_devnet_receipt",ns(start),json!({"t":t,"n":4,"offline":1,"packing_crypto_ns":packing_ns,"aggregate_vector_bytes":aggregate.len(),"dealer_source_target_bytes":dealers.len(),"record_bytes":record_bytes.len(),"header_bytes":header.len(),"registry_coordinate_bytes":registry.len(),"certificate_bytes":certificate.len(),"coefficient_metadata_bytes":treebytes.len(),"total_encoded_bytes":pool.len(),"blobs":bundles.len(),"physical_blob_bytes":bundles.len()*131072,"gas":gas,"blob_gas":blobgas,"transactions":txs,"actual_blocks":block_numbers.len(),"block_capacity_lower_bound":bundles.len().div_ceil(9),"packing":"shared pool, two root limbs in each blob","registry_scope":"coordinate index; authorization registry measured separately","classification":"admissible"}))?;
        for execution_price in [1u64, 10, 100] {
            for blob_price in [1u64, 1000, 1000000000] {
                let fee = gas as u128 * execution_price as u128 * 1_000_000_000
                    + blobgas as u128 * blob_price as u128;
                r.sample("B19","fee_sensitivity",0,"model_with_measured_gas",0,json!({"t":t,"execution_gwei":execution_price,"blob_wei":blob_price,"fee_wei":fee.to_string(),"execution_gas":gas,"blob_gas":blobgas}))?;
            }
        }
        if t <= 64 {
            let data = chain::calldata(
                "storeVector(bytes32,bytes)",
                &[Arg::Word(root), Arg::Bytes(aggregate)],
            );
            let len = data.len();
            let to = d.verifier.clone();
            let start = Instant::now();
            let rc = d.send(Some(&to), data, 0, 0, "storage-vectors")?;
            ensure!(chain::hex_u64(&rc["status"])? == 1, "storage");
            r.sample("B19","contract_storage_two_vectors",0,"measured_devnet_receipt",ns(start),json!({"t":t,"gas":chain::hex_u64(&rc["gasUsed"])?,"calldata_bytes":len,"transaction_hash":rc["transactionHash"]}))?;
        }
    }
    for age in [0u64, 100, 1000] {
        let challenge = 60;
        let round = 30;
        let response = 60;
        let finality = 120;
        let t = 1024usize;
        let dispute = challenge + 2 * t.ilog2() as u64 * round + response + finality;
        let retention = 900;
        r.sample("B18","retention_deadline",age as usize,"time_compressed_policy",0,json!({"t":t,"source_age_s":age,"dispute_horizon_s":dispute,"retention_s":retention,"reanchor_required":age+dispute>retention,"observed_multi_day_availability":false}))?;
    }
    Ok(())
}
use std::collections::BTreeSet;
