use super::*;
use crate::{
    chain::{self, bn, *},
    crypto::rng,
};
use ark_ec::Group;
use ark_ff::Zero;
type W = chain::Word;
fn w(n: u64) -> Arg {
    Arg::Word(word(n))
}
fn words(v: Vec<W>) -> Arg {
    Arg::Words(v)
}
// Transaction parameters are explicit so each receipt scenario is reviewable.
#[allow(clippy::too_many_arguments)]
fn tx(
    d: &mut Devnet,
    r: &mut Recorder,
    id: &str,
    case: &str,
    trial: usize,
    sig: &str,
    args: Vec<Arg>,
    from: usize,
    value: u64,
    expected: bool,
) -> Result<Value> {
    let value = if sig.starts_with("plaintext(") {
        5
    } else {
        value
    };
    let data = calldata(sig, &args);
    let len = data.len();
    let zero = data.iter().filter(|b| **b == 0).count();
    let started = Instant::now();
    let to = d.verifier.clone();
    let receipt = d.send(Some(&to), data, from, value, case)?;
    let elapsed = ns(started);
    let ok = hex_u64(&receipt["status"])? == 1;
    r.sample(id,case,trial,"measured_devnet_receipt",elapsed,json!({"gas":hex_u64(&receipt["gasUsed"])?,"calldata_bytes":len,"zero_bytes":zero,"nonzero_bytes":len-zero,"transaction_hash":receipt["transactionHash"],"status":ok,"expected_status":expected,"logs":receipt["logs"]}))?;
    ensure!(ok == expected, "unexpected EVM status {case}: {receipt}");
    Ok(receipt)
}
fn verdict(receipt: &Value, kind: u64, good: bool) -> bool {
    receipt["logs"].as_array().is_some_and(|logs| {
        logs.iter().any(|l| {
            let data = unhex(l["data"].as_str().unwrap_or("")).unwrap_or_default();
            data.len() == 64 && data[..32] == word(kind) && data[32..] == word(u64::from(good))
        })
    })
}
fn register(d: &mut Devnet, f: &bn::Fixture) -> Result<()> {
    let rc = d.transact(
        "register(uint256,uint256,uint256,uint256,address)",
        vec![
            Arg::Word(f.rec[0]),
            w(0),
            Arg::Word(f.pk[0]),
            Arg::Word(f.pk[1]),
            Arg::Word(address(&d.accounts[2])?),
        ],
        0,
        0,
        "register",
    )?;
    ensure!(hex_u64(&rc["status"])? == 1, "register");
    let collateral = d.transact("deposit()", vec![], 2, 10, "complaint-collateral")?;
    ensure!(hex_u64(&collateral["status"])? == 1, "collateral");
    Ok(())
}
fn anchor(
    d: &mut Devnet,
    r: &mut Recorder,
    f: &bn::Fixture,
    trial: usize,
    t0: usize,
    t1: usize,
) -> Result<BlobBundle> {
    let start = Instant::now();
    let bundle = blob_bundle(f.record_tree.root(), &f.rec.concat())?;
    r.sample("B17","kzg_blob_commit_and_two_root_openings",trial,"measured_component",ns(start),json!({"raw_record_bytes":800,"blob_bytes":131072,"root_slots":2,"opening_bytes":384,"t":t0.max(t1)}))?;
    fs::write(
        d.dir.join(format!("blob-{:05}.bin", d.count)),
        &bundle.bytes,
    )?;
    let data = calldata(
        "anchorBlob(bytes32,bytes32,bytes32,uint256,uint256)",
        &[
            Arg::Word(f.record_tree.root()),
            Arg::Word(f.src_tree.root()),
            Arg::Word(f.tgt_tree.root()),
            w(t0 as u64),
            w(t1 as u64),
        ],
    );
    let start = Instant::now();
    let receipt = d.blob_send(data, &bundle, "blob-anchor")?;
    ensure!(hex_u64(&receipt["status"])? == 1, "anchor");
    r.sample("B19","blob_publication",trial,"measured_devnet_receipt",ns(start),json!({"gas":hex_u64(&receipt["gasUsed"])?,"blob_gas":receipt["blobGasUsed"],"blob_gas_price":receipt["blobGasPrice"],"transaction_hash":receipt["transactionHash"],"t":t0.max(t1),"blobs":1,"payload_bytes":800,"root_slots":2,"full_epoch_publication":false}))?;
    Ok(bundle)
}
fn admission_args(f: &bn::Fixture, b: &BlobBundle) -> Vec<Arg> {
    vec![
        words(f.rec.clone()),
        w(0),
        words(f.record_tree.proof(0)),
        Arg::Bytes(b.point_proofs[0].clone()),
        Arg::Bytes(b.point_proofs[1].clone()),
    ]
}
fn plaintext_args(f: &bn::Fixture, b: &BlobBundle) -> Vec<Arg> {
    vec![
        words(f.rec.clone()),
        words(f.dp.clone()),
        w(0),
        words(f.record_tree.proof(0)),
        Arg::Bytes(b.point_proofs[0].clone()),
        Arg::Bytes(b.point_proofs[1].clone()),
    ]
}
pub fn run(c: &Config, r: &mut Recorder) -> Result<()> {
    let mut d = Devnet::start(&r.dir.join("evm"))?;
    for trial in 0..c.evm_repeats {
        for (j, kind) in [
            "honest",
            "bad_pop",
            "bad_plaintext",
            "bad_decryption",
            "bad_signature",
        ]
        .into_iter()
        .enumerate()
        {
            eprintln!("EVM {kind} trial {trial}");
            let f = bn::fixture(c.seed + trial as u64 * 100 + j as u64, 16, 16, kind);
            register(&mut d, &f)?;
            let b = anchor(&mut d, r, &f, trial, 16, 16)?;
            tx(
                &mut d,
                r,
                "B14",
                &format!("admission_{kind}"),
                trial,
                "admitRecord(uint256[],uint256,bytes32[],bytes,bytes)",
                admission_args(&f, &b),
                0,
                0,
                !["bad_pop", "bad_signature"].contains(&kind),
            )?;
            let receipt = tx(
                &mut d,
                r,
                "B14",
                &format!("plaintext_{kind}"),
                trial,
                "plaintext(uint256[],uint256[],uint256,bytes32[],bytes,bytes)",
                plaintext_args(&f, &b),
                1,
                0,
                !["bad_decryption", "bad_signature"].contains(&kind),
            )?;
            if !["bad_decryption", "bad_signature"].contains(&kind) {
                r.check(
                    "B14",
                    &format!("verdict_{kind}"),
                    verdict(
                        &receipt,
                        if kind == "bad_pop" { 1 } else { 2 },
                        kind == "honest",
                    ),
                    json!({"transaction_hash":receipt["transactionHash"]}),
                )?;
            }
            if kind == "honest" {
                tx(
                    &mut d,
                    r,
                    "B14",
                    "admission_duplicate",
                    trial,
                    "admitRecord(uint256[],uint256,bytes32[],bytes,bytes)",
                    admission_args(&f, &b),
                    0,
                    0,
                    false,
                )?;
                let mut bad = plaintext_args(&f, &b);
                bad[4] = Arg::Bytes({
                    let mut v = b.point_proofs[0].clone();
                    v[191] ^= 1;
                    v
                });
                tx(
                    &mut d,
                    r,
                    "B14",
                    "wrong_kzg_proof",
                    trial,
                    "plaintext(uint256[],uint256[],uint256,bytes32[],bytes,bytes)",
                    bad,
                    1,
                    0,
                    false,
                )?;
                let mut bad = plaintext_args(&f, &b);
                bad[3] = words(vec![[1; 32]]);
                tx(
                    &mut d,
                    r,
                    "B14",
                    "wrong_membership",
                    trial,
                    "plaintext(uint256[],uint256[],uint256,bytes32[],bytes,bytes)",
                    bad,
                    1,
                    0,
                    false,
                )?;
                let delta: Vec<_> = f
                    .target
                    .iter()
                    .zip(&f.source)
                    .flat_map(|(a, b)| bn::words(*a - *b))
                    .collect();
                tx(
                    &mut d,
                    r,
                    "B22",
                    "full_vector_plaintext_check",
                    trial,
                    "fullVector(uint256[],uint256,uint256,uint256)",
                    vec![
                        words(delta),
                        w(7),
                        Arg::Word(f.rec[10]),
                        Arg::Word(f.rec[11]),
                    ],
                    1,
                    0,
                    true,
                )?;
            }
        }
    }
    for &t in &c.evm_thresholds {
        for trial in 0..c.evm_repeats {
            bisection(c, r, &mut d, t, t, trial, "dealer_wrong")?;
        }
    }
    for case in [
        "zero_padding",
        "challenger_wrong",
        "both_wrong",
        "copied_root",
        "wrong_coefficient",
        "timeout",
        "dealer_timeout",
    ] {
        bisection(c, r, &mut d, 3, 2, 0, case)?;
    }
    availability(c, r, &mut d)?;
    key_rotation(c, r, &mut d)?;
    packing(c, r, &mut d)?;
    super::anchors::run(c, r, &mut d)?;
    Ok(())
}
fn bisection(
    c: &Config,
    r: &mut Recorder,
    d: &mut Devnet,
    t0: usize,
    t1: usize,
    trial: usize,
    kind: &str,
) -> Result<()> {
    let fixture_start = Instant::now();
    let mut f = bn::fixture(
        c.seed + 100000 + t0 as u64 * 100 + trial as u64 + kind.bytes().map(u64::from).sum::<u64>(),
        t0,
        t1,
        if kind == "challenger_wrong" {
            "honest"
        } else {
            "inconsistent"
        },
    );
    let n = t0.max(t1);
    if kind == "challenger_wrong" || kind == "both_wrong" {
        *f.truth.last_mut().unwrap() +=
            ark_bn254::G1Projective::generator() * ark_bn254::Fr::from(2u64);
        f.true_tree = bn::Tree::new(
            f.truth
                .iter()
                .enumerate()
                .map(|(i, p)| bn::leaf(i, *p))
                .collect(),
        );
    }
    r.sample("B15","fixture_and_trace_generation",trial,"measured_bn254_fixture",ns(fixture_start),json!({"source_t":t0,"target_t":t1,"kind":kind,"includes_polynomial_fixture":true,"trace_bytes":(n+1)*64*2}))?;
    register(d, &f)?;
    let b = anchor(d, r, &f, trial, t0, t1)?;
    for account in [1, 2] {
        let rc = d.transact("deposit()", vec![], account, 5, "game-collateral")?;
        ensure!(hex_u64(&rc["status"])? == 1, "game collateral");
    }
    let whole = Instant::now();
    let mut gas = 0;
    let mut txs = 0;
    let mut hash_bytes = 0;
    let mut rejected_transactions = 0;
    let receipt = tx(
        d,
        r,
        "B15",
        "bisection_admission",
        trial,
        "admitRecord(uint256[],uint256,bytes32[],bytes,bytes)",
        admission_args(&f, &b),
        0,
        0,
        true,
    )?;
    gas += hex_u64(&receipt["gasUsed"])?;
    txs += 1;
    let id = keccak(&f.rec.concat());
    let cpoint = bn::words(*f.truth.last().unwrap());
    let dealer = address(&d.accounts[2])?;
    let mut begin = vec![
        Arg::Word(id),
        Arg::Word(f.true_tree.root()),
        Arg::Word(f.claimed_tree.root()),
        Arg::Word(cpoint[0]),
        Arg::Word(cpoint[1]),
        words(f.true_tree.proof(0)),
        words(f.true_tree.proof(n)),
        words(f.claimed_tree.proof(0)),
        words(f.claimed_tree.proof(n)),
        Arg::Word(dealer),
        w(600),
    ];
    if kind == "copied_root" {
        begin[1] = Arg::Word(f.claimed_tree.root());
        tx(d,r,"B15","copied_root_rejected",trial,"beginGame(bytes32,bytes32,bytes32,uint256,uint256,bytes32[],bytes32[],bytes32[],bytes32[],address,uint256)",begin,1,0,false)?;
        return Ok(());
    }
    let receipt=tx(d,r,"B15","bisection_endpoints",trial,"beginGame(bytes32,bytes32,bytes32,uint256,uint256,bytes32[],bytes32[],bytes32[],bytes32[],address,uint256)",begin,1,0,true)?;
    gas += hex_u64(&receipt["gasUsed"])?;
    txs += 1;
    if kind == "timeout" || kind == "dealer_timeout" {
        if kind == "dealer_timeout" {
            let mid = n / 2;
            let point = bn::words(f.truth[mid]);
            tx(
                d,
                r,
                "B15",
                "challenger_move_before_dealer_timeout",
                trial,
                "move(uint256,uint256,bytes32[])",
                vec![
                    Arg::Word(point[0]),
                    Arg::Word(point[1]),
                    words(f.true_tree.proof(mid)),
                ],
                1,
                0,
                true,
            )?;
        }
        d.advance(601)?;
        let receipt = tx(
            d,
            r,
            "B15",
            "bisection_timeout",
            trial,
            "gameTimeout()",
            vec![],
            0,
            0,
            true,
        )?;
        r.check(
            "B15",
            "timeout_verdict",
            verdict(&receipt, 8, false),
            json!({}),
        )?;
        return Ok(());
    }
    let (mut lo, mut hi) = (0, n);
    while hi > lo + 1 {
        let mid = (lo + hi) / 2;
        for (from, points, tree) in [
            (1, &f.truth, &f.true_tree),
            (2, &f.claimed, &f.claimed_tree),
        ] {
            let p = bn::words(points[mid]);
            let path = tree.proof(mid);
            hash_bytes += path.len() * 32;
            let receipt = tx(
                d,
                r,
                "B15",
                "bisection_midpoint",
                trial,
                "move(uint256,uint256,bytes32[])",
                vec![Arg::Word(p[0]), Arg::Word(p[1]), words(path)],
                from,
                0,
                true,
            )?;
            gas += hex_u64(&receipt["gasUsed"])?;
            txs += 1;
        }
        if f.truth[mid] == f.claimed[mid] {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let source = bn::words(
        f.source
            .get(lo)
            .copied()
            .unwrap_or_else(ark_bn254::G1Projective::zero),
    );
    let target = bn::words(
        f.target
            .get(lo)
            .copied()
            .unwrap_or_else(ark_bn254::G1Projective::zero),
    );
    let sp = if lo < t0 {
        f.src_tree.proof(lo)
    } else {
        vec![]
    };
    let tp = if lo < t1 {
        f.tgt_tree.proof(lo)
    } else {
        vec![]
    };
    if kind == "wrong_coefficient" {
        let bad = vec![
            w(1),
            w(2),
            Arg::Word(target[0]),
            Arg::Word(target[1]),
            words(sp.clone()),
            words(tp.clone()),
        ];
        let rejected = tx(
            d,
            r,
            "B15",
            "false_source_coefficient_rejected",
            trial,
            "finishGame(uint256,uint256,uint256,uint256,bytes32[],bytes32[])",
            bad,
            1,
            0,
            false,
        )?;
        gas += hex_u64(&rejected["gasUsed"])?;
        txs += 1;
        rejected_transactions += 1;
    }
    let receipt = tx(
        d,
        r,
        "B15",
        "bisection_final_coefficients",
        trial,
        "finishGame(uint256,uint256,uint256,uint256,bytes32[],bytes32[])",
        vec![
            Arg::Word(source[0]),
            Arg::Word(source[1]),
            Arg::Word(target[0]),
            Arg::Word(target[1]),
            words(sp),
            words(tp),
        ],
        1,
        0,
        true,
    )?;
    gas += hex_u64(&receipt["gasUsed"])?;
    txs += 1;
    let (expected, good) = match kind {
        "challenger_wrong" => (5, true),
        "both_wrong" => (7, false),
        _ => (4, false),
    };
    r.check(
        "B15",
        &format!("verdict_{kind}"),
        verdict(&receipt, expected, good),
        json!({"source_t":t0,"target_t":t1,"coefficient":lo}),
    )?;
    r.sample("B15","complete_dispute",trial,"measured_devnet_receipt",ns(whole),json!({"source_t":t0,"target_t":t1,"kind":kind,"transactions":txs,"gas":gas,"midpoint_transactions":txs-3-rejected_transactions,"midpoint_hash_bytes":hash_bytes,"includes_admission_endpoints_final":true,"includes_prepublication":false,"coefficient":lo,"padding_used":lo>=t0||lo>=t1,"finality":"Anvil inclusion only"}))?;
    Ok(())
}
fn contract_u64(d: &Devnet, sig: &str, args: Vec<Arg>) -> Result<u64> {
    let result = rpc(
        &d.url,
        "eth_call",
        json!([{"to":d.verifier,"data":hhex(&calldata(sig,&args))},"latest"]),
    )?;
    let bytes = unhex(result.as_str().context("eth_call result")?)?;
    ensure!(bytes.len() >= 32, "call word");
    Ok(u64::from_be_bytes(bytes[24..32].try_into()?))
}
fn availability(c: &Config, r: &mut Recorder, d: &mut Devnet) -> Result<()> {
    let forfeited_before = contract_u64(d, "forfeited()", vec![])?;
    let f = bn::fixture(c.seed + 909090, 16, 16, "honest");
    register(d, &f)?;
    let b = anchor(d, r, &f, 0, 16, 16)?;
    tx(
        d,
        r,
        "B16",
        "da_record_admission",
        0,
        "admitRecord(uint256[],uint256,bytes32[],bytes,bytes)",
        admission_args(&f, &b),
        0,
        0,
        true,
    )?;
    tx(
        d,
        r,
        "B16",
        "dealer_deposit",
        0,
        "deposit()",
        vec![],
        2,
        1000,
        true,
    )?;
    let id = keccak(&f.rec.concat());
    let dealer = address(&d.accounts[2])?;
    let block = rpc(&d.url, "eth_getBlockByNumber", json!(["latest", false]))?;
    let now = hex_u64(&block["timestamp"])?;
    for (index, case) in ["respond", "default", "expire"].into_iter().enumerate() {
        let key = keccak(case.as_bytes());
        tx(
            d,
            r,
            "B16",
            "finalized_obligation",
            index,
            "oblige(bytes32,bytes32,address,uint256)",
            vec![
                Arg::Word(key),
                Arg::Word(id),
                Arg::Word(dealer),
                w(now + 10000),
            ],
            0,
            0,
            true,
        )?;
        tx(
            d,
            r,
            "B16",
            "da_open",
            index,
            "openDA(bytes32,uint256)",
            vec![Arg::Word(key), w(60)],
            1,
            15,
            true,
        )?;
        tx(
            d,
            r,
            "B16",
            "da_duplicate_open",
            index,
            "openDA(bytes32,uint256)",
            vec![Arg::Word(key), w(60)],
            1,
            15,
            false,
        )?;
        if case == "respond" {
            tx(
                d,
                r,
                "B16",
                "da_wrong_anchor",
                index,
                "answerDA(bytes32,bytes32,uint256,bytes32[])",
                vec![Arg::Word(key), Arg::Word([7; 32]), w(0), words(vec![])],
                2,
                0,
                false,
            )?;
            tx(
                d,
                r,
                "B16",
                "da_response",
                index,
                "answerDA(bytes32,bytes32,uint256,bytes32[])",
                vec![Arg::Word(key), Arg::Word(id), w(0), words(vec![])],
                2,
                0,
                true,
            )?;
        } else {
            tx(
                d,
                r,
                "B16",
                "da_premature_default",
                index,
                "defaultDA(bytes32)",
                vec![Arg::Word(key)],
                0,
                0,
                false,
            )?;
            d.advance(61)?;
            tx(
                d,
                r,
                "B16",
                "da_late_response",
                index,
                "answerDA(bytes32,bytes32,uint256,bytes32[])",
                vec![Arg::Word(key), Arg::Word(id), w(0), words(vec![])],
                2,
                0,
                false,
            )?;
            tx(
                d,
                r,
                "B16",
                "da_default",
                index,
                "defaultDA(bytes32)",
                vec![Arg::Word(key)],
                0,
                0,
                true,
            )?;
        }
    }
    tx(
        d,
        r,
        "B16",
        "da_not_required",
        0,
        "openDA(bytes32,uint256)",
        vec![Arg::Word([99; 32]), w(60)],
        1,
        15,
        true,
    )?;
    for (case, offset) in [("boundary_before", 59u64), ("boundary_exact", 60u64)] {
        let key = keccak(case.as_bytes());
        tx(
            d,
            r,
            "B16",
            "boundary_obligation",
            0,
            "oblige(bytes32,bytes32,address,uint256)",
            vec![
                Arg::Word(key),
                Arg::Word(id),
                Arg::Word(dealer),
                w(now + 10000),
            ],
            0,
            0,
            true,
        )?;
        let opened = tx(
            d,
            r,
            "B16",
            "boundary_open",
            0,
            "openDA(bytes32,uint256)",
            vec![Arg::Word(key), w(60)],
            1,
            15,
            true,
        )?;
        let block = rpc(
            &d.url,
            "eth_getBlockByNumber",
            json!([opened["blockNumber"], false]),
        )?;
        let timestamp = hex_u64(&block["timestamp"])?;
        rpc(
            &d.url,
            "evm_setNextBlockTimestamp",
            json!([timestamp + offset]),
        )?;
        tx(
            d,
            r,
            "B16",
            case,
            0,
            "answerDA(bytes32,bytes32,uint256,bytes32[])",
            vec![Arg::Word(key), Arg::Word(id), w(0), words(vec![])],
            2,
            0,
            true,
        )?;
    }
    let forfeited = contract_u64(d, "forfeited()", vec![])?;
    r.check(
        "B16",
        "invalid_request_bond_forfeited",
        forfeited - forfeited_before == 5,
        json!({"bond_wei":forfeited-forfeited_before,"service_fee_refunded":10}),
    )?;
    let stake = contract_u64(d, "stake(address)", vec![Arg::Word(dealer)])?;
    let burned = contract_u64(d, "burned()", vec![])?;
    let claimant_stake = contract_u64(
        d,
        "stake(address)",
        vec![Arg::Word(address(&d.accounts[1])?)],
    )?;
    let client_credit = contract_u64(
        d,
        "credit(address)",
        vec![Arg::Word(address(&d.accounts[1])?)],
    )?;
    let dealer_credit = contract_u64(d, "credit(address)", vec![Arg::Word(dealer)])?;
    let balance = hex_u64(&rpc(
        &d.url,
        "eth_getBalance",
        json!([d.verifier, "latest"]),
    )?)?;
    r.check("B16","payout_conservation",stake+claimant_stake+burned+client_credit+dealer_credit==balance,json!({"dealer_stake":stake,"claimant_stake":claimant_stake,"burned_unwithdrawable":burned,"claimant_credit":client_credit,"dealer_credit":dealer_credit,"contract_balance":balance,"units":"wei; synthetic economic parameters"}))?;
    tx(
        d,
        r,
        "B16",
        "da_withdraw_claimant",
        0,
        "withdraw()",
        vec![],
        1,
        0,
        true,
    )?;
    tx(
        d,
        r,
        "B16",
        "da_recollateralize",
        0,
        "deposit()",
        vec![],
        2,
        200,
        true,
    )?;
    d.advance(10001)?;
    let expired = keccak(b"retention-expired");
    tx(
        d,
        r,
        "B16",
        "expired_obligation_rejected",
        0,
        "oblige(bytes32,bytes32,address,uint256)",
        vec![
            Arg::Word(expired),
            Arg::Word(id),
            Arg::Word(dealer),
            w(now + 10000),
        ],
        0,
        0,
        false,
    )?;
    Ok(())
}
fn key_rotation(c: &Config, r: &mut Recorder, d: &mut Devnet) -> Result<()> {
    let f = bn::fixture(c.seed + 888888, 16, 16, "honest");
    register(d, &f)?;
    let b = anchor(d, r, &f, 0, 16, 16)?;
    tx(
        d,
        r,
        "B12",
        "key_history_admission",
        0,
        "admitRecord(uint256[],uint256,bytes32[],bytes,bytes)",
        admission_args(&f, &b),
        0,
        0,
        true,
    )?;
    tx(
        d,
        r,
        "B12",
        "key_rotation",
        0,
        "register(uint256,uint256,uint256,uint256,address)",
        vec![
            Arg::Word(f.rec[0]),
            w(1),
            w(1),
            w(2),
            Arg::Word(address(&d.accounts[2])?),
        ],
        0,
        0,
        true,
    )?;
    tx(
        d,
        r,
        "B12",
        "retired_key_new_admission",
        0,
        "admitRecord(uint256[],uint256,bytes32[],bytes,bytes)",
        admission_args(&f, &b),
        0,
        0,
        false,
    )?;
    let receipt = tx(
        d,
        r,
        "B12",
        "historical_key_plaintext_verification",
        0,
        "plaintext(uint256[],uint256[],uint256,bytes32[],bytes,bytes)",
        plaintext_args(&f, &b),
        1,
        0,
        true,
    )?;
    r.check(
        "B12",
        "historical_verdict",
        verdict(&receipt, 2, true),
        json!({}),
    )?;
    Ok(())
}
fn packing(c: &Config, r: &mut Recorder, d: &mut Devnet) -> Result<()> {
    for &t in &c.evm_thresholds {
        let mut random = rng(c.seed, "vector-bytes", t as u64);
        let bytes: Vec<u8> = (0..t * 2)
            .flat_map(|_| {
                crate::crypto::enc(&crate::crypto::Pair::sample(&mut random).commitment())
            })
            .collect();
        tx(
            d,
            r,
            "B19",
            "two_vector_calldata_publication",
            t,
            "publishVector(bytes)",
            vec![Arg::Bytes(bytes.clone())],
            0,
            0,
            true,
        )?;
        r.sample("B19","encoding_capacity",t,"derived_from_encoding",0,json!({"t":t,"ristretto_two_vector_bytes":bytes.len(),"paper_379_raw":379,"paper_31_payload_slots":13,"paper_padded_payload":403,"paper_physical_bytes":416,"one_root_slot_capacity":315,"two_root_slot_capacity":314,"actual_ristretto_record_bytes":437,"actual_bn254_record_bytes":800,"bn254_contiguous_payload_records_per_blob":(4094*31)/800,"record_only":true}))?;
    }
    Ok(())
}
