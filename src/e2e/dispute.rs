//! Uses the actual participant's record/proof and two actual nodes' dispute traces.
use super::{
    core::*,
    model::*,
    runner::{elapsed, tx, Cluster, Samples},
    wire::*,
};
use crate::chain::{self, keccak, word, Arg, BlobBundle, Devnet};
use anyhow::{ensure, Result};
use serde_json::json;
use std::time::Instant;
fn w(n: u64) -> Arg {
    Arg::Word(word(n))
}
fn verdict(r: &serde_json::Value, kind: u64, ok: bool) -> bool {
    r["logs"].as_array().is_some_and(|v| {
        v.iter().any(|l| {
            chain::unhex(l["data"].as_str().unwrap_or(""))
                .is_ok_and(|b| b == [word(kind), word(u64::from(ok))].concat())
        })
    })
}
#[allow(clippy::too_many_arguments)]
pub fn execute(
    c: &Cluster,
    d: &mut Devnet,
    b: &Bundle,
    blob: &BlobBundle,
    result: &ReturnResult,
    samples: &Samples,
    n: usize,
) -> Result<()> {
    for (record, dp) in result.bad.iter().zip(&result.proofs) {
        let j = record.dealer();
        let index = b
            .records
            .iter()
            .position(|r| r.hash() == record.hash())
            .unwrap();
        let proof = b.tree().proof(index);
        let challenger = c.cfg.n + 1;
        let dealer = j;
        for account in [challenger, dealer] {
            tx(d, "deposit()", vec![], account, 250, "dispute-collateral")?;
        }
        let full = Instant::now();
        let count = d.count;
        let args = vec![
            Arg::Words(record.words.clone()),
            w(index as u64),
            Arg::Words(proof.clone()),
            Arg::Bytes(blob.point_proofs[0].clone()),
            Arg::Bytes(blob.point_proofs[1].clone()),
        ];
        tx(
            d,
            "admitRecord(uint256[],uint256,bytes32[],bytes,bytes)",
            args,
            challenger,
            0,
            "actual-record-admission",
        )?;
        let bad_pop = !pop_ok(record).unwrap_or(false);
        let bad_plaintext = !dp.is_empty();
        if bad_plaintext || bad_pop {
            let r = tx(
                d,
                "plaintext(uint256[],uint256[],uint256,bytes32[],bytes,bytes)",
                vec![
                    Arg::Words(record.words.clone()),
                    Arg::Words(dp.clone()),
                    w(index as u64),
                    Arg::Words(proof.clone()),
                    Arg::Bytes(blob.point_proofs[0].clone()),
                    Arg::Bytes(blob.point_proofs[1].clone()),
                ],
                challenger,
                5,
                "actual-record-plaintext-complaint",
            )?;
            ensure!(
                verdict(&r, if bad_pop { 1 } else { 2 }, false),
                "malformed record verdict"
            );
        }
        if !bad_plaintext && !bad_pop {
            let truth: Vec<Point> = call(
                &c.cfg,
                1000 + record.id(),
                "dispute_trace",
                &(b.manifest.id(), record.hash()),
            )?;
            let claim: Vec<Point> = call(
                &c.cfg,
                j as u64,
                "dispute_trace",
                &(b.manifest.id(), record.hash()),
            )?;
            let tt = vector_tree(&truth);
            let dt = vector_tree(&claim);
            let end = truth.len() - 1;
            let point = words(truth[end]);
            tx(
                d,
                "beginGame(bytes32,bytes32,uint256,uint256,bytes32[],bytes32[])",
                vec![
                    Arg::Word(record.hash()),
                    Arg::Word(tt.root()),
                    Arg::Word(point[0]),
                    Arg::Word(point[1]),
                    Arg::Words(tt.proof(0)),
                    Arg::Words(tt.proof(end)),
                ],
                challenger,
                0,
                "actual-record-bisection-start",
            )?;
            tx(
                d,
                "respondGame(bytes32,bytes32[],bytes32[])",
                vec![
                    Arg::Word(dt.root()),
                    Arg::Words(dt.proof(0)),
                    Arg::Words(dt.proof(end)),
                ],
                dealer,
                0,
                "dealer-trace-commitment",
            )?;
            let (mut lo, mut hi) = (0, end);
            while hi > lo + 1 {
                let mid = (lo + hi) / 2;
                for (account, points, tree) in [(challenger, &truth, &tt), (dealer, &claim, &dt)] {
                    let p = words(points[mid]);
                    tx(
                        d,
                        "move(uint256,uint256,bytes32[])",
                        vec![
                            Arg::Word(p[0]),
                            Arg::Word(p[1]),
                            Arg::Words(tree.proof(mid)),
                        ],
                        account,
                        0,
                        "actual-record-bisection-midpoint",
                    )?;
                }
                if truth[mid] == claim[mid] {
                    lo = mid
                } else {
                    hi = mid
                }
            }
            let sv = &b.source.vectors[j - 1];
            let tv = &b.target.vectors[j - 1];
            let s = words(sv.get(lo).copied().unwrap_or_default());
            let t = words(tv.get(lo).copied().unwrap_or_default());
            let r = tx(
                d,
                "finishGame(uint256,uint256,uint256,uint256,bytes32[],bytes32[],uint256,bytes32[],bytes32[])",
                vec![
                    Arg::Word(s[0]),
                    Arg::Word(s[1]),
                    Arg::Word(t[0]),
                    Arg::Word(t[1]),
                    Arg::Words(if lo < sv.len() {
                        vector_tree(sv).proof(lo)
                    } else {
                        vec![]
                    }),
                    Arg::Words(if lo < tv.len() {
                        vector_tree(tv).proof(lo)
                    } else {
                        vec![]
                    }),
                    w(b.records.len() as u64),
                    Arg::Words(if lo < sv.len() { b.vector_root_proof(j, true) } else { vec![] }),
                    Arg::Words(if lo < tv.len() { b.vector_root_proof(j, false) } else { vec![] }),
                ],
                challenger,
                0,
                "actual-record-bisection-verdict",
            )?;
            ensure!(verdict(&r, 4, false), "dealer wrong consistency verdict");
        }
        samples.add(if bad_pop{"possession_proof_dispute"}else if bad_plaintext{"plaintext_dispute"}else{"consistency_dispute"},b.target.epoch,b.target.params.t,n,elapsed(full),json!({"nonce":b.manifest.nonce,"record_hash":hex::encode(record.hash()),"tx_count":d.count-count,"same_lifecycle_record":true,"dealer_wrong":true}))?;
        availability(c, d, b, index, samples, n, false)?;
    }
    Ok(())
}

/// A request is authorized from the finalized obligation and recipient key;
/// admission or possession of the missing record is not a prerequisite.
pub fn availability(
    c: &Cluster,
    d: &mut Devnet,
    b: &Bundle,
    index: usize,
    samples: &Samples,
    n: usize,
    initially_missing: bool,
) -> Result<()> {
    let record = &b.records[index];
    let dealer = record.dealer();
    let challenger = c.cfg.n + 1;
    tx(d, "deposit()", vec![], dealer, 250, "DA-dealer-collateral")?;
    let account = chain::address(&d.accounts[challenger])?;
    let account_bytes: [u8; 20] = account[12..].try_into()?;
    let da = Instant::now();
    let authorization: Sig = call(
        &c.cfg,
        1000 + record.id(),
        "da_authorization",
        &(b.manifest.nonce, dealer as u64, account_bytes),
    )?;
    let r = words(authorization.r);
    let key = keccak(
        &[
            b"VESS-DA-OBLIGATION-v1".as_slice(),
            &word(b.manifest.nonce),
            &word(dealer as u64),
            &word(record.id()),
        ]
        .concat(),
    );
    tx(
        d,
        "openDA(uint256,uint256,uint256,uint256,uint256,uint256)",
        vec![
            w(b.manifest.nonce),
            w(dealer as u64),
            w(record.id()),
            Arg::Word(r[0]),
            Arg::Word(r[1]),
            Arg::Word(sw(authorization.s)),
        ],
        challenger,
        15,
        "finalized-obligation-DA-request",
    )?;
    // The dealer returns the bytes after the request. No admitRecord or admin
    // oblige operation occurs before this request, including a missing-record run.
    tx(
        d,
        "answerDA(bytes32,bytes,uint256,bytes32[])",
        vec![
            Arg::Word(key),
            Arg::Bytes(record.words.concat()),
            w(index as u64),
            Arg::Words(b.tree().proof(index)),
        ],
        dealer,
        0,
        "finalized-obligation-DA-answer",
    )?;
    tx(
        d,
        "withdraw()",
        vec![],
        challenger,
        0,
        "DA-requester-withdraw",
    )?;
    tx(d, "withdraw()", vec![], dealer, 0, "DA-provider-withdraw")?;
    samples.add(if initially_missing { "missing_record_DA_service" } else { "DA_service_and_payout" }, b.target.epoch, b.target.params.t, n, elapsed(da),
       json!({"actual_record":hex::encode(record.hash()),"settled":true,"publication_nonce":b.manifest.nonce,"recipient":record.id(),"initially_missing":initially_missing,"requires_record_admission":false}))?;
    Ok(())
}
