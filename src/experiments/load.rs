use super::*;
use crate::{crypto::*, protocol::*, storage::*};
use std::{
    collections::BTreeMap,
    sync::{mpsc, Mutex},
    time::Duration,
};
pub fn run(c: &Config, r: &mut Recorder) -> Result<()> {
    let mut random = rng(c.seed, "archive-load", 0);
    let src = init(
        Params {
            n: 4,
            k: 2,
            f: 1,
            t: 16,
        },
        0,
        &mut random,
    )?;
    let dst = generate(&src, 16, &mut random)?;
    let keys: Vec<_> = (0..4).map(|_| nonzero(&mut random)).collect();
    let pks: Vec<_> = keys.iter().map(|s| s * g()).collect();
    let vectors: BTreeMap<_, _> = (0..4)
        .map(|j| {
            (
                (j + 1) as u64,
                (src.vectors[j].clone(), dst.vectors[j].clone()),
            )
        })
        .collect();
    let mut archives = Vec::new();
    for id in 1..=8 {
        let sk = nonzero(&mut random);
        let records: Vec<_> = (0..3)
            .map(|j| {
                make_record(
                    &src,
                    &dst,
                    j,
                    id,
                    1,
                    Mode::Difference,
                    sk * g(),
                    keys[j],
                    Fr::ZERO,
                    &mut random,
                )
            })
            .collect();
        archives.push((
            Archive::write(&r.dir.join(format!("return-load/{id}")), &records, &vectors)?,
            sk,
        ));
    }
    let expected = delta(&src.public, &dst.public);
    let jobs = 32usize;
    for &concurrency in &c.concurrency {
        for rate in [100usize, 1000] {
            for trial in 0..c.distributed_repeats {
                let (send, recv) = mpsc::channel::<(usize, Instant)>();
                let recv = Mutex::new(recv);
                let start = Instant::now();
                let samples = std::thread::scope(|scope| {
                    let mut workers = Vec::new();
                    for _ in 0..concurrency {
                        let recv = &recv;
                        let archives = &archives;
                        let pks = &pks;
                        let expected = &expected;
                        workers.push(scope.spawn(move||->Result<Vec<Value>>{let mut out=Vec::new();loop{let next=recv.lock().unwrap().recv();let Ok((job,arrival))=next else{break;};let service=Instant::now();let queued=service.duration_since(arrival).as_nanos()as u64;let (a,sk)=&archives[job%archives.len()];let (token,stats)=recover(a,*sk,pks,2,expected,&mut VectorCache::default())?;ensure!(token.commitment()==eval_commit(expected,Fr::from(a.meta.recipient)),"return load validity");out.push(json!({"job":job,"queue_ns":queued,"service_ns":ns(service),"response_ns":ns(arrival),"bytes":stats.bytes}));}Ok(out)}));
                    }
                    for job in 0..jobs {
                        let due = start
                            + Duration::from_nanos((job as u64) * 1_000_000_000 / rate as u64);
                        let now = Instant::now();
                        if now < due {
                            std::thread::sleep(due - now);
                        }
                        send.send((job, Instant::now())).unwrap();
                    }
                    drop(send);
                    workers
                        .into_iter()
                        .map(|worker| worker.join().unwrap())
                        .collect::<Result<Vec<_>>>()
                });
                let samples = samples?.into_iter().flatten().collect::<Vec<_>>();
                let wall = ns(start);
                r.sample("B20","open_loop_archive_returns",trial,"measured_load",wall,json!({"t":16,"N":64,"offline":8,"concurrency":concurrency,"offered_rate_per_s":rate,"completed_rate_per_s":jobs as f64*1e9/wall as f64,"requests":jobs,"completed":samples.len(),"request_samples":samples,"dealer_cpu_ns":0,"dealer_process":"absent; read-only local archive","client_identities":8,"same_identity_repeated_requests":true,"arrival_pacing":"real offered workload; no synthetic service delay","os_page_cache":"uncontrolled","admission":{"delta":1,"source_t":16,"rho_out_source":8,"target_t":16,"target_rho":1,"eligible":64}}))?;
            }
        }
    }
    monitoring(c, r)?;
    Ok(())
}
fn monitoring(c: &Config, r: &mut Recorder) -> Result<()> {
    use curve25519_dalek::traits::VartimeMultiscalarMul;
    fn audit(src: &[Point], tgt: &[Point], entries: &[(u64, Point)], found: &mut Vec<u64>) {
        let transcript = enc(&(src, tgt, entries));
        let vector = delta(src, tgt);
        let mut coefficient_weights = vec![Fr::ZERO; vector.len()];
        let mut weights_e = Vec::new();
        let mut points_e = Vec::new();
        for (id, e) in entries {
            let w = hs(&[b"E-BATCH-v1", &transcript, &id.to_le_bytes()]);
            weights_e.push(w);
            points_e.push(*e);
            for (l, pow) in powers(Fr::from(*id), vector.len()).into_iter().enumerate() {
                coefficient_weights[l] -= w * pow;
            }
        }
        weights_e.extend(coefficient_weights);
        points_e.extend(vector);
        if Point::vartime_multiscalar_mul(weights_e, points_e) == Pair::zero().commitment() {
            return;
        }
        if entries.len() == 1 {
            found.push(entries[0].0);
            return;
        }
        let half = entries.len() / 2;
        audit(src, tgt, &entries[..half], found);
        audit(src, tgt, &entries[half..], found);
    }
    for &t in &c.thresholds {
        let mut random = rng(c.seed, "monitor-family", t as u64);
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
        let v = delta(&src.vectors[0], &dst.vectors[0]);
        let entries: Vec<_> = (1..=16)
            .map(|id| (id, eval_commit(&v, Fr::from(id))))
            .collect();
        for trial in 0..c.distributed_repeats {
            for bad in [vec![], vec![1u64], vec![1, 7]] {
                let mut es = entries.clone();
                for (id, e) in &mut es {
                    if bad.contains(id) {
                        *e += g();
                    }
                }
                let start = Instant::now();
                let mut found = Vec::new();
                audit(&src.vectors[0], &dst.vectors[0], &es, &mut found);
                ensure!(found == bad, "monitor attribution");
                r.sample("B21","recipient_family_batch_isolation",trial,"measured_component",ns(start),json!({"t":t,"family_size":16,"bad":bad,"identified":found,"authenticated_download_bytes":enc(&(&src.vectors[0],&dst.vectors[0],&es)).len(),"transcript_binds":"source,target,all recipient coordinates and E values","plaintext_keys":false}))?;
            }
        }
    }
    Ok(())
}
