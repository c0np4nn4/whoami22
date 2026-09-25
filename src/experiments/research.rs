use super::*;
use crate::{crypto::*, protocol::*};
use std::collections::BTreeSet;

fn rank(mut a: Vec<Vec<Fr>>, cols: usize) -> usize {
    let mut row = 0;
    for col in 0..cols {
        let Some(pivot) = (row..a.len()).find(|i| a[*i][col] != Fr::ZERO) else {
            continue;
        };
        a.swap(row, pivot);
        let inv = a[row][col].invert();
        for item in a[row].iter_mut().take(cols).skip(col) {
            *item *= inv;
        }
        let pivot = a[row].clone();
        for (i, line) in a.iter_mut().enumerate() {
            if i != row {
                let v = line[col];
                for j in col..cols {
                    line[j] -= v * pivot[j];
                }
            }
        }
        row += 1;
        if row == a.len() {
            break;
        }
    }
    row
}
pub fn run(c: &Config, r: &mut Recorder) -> Result<()> {
    let mut random = rng(c.seed, "key-only", 0);
    let mut epochs = vec![init(
        Params {
            n: 7,
            k: 3,
            f: 2,
            t: 8,
        },
        0,
        &mut random,
    )?];
    for _ in 0..2 {
        epochs.push(generate(epochs.last().unwrap(), 8, &mut random)?);
    }
    let sk = nonzero(&mut random);
    let signers: Vec<_> = (0..7).map(|_| nonzero(&mut random)).collect();
    for mode in ["difference", "snapshot", "mixed"] {
        let start = Instant::now();
        let mut known: BTreeSet<(usize, usize)> = [(0, 0), (1, 1), (2, 2)].into();
        let mut edges = Vec::new();
        let mut equations = Vec::new();
        let mut recovered = std::collections::BTreeMap::new();
        for (state, dealer) in [(0, 0), (1, 1), (2, 2)] {
            recovered.insert((state, dealer), eval(&epochs[state].rows[dealer], Fr::ONE));
            let mut row = vec![Fr::ZERO; 9];
            for (l, pow) in powers(Fr::from((dealer + 1) as u64), 3).iter().enumerate() {
                row[state * 3 + l] = *pow;
            }
            equations.push(row);
        }
        for target in 1..3 {
            for (dealer, signer) in signers.iter().enumerate().take(3) {
                let m = if mode == "snapshot" || (mode == "mixed" && target == 2) {
                    Mode::Snapshot
                } else {
                    Mode::Difference
                };
                let rec = make_record(
                    &epochs[target - 1],
                    &epochs[target],
                    dealer,
                    1,
                    target as u64,
                    m,
                    sk * g(),
                    *signer,
                    Fr::ZERO,
                    &mut random,
                );
                let partial = admit(&rec, *signer * g(), sk)?;
                let mut row = vec![Fr::ZERO; 9];
                for (l, pow) in powers(Fr::from((dealer + 1) as u64), 3).iter().enumerate() {
                    row[target * 3 + l] = *pow;
                    if m == Mode::Difference {
                        row[(target - 1) * 3 + l] = -*pow;
                    }
                }
                equations.push(row);
                if m == Mode::Difference {
                    edges.push(((target - 1, dealer), (target, dealer), partial));
                } else {
                    known.insert((target, dealer));
                    recovered.insert((target, dealer), partial);
                }
            }
        }
        loop {
            let before = known.len();
            for (a, b, diff) in &edges {
                if let Some(v) = recovered.get(a).copied() {
                    known.insert(*b);
                    recovered.insert(*b, v.plus(*diff));
                }
                if let Some(v) = recovered.get(b).copied() {
                    known.insert(*a);
                    recovered.insert(*a, v.minus(*diff));
                }
            }
            if known.len() == before {
                break;
            }
        }
        for (&(state, dealer), value) in &recovered {
            ensure!(
                *value == eval(&epochs[state].rows[dealer], Fr::ONE),
                "exposure graph reconstruction"
            );
        }
        let matrix_rank = rank(equations, 9);
        r.sample("R01",mode,0,"exploratory_rank_real_field",ns(start),json!({"mobile_dealer_sets":[[1],[2],[3]],"participant":1,"state_dealer_nodes":9,"known_nodes":known,"rank":matrix_rank,"unknown_coefficients":9,"record_key_compromised":true,"observation_model":"decrypted partials and dealer-local absolute partials only","claim":"one participant's dealer polynomial, not global secret recovery or complete leakage proof"}))?;
    }
    for size in [1usize, 2, 3] {
        let max = (1024 - 32 - 1) / size;
        r.sample(
            "B10",
            "offline_capacity_bound",
            size,
            "derived_formula",
            0,
            json!({"t":1024,"delta":32,"disjoint_equal_sets":size,"maximum_each":max}),
        )?;
    }
    let examples = [
        vec![
            vec![Fr::ONE, Fr::ONE, Fr::ONE],
            vec![Fr::ONE, Fr::ONE, Fr::ONE],
        ],
        vec![
            vec![Fr::ONE, Fr::ONE, Fr::ONE],
            vec![Fr::ONE, Fr::from(2u64), Fr::from(4u64)],
        ],
    ];
    for (i, rows) in examples.into_iter().enumerate() {
        let base = rank(rows.clone(), 3);
        let mut test = rows;
        test.push(vec![Fr::ONE, Fr::ZERO, Fr::ZERO]);
        r.sample("R01","conservative_count_is_not_reconstruction",i,"exploratory_rank_real_field",0,json!({"observations":2,"threshold":3,"rank":base,"secret_identifiable":rank(test,3)==base,"does_not_modify_release_policy":true}))?;
    }
    economics(r)?;
    r.sample("R03","research_boundaries",0,"not_claimed",0,json!({"asynchronous_security":"not proved by bounded-delay experiments","multi_recipient_encryption":"not implemented; requires new AD and privacy analysis","external_protocol_comparison":"not run; no functionally and cryptographically matched external artifact","secure_erasure":"zeroize calls and staging crash checks, not proof of physical disk/RAM erasure","snapshot_dispute_theorem":"not inferred from difference game measurements"}))?;
    Ok(())
}
fn economics(r: &mut Recorder) -> Result<()> {
    let rows = fs::read_to_string(r.dir.join("samples.jsonl"))?;
    let mut challenger = Vec::new();
    let mut dealer = Vec::new();
    for line in rows.lines() {
        let v: Value = serde_json::from_str(line)?;
        let case = v["case"].as_str().unwrap_or("");
        if let Some(gas) = v["metrics"]["gas"].as_u64() {
            if case == "da_open" {
                challenger.push(gas as f64);
            }
            if case == "da_response" {
                dealer.push(gas as f64);
            }
        }
    }
    let med = |v: &mut Vec<f64>| {
        v.sort_by(f64::total_cmp);
        v.get(v.len() / 2).copied()
    };
    let gc = med(&mut challenger);
    let gd = med(&mut dealer);
    let mut output = fs::File::create(r.dir.join("economic_grid.csv"))?;
    writeln!(
        output,
        "p_ext,r,G_D,G_C,G_delay,B,W,F_serv,F_ext,g_C,g_D,U1,U2,U3,U4,U5,gas_price_gwei"
    )?;
    let mut count = 0;
    let mut all_nonpositive = 0;
    if let (Some(gcgas), Some(gdgas)) = (gc, gd) {
        for fee in [1f64, 10., 100.] {
            let gc = gcgas * fee * 1e-9;
            let gd = gdgas * fee * 1e-9;
            for p in [0., 0.1, 0.5, 1.] {
                for race in [0., 0.5, 1.] {
                    for gain in [0., 0.001, 0.1] {
                        let bond = 0.01;
                        let reward = 0.09;
                        let service = gd;
                        let external = 0.001;
                        let u = [
                            gain - p * (reward + bond),
                            gain - service - external - gc,
                            gain - bond - gc,
                            gain - p * (race * (bond + gc) + (1. - race) * (reward + bond)),
                            gain + p * (service - gd),
                        ];
                        writeln!(output,"{p},{race},{gain},{gain},{gain},{bond},{reward},{service},{external},{gc},{gd},{},{},{},{},{},{fee}",u[0],u[1],u[2],u[3],u[4])?;
                        count += 1;
                        if u.iter().all(|u| *u <= 0.) {
                            all_nonpositive += 1;
                        }
                    }
                }
            }
        }
    }
    let counter = [
        5. - 0.1 * 100.,
        5. - (10. + 1.),
        5. - 0.1 * (1. * (10. + 1.) + 0. * 100.),
    ];
    r.check(
        "R02",
        "preemptive_counterexample",
        counter[0] < 0. && counter[1] < 0. && (counter[2] - 3.9f64).abs() < 1e-9,
        json!({"U1":counter[0],"U3":counter[1],"U4":counter[2]}),
    )?;
    r.sample("R02","five_strategy_grid",0,"model_with_measured_gas",0,json!({"cases":count,"all_five_nonpositive":all_nonpositive,"measured_challenger_gas":gc,"measured_response_gas":gd,"external_parameters":"gas price, gains, probabilities, bonds, rewards; not empirical attacker behavior","units":"ETH in grid; paper counterexample uses normalized units","five_strategies":["never answer","independent griefing","eager self-challenge","preemptive self-challenge","delay then answer"],"counterexample_delay":"F_serv=g_D leaves U5=G_delay","unconditional_availability_claim":false}))?;
    Ok(())
}
