//! Bounded probing with a response deadline for each participant.
//! Queueing behind other participants must not consume that deadline.
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

pub(super) const WORKERS: usize = 16;

pub(super) fn classify(
    ids: &[u64],
    timeout: Duration,
    probe: impl Fn(u64, Duration) -> bool + Sync,
) -> (Vec<u64>, Vec<u64>) {
    let next = AtomicUsize::new(0);
    let responses = std::thread::scope(|scope| {
        let tasks = (0..WORKERS.min(ids.len()))
            .map(|_| {
                scope.spawn(|| {
                    let mut responses = Vec::new();
                    while let Some(&id) = ids.get(next.fetch_add(1, Ordering::Relaxed)) {
                        // Start the clock only when this worker can contact id.
                        let deadline = Instant::now() + timeout;
                        let timely = loop {
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            if remaining.is_zero() {
                                break false;
                            }
                            let responded = probe(id, remaining);
                            if responded && Instant::now() <= deadline {
                                break true;
                            }
                            std::thread::sleep(
                                Duration::from_millis(50)
                                    .min(deadline.saturating_duration_since(Instant::now())),
                            );
                        };
                        responses.push((id, timely));
                    }
                    responses
                })
            })
            .collect::<Vec<_>>();
        tasks
            .into_iter()
            .flat_map(|task| task.join().expect("liveness worker"))
            .collect::<Vec<_>>()
    });
    let (mut online, mut offline) = (Vec::new(), Vec::new());
    for (id, timely) in responses {
        if timely {
            online.push(id);
        } else {
            offline.push(id);
        }
    }
    online.sort_unstable();
    offline.sort_unstable();
    (online, offline)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_full_registry_sweep_does_not_mark_unprobed_tail_offline() {
        let ids = (1..=1280).collect::<Vec<_>>();
        let calls = AtomicUsize::new(0);
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let timeout = Duration::from_millis(200);
        let start = Instant::now();
        let (online, offline) = classify(&ids, timeout, |_, _| {
            calls.fetch_add(1, Ordering::Relaxed);
            let count = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(count, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(5));
            active.fetch_sub(1, Ordering::SeqCst);
            true
        });
        assert!(start.elapsed() > timeout);
        assert_eq!(online, ids);
        assert!(offline.is_empty());
        assert_eq!(calls.load(Ordering::Relaxed), 1280);
        assert!(peak.load(Ordering::SeqCst) <= WORKERS);
    }

    #[test]
    fn retries_transient_failure_but_rejects_missing_and_late_responses() {
        let retry = AtomicUsize::new(0);
        let (online, offline) =
            classify(
                &[1, 2, 3, 4],
                Duration::from_millis(300),
                |id, left| match id {
                    1 => retry.fetch_add(1, Ordering::Relaxed) > 0,
                    2 => false,
                    3 => {
                        std::thread::sleep(left + Duration::from_millis(20));
                        true
                    }
                    _ => true,
                },
            );
        assert_eq!(online, [1, 4]);
        assert_eq!(offline, [2, 3]);
        assert!(retry.load(Ordering::Relaxed) >= 2);
    }
}
