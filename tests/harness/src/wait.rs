//! The harness's one timing primitive.

use std::time::Duration;

use anyhow::{bail, Result};
use tokio::time::sleep;

/// How long every wait in the harness may take, and how often it looks.
///
/// This was twenty seconds, and twenty seconds was wrong for the commonest
/// condition here: something that waits on a component's **initial sync**.
/// Every component a test starts starts cold, so its first sync costs
/// whatever the shared homeserver holds — which is everything every previous
/// run left there, measured at 1 395 rooms and 3 115 devices on one account
/// (#432). Four separate waits were found failing on it in one suite, and the
/// repository has 155 call sites: raising each as it is met is not a plan.
///
/// A longer deadline is close to free, and that is the argument for choosing
/// it over cleverness. A wait returns the moment its condition holds, so a
/// passing run costs nothing at all; only a genuinely failing test takes
/// longer to say so. Nothing here waits for a timeout in order to prove an
/// absence — checked, not assumed — so no test changes meaning.
///
/// It does not fix the accumulation. That is #432's own subject, and until it
/// is dealt with this is what keeps the suites readable.
pub const DEADLINE: Duration = Duration::from_secs(120);
const EVERY: Duration = Duration::from_millis(500);

/// Polls `attempt` every 500 ms until it yields `Some`, or gives up after
/// [`DEADLINE`] — naming the deadline, so a reader asks whether it was ever
/// enough rather than suspecting the component under test.
pub async fn poll_until<T, Fut>(mut attempt: impl FnMut() -> Fut, description: &str) -> Result<T>
where
    Fut: std::future::Future<Output = Option<T>>,
{
    let started = std::time::Instant::now();
    while started.elapsed() < DEADLINE {
        if let Some(value) = attempt().await {
            return Ok(value);
        }
        sleep(EVERY).await;
    }
    bail!(
        "timed out after {:.0}s {description}",
        DEADLINE.as_secs_f64()
    )
}

#[cfg(test)]
mod tests {
    use super::poll_until;

    #[tokio::test]
    async fn returns_the_first_some_and_gives_up_on_a_never() {
        let mut attempts = 0;
        let value = poll_until(
            || {
                attempts += 1;
                async move { (attempts > 1).then_some(attempts) }
            },
            "a value on the second attempt",
        )
        .await
        .expect("the second attempt yields a value");
        assert_eq!(value, 2);

        // A predicate that never matches must fail rather than hang; the
        // deadline is ~20 s, so this case is checked with a tiny timeout.
        let timed_out = tokio::time::timeout(
            std::time::Duration::from_millis(1200),
            poll_until(|| async { None::<()> }, "something that never happens"),
        )
        .await;
        assert!(
            timed_out.is_err(),
            "poll_until must keep polling until its own deadline"
        );
    }
}
