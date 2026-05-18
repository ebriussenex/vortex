use std::time::Duration;

pub async fn retry_with_backoff<T, E, F, Fut>(
    max_attempts: u32,
    delay: Duration,
    mut f: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut delay = delay;
    for attempt in 1..=max_attempts {
        match f().await {
            Ok(val) => return Ok(val),
            Err(e) if attempt == max_attempts => {
                eprintln!("failed after {max_attempts} attempts: {e}");
                return Err(e);
            }
            Err(e) => {
                eprintln!("attempt {attempt} failed: {e}, retrying in {delay:?}");
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
        }
    }
    unreachable!()
}
