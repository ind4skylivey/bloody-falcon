use std::time::{Duration, Instant};

#[derive(Default)]
pub struct RateLimiter {
    last: Option<Instant>,
    min_interval: Duration,
}

impl RateLimiter {
    #[allow(dead_code)]
    pub fn new(min_interval: Duration) -> Self {
        Self {
            last: None,
            min_interval,
        }
    }

    #[allow(dead_code)]
    pub fn allow(&mut self) -> bool {
        let now = Instant::now();
        if let Some(last) = self.last {
            if now.duration_since(last) < self.min_interval {
                return false;
            }
        }
        self.last = Some(now);
        true
    }
}
