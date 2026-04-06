use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

pub struct RateLimiter {
    cells: Arc<Mutex<HashMap<IpAddr, RateLimitState>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            cells: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn check(&mut self, cell: IpAddr, rate: Duration) -> bool {
        let result = {
            let mut cells = self.cells.lock().await;
            let cell: &mut RateLimitState = cells.entry(cell).or_insert(RateLimitState::new());
            cell.check(rate)
        };
        self.collect_garbage(rate).await;
        result
    }

    async fn collect_garbage(&mut self, age: Duration) {
        let mut cells = self.cells.lock().await;
        let deadline = Instant::now() - age;
        cells.retain(|&_ip, state| state.valid_at() > deadline);
    }
}

struct RateLimitState {
    tat: Instant,
}

impl RateLimitState {
    fn new() -> Self {
        Self {
            tat: Instant::now(),
        }
    }

    fn check(&mut self, rate: Duration) -> bool {
        let now = Instant::now();
        if now > self.tat {
            self.tat = now + rate;
            true
        } else {
            false
        }
    }

    fn valid_at(&self) -> Instant {
        self.tat
    }
}
