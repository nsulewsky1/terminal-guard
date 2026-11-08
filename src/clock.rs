//! Injectable time source. Contact age uses a monotonic clock so wall-clock
//! changes cannot make the engine look "more connected". Wall-clock time is
//! used only to bound the freshness of signed contact messages and as an
//! informational timestamp in the audit log.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub trait Clock {
    /// Monotonic time since an arbitrary fixed origin.
    fn monotonic(&self) -> Duration;
    /// Wall-clock milliseconds since the Unix epoch, or `None` if unavailable.
    fn unix_ms(&self) -> Option<u64>;
}

/// Real clock: `Instant` for elapsed time, `SystemTime` for wall time.
#[derive(Debug, Clone)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        SystemClock {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn monotonic(&self) -> Duration {
        self.origin.elapsed()
    }
    fn unix_ms(&self) -> Option<u64> {
        let d = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        u64::try_from(d.as_millis()).ok()
    }
}

/// Deterministic clock for tests and the demo. Clones share the same time.
#[derive(Debug, Clone)]
pub struct MockClock {
    inner: Arc<Mutex<(Duration, Option<u64>)>>,
}

impl MockClock {
    pub fn new(start_unix_ms: u64) -> Self {
        MockClock {
            inner: Arc::new(Mutex::new((Duration::ZERO, Some(start_unix_ms)))),
        }
    }
    /// Advance both monotonic and wall time.
    pub fn advance(&self, d: Duration) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.0 = g.0.saturating_add(d);
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        g.1 = g.1.map(|w| w.saturating_add(ms));
    }
    /// Set the monotonic time directly (tests use this to simulate a clock
    /// that goes backwards, which must never restore permissions).
    pub fn set_monotonic(&self, d: Duration) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).0 = d;
    }
    /// Set wall time (or make it unavailable with `None`).
    pub fn set_unix_ms(&self, ms: Option<u64>) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).1 = ms;
    }
}

impl Clock for MockClock {
    fn monotonic(&self) -> Duration {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).0
    }
    fn unix_ms(&self) -> Option<u64> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).1
    }
}
