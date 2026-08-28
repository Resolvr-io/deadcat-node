//! Wall-clock time for the RFQ runtime.

use core::fmt;
use std::error::Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use deadcat_rfq_provider::{Clock, UnixMillis};

/// Production wall clock used by durable RFQ state transitions.
///
/// The provider [`Clock`] boundary is intentionally infallible, so an invalid
/// host clock cannot be reported as an ordinary provider error. This
/// implementation fails closed by panicking before returning a fabricated or
/// saturated timestamp. Runtime code must execute synchronous provider work in
/// its blocking-task boundary so such a host failure cannot yield a successful
/// quote or signing response.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl SystemClock {
    /// Read and validate the host wall clock without invoking the infallible
    /// [`Clock`] adapter.
    pub fn try_now(self) -> Result<UnixMillis, SystemClockError> {
        unix_millis(SystemTime::now())
    }
}

impl Clock for SystemClock {
    fn now(&self) -> UnixMillis {
        require_valid_time(self.try_now())
    }
}

/// Host-clock failures that cannot be represented at the provider boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemClockError {
    /// The host reports a time before the Unix epoch.
    BeforeUnixEpoch,
    /// Milliseconds since the Unix epoch do not fit the provider's `u64` time.
    MillisecondsOverflow,
}

impl fmt::Display for SystemClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforeUnixEpoch => formatter.write_str("host time is before the Unix epoch"),
            Self::MillisecondsOverflow => {
                formatter.write_str("host time exceeds the RFQ Unix-millisecond range")
            }
        }
    }
}

impl Error for SystemClockError {}

fn unix_millis(time: SystemTime) -> Result<UnixMillis, SystemClockError> {
    let elapsed = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SystemClockError::BeforeUnixEpoch)?;
    unix_millis_from_elapsed(elapsed)
}

fn unix_millis_from_elapsed(elapsed: Duration) -> Result<UnixMillis, SystemClockError> {
    let millis =
        u64::try_from(elapsed.as_millis()).map_err(|_| SystemClockError::MillisecondsOverflow)?;
    Ok(UnixMillis::new(millis))
}

fn require_valid_time(result: Result<UnixMillis, SystemClockError>) -> UnixMillis {
    result.unwrap_or_else(|error| panic!("RFQ system clock is unusable: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_epoch_time_to_checked_milliseconds() {
        assert_eq!(unix_millis(UNIX_EPOCH).expect("epoch").value(), 0);
        let time = UNIX_EPOCH + Duration::new(42, 999_999_999);
        assert_eq!(
            unix_millis(time).expect("representable time").value(),
            42_999
        );
    }

    #[test]
    fn rejects_pre_epoch_and_overflowing_host_times() {
        let before_epoch = UNIX_EPOCH
            .checked_sub(Duration::from_millis(1))
            .expect("platform represents a pre-epoch instant");
        assert_eq!(
            unix_millis(before_epoch),
            Err(SystemClockError::BeforeUnixEpoch)
        );
        assert_eq!(
            unix_millis_from_elapsed(Duration::from_secs(u64::MAX)),
            Err(SystemClockError::MillisecondsOverflow)
        );
    }

    #[test]
    #[should_panic(expected = "RFQ system clock is unusable")]
    fn infallible_provider_adapter_fails_closed() {
        require_valid_time(Err(SystemClockError::BeforeUnixEpoch));
    }

    #[test]
    fn live_read_lies_between_checked_bracketing_reads() {
        let before = unix_millis(SystemTime::now()).expect("valid host clock");
        let observed = Clock::now(&SystemClock);
        let after = unix_millis(SystemTime::now()).expect("valid host clock");

        assert!(before <= observed);
        assert!(observed <= after);
    }
}
