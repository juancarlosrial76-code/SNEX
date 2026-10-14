use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

pub const EPOCH_DURATION_SECONDS: i64 = 180 * 24 * 3600;
pub const CREDENTIAL_LIFETIME_EPOCHS: u64 = 3;
pub const ADVANCE_ISSUANCE_EPOCHS: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Epoch(pub u64);

impl Epoch {
    pub fn current() -> Self {
        let now = Utc::now().timestamp() as u64;
        Self(now / EPOCH_DURATION_SECONDS as u64)
    }

    pub fn from_timestamp(timestamp: u64) -> Self {
        Self(timestamp / EPOCH_DURATION_SECONDS as u64)
    }

    pub fn start_timestamp(&self) -> u64 {
        self.0 * EPOCH_DURATION_SECONDS as u64
    }

    pub fn end_timestamp(&self) -> u64 {
        (self.0 + 1) * EPOCH_DURATION_SECONDS as u64
    }

    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }

    pub fn previous(&self) -> Option<Self> {
        if self.0 == 0 {
            None
        } else {
            Some(Self(self.0 - 1))
        }
    }

    pub fn is_valid_for(&self, credential_epoch: u64) -> bool {
        credential_epoch == self.0 || credential_epoch == self.0 + 1
    }

    pub fn is_governing_for_report(&self, report_window: u64) -> bool {
        let window_epoch = Epoch::from_timestamp(report_window);
        window_epoch == *self
    }

    pub fn is_governing_for_ballot(&self, ballot_opening: u64) -> bool {
        let ballot_epoch = Epoch::from_timestamp(ballot_opening);
        ballot_epoch == *self
    }
}

impl std::fmt::Display for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for Epoch {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Epoch> for u64 {
    fn from(epoch: Epoch) -> Self {
        epoch.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochSchedule {
    pub current_epoch: Epoch,
    pub next_epoch_start: DateTime<Utc>,
    pub advance_issuance_start: DateTime<Utc>,
    pub grace_period_end: Option<DateTime<Utc>>,
}

impl EpochSchedule {
    pub fn new() -> Self {
        let current = Epoch::current();
        let next_start = Utc::now() + Duration::seconds(EPOCH_DURATION_SECONDS - (Utc::now().timestamp() % EPOCH_DURATION_SECONDS));
        let advance_start = Utc::now();
        Self {
            current_epoch: current,
            next_epoch_start: next_start,
            advance_issuance_start: advance_start,
            grace_period_end: None,
        }
    }

    pub fn advance_issuance_active(&self) -> bool {
        Utc::now() >= self.advance_issuance_start && Utc::now() < self.next_epoch_start
    }

    pub fn time_until_next_epoch(&self) -> Duration {
        self.next_epoch_start - Utc::now()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochState {
    pub epoch: Epoch,
    pub issuance_cohort_open: bool,
    pub issuance_cohort_size: u32,
    pub minimum_cohort_size: u32,
    pub cohort_close_deadline: Option<DateTime<Utc>>,
    pub advance_credentials_issued: u32,
    pub grace_active: bool,
    pub grace_deadline: Option<DateTime<Utc>>,
}

impl EpochState {
    pub fn new(epoch: Epoch, minimum_cohort_size: u32) -> Self {
        Self {
            epoch,
            issuance_cohort_open: true,
            issuance_cohort_size: 0,
            minimum_cohort_size,
            cohort_close_deadline: None,
            advance_credentials_issued: 0,
            grace_active: false,
            grace_deadline: None,
        }
    }

    pub fn close_cohort(&mut self) {
        self.issuance_cohort_open = false;
        self.cohort_close_deadline = Some(Utc::now());
    }

    pub fn activate_grace(&mut self, grace_days: u32) {
        self.grace_active = true;
        self.grace_deadline = Some(Utc::now() + Duration::days(grace_days as i64));
    }

    pub fn deactivate_grace(&mut self) {
        self.grace_active = false;
        self.grace_deadline = None;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialLifetime {
    pub issued_epoch: Epoch,
    pub valid_for_epochs: u64,
    pub advance_issued: bool,
}

impl CredentialLifetime {
    pub fn new(issued_epoch: Epoch, advance_issued: bool) -> Self {
        Self {
            issued_epoch,
            valid_for_epochs: CREDENTIAL_LIFETIME_EPOCHS,
            advance_issued,
        }
    }

    pub fn is_valid_in_epoch(&self, epoch: Epoch) -> bool {
        let max_epoch = self.issued_epoch.0 + self.valid_for_epochs;
        epoch.0 <= max_epoch
    }

    pub fn is_governing_for(&self, epoch: Epoch, is_advance: bool) -> bool {
        if is_advance {
            epoch.0 == self.issued_epoch.0 + 1
        } else {
            epoch.0 == self.issued_epoch.0
        }
    }

    pub fn expires_at(&self) -> Epoch {
        Epoch(self.issued_epoch.0 + self.valid_for_epochs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_calculations() {
        let epoch = Epoch::current();
        assert_eq!(epoch.start_timestamp() + EPOCH_DURATION_SECONDS as u64, epoch.end_timestamp());
        assert_eq!(epoch.next().0, epoch.0 + 1);
    }

    #[test]
    fn test_credential_lifetime() {
        let epoch = Epoch::current();
        let lifetime = CredentialLifetime::new(epoch, false);
        assert!(lifetime.is_valid_in_epoch(epoch));
        assert!(lifetime.is_valid_in_epoch(epoch.next()));
        assert!(lifetime.is_valid_in_epoch(epoch.next().next()));
        assert!(!lifetime.is_valid_in_epoch(epoch.next().next().next()));
    }

    #[test]
    fn test_advance_issuance() {
        let epoch = Epoch::current();
        let lifetime = CredentialLifetime::new(epoch, true);
        assert!(lifetime.is_governing_for(epoch.next(), true));
        assert!(!lifetime.is_governing_for(epoch, true));
    }
}