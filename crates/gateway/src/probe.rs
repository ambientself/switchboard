//! `switchboard probe --config=FILE --server=NAME`: the registration probe (decision 0013,
//! section 9).
//!
//! In milestone 3 registration is the approval pull request, and each proxied entry records
//! `probe = { result = "refused", date = ... }`. This command makes that record. It reads the
//! deployment file and that one server's entry in the registry file it names
//! ([`Registry::server_entry`]), and nothing else: it does not apply the loader's probe rule,
//! so an entry can be probed before it has a record, and it needs no database, issuer or
//! credential of the gateway's own. It sends decision 0010's three calls to the entry's
//! address ([`connector_proxy::probe()`]), with the bounds `[servers.<name>]` sets for its calls
//! and, on the third, the probe credential `[drift.probe_credentials]` names for it.
//!
//! It prints each call's verdict, the result and the record line, such as
//! `probe = { result = "refused", date = 2026-10-12 }`, dated today in UTC. A probe that could
//! not connect, or showed no refusal for another reason, is `not_shown`, never `refused`, and
//! the loader refuses any result but `refused`.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use connector_proxy::{CredentialFileError, ProbeCredential, ProbeError, ProbeReport, probe};
use gateway_core::ConnectorName;
use gateway_registry::{Registry, RegistryError};
use thiserror::Error;

use crate::deployment::{DeploymentError, DeploymentFile};

/// Why a probe could not be made. A probe that was made reports its result instead, whatever
/// it is.
#[derive(Debug, Error)]
pub enum ProbeCommandError {
    /// A file could not be read.
    #[error("cannot read `{path}`: {source}")]
    Read {
        /// The file.
        path: PathBuf,
        /// What the operating system said.
        source: std::io::Error,
    },
    /// The deployment file is not valid TOML of the right shape.
    #[error("`{path}` is not a valid deployment file: {message}")]
    Deployment {
        /// The file.
        path: PathBuf,
        /// What the parser said.
        message: String,
    },
    /// The server's bounds are out of range.
    #[error(transparent)]
    Bounds(#[from] DeploymentError),
    /// The server's entry could not be read from the registry file.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// The deployment file names no probe credential for the server.
    #[error(
        "the deployment file gives no probe credential for server `{0}`; name its file under \
         `[drift.probe_credentials]`"
    )]
    NoProbeCredential(ConnectorName),
    /// The probe credential file could not be read, or does not hold one token.
    #[error("the probe credential: {0}")]
    ProbeCredential(#[from] CredentialFileError),
    /// The probe could not begin, such as for an address it cannot reach over plain `http`.
    #[error(transparent)]
    Probe(#[from] ProbeError),
}

/// A probe that was made: the server, where it was reached, and what each call came to.
#[derive(Clone, Debug)]
pub struct Probed {
    /// The server.
    pub server: ConnectorName,
    /// Its address in the registry.
    pub address: String,
    /// The three calls' verdicts.
    pub report: ProbeReport,
    /// The date it was made, `YYYY-MM-DD`, in UTC.
    pub date: String,
}

impl Probed {
    /// The probe record for the registry entry: what was found, and when.
    pub fn record(&self) -> String {
        format!(
            "probe = {{ result = \"{}\", date = {} }}",
            self.report.finding(),
            self.date
        )
    }
}

/// Probes `server`, as the deployment file at `config` and the registry file it names describe
/// it. See the [module documentation](self).
pub async fn run(config: &Path, server: &ConnectorName) -> Result<Probed, ProbeCommandError> {
    let read = |path: &Path| {
        std::fs::read_to_string(path).map_err(|source| ProbeCommandError::Read {
            path: path.to_owned(),
            source,
        })
    };
    let file: DeploymentFile =
        toml::from_str(&read(config)?).map_err(|error| ProbeCommandError::Deployment {
            path: config.to_owned(),
            message: error.to_string(),
        })?;
    let base = config.parent().unwrap_or(Path::new("."));
    let entry = Registry::server_entry(&read(&base.join(&file.registry.file))?, server)?;
    let limits = file.server_bounds(server)?;
    let credential_file = file
        .probe_credential(server)
        .ok_or_else(|| ProbeCommandError::NoProbeCredential(server.clone()))?;
    let credential = ProbeCredential::load(server.clone(), base.join(credential_file))?;
    let bounds = connector_proxy::ProbeBounds {
        deadline: limits.deadline,
        max_response_bytes: limits.max_result_bytes,
    };
    let report = probe(&entry.address, bounds, &credential).await?;
    Ok(Probed {
        server: server.clone(),
        address: entry.address,
        report,
        date: utc_date(SystemTime::now()),
    })
}

/// `at` as a date, `YYYY-MM-DD`, in UTC.
fn utc_date(at: SystemTime) -> String {
    let seconds = at
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    // Days since 1970-01-01 to a civil date, in the proleptic Gregorian calendar (Howard
    // Hinnant's `civil_from_days`).
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_time_is_dated_in_utc() {
        let at = |seconds: u64| utc_date(UNIX_EPOCH + Duration::from_secs(seconds));
        assert_eq!(at(0), "1970-01-01");
        assert_eq!(at(951_782_400), "2000-02-29");
        assert_eq!(at(951_868_799), "2000-02-29");
        assert_eq!(at(951_868_800), "2000-03-01");
        assert_eq!(at(1_791_763_199), "2026-10-11");
        assert_eq!(at(1_791_763_200), "2026-10-12");
        assert_eq!(at(1_798_761_599), "2026-12-31");
        assert_eq!(at(1_798_761_600), "2027-01-01");
    }
}
