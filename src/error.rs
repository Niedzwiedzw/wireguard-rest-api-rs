use thiserror::Error;

use crate::wireguard_conf::WireguardEntry;

#[derive(Error, Debug)]
pub enum WireguardRestApiError {
    #[error("not found")]
    NotFound,
    #[error(transparent)]
    FileReadError(#[from] std::io::Error),
    #[error("failed to parse config file, context: {0}")]
    ConfigParseError(String),
    #[error("entry you're attempting to add ({0}) collides with entry ({1}) (ID: {0})")]
    NonUniquePublicKey(usize, WireguardEntry, WireguardEntry),
    #[error("command returned wrong status: {code:?}. Reason: {message}")]
    CommandError { code: Option<i32>, message: String },
}

pub type WireguardRestApiResult<T> = Result<T, WireguardRestApiError>;
