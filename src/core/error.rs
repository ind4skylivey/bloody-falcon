use std::io;

#[derive(thiserror::Error, Debug)]
pub enum FalconError {
    #[error("network error: {0}")]
    Network(String),
    #[error("timeout")]
    Timeout,
    #[error("http error: {0}")]
    Http(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("db error: {0}")]
    Db(String),
    #[error("provider error: {0}")]
    Provider(String),
    #[error("unknown error")]
    Unknown,
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl From<reqwest::Error> for FalconError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            FalconError::Timeout
        } else if err.is_connect() {
            FalconError::Network(err.to_string())
        } else if err.is_status() {
            FalconError::Http(err.to_string())
        } else {
            FalconError::Unknown
        }
    }
}

impl From<rusqlite::Error> for FalconError {
    fn from(err: rusqlite::Error) -> Self {
        FalconError::Db(err.to_string())
    }
}
