#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceKind {
    Offline,
    Github,
    Paste,
    Ct,
    Social,
    Feeds,
}

pub mod cache;
pub mod rate_limiter;
