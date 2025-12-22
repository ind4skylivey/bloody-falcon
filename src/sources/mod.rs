#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceKind {
    Offline,
    #[allow(dead_code)]
    Github,
    #[allow(dead_code)]
    Paste,
    #[allow(dead_code)]
    Ct,
    #[allow(dead_code)]
    Social,
    #[allow(dead_code)]
    Feeds,
}

pub mod cache;
pub mod rate_limiter;
