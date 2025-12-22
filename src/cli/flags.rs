use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::core::types::OutputFormat;

#[derive(Parser, Debug)]
#[command(
    name = "bloodyfalcon",
    version,
    about = "BloodyFalcon v2 defensive OSINT radar"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Scope file path (required unless --demo-safe)
    #[arg(long)]
    pub scope: Option<PathBuf>,

    /// Client name mapped to clients/<name>.toml
    #[arg(long)]
    pub client: Option<String>,

    /// Allow running without scope in safe mode
    #[arg(long)]
    pub demo_safe: bool,

    /// Disable network access
    #[arg(long)]
    pub no_network: bool,

    /// Output format
    #[arg(long, value_enum)]
    pub format: Option<OutputFormatArg>,

    /// Output path (file or directory)
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Manifest output path
    #[arg(long)]
    pub manifest: Option<PathBuf>,

    /// Alert transport (webhook)
    #[arg(long)]
    pub alerts: Option<String>,

    /// Webhook URL for alerts
    #[arg(long)]
    pub webhook_url: Option<String>,

    /// Override policy file path
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Restrict detectors
    #[arg(long, value_delimiter = ',')]
    pub detectors: Option<Vec<String>>,

    /// Restrict sources
    #[arg(long, value_delimiter = ',')]
    pub sources: Option<Vec<String>>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run a scan using detectors
    Scan,
    /// Replay a fixture
    Replay {
        #[arg(long)]
        fixture: PathBuf,
        /// Scope file path (required unless --demo-safe)
        #[arg(long)]
        scope: Option<PathBuf>,
        /// Client name mapped to clients/<name>.toml
        #[arg(long)]
        client: Option<String>,
        /// Allow running without scope in safe mode
        #[arg(long)]
        demo_safe: bool,
        /// Disable network access
        #[arg(long)]
        no_network: bool,
        /// Output format
        #[arg(long, value_enum)]
        format: Option<OutputFormatArg>,
        /// Output path (file or directory)
        #[arg(long)]
        output: Option<PathBuf>,
        /// Manifest output path
        #[arg(long)]
        manifest: Option<PathBuf>,
    },
    /// Generate a report from latest stored run
    Report {
        /// Scope file path (required unless --demo-safe)
        #[arg(long)]
        scope: Option<PathBuf>,
        /// Client name mapped to clients/<name>.toml
        #[arg(long)]
        client: Option<String>,
        /// Allow running without scope in safe mode
        #[arg(long)]
        demo_safe: bool,
        /// Disable network access
        #[arg(long)]
        no_network: bool,
        /// Output format
        #[arg(long, value_enum)]
        format: Option<OutputFormatArg>,
        /// Output path (file or directory)
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Show trend intelligence from stored runs
    Trend {
        /// Window size (7d|30d|90d)
        #[arg(long)]
        window: String,
        /// Scope file path (required unless --demo-safe)
        #[arg(long)]
        scope: Option<PathBuf>,
        /// Client name mapped to clients/<name>.toml
        #[arg(long)]
        client: Option<String>,
        /// Allow running without scope in safe mode
        #[arg(long)]
        demo_safe: bool,
        /// Disable network access
        #[arg(long)]
        no_network: bool,
        /// Output format
        #[arg(long, value_enum)]
        format: Option<OutputFormatArg>,
        /// Output path (file or directory)
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Read-only TUI to browse latest stored signals/findings
    Tui {
        /// Scope file path (required unless --demo-safe)
        #[arg(long)]
        scope: Option<PathBuf>,
        /// Client name mapped to clients/<name>.toml
        #[arg(long)]
        client: Option<String>,
        /// Allow running without scope in safe mode
        #[arg(long)]
        demo_safe: bool,
        /// Disable network access (unused for TUI; parity with other cmds)
        #[arg(long)]
        no_network: bool,
    },
}

#[derive(ValueEnum, Clone, Debug)]
pub enum OutputFormatArg {
    Json,
    Jsonl,
    Markdown,
    Sarif,
    Csv,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(value: OutputFormatArg) -> Self {
        match value {
            OutputFormatArg::Json => OutputFormat::Json,
            OutputFormatArg::Jsonl => OutputFormat::Jsonl,
            OutputFormatArg::Markdown => OutputFormat::Markdown,
            OutputFormatArg::Sarif => OutputFormat::Sarif,
            OutputFormatArg::Csv => OutputFormat::Csv,
        }
    }
}
