mod cli;
mod core;
mod detectors;
mod pipeline;
mod sources;
mod ui;

use anyhow::Result;
use clap::Parser;
use cli::commands::run;
use cli::flags::Cli;

fn main() -> Result<()> {
    let cli = Cli::parse();
    run(cli)
}
