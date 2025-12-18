use anyhow::Result;

use crate::core::scope::Scope;
use crate::core::types::Signal;
use crate::pipeline::collector::RunCtx;
use crate::sources::SourceKind;

pub mod typosquat;

pub trait Detector {
    fn name(&self) -> &'static str;
    fn sources(&self) -> Vec<SourceKind>;
    fn run(&self, scope: &Scope, ctx: &RunCtx) -> Result<Vec<Signal>>;
}
