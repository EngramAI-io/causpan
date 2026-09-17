//! Causpan evaluator library — attribution strategy evaluation.

pub mod metrics;
pub mod strategies;

pub use metrics::{EvaluationResults, EventMatcher, MatchedPair, StrategyResults};
pub use strategies::AttributionStrategy;
