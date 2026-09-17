//! Causpan experiment runner — reads a TOML experiment config, drives the
//! full pipeline (workload → strace → collector → evaluator) for each
//! configuration, and produces aggregated results.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --release --bin experiment-runner -- \
//!   --config experiments/configs/exp-001-concurrency.toml
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

// External deps used in main().
use tracing::info;
use clap::Parser;
use tracing_subscriber::EnvFilter;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("command '{0}' failed: {1}")]
    CommandFailed(String, String),

    #[error("missing field '{0}' in config section [{1}]")]
    MissingField(&'static str, &'static str),
}

pub type Result<T> = std::result::Result<T, RunnerError>;

// ---------------------------------------------------------------------------
// Config types (mirrors TOML structure)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ExperimentConfig {
    pub experiment: ExperimentMeta,
    pub workload: WorkloadConfig,
    pub evaluator: EvaluatorConfig,
    #[serde(default)]
    pub strace: StraceConfig,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ExperimentMeta {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,

    #[serde(default = "default_runs")]
    pub runs_per_config: usize,

    #[serde(default = "default_output_dir")]
    pub output_dir: String,
}

fn default_runs() -> usize {
    5
}

fn default_output_dir() -> String {
    "results/default".to_string()
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct WorkloadConfig {
    /// Concurrency levels to test.
    pub concurrency: Vec<usize>,

    /// Number of operations per RPC.
    #[serde(default = "default_ops_per_rpc")]
    pub operations_per_rpc: usize,

    /// Workload scenario.
    #[serde(default = "default_scenario")]
    pub scenario: String,

    /// Random seed for reproducibility.
    #[serde(default = "default_seed")]
    pub seed: u64,

    /// Base directory for file operations.
    #[serde(default = "default_data_dir")]
    pub data_dir: String,

    /// Network host for connect operations.
    #[serde(default = "default_net_host")]
    pub net_host: String,

    /// Network port for connect operations.
    #[serde(default = "default_net_port")]
    pub net_port: u16,

    /// Tokio worker threads.
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,
}

fn default_ops_per_rpc() -> usize { 4 }
fn default_scenario() -> String { "mixed".to_string() }
fn default_seed() -> u64 { 42 }
fn default_data_dir() -> String { "/tmp/causpan".to_string() }
fn default_net_host() -> String { "127.0.0.1".to_string() }
fn default_net_port() -> u16 { 9999 }
fn default_worker_threads() -> usize { 2 }

#[derive(Debug, Clone, serde::Deserialize)]
pub struct EvaluatorConfig {
    /// Time windows (ms) to evaluate.
    #[serde(default = "default_time_windows")]
    pub time_windows_ms: Vec<u64>,
}

fn default_time_windows() -> Vec<u64> {
    vec![1, 5, 10, 50, 100, 500, 1000]
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
pub struct StraceConfig {
    /// Syscall classes to trace.
    #[serde(default = "default_strace_syscalls")]
    pub syscalls: String,

    /// Output file pattern. {tag} is replaced with a unique identifier.
    #[serde(default = "default_strace_output")]
    pub output_pattern: String,
}

fn default_strace_syscalls() -> String {
    "openat,read,write,socket,connect,clone,fork,execve".to_string()
}

fn default_strace_output() -> String {
    "strace.{tag}".to_string()
}

// ---------------------------------------------------------------------------
// Per-run result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RunResult {
    pub concurrency: usize,
    pub run: usize,
    pub tag: String,
    pub strategy: String,
    pub correct: usize,
    pub wrong_rpc: usize,
    pub unattributed: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub wrong_rate: f64,
    pub unattributed_rate: f64,
}

// ---------------------------------------------------------------------------
// Aggregated result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize)]
pub struct AggregatedResult {
    pub concurrency: usize,
    pub strategy: String,
    pub runs: usize,
    pub precision_mean: f64,
    pub precision_std: f64,
    pub recall_mean: f64,
    pub recall_std: f64,
    pub f1_mean: f64,
    pub f1_std: f64,
    pub wrong_rate_mean: f64,
    pub wrong_rate_std: f64,
}

// ---------------------------------------------------------------------------
// Pipeline runner
// ---------------------------------------------------------------------------

pub struct ExperimentRunner {
    config: ExperimentConfig,
    output_dir: PathBuf,
    strace_available: bool,
}

impl ExperimentRunner {
    pub fn new(config: ExperimentConfig) -> Result<Self> {
        let output_dir = PathBuf::from(&config.experiment.output_dir);
        fs::create_dir_all(&output_dir)?;
        fs::create_dir_all(output_dir.join("ground-truth"))?;
        fs::create_dir_all(output_dir.join("kernel-events"))?;

        // Check if strace is available.
        let strace_available = Command::new("strace")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !strace_available {
            eprintln!("WARNING: strace not found. Kernel events will not be collected.");
            eprintln!("Install strace to run the full pipeline.");
        }

        Ok(Self {
            config,
            output_dir,
            strace_available,
        })
    }

    /// Run the full experiment matrix.
    pub fn run(&self) -> Result<Vec<RunResult>> {
        let mut all_results = Vec::new();
        let total = self.config.workload.concurrency.len() * self.config.experiment.runs_per_config;
        let mut current = 0;

        for &concurrency in &self.config.workload.concurrency {
            for run in 1..=self.config.experiment.runs_per_config {
                current += 1;
                let tag = format!(
                    "c{:03}-r{:03}",
                    concurrency, run
                );
                eprintln!(
                    "[{}/{}] concurrency={} run={}",
                    current, total, concurrency, run
                );

                let results = self.run_single(concurrency, run, &tag)?;
                all_results.extend(results);
            }
        }

        // Write raw results.
        let raw_csv = self.output_dir.join("raw-results.csv");
        Self::write_results_csv(&all_results, &raw_csv)?;
        eprintln!("Raw results: {}", raw_csv.display());

        // Aggregate and write summary.
        let aggregated = Self::aggregate(&all_results);
        let agg_csv = self.output_dir.join("aggregated-results.csv");
        Self::write_aggregated_csv(&aggregated, &agg_csv)?;
        eprintln!("Aggregated results: {}", agg_csv.display());

        Ok(all_results)
    }

    /// Run a single configuration: strace captures both kernel events AND
    /// ground truth in one execution (same PIDs/TIDs).
    fn run_single(&self, concurrency: usize, run: usize, tag: &str) -> Result<Vec<RunResult>> {
        let cfg = &self.config.workload;
        let gt_dir = self.output_dir.join("ground-truth");
        let ke_dir = self.output_dir.join("kernel-events");

        // Per-run subdirectories to isolate strace files.
        let strace_subdir = ke_dir.join(format!("{}-strace", tag));
        fs::create_dir_all(&strace_subdir)?;

        let gt_file = gt_dir.join(format!("{}.jsonl", tag));
        let strace_base = strace_subdir.join("trace");
        let ke_file = ke_dir.join(format!("{}.jsonl", tag));

        // Step 1: Run workload under strace (single execution — ground truth
        // and kernel events share the same PIDs/TIDs).
        if self.strace_available {
            self.run_strace(concurrency, &strace_base, &gt_file)?;

            // Step 2: Collect kernel events from strace.
            self.run_collector(&strace_subdir, &ke_file, &self.config.workload.data_dir)?;
        } else {
            // Fallback: run workload without strace.
            self.run_workload(concurrency, &gt_file)?;
            fs::write(&ke_file, "")?;
        }

        // Step 3: Run evaluator.
        let eval_output = self.output_dir.join(format!("eval-{}.csv", tag));
        self.run_evaluator(&gt_file, &ke_file, &eval_output)?;

        // Step 4: Read per-run results.
        Self::read_results_csv(&eval_output, concurrency, run)
    }

    fn run_workload(&self, concurrency: usize, output: &Path) -> Result<()> {
        let cfg = &self.config.workload;
        let scenario = match cfg.scenario.as_str() {
            "file_only" => "file_only",
            "network_only" => "network_only",
            "mixed" => "mixed",
            "with_process_spawn" => "with_process_spawn",
            other => other,
        };

        let status = Command::new(Self::binary_path("workload"))
            .arg("--concurrency")
            .arg(concurrency.to_string())
            .arg("--operations-per-rpc")
            .arg(cfg.operations_per_rpc.to_string())
            .arg("--seed")
            .arg(cfg.seed.to_string())
            .arg("--output")
            .arg(output)
            .arg("--data-dir")
            .arg(&cfg.data_dir)
            .arg("--net-host")
            .arg(&cfg.net_host)
            .arg("--net-port")
            .arg(cfg.net_port.to_string())
            .arg("--scenario")
            .arg(scenario)
            .arg("--worker-threads")
            .arg(cfg.worker_threads.to_string())
            .status()
            .map_err(|e| RunnerError::CommandFailed("workload".into(), e.to_string()))?;

        if !status.success() {
            return Err(RunnerError::CommandFailed(
                "workload".into(),
                format!("exit code: {:?}", status.code()),
            ));
        }

        // Verify the output file exists and is non-empty.
        if !output.exists() || fs::metadata(output).map(|m| m.len()).unwrap_or(0) == 0 {
            return Err(RunnerError::CommandFailed(
                "workload".into(),
                "produced empty output file".into(),
            ));
        }

        Ok(())
    }

    fn run_strace(
        &self,
        concurrency: usize,
        output: &Path,
        gt_path: &Path,
    ) -> Result<()> {
        let cfg = &self.config.workload;
        let scenario = match cfg.scenario.as_str() {
            "file_only" => "file_only",
            "network_only" => "network_only",
            "mixed" => "mixed",
            "with_process_spawn" => "with_process_spawn",
            other => other,
        };

        let status = Command::new("strace")
            .arg("-f")           // prefix each line with PID
            .arg("-ff")          // one file per thread (TID from filename)
            .arg("-ttt")         // absolute timestamps (seconds.microseconds)
            .arg("-e")
            .arg(&self.config.strace.syscalls)
            .arg("-o")
            .arg(output)  // strace appends .<tid> for each thread
            .arg(Self::binary_path("workload"))
            .arg("--concurrency")
            .arg(concurrency.to_string())
            .arg("--operations-per-rpc")
            .arg(cfg.operations_per_rpc.to_string())
            .arg("--seed")
            .arg(cfg.seed.to_string())
            .arg("--output")
            .arg(gt_path)        // write ground truth during this execution
            .arg("--data-dir")
            .arg(&cfg.data_dir)
            .arg("--net-host")
            .arg(&cfg.net_host)
            .arg("--net-port")
            .arg(cfg.net_port.to_string())
            .arg("--scenario")
            .arg(scenario)
            .arg("--worker-threads")
            .arg(cfg.worker_threads.to_string())
            .status()
            .map_err(|e| RunnerError::CommandFailed("strace".into(), e.to_string()))?;

        if !status.success() {
            // strace often returns non-zero when tracing certain syscalls;
            // check that output files were produced before erroring.
            let has_output = fs::read_dir(output.parent().unwrap_or(Path::new(".")))
                .map(|entries| entries.filter(|e| e.is_ok()).count() > 0)
                .unwrap_or(false);
            if !has_output {
                return Err(RunnerError::CommandFailed(
                    "strace".into(),
                    format!("exit code: {:?}", status.code()),
                ));
            }
        }

        Ok(())
    }

    fn run_collector(&self, strace_dir: &Path, output: &Path, data_dir: &str) -> Result<()> {
        let status = Command::new(Self::binary_path("collector"))
            .arg("--format")
            .arg("straces")
            .arg("--data-dir")
            .arg(data_dir)
            .arg(strace_dir)
            .arg(output)
            .status()
            .map_err(|e| RunnerError::CommandFailed("collector".into(), e.to_string()))?;

        if !status.success() {
            return Err(RunnerError::CommandFailed(
                "collector".into(),
                format!("exit code: {:?}", status.code()),
            ));
        }

        Ok(())
    }

    fn run_evaluator(&self, gt: &Path, ke: &Path, output: &Path) -> Result<()> {
        let mut cmd = Command::new(Self::binary_path("evaluator"));
        cmd.arg("--ground-truth")
            .arg(gt)
            .arg("--kernel-events")
            .arg(ke)
            .arg("--output")
            .arg(output);

        // Add time windows.
        for &ms in &self.config.evaluator.time_windows_ms {
            cmd.arg("--time-windows-ms").arg(ms.to_string());
        }

        let status = cmd
            .status()
            .map_err(|e| RunnerError::CommandFailed("evaluator".into(), e.to_string()))?;

        if !status.success() {
            return Err(RunnerError::CommandFailed(
                "evaluator".into(),
                format!("exit code: {:?}", status.code()),
            ));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // CSV I/O
    // -----------------------------------------------------------------------

    fn write_results_csv(results: &[RunResult], path: &Path) -> Result<()> {
        let mut file = fs::File::create(path)?;
        use std::io::Write;
        writeln!(
            file,
            "concurrency,run,tag,strategy,correct,wrong_rpc,unattributed,precision,recall,f1,wrong_rate,unattributed_rate"
        )?;
        for r in results {
            writeln!(
                file,
                "{},{},{},{},{},{},{},{:.4},{:.4},{:.4},{:.4},{:.4}",
                r.concurrency,
                r.run,
                r.tag,
                r.strategy,
                r.correct,
                r.wrong_rpc,
                r.unattributed,
                r.precision,
                r.recall,
                r.f1,
                r.wrong_rate,
                r.unattributed_rate,
            )?;
        }
        Ok(())
    }

    fn read_results_csv(path: &Path, concurrency: usize, run: usize) -> Result<Vec<RunResult>> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(path)?;
        let mut results = Vec::new();

        for (i, line) in content.lines().enumerate() {
            if i == 0 {
                continue; // skip header
            }
            let parts: Vec<&str> = line.split(',').collect();
            // evaluator writes: strategy,correct,wrong_rpc,unattributed,
            //                    precision,recall,f1,wrong_rate,unattributed_rate
            if parts.len() < 9 {
                continue;
            }
            results.push(RunResult {
                concurrency,
                run,
                tag: format!("c{:03}-r{:03}", concurrency, run),
                strategy: parts[0].to_string(),
                correct: parts[1].parse().unwrap_or(0),
                wrong_rpc: parts[2].parse().unwrap_or(0),
                unattributed: parts[3].parse().unwrap_or(0),
                precision: parts[4].parse().unwrap_or(0.0),
                recall: parts[5].parse().unwrap_or(0.0),
                f1: parts[6].parse().unwrap_or(0.0),
                wrong_rate: parts[7].parse().unwrap_or(0.0),
                unattributed_rate: parts[8].parse().unwrap_or(0.0),
            });
        }

        Ok(results)
    }

    fn aggregate(results: &[RunResult]) -> Vec<AggregatedResult> {
        // Group by (concurrency, strategy).
        let mut groups: BTreeMap<(usize, String), Vec<&RunResult>> = BTreeMap::new();
        for r in results {
            groups
                .entry((r.concurrency, r.strategy.clone()))
                .or_default()
                .push(r);
        }

        groups
            .into_iter()
            .map(|((concurrency, strategy), runs)| {
                let n = runs.len() as f64;
                let mean_std = |values: &[f64]| {
                    let mean = values.iter().sum::<f64>() / n;
                    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
                    (mean, variance.sqrt())
                };

                let (p_mean, p_std) = mean_std(&runs.iter().map(|r| r.precision).collect::<Vec<_>>());
                let (r_mean, r_std) = mean_std(&runs.iter().map(|r| r.recall).collect::<Vec<_>>());
                let (f_mean, f_std) = mean_std(&runs.iter().map(|r| r.f1).collect::<Vec<_>>());
                let (w_mean, w_std) = mean_std(&runs.iter().map(|r| r.wrong_rate).collect::<Vec<_>>());

                AggregatedResult {
                    concurrency,
                    strategy,
                    runs: runs.len(),
                    precision_mean: p_mean,
                    precision_std: p_std,
                    recall_mean: r_mean,
                    recall_std: r_std,
                    f1_mean: f_mean,
                    f1_std: f_std,
                    wrong_rate_mean: w_mean,
                    wrong_rate_std: w_std,
                }
            })
            .collect()
    }

    fn write_aggregated_csv(results: &[AggregatedResult], path: &Path) -> Result<()> {
        let mut file = fs::File::create(path)?;
        use std::io::Write;
        writeln!(
            file,
            "concurrency,strategy,runs,precision_mean,precision_std,recall_mean,recall_std,f1_mean,f1_std,wrong_rate_mean,wrong_rate_std"
        )?;
        for r in results {
            writeln!(
                file,
                "{},{},{},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4}",
                r.concurrency,
                r.strategy,
                r.runs,
                r.precision_mean,
                r.precision_std,
                r.recall_mean,
                r.recall_std,
                r.f1_mean,
                r.f1_std,
                r.wrong_rate_mean,
                r.wrong_rate_std,
            )?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Find the compiled binary in target/release (or target/debug).
    fn binary_path(name: &str) -> PathBuf {
        // Try release first, then debug.
        let release = PathBuf::from(format!("target/release/{}", name));
        if release.exists() {
            return release;
        }
        PathBuf::from(format!("target/debug/{}", name))
    }
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

#[derive(Debug, clap::Parser)]
struct Cli {
    /// Path to the experiment TOML config.
    #[arg(long, default_value = "experiments/configs/exp-001-concurrency.toml")]
    config: PathBuf,
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("experiment-runner=info")),
        )
        .init();

    eprintln!("=== Causpan Experiment Runner ===");
    eprintln!("Config: {}", cli.config.display());
    eprintln!();

    let config_str = std::fs::read_to_string(&cli.config)?;
    let config: ExperimentConfig = toml::from_str(&config_str)?;

    eprintln!(
        "Experiment: {} — {}",
        config.experiment.name, config.experiment.description
    );
    eprintln!(
        "Concurrency levels: {:?} ({} runs each)",
        config.workload.concurrency, config.experiment.runs_per_config
    );
    eprintln!(
        "Time windows: {:?} ms",
        config.evaluator.time_windows_ms
    );
    eprintln!();

    let runner = ExperimentRunner::new(config)?;
    let results = runner.run()?;

    eprintln!("\n=== Experiment complete ===");
    eprintln!("Total runs: {}", results.len());
    Ok(())
}
