//! A module for anything related to logging
use std::env;

use color_eyre::eyre::Result;
use eyre::WrapErr;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_log::LogTracer;
use tracing_subscriber::filter::{Directive, EnvFilter};
use tracing_subscriber::fmt::Subscriber;

pub const ENV_KEY: &str = "NAMADA_LOG";

// Env var to enable/disable color log
const COLOR_ENV_KEY: &str = "NAMADA_LOG_COLOR";
// Env var to log formatting (one of "full" (default), "json", "pretty")
const FMT_ENV_KEY: &str = "NAMADA_LOG_FMT";
// Env var to append logs to file(s) in the given dir
const DIR_ENV_KEY: &str = "NAMADA_LOG_DIR";
// Env var to set rolling log frequency
const ROLLING_ENV_KEY: &str = "NAMADA_LOG_ROLLING";

const LOG_FILE_NAME_PREFIX: &str = "namada.log";

#[derive(Clone, Debug, Default)]
enum Fmt {
    #[default]
    Full,
    Json,
    Pretty,
}

/// When logging to a file is enabled, returns a guard that handles flushing of
/// remaining logs on termination.
///
/// Important: The returned guard, if any, must be assigned to a binding that is
/// not _, as _ will result in the WorkerGuard being dropped immediately.
pub fn init_from_env_or(
    default: impl Into<Directive>,
) -> Result<Option<WorkerGuard>> {
    let filter = filter_from_env_or(default);
    let guard = set_subscriber(filter)?;
    init_log_tracer()?;
    Ok(guard)
}

pub fn filter_from_env_or(default: impl Into<Directive>) -> EnvFilter {
    env::var(ENV_KEY)
        .map(EnvFilter::new)
        .unwrap_or_else(|_| EnvFilter::default().add_directive(default.into()))
}

pub fn init_log_tracer() -> Result<()> {
    LogTracer::init().wrap_err("Failed to initialize log adapter")
}

pub fn set_subscriber(filter: EnvFilter) -> Result<Option<WorkerGuard>> {
    let with_color = if let Ok(val) = env::var(COLOR_ENV_KEY) {
        !val.eq_ignore_ascii_case("false")
    } else {
        true
    };
    let format = env::var(FMT_ENV_KEY)
        .ok()
        .and_then(|val| match val.to_ascii_lowercase().as_str() {
            "full" => Some(Fmt::Full),
            "json" => Some(Fmt::Json),
            "pretty" => Some(Fmt::Pretty),
            _ => None,
        })
        .unwrap_or_default();
    let log_dir = env::var(DIR_ENV_KEY).ok();

    let builder = Subscriber::builder()
        .with_ansi(with_color)
        .with_env_filter(filter);

    // We're using macros here to help as the `format` match arms and `log_dir`
    // if/else branches have incompatible types.
    macro_rules! finish {
        ($($builder:tt)*) => {
            {
                let my_collector = $($builder)*.finish();
                tracing::subscriber::set_global_default(my_collector)
                    .wrap_err("Failed to set log subscriber")
            }
        }
    }
    macro_rules! select_format {
        ($($builder:tt)*) => {
            {
                match format {
                    Fmt::Full => finish!($($builder)*),
                    Fmt::Json => finish!($($builder)*.json()),
                    Fmt::Pretty => finish!($($builder)*.pretty()),
                }
            }
        }
    }

    if let Some(dir) = log_dir {
        use tracing_appender::rolling::{self, RollingFileAppender};

        let rolling_fn: fn(_, _) -> RollingFileAppender = match rolling_freq() {
            RollingFreq::Never => rolling::never,
            RollingFreq::Minutely => rolling::minutely,
            RollingFreq::Hourly => rolling::hourly,
            RollingFreq::Daily => rolling::daily,
        };
        let file_appender = rolling_fn(dir, LOG_FILE_NAME_PREFIX);
        let (non_blocking, guard) =
            tracing_appender::non_blocking(file_appender);
        let builder = builder.with_writer(non_blocking);
        select_format!(builder)?;
        Ok(Some(guard))
    } else {
        select_format!(builder)?;
        Ok(None)
    }
}

enum RollingFreq {
    Never,
    Minutely,
    Hourly,
    Daily,
}

/// Get the rolling frequency from env var or default to `Never`.
fn rolling_freq() -> RollingFreq {
    if let Ok(freq) = env::var(ROLLING_ENV_KEY) {
        match freq.to_ascii_lowercase().as_str() {
            "never" => RollingFreq::Never,
            "minutely" => RollingFreq::Minutely,
            "hourly" => RollingFreq::Hourly,
            "daily" => RollingFreq::Daily,
            _ => {
                panic!(
                    "Unrecognized option set for {ROLLING_ENV_KEY}. Expecting \
                     one of: never, minutely, hourly, daily. Default is never."
                );
            }
        }
    } else {
        RollingFreq::Never
    }
}
