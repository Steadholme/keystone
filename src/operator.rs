//! Offline operator commands for non-human service principals.
//!
//! This module deliberately bypasses the HTTP/login surface and talks directly to the
//! existing PostgreSQL authority. Schema migration remains an explicit deployment step;
//! operator commands perform DML only.

use std::collections::HashMap;
use std::env;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use keystone::store::{PgStore, ServicePrincipalError, Store};

pub const USAGE: &str = "Usage:\n  keystone service-principal create --slug <slug> --display-name <name> --actor <actor>\n  keystone service-principal disable --slug <slug> --actor <actor>";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Command {
    Create {
        slug: String,
        display_name: String,
        actor: String,
    },
    Disable {
        slug: String,
        actor: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Invocation {
    Help,
    Run(Command),
}

type CommandBuilder = fn(HashMap<String, String>) -> Result<Command, OperatorError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Success {
    Help,
    PrincipalCreated,
    PrincipalDisabled,
    PrincipalAlreadyDisabled,
}

impl Success {
    pub fn message(self) -> &'static str {
        match self {
            Self::Help => USAGE,
            Self::PrincipalCreated => "service principal created without credentials",
            Self::PrincipalDisabled => "service principal disabled",
            Self::PrincipalAlreadyDisabled => "service principal was already disabled; no change",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperatorError {
    InvalidArguments,
    MissingDatabaseUrl,
    DatabaseUnavailable,
    ClockUnavailable,
    PrincipalInvalid,
    PrincipalAlreadyExists,
    PrincipalNotFound,
    StoreUnavailable,
}

impl fmt::Display for OperatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidArguments => "invalid arguments",
            Self::MissingDatabaseUrl => "DATABASE_URL is required",
            Self::DatabaseUnavailable => "database connection failed",
            Self::ClockUnavailable => "system clock is unavailable",
            Self::PrincipalInvalid => "service principal input is invalid",
            Self::PrincipalAlreadyExists => "service principal already exists; no change",
            Self::PrincipalNotFound => "service principal was not found",
            Self::StoreUnavailable => "service principal authority is unavailable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OperatorError {}

pub async fn run_from_env(args: &[String]) -> Result<Success, OperatorError> {
    let invocation = parse_args(args)?;
    let Invocation::Run(command) = invocation else {
        return Ok(Success::Help);
    };

    let database_url = env::var("DATABASE_URL").map_err(|_| OperatorError::MissingDatabaseUrl)?;
    if database_url.trim().is_empty() {
        return Err(OperatorError::MissingDatabaseUrl);
    }
    let store = PgStore::connect(&database_url)
        .await
        .map_err(|_| OperatorError::DatabaseUnavailable)?;
    drop(database_url);

    execute_at(&store, command, unix_time()?).await
}

fn parse_args(args: &[String]) -> Result<Invocation, OperatorError> {
    let Some(subcommand) = args.first().map(String::as_str) else {
        return Ok(Invocation::Help);
    };
    if subcommand == "help" || subcommand == "--help" || subcommand == "-h" {
        return if args.len() == 1 {
            Ok(Invocation::Help)
        } else {
            Err(OperatorError::InvalidArguments)
        };
    }

    let (required, kind): (&[&str], CommandBuilder) = match subcommand {
        "create" => (&["--slug", "--display-name", "--actor"], command_create),
        "disable" => (&["--slug", "--actor"], command_disable),
        _ => return Err(OperatorError::InvalidArguments),
    };
    let options = parse_options(&args[1..], required)?;
    kind(options).map(Invocation::Run)
}

fn parse_options(
    args: &[String],
    required: &[&str],
) -> Result<HashMap<String, String>, OperatorError> {
    if args.len() != required.len() * 2 {
        return Err(OperatorError::InvalidArguments);
    }
    let mut options = HashMap::with_capacity(required.len());
    for pair in args.chunks_exact(2) {
        let key = pair[0].as_str();
        let value = pair[1].as_str();
        if !required.contains(&key)
            || value.is_empty()
            || value.starts_with("--")
            || options.insert(key.to_string(), value.to_string()).is_some()
        {
            return Err(OperatorError::InvalidArguments);
        }
    }
    if required.iter().any(|key| !options.contains_key(*key)) {
        return Err(OperatorError::InvalidArguments);
    }
    Ok(options)
}

fn take(options: &mut HashMap<String, String>, key: &str) -> Result<String, OperatorError> {
    options
        .remove(key)
        .filter(|value| !value.trim().is_empty())
        .ok_or(OperatorError::InvalidArguments)
}

fn command_create(mut options: HashMap<String, String>) -> Result<Command, OperatorError> {
    Ok(Command::Create {
        slug: take(&mut options, "--slug")?,
        display_name: take(&mut options, "--display-name")?,
        actor: take(&mut options, "--actor")?,
    })
}

fn command_disable(mut options: HashMap<String, String>) -> Result<Command, OperatorError> {
    Ok(Command::Disable {
        slug: take(&mut options, "--slug")?,
        actor: take(&mut options, "--actor")?,
    })
}

fn unix_time() -> Result<u64, OperatorError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| OperatorError::ClockUnavailable)
}

fn map_store_error(error: ServicePrincipalError) -> OperatorError {
    match error {
        ServicePrincipalError::Invalid => OperatorError::PrincipalInvalid,
        ServicePrincipalError::AlreadyExists => OperatorError::PrincipalAlreadyExists,
        ServicePrincipalError::NotFound => OperatorError::PrincipalNotFound,
        ServicePrincipalError::Backend => OperatorError::StoreUnavailable,
    }
}

async fn execute_at<S>(store: &S, command: Command, now: u64) -> Result<Success, OperatorError>
where
    S: Store + ?Sized,
{
    if now == 0 {
        return Err(OperatorError::ClockUnavailable);
    }
    match command {
        Command::Create {
            slug,
            display_name,
            actor,
        } => {
            store
                .create_service_principal(&slug, &display_name, &actor, now)
                .await
                .map_err(map_store_error)?;
            Ok(Success::PrincipalCreated)
        }
        Command::Disable { slug, actor } => {
            let changed = store
                .set_service_principal_disabled(&slug, true, &actor, now)
                .await
                .map_err(map_store_error)?;
            if changed {
                Ok(Success::PrincipalDisabled)
            } else {
                Ok(Success::PrincipalAlreadyDisabled)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone::store::InMemoryStore;

    fn create_command() -> Command {
        Command::Create {
            slug: "system-core".to_string(),
            display_name: "System Core".to_string(),
            actor: "operator-test".to_string(),
        }
    }

    fn disable_command() -> Command {
        Command::Disable {
            slug: "system-core".to_string(),
            actor: "operator-test".to_string(),
        }
    }

    #[test]
    fn parser_accepts_only_create_and_disable_with_explicit_actor() {
        for args in [
            vec![
                "create",
                "--slug",
                "system-core",
                "--display-name",
                "System Core",
                "--actor",
                "operator-test",
            ],
            vec![
                "disable",
                "--slug",
                "system-core",
                "--actor",
                "operator-test",
            ],
        ] {
            let args = args.into_iter().map(str::to_string).collect::<Vec<_>>();
            assert!(matches!(parse_args(&args), Ok(Invocation::Run(_))));
        }

        for args in [
            vec!["unknown"],
            vec!["disable", "--slug", "system-core"],
            vec![
                "disable",
                "--slug",
                "system-core",
                "--token",
                "unexpected",
                "--actor",
                "operator-test",
            ],
        ] {
            let args = args.into_iter().map(str::to_string).collect::<Vec<_>>();
            assert_eq!(parse_args(&args), Err(OperatorError::InvalidArguments));
        }
    }

    #[tokio::test]
    async fn create_reports_existing_principal_without_claiming_a_change() {
        let store = InMemoryStore::new();
        assert_eq!(
            execute_at(&store, create_command(), 1_000).await,
            Ok(Success::PrincipalCreated)
        );
        assert_eq!(
            execute_at(&store, create_command(), 1_001).await,
            Err(OperatorError::PrincipalAlreadyExists)
        );
    }

    #[tokio::test]
    async fn disable_reports_when_the_principal_was_already_disabled() {
        let store = InMemoryStore::new();
        execute_at(&store, create_command(), 1_000)
            .await
            .expect("create principal");
        assert_eq!(
            execute_at(&store, disable_command(), 1_001).await,
            Ok(Success::PrincipalDisabled)
        );
        assert_eq!(
            execute_at(&store, disable_command(), 1_002).await,
            Ok(Success::PrincipalAlreadyDisabled)
        );
    }
}
