//! JSON-only command-line interface for deterministic AIOS IR validation.

mod adapter;

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process;

use adapter::{AdapterError, LibraryAdapter};
use aios_ir::ValidationReport;
use clap::error::ErrorKind;
use clap::{ColorChoice, Parser, Subcommand};
use serde::Serialize;
use serde_json::{Map, Value};

const EXIT_VALID: i32 = 0;
const EXIT_OPERATIONAL_ERROR: i32 = 1;
const EXIT_REJECTED: i32 = 2;

#[derive(Debug, Parser)]
#[command(
    name = "aios-ir",
    version,
    about = "Deterministic AIOS IR v0.1 development CLI",
    color = ColorChoice::Never
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate a candidate program against an explicit immutable registry bundle.
    Validate(ProgramCommand),
    /// Emit the normalized semantic form of a valid candidate program.
    Normalize(ProgramCommand),
    /// Emit the semantic hash of a valid candidate program.
    Hash(ProgramCommand),
    /// Emit the static effect summary of a valid candidate program.
    Effects(ProgramCommand),
    /// Explain one stable validator or registry reason code.
    ExplainError {
        /// Stable reason code such as `IR_GRAPH_CYCLE`.
        reason_code: String,
    },
}

#[derive(Debug, clap::Args)]
struct ProgramCommand {
    /// Candidate AIOS IR JSON file.
    program: PathBuf,

    /// Explicit local registry bundle directory.
    #[arg(long, value_name = "PATH", required = true)]
    registry: PathBuf,
}

fn main() {
    let exit_code = entry(std::env::args_os());
    process::exit(exit_code);
}

fn entry<I, T>(arguments: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match Cli::try_parse_from(arguments) {
        Ok(cli) => match run(cli) {
            Ok(outcome) => emit_and_status(&outcome.output, outcome.exit_code),
            Err(error) => emit_adapter_error(&error),
        },
        Err(error) => emit_clap_error(&error),
    }
}

fn run(cli: Cli) -> Result<CommandOutcome, AdapterError> {
    match cli.command {
        Command::Validate(arguments) => {
            let report = LibraryAdapter::validate_path(&arguments.program, &arguments.registry)?;
            report_outcome(&report, ReportView::Full)
        }
        Command::Normalize(arguments) => {
            let report = LibraryAdapter::validate_path(&arguments.program, &arguments.registry)?;
            report_outcome(&report, ReportView::Normalized)
        }
        Command::Hash(arguments) => {
            let report = LibraryAdapter::validate_path(&arguments.program, &arguments.registry)?;
            report_outcome(&report, ReportView::SemanticHash)
        }
        Command::Effects(arguments) => {
            let report = LibraryAdapter::validate_path(&arguments.program, &arguments.registry)?;
            report_outcome(&report, ReportView::Effects)
        }
        Command::ExplainError { reason_code } => {
            let explanation = LibraryAdapter::explain_reason(&reason_code)?;
            let mut output = Map::new();
            output.insert("schema_version".to_owned(), Value::String("0.1".to_owned()));
            output.insert("reason_code".to_owned(), Value::String(reason_code));
            output.insert("explanation".to_owned(), explanation);
            Ok(CommandOutcome {
                output: Value::Object(output),
                exit_code: EXIT_VALID,
            })
        }
    }
}

#[derive(Clone, Copy)]
enum ReportView {
    Full,
    Normalized,
    SemanticHash,
    Effects,
}

fn report_outcome(
    report: &ValidationReport,
    view: ReportView,
) -> Result<CommandOutcome, AdapterError> {
    let valid = report.output.validation.valid;
    if valid {
        enforce_valid_report_contract(report, view)?;
    }

    let output = match view {
        ReportView::Full => to_json_value(&report.output)?,
        ReportView::Normalized => {
            report_projection(report, "normalized", to_json_value(&report.normalized)?)?
        }
        ReportView::SemanticHash => report_projection(
            report,
            "semantic_hash",
            to_json_value(&report.output.validation.semantic_hash)?,
        )?,
        ReportView::Effects => report_projection(
            report,
            "effect_summary",
            to_json_value(&report.output.effect_summary)?,
        )?,
    };

    Ok(CommandOutcome {
        output,
        exit_code: if valid { EXIT_VALID } else { EXIT_REJECTED },
    })
}

fn enforce_valid_report_contract(
    report: &ValidationReport,
    view: ReportView,
) -> Result<(), AdapterError> {
    let present = match view {
        ReportView::Full => true,
        ReportView::Normalized => report.normalized.is_some(),
        ReportView::SemanticHash => report.output.validation.semantic_hash.is_some(),
        ReportView::Effects => report.output.effect_summary.is_some(),
    };

    if present {
        Ok(())
    } else {
        Err(AdapterError::operational(
            "CLI_LIBRARY_CONTRACT_VIOLATION",
            "the validator returned a valid report without the requested derived output",
        ))
    }
}

fn report_projection(
    report: &ValidationReport,
    field_name: &'static str,
    field_value: Value,
) -> Result<Value, AdapterError> {
    let mut object = Map::new();
    object.insert("schema_version".to_owned(), Value::String("0.1".to_owned()));
    object.insert(
        "validation".to_owned(),
        to_json_value(&report.output.validation)?,
    );
    object.insert(field_name.to_owned(), field_value);
    Ok(Value::Object(object))
}

fn to_json_value(value: &impl Serialize) -> Result<Value, AdapterError> {
    serde_json::to_value(value).map_err(|error| {
        AdapterError::operational(
            "CLI_OUTPUT_SERIALIZATION_FAILED",
            format!("could not serialize validator output: {error}"),
        )
    })
}

struct CommandOutcome {
    output: Value,
    exit_code: i32,
}

#[derive(Serialize)]
struct OperationalResponse<'a> {
    schema_version: &'static str,
    ok: bool,
    error: OperationalError<'a>,
}

#[derive(Serialize)]
struct OperationalError<'a> {
    code: &'a str,
    message: &'a str,
}

fn emit_clap_error(error: &clap::Error) -> i32 {
    let informational = matches!(
        error.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    );
    if informational {
        let response = serde_json::json!({
            "schema_version": "0.1",
            "ok": true,
            "information": error.to_string(),
        });
        emit_and_status(&response, EXIT_VALID)
    } else {
        let error = AdapterError::operational("CLI_ARGUMENT_INVALID", error.to_string());
        emit_adapter_error(&error)
    }
}

fn emit_adapter_error(error: &AdapterError) -> i32 {
    let response = OperationalResponse {
        schema_version: "0.1",
        ok: false,
        error: OperationalError {
            code: error.code,
            message: &error.message,
        },
    };
    emit_and_status(&response, EXIT_OPERATIONAL_ERROR)
}

fn emit_and_status(value: &impl Serialize, intended_status: i32) -> i32 {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if serde_json::to_writer(&mut output, value).is_err() || output.write_all(b"\n").is_err() {
        return EXIT_OPERATIONAL_ERROR;
    }
    intended_status
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command};
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn all_program_commands_require_an_explicit_registry() {
        for command in ["validate", "normalize", "hash", "effects"] {
            let result = Cli::try_parse_from(["aios-ir", command, "program.json"]);
            assert!(result.is_err(), "{command} accepted no registry");
        }
    }

    #[test]
    fn parses_explicit_program_and_registry_paths() {
        let cli = Cli::try_parse_from([
            "aios-ir",
            "validate",
            "program.json",
            "--registry",
            "registry",
        ])
        .expect("parse validate arguments");

        let Command::Validate(arguments) = cli.command else {
            panic!("expected validate command");
        };
        assert_eq!(arguments.program, PathBuf::from("program.json"));
        assert_eq!(arguments.registry, PathBuf::from("registry"));
    }

    #[test]
    fn explain_error_does_not_accept_a_registry_or_program() {
        let cli = Cli::try_parse_from(["aios-ir", "explain-error", "IR_GRAPH_CYCLE"])
            .expect("parse explain-error arguments");

        let Command::ExplainError { reason_code } = cli.command else {
            panic!("expected explain-error command");
        };
        assert_eq!(reason_code, "IR_GRAPH_CYCLE");
    }
}
