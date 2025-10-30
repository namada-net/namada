//! Namada CLI.
//!
//! This CLI groups together the most commonly used commands inlined from the
//! node and the client. The other commands for the node, client and wallet can
//! be dispatched via `namada node ...`, `namada client ...` or `namada wallet
//! ...`, respectively.

use std::env;
use std::process::Command;

use eyre::Result;
use namada_apps_lib::cli;

pub fn main() -> Result<()> {
    let (cmd, raw_sub_cmd) = cli::namada_cli(namada_apps::namada_version());
    handle_command(cmd, raw_sub_cmd)
}

fn handle_command(cmd: cli::cmds::Namada, raw_sub_cmd: String) -> Result<()> {
    let args = env::args();

    let is_bin_sub_cmd = matches!(
        cmd,
        cli::cmds::Namada::Node(_)
            | cli::cmds::Namada::Client(_)
            | cli::cmds::Namada::Wallet(_)
    );

    // Skip the first arg, which is the name of the binary
    let mut sub_args: Vec<String> = args.skip(1).collect();

    if is_bin_sub_cmd {
        // Because there may be global args before the `cmd`, we have to find it
        // before removing it.
        sub_args
            .iter()
            .position(|arg| arg == &raw_sub_cmd)
            .map(|e| sub_args.remove(e));
    }

    match cmd {
        cli::cmds::Namada::Node(_) | cli::cmds::Namada::Ledger(_) => {
            handle_subcommand("namadan", sub_args)
        }
        cli::cmds::Namada::Client(_)
        | cli::cmds::Namada::TxCustom(_)
        | cli::cmds::Namada::TxTransparentTransfer(_)
        | cli::cmds::Namada::TxShieldedTransfer(_)
        | cli::cmds::Namada::TxShieldingTransfer(_)
        | cli::cmds::Namada::TxUnshieldingTransfer(_)
        | cli::cmds::Namada::TxIbcTransfer(_)
        | cli::cmds::Namada::TxOsmosisSwap(_)
        | cli::cmds::Namada::TxUpdateAccount(_)
        | cli::cmds::Namada::TxRevealPk(_)
        | cli::cmds::Namada::TxInitProposal(_)
        | cli::cmds::Namada::TxVoteProposal(_) => {
            handle_subcommand("namadac", sub_args)
        }
        cli::cmds::Namada::Wallet(_) => handle_subcommand("namadaw", sub_args),
        cli::cmds::Namada::Complete(cli::cmds::Complete(
            cli::args::Complete { shell },
        )) => {
            use std::io::stdout;

            use clap_complete::{generate, shells};
            use clap_complete_nushell::Nushell;

            let version = namada_apps::namada_version();
            for (mut app, name) in [
                (cli::namada_app(version), "namada"),
                (cli::namada_node_app(version), "namadan"),
                (cli::namada_client_app(version), "namadac"),
                (cli::namada_wallet_app(version), "namadaw"),
            ] {
                match shell {
                    cli::args::Shell::Bash => {
                        generate(shells::Bash, &mut app, name, &mut stdout())
                    }
                    cli::args::Shell::Elvish => {
                        generate(shells::Elvish, &mut app, name, &mut stdout())
                    }
                    cli::args::Shell::Fish => {
                        generate(shells::Fish, &mut app, name, &mut stdout())
                    }
                    cli::args::Shell::PowerShell => generate(
                        shells::PowerShell,
                        &mut app,
                        name,
                        &mut stdout(),
                    ),
                    cli::args::Shell::Zsh => {
                        generate(shells::Zsh, &mut app, name, &mut stdout())
                    }
                    cli::args::Shell::Nushell => {
                        generate(Nushell, &mut app, name, &mut stdout())
                    }
                };
            }
            Ok(())
        }
    }
}

fn handle_subcommand(program: &str, mut sub_args: Vec<String>) -> Result<()> {
    let env_vars = env::vars_os();

    let cmd_name = if env::var("CARGO").is_ok() {
        // When the command is ran from inside `cargo run`, we also want to
        // call the sub-command via `cargo run` to rebuild if necessary.
        // We do this by prepending the arguments with `cargo run` arguments.
        let mut cargo_args =
            vec!["run".to_string(), format!("--bin={}", program), "--".into()];
        cargo_args.append(&mut sub_args);
        sub_args = cargo_args;
        "cargo".into()
    } else {
        // Get the full path to the program to be inside the parent directory of
        // the current process
        let namada_path = env::current_exe()?;
        namada_path.parent().unwrap().join(program)
    };

    let mut cmd = Command::new(cmd_name);
    cmd.args(sub_args).envs(env_vars);
    exec_subcommand(program, cmd)
}

/// Borrowed and adapted from cargo's subcommand dispatch, which replaces the
/// current process with the sub-command:
/// <https://github.com/rust-lang/cargo/blob/94ca096afbf25f670e76e07dca754fcfe27134be/crates/cargo-util/src/process_builder.rs#L385>
///
/// Replaces the current process with the target process.
///
/// On Unix, this executes the process using the Unix syscall `execvp`, which
/// will block this process, and will only return if there is an error.
///
/// On Windows this isn't technically possible. Instead we emulate it to the
/// best of our ability. One aspect we fix here is that we specify a handler for
/// the Ctrl-C handler. In doing so (and by effectively ignoring it) we should
/// emulate proxying Ctrl-C handling to the application at hand, which will
/// either terminate or handle it itself. According to Microsoft's documentation
/// at <https://docs.microsoft.com/en-us/windows/console/ctrl-c-and-ctrl-break-signals>.
/// the Ctrl-C signal is sent to all processes attached to a terminal, which
/// should include our child process. If the child terminates then we'll reap
/// them in Cargo pretty quickly, and if the child handles the signal then we
/// won't terminate (and we shouldn't!) until the process itself later exits.
pub fn exec_subcommand(program: &str, cmd: Command) -> Result<()> {
    imp::exec_subcommand(program, cmd)
}

#[cfg(unix)]
mod imp {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    use eyre::{Result, eyre};

    pub fn exec_subcommand(program: &str, mut cmd: Command) -> Result<()> {
        let error = cmd.exec();
        Err(eyre!("Command {} failed with {}.", program, error))
    }
}
#[cfg(windows)]
mod imp {
    use std::process::Command;

    use eyre::{Result, WrapErr, eyre};
    use winapi::shared::minwindef::{BOOL, DWORD, FALSE, TRUE};
    use winapi::um::consoleapi::SetConsoleCtrlHandler;

    unsafe extern "system" fn ctrlc_handler(_: DWORD) -> BOOL {
        // Do nothing; let the child process handle it.
        TRUE
    }

    pub fn exec_subcommand(program: &str, mut cmd: Command) -> Result<()> {
        unsafe {
            if SetConsoleCtrlHandler(Some(ctrlc_handler), TRUE) == FALSE {
                return Err(eyre!("Could not set Ctrl-C handler."));
            }
        }

        let exit = cmd
            .status()
            .wrap_err_with(|| eyre!("Could not execute command {}", program))?;

        if exit.success() {
            Ok(())
        } else {
            Err(eyre!("Command {} failed.", program))
        }
    }
}
