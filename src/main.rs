use colored::Colorize;
use std::path::PathBuf;
use std::fs;

mod pipes;
mod db;
mod generate;
mod util;
mod analysis;
mod find;

use crate::db::*;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "Symbo")]
struct Cli {
    #[command(subcommand)]
    command: Command
}

#[derive(Subcommand)]
enum Command {
    Generate {
        exec: PathBuf,

        #[clap(short, long)]
        output: Option<PathBuf>
    },
    Run {
        from: PathBuf,
        to: PathBuf,
        #[clap(short, long)]
        out: Option<PathBuf>
    },
    Print {
        exec: PathBuf,
        addr: u64
    },
    /// Remove unverified symbols from symdb
    Strip {
        file: PathBuf
    },
    /// Attempt to find specific symbol
    Find {
        from: PathBuf,
        to: PathBuf,
        #[clap(short, long)]
        symbol: String,
        #[clap(short, long)]
        out: PathBuf
    }
}

fn main() {

    let args = Cli::parse();

    match args.command {
        Command::Generate { exec, output } => {
            let out_file = output.unwrap_or_else(|| PathBuf::from((exec.file_name().unwrap().to_string_lossy() + ".exdb").to_string()));
            fs::write(&out_file, "").expect("Unable to write to output file!");

            let out_data = generate::generate(exec.display().to_string()).unwrap();
            fs::write(&out_file, pot::to_vec(&out_data).unwrap()).unwrap();

        },
        
        Command::Run { from, to, out } => {
            let pair = ExecPair {
                input: pot::from_slice(&std::fs::read(from).unwrap()).expect("Invalid exdb file"),
                output: pot::from_slice(&std::fs::read(to).unwrap()).expect("Invalid exdb file")
            };

            let file_path = out.unwrap_or(PathBuf::from("symbols.symdb"));

            let mut binds = if file_path.exists() {
                serde_json::from_slice(&std::fs::read(&file_path).unwrap()).expect("Invalid symdb file")
            } else {
                BindDB::new(&pair)
            };

            println!("To do!");

            binds.process(analysis::string_xref_strat(&pair, &binds), &file_path);
            binds.process(analysis::block_traverse_strat(&pair, &binds), &file_path);
            binds.process(analysis::call_xref_strat(&pair, &binds), &file_path);
            binds.process(analysis::call_block_strat(&pair, &binds), &file_path);
        },

        Command::Strip { file } => {
            let mut binds: BindDB = serde_json::from_slice(&std::fs::read(&file).unwrap()).expect("Invalid symdb file");
            let before_count = binds.binds.len();

            binds.binds.retain(|_, x| !matches!(x, Bind::Unverified(_)));

            println!("Removed {} symbols", (before_count - binds.binds.len()).to_string().bright_green());

            std::fs::write(file, serde_json::to_string_pretty(&binds).unwrap()).unwrap();
        },

        Command::Find { from, to, symbol, out } => {
            let pair = ExecPair {
                input: pot::from_slice(&std::fs::read(from).unwrap()).expect("Invalid exdb file"),
                output: pot::from_slice(&std::fs::read(to).unwrap()).expect("Invalid exdb file")
            };

            let mut binds: BindDB = serde_json::from_slice(&std::fs::read(&out).unwrap()).expect("Invalid symdb file");
            find::find_symbol(&pair, &mut binds, symbol);

        }

        Command::Print { exec, addr } => {
            let exec: ExecDB = pot::from_slice(&std::fs::read(exec).unwrap()).expect("Invalid exdb file");
            println!("{:#?}", exec.fns.get(&addr));
        }
    }
}
