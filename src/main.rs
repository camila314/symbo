use std::path::PathBuf;
use std::fs;

mod pipes;
mod db;
mod generate;
mod util;
mod analysis;

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

            let mut binds = if let Some(ref out) = out {
                serde_json::from_slice(&std::fs::read(out).unwrap()).expect("Invalid symdb file")
            } else {
                BindDB::new(&pair)
            };

            println!("To do!");

            let out_file = out.clone().unwrap_or(PathBuf::from("symbols.symdb"));

            binds.process(analysis::string_xref_strat(&pair, &binds), &out_file);
            binds.process(analysis::call_xref_strat(&pair, &binds), &out_file);
            binds.process(analysis::call_block_strat(&pair, &binds), &out_file);

        },

        Command::Print { exec, addr } => {
            let exec: ExecDB = pot::from_slice(&std::fs::read(exec).unwrap()).expect("Invalid exdb file");
            println!("{:#?}", exec.fns.get(&addr));
        }
    }
}
