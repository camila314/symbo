use std::path::Path;
use std::path::PathBuf;
use clap::Parser;
use file::PipePair;

use crate::initial::vtable;

mod file;
mod strategies;
mod util;
mod initial;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Input Port
    input: u32,

    /// Output Port
    output: u32,

    /// Path to Symbol Map
    #[clap(short)]
    symbol_map: Option<PathBuf>
}

fn main() {
    let cli = Cli::parse();

    let mut pipe_pair = PipePair::new(cli.input, cli.output);

    if let Some(ref path) = cli.symbol_map {
        pipe_pair.import(&path);
    } else {
        println!("No symbol map found, initializing...");
        vtable(&mut pipe_pair);
        println!("Found {} symbols", pipe_pair.symbol_map.len());
    }

    loop {
        println!("Running cycle");

        let symbs = pipe_pair.run_strategies();
        println!("Found {} symbols", symbs);

        pipe_pair.export(cli.symbol_map.as_deref().unwrap_or(Path::new("symbol_map.json")));
        if symbs == 0 {
            break;
        }
    }

    println!("Done!");

}
