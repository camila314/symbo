mod pipes;
mod db;
mod generate;
mod util;
mod analysis;

fn main() {
    let input_db: db::ExecDB = pot::from_slice(&std::fs::read("android.exdb").unwrap()).unwrap();
    let output_db: db::ExecDB = pot::from_slice(&std::fs::read("mac.exdb").unwrap()).unwrap();

    let pair = db::ExecPair {
        input: input_db,
        output: output_db
    };

    let binds = analysis::create_bind(&pair);
    // write output to file with serde_json, pretty print
    println!("Outputting");

    std::fs::write("binds.symdb", serde_json::to_string_pretty(&binds).unwrap()).unwrap();


    /*{
        let output = generate::generate("/Users/jakrillis/projects/symbo/test/android211").unwrap();

        // write output to file with serde
        println!("Outputting");

        let output = pot::to_vec(&output).unwrap();
        std::fs::write("android.exdb", output).unwrap();
    }

    {
        let output = generate::generate("/Users/jakrillis/projects/symbo/test/mac211").unwrap();

        // write output to file with serde
        println!("Outputting");

        let output = pot::to_vec(&output).unwrap();
        std::fs::write("mac.exdb", output).unwrap();
    }*/
}
