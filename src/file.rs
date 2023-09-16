use dynfmt::Format;
use dynfmt::SimpleCurlyFormat;
use tempfile::NamedTempFile;
use std::path::Path;
use std::fs::File;
use std::io::{BufReader};
use std::collections::HashMap;

use serde_json::Value;
use rzpipe::RzPipe;

use crate::strategies;
use crate::util::hex_to_u64;

pub struct PipePair {
	pub in_pipe: RzPipe,
	pub out_pipe: RzPipe,
	pub symbol_map: HashMap<String, u64>,

	pub android_symbol_map: HashMap<String, u64>,
	pub android_addr_map: HashMap<u64, String>,
	pub android_name_map: HashMap<String, u64>
}

impl PipePair {
	// convenience
	pub fn cmd(&mut self, cmd: &str, is_in: bool) -> String {
		if is_in {
			self.in_pipe.cmd(cmd).unwrap().to_string()
		} else {
			self.out_pipe.cmd(cmd).unwrap().to_string()
		}
	}
	pub fn cmdj(&mut self, cmd: &str, is_in: bool) -> Value {
		if is_in {
			self.in_pipe.cmdj(cmd).unwrap()
		} else {
			self.out_pipe.cmdj(cmd).unwrap()
		}
	}
	pub fn in_cmdj(&mut self, cmd: &str) -> Value {
		self.in_pipe.cmdj(cmd).unwrap()
	}
	pub fn out_cmdj(&mut self, cmd: &str) -> Value {
		self.out_pipe.cmdj(cmd).unwrap()
	}

	pub fn cmd_bulk(&mut self, command: &str, offsets: &Vec<u64>, is_in: bool) -> String {
		let tmp_file = NamedTempFile::new().unwrap();

		std::fs::write(
			tmp_file.path(),
			offsets.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("\n")
		).unwrap();

		self.cmd(&SimpleCurlyFormat.format(command, &[tmp_file.path().to_str().unwrap()]).unwrap(), is_in)
	}

	// Creates a PipePair using two http ports
	pub fn new(in_port: u32, out_port: u32) -> PipePair {
		let mut in_pipe = RzPipe::http(&format!("localhost:{}", in_port)).unwrap();
		let out_pipe = RzPipe::http(&format!("localhost:{}", out_port)).unwrap();

		// fill our symbol maps up
		let bind = in_pipe.cmd("isq~_Z").unwrap().to_string();
		let android_symbol_iter = bind
			.lines()
			.map(|x| x.split(" ").collect::<Vec<_>>())
			.map(|x| (x[2].to_string(), hex_to_u64(x[0]).unwrap()));

		let android_symbol_map: HashMap<_, _> = android_symbol_iter.clone().collect();
		let android_addr_map: HashMap<_, _> = android_symbol_iter.map(|x| (x.1, x.0)).collect();

		// fill our name maps up
		let bind2 = in_pipe.cmd("aflq~method").unwrap().to_string();
		let android_name_map: HashMap<_, _> = bind2
			.lines()
			.map(|x| x.split(" "))
			.map(|mut x| (hex_to_u64(x.next().unwrap()).unwrap(), x.next().unwrap().to_string()))
			.map(|x| (x.1, x.0))
			.collect();

		PipePair {
			in_pipe,
			out_pipe,
			symbol_map: HashMap::new(),
			android_symbol_map,
			android_addr_map,
			android_name_map,
		}
	}

	pub fn import(&mut self, path: &Path) {
		let file = File::open(path).unwrap();
		let reader = BufReader::new(file);
		self.symbol_map = serde_json::from_reader(reader).unwrap();
	}

	pub fn export(&self, path: &Path) {
		// export symbol map json to path, pretty-print it.
		let file = File::create(path).unwrap();
		serde_json::to_writer_pretty(file, &self.symbol_map).unwrap();
	}

	pub fn run_strategies(&mut self) -> u32 {
		let count = self.symbol_map.len();

		strategies::run_all(self);

		(self.symbol_map.len() - count) as u32
	}
}


