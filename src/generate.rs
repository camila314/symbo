use std::io::Write;
use std::collections::{HashMap, BTreeMap};

use crate::pipes::PipeExt;
use crate::db::*;
use crate::util::{Warn, AsSome};

use serde_json::Value;
use rzpipe::{RzPipe, RzPipeSpawnOptions};

fn hex_to_u64(hex: &str) -> Option<u64> {
	u64::from_str_radix(hex.strip_prefix("0x").unwrap_or("j"), 16).ok().warn_if(format!("Unable to decode hex: {}", hex))
}

fn get_branch_type(inst: &str, jump: u64, fail: u64) -> Branch {
	let mut iter = inst.split(" ");
	let opcode = iter.next().unwrap();

	if opcode == "ret" {
		Branch::Return
	} else {
		//let operand = iter.next().expect(&format!("Bad instruction: {} at address {}", inst, fail));
		let fail = Dest::Known(fail);
		let jump = if jump == 0 {
			Dest::Unknown
		} else {
			Dest::Known(jump)
		};

		match opcode {
			"ret" => Branch::Return,
			"ble" | "blt" | "bls" | "jb" | "jl" | "jle" | "jbe" => Branch::Inequality(fail, jump),
			"bge" | "bgt" | "bhi" | "ja" | "jg" | "jge" | "jae" => Branch::Inequality(jump, fail),
			"beq" | "bpl" | "je" | "jz" | "jp" => Branch::Equality(jump, fail),
			"bne" | "bmi" | "jne" | "jnz" | "jnp" => Branch::Equality(fail, jump),
			"b" | "br" | "bx" | "bxr" | "jmp" => Branch::Neutral(jump),
			_ => Branch::Neutral(fail)
		}
	}
}

fn nearest_block(val: u64, possible: &Vec<u64>) -> Option<u64> {
	let mut low = 0;
	let mut high = possible.len() - 1;

	while low <= high {
		let mid = (low + high) / 2;
		let mid_val = *possible.get(mid)?;

		if mid_val == val {
			return Some(mid_val);
		} else if mid_val > val {
			high = mid - 1;
		} else {
			low = mid + 1;
		}
	}

	// return the nearest block
	Some(possible[high])
}


pub fn generate(rizin_proj: impl ToString) -> Result<ExecDB, Box<dyn std::error::Error>> {
	println!("Initializing");

	let mut pipe = RzPipe::spawn("-M", 	Some(RzPipeSpawnOptions {
	    exepath: String::from("rizin"),
	    args: vec!["-p".to_string(), rizin_proj.to_string()]
	}))?;

	let label_map: HashMap<String, u64> = pipe.cmd("aflq")?
		.lines()
		.map(|x| x.split_whitespace())
		.filter_map(|mut x| (hex_to_u64(x.next()?)?, x.collect()).as_some())
		.map(|(x, y)| (y, x))
		.collect();
	let function_addrs: Vec<u64> = label_map.values().map(|x| *x).collect();

	let block_pool: BTreeMap<u64, u64> = pipe.cmd_bulk("afbj @@. {}", &function_addrs)?
		.lines()
		.zip(&function_addrs)
		.filter_map(|(x, y)| (serde_json::from_str::<Vec<Value>>(x).ok()?, y).as_some())
		.map(|(x, y)| x.into_iter()
			.filter_map(|x| x.get("addr").and_then(|x| x.as_u64()))
			.map(|x| (x, *y))
		).flatten().collect();
	let block_keys: Vec<_> = block_pool.keys().map(|x| *x).collect();

	println!("Blocks: {}", block_keys.len());

	println!("Loading Symbols");

	let symbols: HashMap<u64, String> = pipe.cmd("isq~Z")?
		.lines()
		.map(|x| x.split_whitespace())
		.filter_map(|mut x| (hex_to_u64(x.next()?)?, x.skip(1).next()?.to_string()).as_some())
		.collect();

	println!("Loading Vtables");

	let vtables_raw: Vec<(u64, Vec<u64>)> = pipe.cmdj("avj")?
		.as_array().unwrap()
		.into_iter()
		.map(|x| (
			x.get("offset").unwrap().as_u64().unwrap(),
			x.get("methods").unwrap().as_array().unwrap().into_iter()
				.map(|x| nearest_block(x.get("offset").unwrap().as_u64().unwrap(), &block_keys).unwrap())
				.collect()
		)).collect();

	let vtable_addrs: Vec<u64> = vtables_raw.iter().map(|x| x.0).collect();

	let vtables: HashMap<String, Vtable> = pipe.cmd_bulk("avrj @@= `cat {}`", &vtable_addrs)?
		.lines()
		.zip(vtables_raw)
		.filter_map(|(x, y)| (
			serde_json::from_str::<Vec<Value>>(x).ok()?.into_iter().next()?,
			y
		).as_some())
		.map(|(x, y)| (
			x.get("type_desc").unwrap_or(&x).get("name").and_then(|x| x.as_str()).unwrap_or("").to_string(),
			y
		)) .map(|(x, y)| Vtable {
			name: pipe.cmd(&format!("avrD \"{}\"", x)).unwrap().trim().to_string(),
			address: y.0,
			function_addrs: y.1
		}).map(|x| (x.name.to_string(), x)).collect();

	println!("Loading Xrefs");

	let xrefs_raw: Vec<(u64, Vec<u64>)> = pipe.cmd_bulk("axtj @@. {}", &function_addrs)?
		.lines()
		.filter_map(|x| serde_json::from_str::<Vec<Value>>(x).ok())
		.filter(|x| !x.is_empty())
		.filter_map(|x| (
			x.first().unwrap().get("to").and_then(|x| x.as_u64())?,
			x.into_iter().filter_map(|x| (x.get("type").and_then(|x| x.as_str()).unwrap_or("") == "CALL").then(||
				x.get("from").and_then(|x| x.as_u64())
			)?).collect()
		).as_some()).collect();
	let xrefs: HashMap<u64, Vec<Address>> = xrefs_raw.into_iter()
		.map(|(x, y)| (
			x,
			y.into_iter().filter_map(|val|
				(val, nearest_block(val, &block_keys)?).as_some()
			).map(|(adr, blk)| Address {
				addr: adr,
				block_addr: blk,
				function_addr: *block_pool.get(&blk).unwrap_or(&0)
			}).collect::<Vec<_>>()
		)).collect();

	println!("Xrefs Found: {}", xrefs.len());

	println!("Loading Blocks");

	// Vec<(block_addr, size, jump_addr)
	let blocks_raw: Vec<(u64, u64, u64)> = pipe.cmd_bulk("abi @@. {}", &block_keys)?
		.lines()
		.map(|x| x.split_whitespace().collect::<Vec<_>>())
		.filter_map(|x| (
			hex_to_u64(x[0])?,
			x[3].parse().ok()?,
			x.get(5).and_then(|x| hex_to_u64(x)).unwrap_or(0)
		).as_some()).collect();
	let block_ends: Vec<_> = blocks_raw.iter().map(|x| x.0 + x.1).collect();

	println!("Loading Branches");

	// No calls yet!!
	let mut blocks: HashMap<u64, Block> = pipe.cmd_bulk("pi -1 @@. {}", &block_ends)?
		.lines()
		.zip(blocks_raw)
		.map(|(instr, (addr, size, jump))| (addr, Block {
			address: Address {
				addr: addr,
				block_addr: addr,
				function_addr: *block_pool.get(&addr).unwrap()
			},
			branch: get_branch_type(&instr, jump, addr + size),
			calls: Vec::new(),
			strings: Vec::new()
		})).collect();

	print!("Finding Calls");

	//TODO: replace with function_addrs.len()
	let len = function_addrs.len();
	let call_pool: Vec<(u64, Dest)> = (0..len).step_by(100).filter_map(|x| {
		print!("\rFinding Calls {} / {}", x / 100, len / 100);
		std::io::stdout().flush().unwrap();

		let upper = std::cmp::min(x + 100, len);
		let batch = &function_addrs[x..upper];

		Some(pipe.cmd_bulk("pDq `afi~size[1]` @@= `cat {}`", &batch).warn_if("Call find failed!").ok()?)
	}).map(|x|
		x.lines()
			.filter(|x| x.contains(" call ") || x.contains(" bl ") || x.contains(" blr ") || x.contains(" blx "))
			.map(|x| x.split_whitespace().map(|x| x.to_string()))
			.filter_map(|mut x| (hex_to_u64(&x.next()?)?, x.skip(1).collect::<String>()).as_some())
			.filter_map(|(x, y)| (
				nearest_block(x, &block_keys)?,
				label_map.get(&y).map(|x| Dest::Known(*x)).unwrap_or(Dest::Unknown)
			).as_some()).collect::<Vec<_>>()
	).flatten().collect();

	println!("\rFinding Calls {} / {}", len / 100, len / 100);
	println!("Loading Calls");

	call_pool.into_iter().for_each(|(x, y)| {
		blocks
			.get_mut(&x)
			.warn_if(format!("Block not found: {}", x))
			.map(|x| x.calls.push(y));
	});
	println!("Loading Strings");

	let strings_raw: Vec<(u64, String)> = pipe.cmd("izq")?
		.lines()
		.map(|x| x.split_whitespace())
		.filter_map(|mut x| (hex_to_u64(x.next()?)?, x.skip(2).collect::<String>()).as_some())
		.collect();
	let string_addrs = strings_raw.iter().map(|x| x.0).collect::<Vec<_>>();

	let strings: HashMap<String, StringRef> = pipe.cmd_bulk("axtj @@. {}", &string_addrs)?
		.lines()
		.zip(strings_raw)
		.filter_map(|(x, y)| (
			serde_json::from_str::<Vec<Value>>(x).ok()?,
			y
		).as_some())
		.map(|(x, y)| StringRef {
			string: y.1,
			xrefs: x.into_iter()
				.filter_map(|x| x.get("from").and_then(|x| x.as_u64()))
				.filter_map(|x| (x, nearest_block(x, &block_keys)?).as_some())
				.filter_map(|(x, y)| Some(Address {
					addr: x,
					block_addr: y,
					function_addr: block_pool.get(&y).cloned()?
				})).collect()
		})
		.filter(|x| x.xrefs.len() > 0)
		.fold(HashMap::<String, StringRef>::new(), |mut h, r| {
			if let Some(x) = h.get_mut(&r.string) {
				x.xrefs.extend(r.xrefs);
			} else {
				h.insert(r.string.clone(), r);
			}
			h
		});

	strings.values().for_each(|x|
		x.xrefs.iter().for_each(|y| {
			blocks.get_mut(&y.block_addr).map(|y| y.strings.push(x.string.to_string()));
		})
	);

	println!("Loading Functions");

	let mut functions: HashMap<u64, Function> = function_addrs.into_iter()
		.map(|x| (x, Function {
			name: symbols.get(&x).cloned(),
			address: Address {
				addr: x,
				block_addr: x,
				function_addr: x
			},
			blocks: Vec::new(),
			xrefs: xrefs.get(&x).cloned().unwrap_or_else(|| Vec::new())
		})).collect();

	blocks.drain().for_each(|(_, x)| {
		functions.get_mut(&x.address.function_addr).unwrap().blocks.push(x);
	});

	println!("Done");

	Ok(ExecDB {
		fns: functions,
		vtables: vtables,
		strings: strings
	})
}