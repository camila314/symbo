use std::collections::HashMap;
use serde_json::Value;
use std::cell::RefCell;
use std::rc::Rc;

use crate::file::PipePair;
use crate::util::hex_to_u64;

#[derive(Debug)]
enum Branch {
	Return,
	Neutral(u64),
	Equality(u64, u64),
	// A if greater than B
	Inequality(u64, u64)
}

#[derive(Clone)]
#[derive(Debug)]
enum Call {
	Value(u64),
	Register
}

#[derive(Debug)]
struct Block {
	pub address: u64,
	pub calls: Vec<Call>,
	pub branch: Branch,
}

type Blocks = Vec<Rc<RefCell<Block>>>;
// Address, Block, Function
type Xref = (u64, u64, u64);

pub fn run_all(pair: &mut PipePair) {
	let mut blocks: Blocks = Vec::new();

	// (in_fn, out_fn)
	let paired_fns: Vec<_> = pair.symbol_map.iter().map(|(k, v)| (*pair.android_symbol_map.get(k).unwrap(), *v)).collect();

	xrefs(&mut blocks, pair, &paired_fns);
	for paired_fn in paired_fns {
		traverse_block(&mut blocks, pair, paired_fn.0, paired_fn.1);
	}
}

fn compare_symbols(pair: &PipePair, in_fn: u64, out_fn: u64) -> bool {
	let out_symbol = pair.symbol_map.iter().find(|(_, v)| **v == out_fn).map(|x| x.0.as_str()).unwrap_or("");
	let in_symbol = pair.android_addr_map.get(&in_fn).map(|x| x.as_str()).unwrap_or("-");

	//println!("Comparing {} {}", in_symbol, out_symbol);

	return in_symbol == out_symbol;
}

fn get_block(blocks: &mut Blocks, pair: &mut PipePair, address: u64, is_in: bool) -> Rc<RefCell<Block>> {
	println!("New Block! {} {}", address, is_in);
	if let Some(item) = blocks.iter().find(|x| x.borrow().address == address) {
		//println!("duplicate");
		return Rc::clone(item);
	}

	let out = Rc::new(RefCell::new(Block {
		address,
		branch: Branch::Return,
		calls: Vec::new(),
	}));
	blocks.push(out.clone());


	let block_info = pair.cmdj(&format!("abij @ {}", address), is_in);

	let jump = block_info["jump"].as_u64();
	let addr = block_info["addr"].as_u64().unwrap();

	let disasm = pair.cmd(&format!("pib @ {}", addr), is_in);
	let has_pop = disasm.contains("pop rbp");

	let call_lines = disasm.lines().filter(|x| 
		x.starts_with("call") ||
		(has_pop && x.starts_with("jmp")) ||
		x.starts_with("bl") ||
		x.starts_with("blx") ||
		x.starts_with("blr")
	);

	let call_names = call_lines.map(|x| x.split_whitespace().last().unwrap());

	let calls: Vec<_> = if is_in {
		call_names.map(|x| {
			if let Some(addr) = pair.android_name_map.get(x) {
				Call::Value(*addr)
			} else {
				Call::Register
			}
		}).collect()
	} else {
		call_names.map(|x| {
			if x.starts_with("sym.func.") {
				let addr = hex_to_u64(&(String::from("0x") + x.split(".").last().unwrap())).unwrap();
				Call::Value(addr)
			} else {
				Call::Register
			}
		}).collect()
	};

	let branch = if jump.is_none() {
		Branch::Return
	} else if block_info.get("fail").is_none() {
		if has_pop {
			Branch::Return
		} else {
			Branch::Neutral(jump.unwrap())
		}
	} else {
		let branch_instruction = disasm
			.lines().last().unwrap()
			.split_whitespace().next().unwrap()
			.split(".").next().unwrap();

		let fail = block_info["fail"].as_u64().unwrap();

		match branch_instruction {
			"ble" | "blt" | "bls" | "jb" | "jl" | "jle" | "jbe" => Branch::Inequality(fail, jump.unwrap()),
			"bge" | "bgt" | "bhi" | "ja" | "jg" | "jge" | "jae" => Branch::Inequality(jump.unwrap(), fail),
			"beq" | "bpl" | "je" | "jz" | "jp" => Branch::Equality(jump.unwrap(), fail),
			"bne" | "bmi" | "jne" | "jnz" | "jnp" => Branch::Equality(fail, jump.unwrap()),
			_ => Branch::Equality(jump.unwrap(), fail),
		}
	};

	out.borrow_mut().branch = branch;
	out.borrow_mut().calls = calls;
	out
}

fn traverse_block(blocks: &mut Blocks, pair: &mut PipePair, in_addr: u64, out_addr: u64) {
	//println!("Traversing {} and {}", in_addr, out_addr);

	let in_block = get_block(blocks, pair, in_addr, true);
	let out_block = get_block(blocks, pair, out_addr, false);

	//println!("Call length {} {}", in_block.borrow().calls.len(), out_block.borrow().calls.len());
	if in_block.borrow().calls.len() == out_block.borrow().calls.len() {
		for (in_call, out_call) in in_block.borrow().calls.iter().zip(&out_block.borrow().calls) {
			match (in_call, out_call) {
				(Call::Value(in_val), Call::Value(out_val)) => {
					// call!
					let symbol = pair.android_addr_map.get(&in_val).unwrap();

					if let Some(out_sym) = pair.symbol_map.iter().find(|x| *x.1 == *out_val) {
						if symbol != out_sym.0 {
							println!("Incompatible symbols: {} and {} in block {}", symbol, out_sym.0, in_addr);
							return;
						}
					}

					if let Some(dupe) = pair.symbol_map.get(symbol) {
						if dupe != out_val {
							println!("Duplicate symbols: {} and {} for {}", out_val, dupe, symbol);
							return;
						}
					} else {
						println!("Added {}", symbol);
						pair.symbol_map.insert(symbol.to_string(), *out_val);

						traverse_block(blocks, pair, *in_val, *out_val);

					}
				}
				(Call::Register, Call::Register) => (),
				_ => {
					println!("Incompatible blocks: {} and {}", in_addr, out_addr);
					return;
				}
			}
		}
	}

	match (&in_block.borrow().branch, &out_block.borrow().branch) {
		(Branch::Return, Branch::Return) => {
			//println!("Returning now!");
		},

		(Branch::Neutral(in_new), Branch::Neutral(out_new)) => {
			let in_block = get_block(blocks, pair, *in_new, true);
			let out_block = get_block(blocks, pair, *out_new, false);

			//println!("Next Branch!");
			traverse_block(blocks, pair, in_block.borrow().address, out_block.borrow().address);
		},

		(Branch::Equality(in_eq, in_ne), Branch::Equality(out_eq, out_ne)) => {
			let in_eq_block = get_block(blocks, pair, *in_eq, true);
			let in_ne_block = get_block(blocks, pair, *in_ne, true);
			let out_eq_block = get_block(blocks, pair, *out_eq, false);
			let out_ne_block = get_block(blocks, pair, *out_ne, false);

			//println!("Next Branch (if equal)");
			traverse_block(blocks, pair, in_eq_block.borrow().address, out_eq_block.borrow().address);
			//println!("Next Branch (if unequal)");
			traverse_block(blocks, pair, in_ne_block.borrow().address, out_ne_block.borrow().address);
		
		},

		(Branch::Inequality(in_gt, in_lt), Branch::Inequality(out_gt, out_lt)) => {
			let in_gt_block = get_block(blocks, pair, *in_gt, true);
			let in_lt_block = get_block(blocks, pair, *in_lt, true);
			let out_gt_block = get_block(blocks, pair, *out_gt, false);
			let out_lt_block = get_block(blocks, pair, *out_lt, false);

			//println!("Next Branch (if greater)");
			traverse_block(blocks, pair, in_gt_block.borrow().address, out_gt_block.borrow().address);
			//println!("Next Branch (if less)");
			traverse_block(blocks, pair, in_lt_block.borrow().address, out_lt_block.borrow().address);
		},
		_ => {
			//println!("Mismatched branch types: {} {}", in_addr, out_addr);
			return;
		}
	};
}

fn name_xrefs(blocks: &mut Blocks, pair: &mut PipePair, in_xrefs: &Vec<Xref>, out_xrefs: &Vec<Xref>) {
	// Clean: Remove non-symbolic in_xrefs and named in_xref-out_xref pairs
	let named_xrefs: Vec<_> = out_xrefs.clone().into_iter()
		.filter_map(|(_, _, f)|
			pair.symbol_map.iter().find(|(_, v)| **v == f)
		).collect();

	let cleaned_out_xrefs: Vec<Xref> = out_xrefs.iter().cloned()
		.filter(|(_, _, f)|
			named_xrefs.iter().find(|(_, x)| f == *x).is_none()
		).collect();

	let mut cleaned_in_xrefs: Vec<Xref> = in_xrefs.iter().cloned()
		.filter(|(_, _, f)| pair.android_addr_map.get(&f).is_some())
		.filter(|(_, _, f)|
			named_xrefs.iter().find(|(x, _)| pair.android_addr_map.get(&f).unwrap() == *x).is_none()
		).collect();

	//println!("{} {}", in_xrefs.len(), cleaned_out_xrefs.len());

	// if there's only one left, what else would it be?
	if cleaned_in_xrefs.len() == 1 && cleaned_out_xrefs.len() == 1 {
		let symbol = pair.android_addr_map.get(&cleaned_in_xrefs[0].2).unwrap().to_string();
		println!("Added {} (one left)", &symbol);
		pair.symbol_map.insert(symbol, cleaned_out_xrefs[0].2);
		return;
	}

	// Run finder loop
	let mut in_blocks: Vec<_> = cleaned_in_xrefs.clone().into_iter()
		.map(|x| (x, get_block(blocks, pair, x.1, true)))
		.collect();
	for out_xref in cleaned_out_xrefs {
		let out_block = get_block(blocks, pair, out_xref.2, false);

		let model: Vec<_> = in_blocks.iter()
			.filter(|x| x.1.borrow().calls.len() == out_block.borrow().calls.len()).cloned()
			.collect();

		if model.len() > 0 {
			// check if shares symbols
			let call_map: Vec<_> = out_block.borrow().calls.iter()
				.map(|x| match x {
					Call::Register => None,
					Call::Value(y) => pair.symbol_map.iter().find(|(_, v)| **v == *y).and_then(|(k, _)| Some(k))
				}).collect();

			let in_matches: Vec<_> = model.iter().filter(|x|
				x.1.borrow().calls.iter()
					.map(|y| match y {
						Call::Register => None,
						Call::Value(y) => Some(y)
					}).zip(&call_map)
					.filter(|(adr, sym)| sym.is_some() && adr.is_some())
					.all(|(adr, sym)| sym.unwrap() == pair.android_addr_map.get(&adr.unwrap()).unwrap())
			).collect();

			if in_matches.len() == 1 {
				let symbol = pair.android_addr_map.get(&in_matches[0].0.2).unwrap().to_string();
				println!("Added {} (symbol share: {})", &symbol, in_matches[0].0.0);
				pair.symbol_map.insert(symbol, out_xref.2);

				// remove item from vecs
				in_blocks.retain(|x| x.0 != in_matches[0].0);
				cleaned_in_xrefs.retain(|x| *x != in_matches[0].0);

				continue;
			}

			// Give up....
		}

	}
}

fn xref_matches(blocks: &mut Blocks, pair: &mut PipePair, in_xref: Xref, out_xref: Xref) {
	let in_block = get_block(blocks, pair, in_xref.1, true);
	let out_block = get_block(blocks, pair, out_xref.1, false);

	if in_block.borrow().calls.len() != out_block.borrow().calls.len() {
		println!("how did this happen: {} {}", in_block.borrow().calls.len(), out_block.borrow().calls.len());
		return;
	}

	let binding = in_block.borrow();
    let in_calls: Vec<_> = binding.calls.iter()
		.filter_map(|x| match x {
			Call::Register => None,
			Call::Value(y) => Some(y)
		}).collect();

	let binding = out_block.borrow();
    let out_calls: Vec<_> = binding.calls.iter()
		.filter_map(|x| match x {
			Call::Register => None,
			Call::Value(y) => Some(y)
		}).collect();

	if in_calls.len() != out_calls.len() {
		println!("mismatch??");
		return;
	}

	// check if all named calls match up, return if otherwise
	if in_calls.iter().zip(&out_calls).all(|(in_fn, out_fn)| compare_symbols(pair, **in_fn, **out_fn)) {
		println!("epic fail!");
		return;
	}

	// set the names of unnamed in functions to the corresponding named function in out functions
	in_calls.into_iter().zip(out_calls)
		.for_each(|(in_fn, out_fn)| {
			let symbol = pair.android_addr_map.get(in_fn).unwrap_or(&format!("something_{}", in_fn)).to_string();
			println!("Added {}", symbol);
			pair.symbol_map.insert(symbol, *out_fn);
		});
}

fn xrefs(blocks: &mut Blocks, pair: &mut PipePair, fns: &Vec<(u64, u64)>) {
	println!("Running Xrefs");

	let (in_fns, out_fns): (Vec<u64>, Vec<u64>) = fns.iter().cloned().unzip();

	let mut generate_model = |fns: Vec<u64>, is_in: bool| -> Vec<Vec<Xref>> {
		println!("{:?}", fns);
		pair.cmd_bulk("axtj @@. {}", &fns, is_in)
			.lines().clone()
			.map(|x| {
				serde_json::from_str::<Vec<Value>>(x).unwrap().into_iter()
					.map(|x| x["from"].as_u64().unwrap())
					.map(|x| (
						x, 
						hex_to_u64(&pair.cmd(&format!("abi~[0] @ {}", x), is_in).trim().to_string()),
						pair.cmdj(&format!("afij @ {}", x), is_in).get(0).cloned()
					))
					.filter(|x| x.1.is_some() && x.2.is_some())
					.map(|x| (x.0, x.1.unwrap(), x.2.unwrap()["offset"].as_u64().unwrap()))
					.collect()
			}
			)
			.collect()
	};

	// Address, Block, Function
	let in_xrefs_list = generate_model(in_fns, true);
	let out_xrefs_list = generate_model(out_fns, false);

	println!("list {} {}", in_xrefs_list[0].len(), out_xrefs_list[0].len());

	let xrefs_pairs = in_xrefs_list.iter().zip(out_xrefs_list).collect::<Vec<_>>();


	xrefs_pairs.iter().for_each(|(i, o)| name_xrefs(blocks, pair, i, &o));

	// generate mapping of named symbols. (out_addr, in_addr)
	let named_xref_maps = xrefs_pairs.iter()
		.map(|(in_xrefs, out_xrefs)|
			out_xrefs.iter()
				.map(|out_xref| (
					out_xref,
					in_xrefs.iter().filter(|in_xref| compare_symbols(pair, in_xref.2, out_xref.2)).collect()
				)).collect()
		).collect::<Vec<HashMap<_, Vec<_>>>>();

	for xref_map in &named_xref_maps {
		for (out_xref, in_xrefs) in xref_map {
			if in_xrefs.len() == 1 {
				println!("looking for matches");
				xref_matches(blocks, pair, *in_xrefs[0], **out_xref);
			}
		}
	}
}
