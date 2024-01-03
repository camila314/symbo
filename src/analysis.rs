use std::path::Path;
use std::io::Write;
use colored::Colorize;
use std::collections::HashMap;

use crate::util::*;
use crate::db::*;

use crossterm::event;
use crossterm::terminal::{enable_raw_mode, disable_raw_mode};

// Silly helpers
fn block_compare<'a>(bind_db: &BindDB, pair: &ExecPair, in_blk: &'a Block, mut out_blks: Vec<&'a Block>) -> Option<&'a Block> {
	// sanity check
	if let Some(sym_name) = pair.input.fns.get(&in_blk.address.function_addr).and_then(|x| x.name.as_ref()) {
		let matching = bind_db.binds.get(sym_name).and_then(|x| x.get_addr());
		if let Some(matching) = matching {
			if out_blks.iter().find(|x| x.address.function_addr == matching).is_none() {
				return None;
			}

			let possible: Vec<_> = out_blks.into_iter().filter(|x| x.address.function_addr == matching).collect();
			if possible.len() == 1 {
				return Some(possible[0]);
			} else {
				out_blks = possible;
			}
		}
	}

	// string check!
	let strings_matching: Vec<_> = out_blks.iter().filter(|x| x.strings == in_blk.strings).collect();
	if strings_matching.len() == 1 {
		return Some(strings_matching[0]);
	}

	// call check!
	let calls_matching: Vec<_> = out_blks.iter()
		.filter(|x| x.calls.len() == in_blk.calls.len())
		.filter(|x| x.calls.iter().zip(&in_blk.calls).all(|(o, i)|
			match (i, o) {
				(Dest::Unknown, Dest::Unknown) => true,
				(Dest::Known(i), Dest::Known(o)) => {
					pair.input.fns.get(&i)
						.map(|x| x.name.clone())
						.flatten()
						.and_then(|x| bind_db.binds.get(&x))
						.map(|x| x.get_addr().map(|x| x == *o).unwrap_or(false))
						.unwrap_or(true)
				},
				_ => false
			}
		)
		).collect();
	if calls_matching.len() == 1 {
		return Some(calls_matching[0]);
	}

	// do both!!
	let both_matching = strings_matching.iter().filter(|x| calls_matching.contains(x)).collect::<Vec<_>>();
	if both_matching.len() == 1 {
		return Some(both_matching[0]);
	}

	None
}

fn block_traverse<'a>(binds: &BindDB, pair: &'a ExecPair, blocks: Vec<(&'a Block, &'a Block)>) -> Vec<(&'a Block, &'a Block)> {
	let mut total_blocks: Vec<(&'a Block, &'a Block)> = Vec::new();

	let mut current_blocks = blocks.clone();

	while !current_blocks.is_empty() {
		total_blocks.extend(&current_blocks);
		let mut next_blocks: Vec<(&'a Block, &'a Block)> = Vec::new();

		for (in_blk, out_blk) in &current_blocks {
			let has_inline = in_blk.calls.iter().filter_map(|x| match x {
				Dest::Known(x) => pair.input.fns.get(x)?.name.clone(),
				Dest::Unknown => None
			}).any(|x| matches!(binds.binds.get(&x), Some(Bind::Inline)));

			if has_inline {
				continue;
			}

			match (&in_blk.branch, &out_blk.branch) {
				(Branch::Neutral(Dest::Known(x)), Branch::Neutral(Dest::Known(y))) => {
					(
						pair.input.addr_to_block(&Address {
							function_addr: in_blk.address.function_addr,
							block_addr: *x,
							addr: *x
						}),
						pair.output.addr_to_block(&Address {
							function_addr: out_blk.address.function_addr,
							block_addr: *y,
							addr: *y
						})
					).as_some()
					.and_then(|(x, y)| (x?,y?).as_some())
					.map(|x| next_blocks.push(x));
				},
				(Branch::Equality(Dest::Known(xeq), Dest::Known(xneq)), Branch::Equality(Dest::Known(yeq), Dest::Known(yneq))) => {
					//next_blocks.push((xeq, yeq));
					(
						pair.input.addr_to_block(&Address {
							function_addr: in_blk.address.function_addr,
							block_addr: *xeq,
							addr: *xeq
						}), 
						pair.output.addr_to_block(&Address {
							function_addr: out_blk.address.function_addr,
							block_addr: *yeq,
							addr: *yeq
						})
					).as_some()
					 .and_then(|(x, y)| (x?,y?).as_some())
					 .map(|x| next_blocks.push(x));

					//next_blocks.push((xneq, yneq));
					(
						pair.input.addr_to_block(&Address {
							function_addr: in_blk.address.function_addr,
							block_addr: *xneq,
							addr: *xneq
						}), 
						pair.output.addr_to_block(&Address {
							function_addr: out_blk.address.function_addr,
							block_addr: *yneq,
							addr: *yneq
						})
					).as_some()
					 .and_then(|(x, y)| (x?,y?).as_some())
					 .map(|x| next_blocks.push(x));
				
				},
				(Branch::Inequality(Dest::Known(xgt), Dest::Known(xlt)), Branch::Inequality(Dest::Known(ygt), Dest::Known(ylt))) => {
					//next_blocks.push((xgt, ygt));
					(
						pair.input.addr_to_block(&Address {
							function_addr: in_blk.address.function_addr,
							block_addr: *xgt,
							addr: *xgt
						}), 
						pair.output.addr_to_block(&Address {
							function_addr: out_blk.address.function_addr,
							block_addr: *ygt,
							addr: *ygt
						})
					).as_some()
					 .and_then(|(x, y)| (x?,y?).as_some())
					 .map(|x| next_blocks.push(x));


					//next_blocks.push((xlt, ylt));
					(
						pair.input.addr_to_block(&Address {
							function_addr: in_blk.address.function_addr,
							block_addr: *xlt,
							addr: *xlt
						}), 
						pair.output.addr_to_block(&Address {
							function_addr: out_blk.address.function_addr,
							block_addr: *ylt,
							addr: *ylt
						})
					).as_some()
					 .and_then(|(x, y)| (x?,y?).as_some())
					 .map(|x| next_blocks.push(x));
				
				},

				_ => continue
			}
		}

		current_blocks = next_blocks;

	}

	total_blocks
}

pub fn xref_binds(bind_db: &BindDB, pair: &ExecPair, xrefs: Vec<(&Vec<Address>, &Vec<Address>)>) -> HashMap<String, u64> {
	let mut output = HashMap::new();

	// Only one xref
	xrefs.iter()
		.filter(|(x, y)| x.len() == 1 && y.len() == 1)
		.filter_map(|(x, y)| (
			pair.input.fns.get(&x.first()?.function_addr)?.name.clone()?,
			y.first()?.function_addr
		).as_some())
		.for_each(|(x, y)| {

			output.insert(x, y);
		});

	// Multiple xrefs
	xrefs.iter()
		.filter(|(x, y)| x.len() > 1 && y.len() > 1)
		.map(|(x, y)| {
			let oblocks: Vec<_> = y.iter().map(|x| pair.output.addr_to_block(x).unwrap()).collect();
			x.iter()
				.map(move |x| (pair.input.addr_to_block(x).unwrap(), oblocks.clone()))
				.map(|(x, y)| (x, block_compare(bind_db, pair, x, y)?).as_some())
		}).flatten()
		.filter_map(|x| x.and_then(|(x, y)| (
			pair.input.fns.get(&x.address.function_addr).unwrap().name.clone()?,
			y
		).as_some()))
		.for_each(|(x, y)| {
			output.insert(x, y.address.function_addr);
		});

	output
}

pub fn block_binds(bind_db: &BindDB, pair: &ExecPair, blocks: Vec<(&Block, &Block)>) -> HashMap<String, u64> {
	blocks.into_iter().map(|(i_block, o_block)| i_block.calls.iter().zip(&o_block.calls).map(|(x, y)| {
		match (x, y) {
			(Dest::Unknown, Dest::Unknown) => Ok(None),
			(Dest::Known(i), Dest::Known(o)) => {
				let out = pair.input.fns.get(&i)
					.and_then(|x| x.name.as_ref())
					.map(|x| (x.clone(), *o));

				if let Some(ref x) = out {
					if matches!(bind_db.binds.get(&x.0), Some(Bind::Inline)) {
						// stop immediately for inlines
						return Err(());
					}
				}

				Ok(out)
			},
			_ => {
				println!("Block mismatch! {} - {} (Potential Inline?)",
					i_block.address.block_addr.as_hex().blue(), 
					o_block.address.block_addr.as_hex().blue()
				);

				Err(())
			}
		}
	}).take_while(|x| x.is_ok()).filter_map(|x| x.unwrap())).flatten().collect()
}

// Strategies

pub fn call_block_strat(pair: &ExecPair, binds: &BindDB) -> HashMap<String, u64> {
	let call_pairs: Vec<(&Vec<Address>, &Vec<Address>)> = pair.input.fns.iter()
		.filter_map(|x| (
			&x.1.xrefs,
			&pair.output.fns.get(
				&binds.binds.get(x.1.name.as_ref()?)?.get_addr()?
			)?.xrefs
		).as_some()).collect();

	let blocks: Vec<(&Block, &Block)> = call_pairs.iter()
		.map(|(i, o)| (
			i,
			o.iter().filter_map(|x| pair.output.addr_to_block(x)).collect::<Vec<_>>()
		))
		.map(|(i, o)|
			i.iter()
				.filter_map(|x| (x, pair.input.fns.get(&x.function_addr)?.name.as_ref()?).as_some())
				.filter_map(|(x, y)| (
					pair.input.addr_to_block(x)?,
					{
						let addr = binds.binds.get(y).and_then(|x| x.get_addr());

						let possible: Vec<_> = o.iter()
							// too much time lol
							//.filter(|y| binds.binds.values().find(|x| x.get_addr() == Some(y.address.function_addr)).is_some())
							.filter(|x| addr == Some(x.address.function_addr))
							.collect();

						if possible.len() == 1 {
							*possible[0]
						} else {
							None?
						}
					}
				).as_some()).collect::<Vec<_>>()
		).flatten().collect();

	block_binds(binds, pair, blocks)
}

pub fn block_traverse_strat(pair: &ExecPair, binds: &BindDB) -> HashMap<String, u64> {

	let fns_by_name: HashMap<_, _> = pair.input.fns.iter()
		.filter_map(|x| (x.1.name.clone()?, x.1.blocks.iter().find(|y| y.address.block_addr == x.1.address.function_addr)?).as_some())
		.collect();


	// Vec<(In, Out)>
	let block_pairs: Vec<_> = binds.binds.iter().filter_map(|(x, y)| (
		*fns_by_name.get(x)?,
		pair.output.fns.get(&y.get_addr()?)?
			.blocks
			.iter()
			.find(|x| Some(x.address.block_addr) == y.get_addr())?
	).as_some()).collect();

	block_binds(binds, pair, block_traverse(binds, pair, block_pairs))
}

pub fn call_xref_strat(pair: &ExecPair, binds: &BindDB) -> HashMap<String, u64> {
	let call_pairs: Vec<(&Vec<Address>, &Vec<Address>)> = pair.input.fns.iter()
		.filter_map(|x| (
			&x.1.xrefs,
			&pair.output.fns.get(
				&binds.binds.get(x.1.name.as_ref()?)?.get_addr()?
			)?.xrefs
		).as_some()).collect();

	xref_binds(binds, pair, call_pairs)
}

pub fn string_xref_strat(pair: &ExecPair, binds: &BindDB) -> HashMap<String, u64> {
	let string_pairs: Vec<(&Vec<Address>, &Vec<Address>)> = pair.input.strings.iter()
		.filter_map(|x| (&x.1.xrefs, &pair.output.strings.get(x.0)?.xrefs).as_some())
		.collect();

	xref_binds(binds, pair, string_pairs)
}

// The big stuff
fn confirm(msg: &str) -> bool {
	print!("{} {}", msg, "[y/n] ".dimmed());
	std::io::stdout().flush().unwrap();

	enable_raw_mode().unwrap();

	loop {
		let evt = event::read();
		match evt {
			Ok(event::Event::Key(event::KeyEvent { code: event::KeyCode::Char('y'), kind: event::KeyEventKind::Press, .. })) => {
				disable_raw_mode().unwrap();
				println!("yes");
				return true;
			},
			Ok(event::Event::Key(event::KeyEvent { code: event::KeyCode::Char('n'), kind: event::KeyEventKind::Press, .. })) => {
				disable_raw_mode().unwrap();
				println!("no");
				return false;
			},

			Ok(event::Event::Key(event::KeyEvent { code: event::KeyCode::Char('c'), modifiers: event::KeyModifiers::CONTROL, .. })) => {
				disable_raw_mode().unwrap();
				std::process::exit(0);
			},
			_=>()
		};
	}
}

fn conflict_confirm(sym: &str, addr: u64) -> bool {
	let sym_demangle = cpp_demangle::Symbol::new(sym)
		.map(|x| x.to_string())
		.unwrap_or(sym.to_string());

	confirm(&format!("Is {} located at {}", sym_demangle.yellow(), addr.as_hex().blue()))
}


impl BindDB {
	pub fn process(&mut self, new: HashMap<String, u64>, outfile: &Path) {
		let before_count = self.binds.len();
		let mut verify_count = 0;

		println!("Processing {} new symbols", new.len().to_string().bright_green());

		for (k, v) in new {
			if let Some(x) = self.binds.get_mut(&k) {
				match x {
					Bind::Unverified(a) => {
						if *a != v {
							// CONFLICT
							if conflict_confirm(&k, v) {
								verify_count += 1;
								*x = Bind::Verified(v);
							} else if conflict_confirm(&k, *a) {
								verify_count += 1;
								*x = Bind::Verified(*a);
							} else {
								*x = Bind::Not(vec![*a, v]);
							}
						}
					}
					Bind::Not(a) => {
						if a.iter().find(|x| **x == v).is_none() {
							if conflict_confirm(&k, v) {
								verify_count += 1;
								*x = Bind::Verified(v);
							} else {
								a.push(v);
							}
						}
					}
					Bind::Verified(_) | Bind::Inline  => {}
				}
			} else {
				self.binds.insert(k, Bind::Unverified(v));
			}

			std::fs::write(outfile, serde_json::to_string_pretty(&self).unwrap()).unwrap();
		}

		// mfw rust
		let binds_clone = self.binds.clone();
		for (_, v) in binds_clone.iter() {
			if let Bind::Unverified(a) = v {
				let appearances: Vec<_> = binds_clone.iter().filter(|(_, x)| x.get_addr() == v.get_addr()).collect();

				//println!("{:?}", appearances);

				if appearances.len() > 1 {
					println!("{:?}", appearances);
					if let Some(verified) = appearances.iter().find(|x| matches!(x.1, Bind::Verified(_))) {
						self.binds.insert(verified.0.to_string(), verified.1.clone());
					} else {
						for bind in &appearances {
							println!("{:?}", bind);
							if conflict_confirm(bind.0, *a) {
								verify_count += 1;
								self.binds.insert(bind.0.to_string(), Bind::Verified(*a));
								break;
							} else {
								self.binds.insert(bind.0.to_string(), Bind::Not(vec![*a]));
							}
						
						}
					}

					for bind in appearances {
						if let Some(Bind::Unverified(_)) = self.binds.get(bind.0) {
							self.binds.remove(bind.0);
						}
					}

					std::fs::write(outfile, serde_json::to_string_pretty(&self).unwrap()).unwrap();
				}
			}
		}

		println!("Added {} symbols", (self.binds.len() - before_count).to_string().bright_green());

		if verify_count > 0 {
			println!("Verified {} symbols", verify_count.to_string().bright_green());
		}
	}

	pub fn new(pair: &ExecPair) -> Self {
		let mut bind_db = BindDB {
			binds: HashMap::new()
		};

		// Vtables
		pair.input.vtables.values()
			.map(|x| (&x.name, x.function_addrs.iter().map(|x| pair.input.fns.get(x))))
			.filter_map(|(x, y)| y.zip(&pair.output.vtables.get(x)?.function_addrs).as_some())
			.flatten()
			.filter_map(|(i, o)| (i?.name.clone()?, Bind::Verified(*o)).as_some())
			.for_each(|(x, y)| {
				bind_db.binds.insert(x, y);
			});

		// Do a little string xref
		//bind_db.process(string_xref_strat(pair, &bind_db));

		bind_db
	}
}
