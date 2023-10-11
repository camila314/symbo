use std::io::Write;
use colored::Colorize;
use std::collections::HashMap;

use crate::util::*;
use crate::db::*;

use crossterm::event;
use crossterm::terminal::{enable_raw_mode, disable_raw_mode};

// Silly helpers
fn xref_compare<'a>(bind_db: &BindDB, pair: &ExecPair, in_blk: &'a Block, out_blks: Vec<&'a Block>) -> Option<&'a Block> {
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
				.map(|(x, y)| (x, xref_compare(bind_db, pair, x, y)?).as_some())
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

// Strategies TODO: not as many debug prints

pub fn call_xref_strat(pair: &ExecPair, binds: &BindDB) -> HashMap<String, u64> {
	let call_pairs: Vec<(&Option<String>, &Vec<Address>, &Vec<Address>)> = pair.input.fns.iter()
		.filter_map(|x| (
			&x.1.name,
			&x.1.xrefs,
			&pair.output.fns.get(
				&binds.binds.get(x.1.name.as_ref()?)?.get_addr()?
			)?.xrefs
		).as_some()).collect();

	xref_binds(binds, pair, call_pairs.into_iter().map(|(_, y, z)| (y,z)).collect())
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
			Ok(event::Event::Key(event::KeyEvent { code: event::KeyCode::Char('y'), .. })) => {
				disable_raw_mode().unwrap();
				println!("yes");
				return true;
			},
			Ok(event::Event::Key(event::KeyEvent { code: event::KeyCode::Char('n'), .. })) => {
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

	confirm(&format!("Is {} located at {}?", sym_demangle.yellow(), addr.as_hex().blue()))
}


impl BindDB {
	pub fn process(&mut self, new: HashMap<String, u64>) {
		let before_count = self.binds.len();
		let mut verify_count = 0;

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
		bind_db.process(string_xref_strat(pair, &bind_db));

		bind_db
	}
}
