use std::path::Path;
use std::collections::HashMap;
use colored::Colorize;
use crate::util::*;
use crate::db::*;

fn subset_of<T>(a: &[T], b: &[T]) -> bool where T: PartialEq + std::clone::Clone {
	a.iter().all(|x| 
		b.iter().position(|y| y == x).is_some()
	)
}

fn find_symbols(pair: &ExecPair, binds: &mut BindDB, symbol: String, candidates: &HashMap<u64, Function>) {
	let threshold = 10;

	let input_fn = pair.input.fns.iter().find(|(_,x)| x.name.as_ref() == Some(&symbol)).expect("Symbol not found");

	let binds_reversed = binds.binds.iter()
		.filter_map(|(x, y)| y.get_addr().map(|y| (y, x.to_string())))
		.collect::<HashMap<_, _>>();

	let mut binds_reversed_ver = binds.binds.iter()
		.filter(|(_, y)| matches!(y, Bind::Verified(_)))
		.filter_map(|(x, y)| y.get_addr().map(|y| (y, x.to_string())))
		.collect::<HashMap<_, _>>();

	if let Some(bind) = binds.binds.get_mut(&symbol) {
		match bind {
			Bind::Verified(x) => {
				println!("{} is already verified at {:#x}", symbol.bright_green(), x);
				return;
			},

			Bind::Unverified(x) => {
				if conflict_confirm(&symbol, *x) == Some(true) {
					*bind = Bind::Verified(*x);
					return;
				} else {
					*bind = Bind::Not(vec![*x]);
				}
			},

			_ => ()
		}
	}

	let mut verified_xrefs: Vec<_> = input_fn.1.xrefs.iter()
		.map(|x| x.function_addr)
		.filter_map(|x| pair.input.fns.get(&x)?.name.clone())
		.filter(|x| binds.binds.get(x).and_then(|x| x.get_addr()).is_some())
		.collect();
	verified_xrefs.sort();

	let candidates: Vec<u64> = candidates.iter()
		.map(|(x, y)| (*x,
			y.xrefs.iter()
				.map(|x| x.function_addr)
				.filter_map(|x| binds_reversed.get(&x))
				.map(|x| x.to_string())
				.collect::<Vec<_>>()
		))
		.map(|(x, mut y)| {
			y.sort();
			(x, y)
		})
		.filter(|(_, y)| y == &verified_xrefs)
		.map(|(x, _)| x)
		.collect();

	println!("Found {} possible candidates", candidates.len().to_string().bright_green());

	if candidates.len() <= threshold {
		for candidate in candidates {
			if binds_reversed_ver.get(&candidate).is_some() {
				continue;
			}

			if conflict_confirm(&symbol, candidate) == Some(true) {
				binds.binds.insert(symbol.clone(), Bind::Verified(candidate));
				binds_reversed_ver.insert(candidate, symbol.clone());
				return;
			} else {
				match binds.binds.get_mut(&symbol) {
					Some(Bind::Not(x)) => x.push(candidate),
					_ => { binds.binds.insert(symbol.clone(), Bind::Not(vec![candidate])); }
				}
			}
		}

		return;
	}

	println!("Checking Calls");

	let mut verified_calls = input_fn.1.blocks.iter()
		.map(|x| x.calls.clone())
		.flatten()
		.filter_map(|x| match x {
			Dest::Known(x) => Some(x),
			Dest::Unknown => None
		})
		.filter_map(|x| pair.input.fns.get(&x)?.name.clone())
		.filter(|x| binds.binds.get(x).and_then(|x| x.get_addr()).is_some())
		.collect::<Vec<_>>();
	verified_calls.sort();


	let candidates: Vec<_> = candidates.iter()
		.filter_map(|x| pair.output.fns.get(x))
		.map(|x| (x.address.function_addr, x.blocks.iter()
			.map(|x| x.calls.clone())
			.flatten()
			.filter_map(|x| match x {
				Dest::Known(x) => Some(x),
				Dest::Unknown => None
			})
			.filter_map(|x| binds_reversed.get(&x))
			.map(|x| x.to_string())
			.collect::<Vec<_>>()
		))
		.map(|(x, mut y)| {
			y.sort();
			(x, y)
		})
		.filter(|(_, y)| subset_of(&verified_calls, y))
		.map(|(x, _)| x)
		.collect();

	println!("Found {} possible candidates", candidates.len().to_string().bright_green());

	if candidates.len() <= threshold {
		for candidate in candidates {
			if binds_reversed_ver.get(&candidate).is_some() {
				continue;
			}

			if conflict_confirm(&symbol, candidate) == Some(true) {
				binds.binds.insert(symbol.clone(), Bind::Verified(candidate));
				binds_reversed_ver.insert(candidate, symbol.clone());
				return;
			} else {
				match binds.binds.get_mut(&symbol) {
					Some(Bind::Not(x)) => x.push(candidate),
					_ => { binds.binds.insert(symbol.clone(), Bind::Not(vec![candidate])); }
				}
			}
		}

		return;
	}

	println!("Too many candidates, sorry!");

	//todo!();
}

pub fn find_symbol(pair: &ExecPair, binds: &mut BindDB, symbol: String) {
	return find_symbols(pair, binds, symbol, &pair.output.fns);
}

pub fn find_range(pair: &ExecPair, binds: &mut BindDB, cls: String, range_begin: u64, range_end: u64, outfile: &Path) {
	let candidates = pair.output.fns.clone().into_iter()
		.filter(|(_, x)| x.address.function_addr >= range_begin && x.address.function_addr <= range_end)
		.collect::<HashMap<_, _>>();

	let symbols = pair.input.fns.iter()
		.filter(|(_, x)| x.name.as_ref().map(|x| x.starts_with(&format!("_ZN{}{}", cls.len(), cls))).unwrap_or(false))
		.map(|(_, x)| x.name.clone().unwrap())
		.collect::<Vec<_>>();

	for symbol in symbols {
		find_symbols(pair, binds, symbol, &candidates);
		std::fs::write(outfile, serde_json::to_string_pretty(&binds).unwrap()).unwrap();
	}
}
