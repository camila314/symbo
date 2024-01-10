use colored::Colorize;
use crate::util::*;
use crate::db::*;

fn subset_of<T>(a: &[T], b: &[T]) -> bool where T: PartialEq + std::clone::Clone {
	let mut b_clone: Vec<T> = b.to_vec();
	a.iter().all(|x| 
		b_clone.iter().position(|y| y == x).is_some()
	)
}


pub fn find_symbol(pair: &ExecPair, binds: &mut BindDB, symbol: String) {
	let threshold = 10;

	let input_fn = pair.input.fns.iter().find(|(_,x)| x.name.as_ref() == Some(&symbol)).expect("Symbol not found");

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

	dbg!(&verified_xrefs);

	let candidates: Vec<u64> = pair.output.fns.iter()
		.map(|(x, y)| (*x,
			y.xrefs.iter()
				.map(|x| x.function_addr)
				.filter_map(|x| binds.binds.iter().find(|y| y.1.get_addr() == Some(x)))
				.map(|x| x.0.to_string())
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
			if conflict_confirm(&symbol, candidate) == Some(true) {
				binds.binds.insert(symbol.clone(), Bind::Verified(candidate));
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
			.filter_map(|x| binds.binds.iter().find(|y| y.1.get_addr() == Some(x)))
			.map(|x| x.0.to_string())
			.collect::<Vec<_>>()
		))
		.map(|(x, mut y)| {
			y.sort();
			(x, y)
		})
		.filter(|(_, y)| subset_of(&verified_calls, y))
		.map(|(x, _)| x)
		.collect();

	if candidates.len() <= threshold {
		for candidate in candidates {
			if conflict_confirm(&symbol, candidate) == Some(true) {
				binds.binds.insert(symbol.clone(), Bind::Verified(candidate));
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

	todo!();
}