#![allow(unused)]

use std::collections::HashMap;
use crate::util::{AsSome, Warn};
use crate::db::*;

fn pair_items<'a, T>(in_fns: Vec<&'a T>, out_fns: Vec<&'a T>) -> Vec<(&'a T, &'a T)> {
	in_fns.into_iter()
		.map(|i| out_fns.iter().map(move |o| (i, *o)))
		.flatten()
		.collect()
}

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

pub fn xref_binds(mut bind_db: &BindDB, pair: &ExecPair, xrefs: Vec<(&Vec<Address>, &Vec<Address>)>) -> HashMap<String, Bind> {
	let mut output = HashMap::new();

	// Only one xref
	xrefs.iter()
		.filter(|(x, y)| x.len() == 1 && y.len() == 1)
		.filter_map(|(x, y)| (
			pair.input.fns.get(&x.first()?.function_addr)?.name.clone()?,
			Bind::Unverified(y.first()?.function_addr)
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
			Bind::Unverified(y.address.function_addr)
		).as_some()))
		.for_each(|(x, y)| {
			output.insert(x, y);
		});

	output
}

pub fn create_bind(pair: &ExecPair) -> BindDB {
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

	let string_pairs: Vec<(&Vec<Address>, &Vec<Address>)> = pair.input.strings.iter()
		.filter_map(|x| (&x.1.xrefs, &pair.output.strings.get(x.0)?.xrefs).as_some())
		.collect();

	bind_db.binds.extend(xref_binds(&bind_db, pair, string_pairs));

	bind_db
}