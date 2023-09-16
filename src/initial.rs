use itertools::Itertools;
use std::collections::HashMap;
use crate::PipePair;
use serde_json::Value;

pub fn vtable(pair: &mut PipePair) {
	// mini helper functions

	let gen_model = |avraj: Vec<Value>, avj: Vec<Value>| -> HashMap<String, Vec<Vec<u64>>> {
		// HashMap<class_vtable, class_name>
		let rtti_model: HashMap<u64, String> = avraj.iter()
			.map(|x| (x["class_vtable"].as_u64().unwrap(), x["name"].as_str().unwrap().to_string()))
			.collect();
		// Vec<(class_vtable, Vec<method>)
 		let vtable_model = avj.iter()
			.filter(|x| rtti_model.contains_key(&x["offset"].as_u64().unwrap()))
			.map(|x| (
				x["offset"].as_u64().unwrap(),
				x["methods"].as_array().unwrap()
					.iter()
					.map(|x| x["offset"].as_u64().unwrap())
					.collect()
			)).collect::<Vec<(u64, Vec<u64>)>>();
		// HashMap<class_name, Vec<Vec<method>>>
		rtti_model
			.values()
			.unique()
			.map(|x| (
				x.to_string(),
				vtable_model.iter()
					.filter(|y| x == rtti_model.get(&y.0).unwrap())
					.cloned()
					.sorted_by_key(|x| x.0)
					.map(|x| x.1)
					.collect()
			)).collect()
	};

	let in_model = gen_model(pair.in_cmdj("avraj").as_array().unwrap().clone(), pair.in_cmdj("avj").as_array().unwrap().clone());
	let out_model = gen_model(pair.out_cmdj("avraj").as_array().unwrap().clone(), pair.out_cmdj("avj").as_array().unwrap().clone());

	for k in out_model.keys().filter(|x| in_model.contains_key(*x)) {

		// iterate over a zip of the value of in_model and out_model
		for (in_vtable, out_vtable) in in_model.get(k).unwrap().iter().zip(out_model.get(k).unwrap().iter()) {
			// iterate over a zip of the value of in_vtable and out_vtable
			for (in_method, out_method) in in_vtable.iter().zip(out_vtable.iter()) {
				let method_name = pair.android_addr_map.get(&(in_method - 1)).unwrap().to_string();
				pair.symbol_map.insert(method_name, *out_method);
			}
		}

	}
}