use std::collections::HashMap;
use serde::{Serialize, Deserialize};

// For Executable

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename = "D")]
pub enum Dest {
	#[serde(rename = "K")]
	Known(u64),
	#[serde(rename = "U")]
	Unknown
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename = "T")]
pub enum Branch {
	#[serde(rename = "R")]
	Return,
	#[serde(rename = "N")]
	Neutral(Dest),
	#[serde(rename = "E")]
	Equality(Dest, Dest),
	// A if greater than B
	#[serde(rename = "I")]
	Inequality(Dest, Dest)
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq)]
#[serde(rename = "A")]
pub struct Address {
	#[serde(rename = "A")]
	pub addr: u64,
	#[serde(rename = "B")]
	pub block_addr: u64,
	#[serde(rename = "F")]
	pub function_addr: u64
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "S")]
pub struct StringRef {
	#[serde(rename = "S")]
	pub string: String,
	#[serde(rename = "X")]
	pub xrefs: Vec<Address>
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename = "B")]
pub struct Block {
	#[serde(rename = "A")]
	pub address: Address,
	#[serde(rename = "C")]
	pub calls: Vec<Dest>,
	#[serde(rename = "B")]
	pub branch: Branch,
	#[serde(rename = "S")]
	pub strings: Vec<String>
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "F")]
pub struct Function {
	#[serde(rename = "N")]
	pub name: Option<String>,
	#[serde(rename = "A")]
	pub address: Address,
	#[serde(rename = "B")]
	pub blocks: Vec<Block>,
	#[serde(rename = "X")]
	pub xrefs: Vec<Address>
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "F")]
pub struct Vtable {
	#[serde(rename = "N")]
	pub name: String,
	#[serde(rename = "A")]
	pub address: u64,
	#[serde(rename = "F")]
	pub function_addrs: Vec<u64>
}

#[derive(Serialize, Deserialize)]
pub struct ExecDB {
	#[serde(rename = "F")]
	pub fns: HashMap<u64, Function>,
	#[serde(rename = "V")]
	pub vtables: HashMap<String, Vtable>,
	#[serde(rename = "S")]
	pub strings: HashMap<String, StringRef>
}

pub struct ExecPair {
	pub input: ExecDB,
	pub output: ExecDB
}

// For Binds

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum Bind {
	Verified(u64),
	Unverified(u64),
	Not(Vec<u64>),
	Inline
}

#[derive(Serialize, Deserialize)]
pub struct BindDB {
	pub binds: HashMap<String, Bind>
}

impl ExecDB {
	pub fn addr_to_block(&self, addr: &Address) -> Option<&Block> {
		self.fns.get(&addr.function_addr)?.blocks.iter()
			.find(|x| x.address.block_addr == addr.block_addr)
	}
}

impl Bind {
	pub fn get_addr(&self) -> Option<u64> {
		match self {
			Bind::Verified(x) => Some(*x),
			Bind::Unverified(x) => Some(*x),
			_ => None
		}
	}
}
