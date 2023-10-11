use std::fmt::Display;

pub trait AsHex {
	fn as_hex(&self) -> String;
}

impl AsHex for u64 {
	fn as_hex(&self) -> String {
		format!("{:#x}", self)
	}
}

pub trait AsSome {
	fn as_some(self) -> Option<Self> where Self: Sized;
}
impl<T> AsSome for T {
	fn as_some(self) -> Option<Self> {
		Some(self)
	}
}

pub trait Warn<T> {
	fn warn_if(self, msg: impl Display) -> Self;
}
impl<T, E: std::fmt::Display> Warn<T> for Result<T, E> {
	fn warn_if(self, msg: impl Display) -> Self {
		if let Err(e) = &self {
			println!("{}: {}", msg, e);
		}
		self
	}
}
impl<T> Warn<T> for Option<T> {
	fn warn_if(self, msg: impl Display) -> Self {
		if let None = &self {
			println!("{}", msg);
		}
		self
	}
}
