use std::io::Write;
use std::fmt::Display;

use crossterm::event;
use crossterm::terminal::{enable_raw_mode, disable_raw_mode};
use colored::Colorize;

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

fn confirm(msg: &str) -> Option<bool> {
	print!("{} {}", msg, "[y/n/i] ".dimmed());
	std::io::stdout().flush().unwrap();

	enable_raw_mode().unwrap();

	loop {
		let evt = event::read();
		match evt {
			Ok(event::Event::Key(event::KeyEvent { code: event::KeyCode::Char('y'), kind: event::KeyEventKind::Press, .. })) => {
				disable_raw_mode().unwrap();
				println!("yes");
				return Some(true);
			},
			Ok(event::Event::Key(event::KeyEvent { code: event::KeyCode::Char('n'), kind: event::KeyEventKind::Press, .. })) => {
				disable_raw_mode().unwrap();
				println!("no");
				return Some(false);
			},

			Ok(event::Event::Key(event::KeyEvent { code: event::KeyCode::Char('i'), kind: event::KeyEventKind::Press, .. })) => {
				disable_raw_mode().unwrap();
				println!("ignore");
				return None;
			},

			Ok(event::Event::Key(event::KeyEvent { code: event::KeyCode::Char('c'), modifiers: event::KeyModifiers::CONTROL, .. })) => {
				disable_raw_mode().unwrap();
				std::process::exit(0);
			},
			_=>()
		};
	}
}

pub fn conflict_confirm(sym: &str, addr: u64) -> Option<bool> {
	let sym_demangle = cpp_demangle::Symbol::new(sym)
		.map(|x| x.to_string())
		.unwrap_or(sym.to_string());

	confirm(&format!("Is {} located at {}", sym_demangle.yellow(), addr.as_hex().blue()))
}

