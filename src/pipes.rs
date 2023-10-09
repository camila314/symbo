use dynfmt::Format;
use tempfile::NamedTempFile;
use dynfmt::SimpleCurlyFormat;
use rzpipe::{RzPipe, RzPipeError};
use serde_json::Value;

pub trait PipeExt {
	fn cmd_bulk(&mut self, command: &str, offsets: &[u64]) -> Result<String, RzPipeError>;
	fn cmdj_bulk(&mut self, command: &str, offsets: &[u64]) -> Result<Value, RzPipeError>;
}

impl PipeExt for RzPipe {
	fn cmd_bulk(&mut self, command: &str, offsets: &[u64]) -> Result<String, RzPipeError> {
		let tmp_file = NamedTempFile::new().unwrap();

		std::fs::write(
			tmp_file.path(),
			offsets.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("\n")
		).unwrap();

		self.cmd(&SimpleCurlyFormat.format(command, &[tmp_file.path().to_str().unwrap()]).unwrap())
	}

	fn cmdj_bulk(&mut self, command: &str, offsets: &[u64]) -> Result<Value, RzPipeError> {
		let tmp_file = NamedTempFile::new().unwrap();

		std::fs::write(
			tmp_file.path(),
			offsets.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("\n")
		).unwrap();

		self.cmdj(&SimpleCurlyFormat.format(command, &[tmp_file.path().to_str().unwrap()]).unwrap())
	}
}