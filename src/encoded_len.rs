pub struct EncodedLen {
	pub offset: usize,
	pub buffer: [u8; 9],
}

impl EncodedLen {
	pub fn value(&self) -> &[u8] {
		&self.buffer[self.offset..]
	}

	pub fn left_encode(len: usize) -> Self {
		let mut buffer = [0u8; 9];
		buffer[1..].copy_from_slice(&(len as u64).to_be_bytes());
		let offset = buffer.iter().position(|i| *i != 0).unwrap_or(8);
		buffer[offset - 1] = 9 - offset as u8;
	
		EncodedLen {
			offset: offset - 1,
			buffer,
		}
	}

	pub fn right_encode(len: usize) -> Self {
		let mut buffer = [0u8; 9];
		buffer[..8].copy_from_slice(&(len as u64).to_be_bytes());
		let offset = buffer.iter().position(|i| *i != 0).unwrap_or(7);
		buffer[8] = 8 - offset as u8;
		EncodedLen { offset, buffer }
	}
}
