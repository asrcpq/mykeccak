use crate::{bits_to_rate, keccakf::KeccakF, Hasher, KeccakState};

#[derive(Clone)]
pub struct Sha3 {
	state: KeccakState<KeccakF>,
}

impl Sha3 {
	const DELIM: u8 = 0x06;

	/// Creates  new [`Sha3`] hasher with a security level of 224 bits.
	///
	/// [`Sha3`]: struct.Sha3.html
	pub fn v224() -> Sha3 {
		Sha3::new(224)
	}

	/// Creates  new [`Sha3`] hasher with a security level of 256 bits.
	///
	/// [`Sha3`]: struct.Sha3.html
	pub fn v256() -> Sha3 {
		Sha3::new(256)
	}

	/// Creates  new [`Sha3`] hasher with a security level of 384 bits.
	///
	/// [`Sha3`]: struct.Sha3.html
	pub fn v384() -> Sha3 {
		Sha3::new(384)
	}

	/// Creates  new [`Sha3`] hasher with a security level of 512 bits.
	///
	/// [`Sha3`]: struct.Sha3.html
	pub fn v512() -> Sha3 {
		Sha3::new(512)
	}

	fn new(bits: usize) -> Sha3 {
		Sha3 {
			state: KeccakState::new(bits_to_rate(bits), Self::DELIM),
		}
	}
}

impl Hasher for Sha3 {
	fn update(&mut self, input: &[u8]) {
		self.state.update(input);
	}

	fn finalize(self, output: &mut [u8]) {
		self.state.finalize(output);
	}
}
