//! The `Keccak` hash functions.

use super::{bits_to_rate, keccakf::KeccakF, Hasher, KeccakState};

#[derive(Clone)]
pub struct Keccak {
	state: KeccakState<KeccakF>,
}

impl Keccak {
	const DELIM: u8 = 0x01;

	/// Creates  new [`Keccak`] hasher with a security level of 224 bits.
	///
	/// [`Keccak`]: struct.Keccak.html
	pub fn v224() -> Keccak {
		Keccak::new(224)
	}

	/// Creates  new [`Keccak`] hasher with a security level of 256 bits.
	///
	/// [`Keccak`]: struct.Keccak.html
	pub fn v256() -> Keccak {
		Keccak::new(256)
	}

	/// Creates  new [`Keccak`] hasher with a security level of 384 bits.
	///
	/// [`Keccak`]: struct.Keccak.html
	pub fn v384() -> Keccak {
		Keccak::new(384)
	}

	/// Creates  new [`Keccak`] hasher with a security level of 512 bits.
	///
	/// [`Keccak`]: struct.Keccak.html
	pub fn v512() -> Keccak {
		Keccak::new(512)
	}

	fn new(bits: usize) -> Keccak {
		Keccak {
			state: KeccakState::new(bits_to_rate(bits), Self::DELIM),
		}
	}
}

impl Hasher for Keccak {
	/// Absorb additional input. Can be called multiple times.
	///
	/// # Example
	///
	/// ```
	/// # use tiny_keccak::{Hasher, Keccak};
	/// #
	/// # fn main() {
	/// # let mut keccak = Keccak::v256();
	/// keccak.update(b"hello");
	/// keccak.update(b" world");
	/// # }
	/// ```
	fn update(&mut self, input: &[u8]) {
		self.state.update(input);
	}

	/// Pad and squeeze the state to the output.
	///
	/// # Example
	///
	/// ```
	/// # use tiny_keccak::{Hasher, Keccak};
	/// #
	/// # fn main() {
	/// # let keccak = Keccak::v256();
	/// # let mut output = [0u8; 32];
	/// keccak.finalize(&mut output);
	/// # }
	/// #
	/// ```
	fn finalize(self, output: &mut [u8]) {
		self.state.finalize(output);
	}
}
