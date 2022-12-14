use crate::{EncodedLen, CShake, Hasher, IntoXof, Xof};

#[derive(Clone)]
pub struct TupleHash {
	state: CShake,
}

impl TupleHash {
	/// Creates  new [`TupleHash`] hasher with a security level of 128 bits.
	///
	/// [`TupleHash`]: struct.TupleHash.html
	pub fn v128(custom_string: &[u8]) -> TupleHash {
		TupleHash::new(custom_string, 128)
	}

	/// Creates  new [`TupleHash`] hasher with a security level of 256 bits.
	///
	/// [`TupleHash`]: struct.TupleHash.html
	pub fn v256(custom_string: &[u8]) -> TupleHash {
		TupleHash::new(custom_string, 256)
	}

	fn new(custom_string: &[u8], bits: usize) -> TupleHash {
		TupleHash {
			state: CShake::new(b"TupleHash", custom_string, bits),
		}
	}
}

impl Hasher for TupleHash {
	fn update(&mut self, input: &[u8]) {
		self.state.update(EncodedLen::left_encode(input.len() * 8).value());
		self.state.update(input)
	}

	fn finalize(mut self, output: &mut [u8]) {
		self.state.update(EncodedLen::right_encode(output.len() * 8).value());
		self.state.finalize(output)
	}
}

#[derive(Clone)]
pub struct TupleHashXof {
	state: CShake,
}

impl IntoXof for TupleHash {
	type Xof = TupleHashXof;

	fn into_xof(mut self) -> TupleHashXof {
		self.state.update(EncodedLen::right_encode(0).value());
		TupleHashXof { state: self.state }
	}
}

impl Xof for TupleHashXof {
	fn squeeze(&mut self, output: &mut [u8]) {
		self.state.squeeze(output)
	}
}
