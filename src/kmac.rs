use crate::{
	bits_to_rate, EncodedLen, CShake, Hasher, IntoXof, Xof,
};

#[derive(Clone)]
pub struct Kmac {
	state: CShake,
}

impl Kmac {
	/// Creates  new [`Kmac`] hasher with a security level of 128 bits.
	///
	/// [`Kmac`]: struct.Kmac.html
	pub fn v128(key: &[u8], custom_string: &[u8]) -> Kmac {
		Kmac::new(key, custom_string, 128)
	}

	/// Creates  new [`Kmac`] hasher with a security level of 256 bits.
	///
	/// [`Kmac`]: struct.Kmac.html
	pub fn v256(key: &[u8], custom_string: &[u8]) -> Kmac {
		Kmac::new(key, custom_string, 256)
	}

	fn new(key: &[u8], custom_string: &[u8], bits: usize) -> Kmac {
		let rate = bits_to_rate(bits);
		let mut state = CShake::new(b"KMAC", custom_string, bits);
		state.update(EncodedLen::left_encode(rate).value());
		state.update(EncodedLen::left_encode(key.len() * 8).value());
		state.update(key);
		state.fill_block();
		Kmac { state }
	}
}

impl Hasher for Kmac {
	fn update(&mut self, input: &[u8]) {
		self.state.update(input)
	}

	fn finalize(mut self, output: &mut [u8]) {
		self.state.update(EncodedLen::right_encode(output.len() * 8).value());
		self.state.finalize(output)
	}
}

#[derive(Clone)]
pub struct KmacXof {
	state: CShake,
}

impl IntoXof for Kmac {
	type Xof = KmacXof;

	fn into_xof(mut self) -> Self::Xof {
		self.state.update(EncodedLen::right_encode(0).value());
		KmacXof { state: self.state }
	}
}

impl Xof for KmacXof {
	fn squeeze(&mut self, output: &mut [u8]) {
		self.state.squeeze(output)
	}
}
