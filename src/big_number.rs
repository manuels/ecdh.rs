use libc::c_int;
use std::ptr;

use bindings_ecdh::BN_new;
use bindings_ecdh::BN_free;
use bindings_ecdh::BN_bn2bin;
use bindings_ecdh::BN_bin2bn;
use bindings_ecdh::BN_num_bytes;
use bindings_ecdh::BN_CTX_new;
use bindings_ecdh::BN_CTX_free;
use bindings_ecdh::{bignum_ctx, bignum_st};

pub struct BigNumber {
	ptr: *mut bignum_st,
}

impl BigNumber {
	pub fn new() -> BigNumber {
		let ptr = unsafe { BN_new() };
		assert!(!ptr.is_null());

		BigNumber {
			ptr: ptr
		}
	}

	pub fn from_ptr(ptr: *mut bignum_st) -> BigNumber {
		assert!(!ptr.is_null());

		BigNumber {
			ptr: ptr
		}
	}

	pub fn from_vec(vec: &Vec<u8>) -> Result<BigNumber,()> {
        let ptr = unsafe {
        	BN_bin2bn(vec.as_ptr(), vec.len() as c_int, ptr::null_mut())
        };

        if ptr.is_null() {
        	Err(())
        } else {
        	Ok(BigNumber {ptr: ptr})
        }
	}

	pub fn as_mut_ptr(&self) -> *mut bignum_st {
		self.ptr
	}

	pub fn as_ptr(&self) -> *const bignum_st {
		self.ptr
	}

	pub fn to_vec(&self) -> Vec<u8> {
		let expected_len = unsafe {
			BN_num_bytes(self.as_mut_ptr()) as usize
		};
		let mut vec = vec![0; expected_len];

		let actual_len = unsafe {
			BN_bn2bin(self.as_ptr(), vec.as_mut_ptr())
		};
		assert_eq!(expected_len, actual_len as usize);

		vec
	}
}

impl Drop for BigNumber {
	fn drop(&mut self) {
		unsafe { BN_free(self.ptr) }
	}
}

pub struct BigNumberContext {
		ptr: *mut bignum_ctx,
}

impl BigNumberContext {
	pub fn new() -> BigNumberContext {
		let ptr = unsafe { BN_CTX_new() };
		assert!(!ptr.is_null());

		BigNumberContext {
			ptr: ptr
		}
	}

	pub fn as_ptr(&self) -> *const bignum_ctx {
		self.ptr
	}

	pub fn as_mut_ptr(&self) -> *mut bignum_ctx {
		self.ptr
	}
}

impl Drop for BigNumberContext {
	fn drop(&mut self) {
		unsafe { BN_CTX_free(self.ptr) };
	}
}
