use std::ffi::c_str_to_bytes;
use std::ptr;

use bindings_ecdh::ec_key_st;
use bindings_ecdh::ec_point_st;
use bindings_ecdh::bignum_st;
use bindings_ecdh::EC_KEY_get0_public_key;
use bindings_ecdh::EC_KEY_new;
use bindings_ecdh::EC_KEY_free;
use bindings_ecdh::EC_KEY_set_group;
use bindings_ecdh::EC_KEY_generate_key;
use bindings_ecdh::EC_KEY_get0_private_key;
use bindings_ecdh::EC_KEY_set_public_key;
use bindings_ecdh::EC_KEY_set_private_key;
use bindings_ecdh::EC_POINT_hex2point;
use bindings_ecdh::EC_POINT_new;
use bindings_ecdh::EC_POINT_free;
use bindings_ecdh::EC_POINT_mul;
use bindings_ecdh::BN_bn2hex;
use bindings_ecdh::BN_hex2bn;
use bindings_ecdh::BN_CTX_new;
use bindings_ecdh::BN_CTX_free;
use bindings_ecdh::BN_free;

use public_key::PublicKey;
use group::Group;
use key;
use key::Key;

pub struct PrivateKey {
	ptr: *mut ec_key_st
}

impl key::Key for PrivateKey {
	fn as_mut_key_ptr(&self) -> *mut ec_key_st {
		assert!(!self.ptr.is_null());
		self.ptr
	}
}

impl PrivateKey {
	pub fn generate() -> Result<PrivateKey,()> {
		let ptr = key::new_empty_key();
		let key = PrivateKey {ptr: ptr};
		
		let res = unsafe {
			EC_KEY_generate_key(key.as_mut_key_ptr())
		};
		if res != 1 {
			return Err(());
		}

		if key.is_valid() {
			Ok(key)
		} else {
			Err(())
		}
	}

	pub fn from_vec(vec: &Vec<i8>) -> Result<PrivateKey,()> {
		let ptr = key::new_empty_key();
		let key = PrivateKey {ptr: ptr};
		let mut bn: *mut bignum_st = ptr::null_mut();

		let mut v = vec.clone();
		v.push(0);
		let res = unsafe {
			BN_hex2bn(&mut bn, v.as_ptr())
		};
		if res+1 != v.len() as i32 {
			warn!("PrivateKey::from_vec(): BN_hex2bn() returned {}", res);
			if !bn.is_null() {
				unsafe { BN_free(bn) };
			}
			return Err(());
		}

		let res = unsafe {
			EC_KEY_set_private_key(key.as_mut_key_ptr(), bn)
		};
		unsafe { BN_free(bn) };
		if res != 1 {
			warn!("PrivateKey::from_vec(): EC_KEY_set_private_key() failed");
			return Err(());
		}

		try!(key.calculate_public_key());

		if key.is_valid() {
			Ok(key)
		} else {
			warn!("PrivateKey::from_vec(): Key is invalid");
			Err(())
		}
	}

	fn calculate_public_key(&self) -> Result<(),()> {
		unsafe {
			let group = self.as_group_ptr();
			let bn = EC_KEY_get0_private_key(self.as_mut_key_ptr());
			let null = ptr::null();
			let null_mut = ptr::null_mut();

			let ctx = BN_CTX_new();
			assert!(!ctx.is_null());
			let point = EC_POINT_new(group);
			assert!(!point.is_null());

			let res = EC_POINT_mul(group, point, bn, null_mut, null, ctx);
			BN_CTX_free(ctx);

			if res != 1 {
				warn!("PrivateKey::calculate_public_key(): EC_POINT_mul() failed");
				EC_POINT_free(point);
				return Err(());
			}

			let res = EC_KEY_set_public_key(self.as_mut_key_ptr(), point);
			EC_POINT_free(point);
			if res == 1 {
				Ok(())
			} else {
				Err(())
			}
		}
	}

	pub fn to_vec(&self) -> Vec<i8> {
		unsafe {
			let bn = EC_KEY_get0_private_key(self.as_mut_key_ptr());
			assert!(!bn.is_null());

			let ptr = BN_bn2hex(bn) as *const i8;
			assert!(!ptr.is_null());

			let vec = c_str_to_bytes(&ptr).to_vec();
			//OPENSSL_free(vec); TODO
			warn!("OPENSSL_free() missing!");

			vec.map_in_place(|x|x as i8)
		}
	}

	pub fn get_public_key(&self) -> PublicKey {
		let ptr = self.as_point_ptr();
		PublicKey::from_point_ptr(ptr)
	}
}

impl Drop for PrivateKey {
	fn drop(&mut self) {
		self.key_drop();
	}
}
