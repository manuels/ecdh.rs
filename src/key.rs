use bindings_ecdh::ec_key_st;
use bindings_ecdh::ec_point_st;
use bindings_ecdh::EC_KEY_get0_public_key;
use bindings_ecdh::EC_KEY_new;
use bindings_ecdh::EC_KEY_free;
use bindings_ecdh::EC_KEY_set_group;
use bindings_ecdh::EC_KEY_generate_key;

use group::Group;

pub struct Key {
	ptr: *mut ec_key_st
}

impl Key {
	fn new() -> Key {
		let grp = Group::new();

		let key = unsafe {
			let k = EC_KEY_new();

			EC_KEY_set_group(k, grp.as_ptr());

			let res = EC_KEY_generate_key(k);
			assert!(res == 1);

			k
		};
		drop(grp);

		Key {ptr: key }
	}

	pub fn generate() -> Result<Key,()> {
		let key = Key::new();
		
		unsafe {
			match EC_KEY_generate_key(key.as_mut_ptr()) {
				1 => Ok(key),
				_ => Err(())
			}
		}
	}

	pub fn as_ptr(&self) -> *const ec_key_st {
		assert!(!self.ptr.is_null());
		self.ptr
	}

	pub fn as_mut_ptr(&self) -> *mut ec_key_st {
		assert!(!self.ptr.is_null());
		self.ptr
	}

	pub fn public_key(&self) -> *const ec_point_st {
		unsafe {
			EC_KEY_get0_public_key(self.as_ptr())
		}
	}
}

impl Drop for Key {
	fn drop(&mut self) {
		unsafe {
			assert!(!self.as_ptr().is_null());
			EC_KEY_free(self.as_mut_ptr());
		}
	}
}
