use bindings_ecdh::ec_point_st;
use bindings_ecdh::ec_key_st;
use bindings_ecdh::ec_group_st;
use bindings_ecdh::EC_KEY_new;
use bindings_ecdh::EC_KEY_free;
use bindings_ecdh::EC_KEY_set_group;
use bindings_ecdh::EC_KEY_get0_public_key;
use bindings_ecdh::EC_KEY_check_key;
use bindings_ecdh::EC_KEY_get0_group;
use bindings_ecdh::EC_KEY_set_asn1_flag;
use bindings_ecdh::OPENSSL_EC_NAMED_CURVE;

use group::Group;

pub fn new_empty_key() -> *mut ec_key_st {
	let grp = Group::new();

	let ptr = unsafe {
		let k = EC_KEY_new();

		EC_KEY_set_group(k, grp.as_ptr());
		EC_KEY_set_asn1_flag(k, OPENSSL_EC_NAMED_CURVE);

		k
	};
	drop(grp);

	assert!(!ptr.is_null());
	ptr
}

pub trait Key {
	fn as_key_ptr(&self) -> *const ec_key_st {
		let ptr = self.as_mut_key_ptr() as *const ec_key_st;
		assert!(!ptr.is_null());
		ptr
	}

	fn as_mut_key_ptr(&self) -> *mut ec_key_st;

	fn as_point_ptr(&self) -> *const ec_point_st {
		let ptr = unsafe {
			EC_KEY_get0_public_key(self.as_key_ptr())
		}; // to not free ptr!
		assert!(!ptr.is_null());
		ptr
	}

	fn as_group_ptr(&self) -> *const ec_group_st {
		let group = unsafe {
			EC_KEY_get0_group(self.as_key_ptr())
		};
		assert!(!group.is_null());
		group
	}

	fn key_drop(&mut self) {
		unsafe {
			assert!(!self.as_key_ptr().is_null());
			EC_KEY_free(self.as_mut_key_ptr());
		}
	}

	fn is_valid(&self) -> bool {
		1 == unsafe {
			EC_KEY_check_key(self.as_key_ptr())
		}
	}
}
