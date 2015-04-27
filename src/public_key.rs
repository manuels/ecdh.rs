use std::ptr;
use std::ffi::CStr;

use bindings_ecdh::evp_pkey_st;
use bindings_ecdh::ec_key_st;
use bindings_ecdh::ec_point_st;
use bindings_ecdh::EC_KEY_set_public_key;
use bindings_ecdh::EC_POINT_point2hex;
use bindings_ecdh::EC_POINT_hex2point;
use bindings_ecdh::EC_POINT_free;
use bindings_ecdh::point_conversion_form_t::POINT_CONVERSION_COMPRESSED;
use bindings_ecdh::EVP_PKEY_new;
use bindings_ecdh::EVP_PKEY_free;
use bindings_ecdh::EVP_PKEY_set1_EC_KEY;

use group::Group;
use key;
use key::Key;

pub struct PublicKey {
	ptr: *mut ec_key_st
}

unsafe impl Send for PublicKey {}

impl key::Key for PublicKey {
	fn as_mut_key_ptr(&self) -> *mut ec_key_st {
		assert!(!self.ptr.is_null());
		self.ptr
	}
}

impl PublicKey {
	/// Does not takes over ownership of 'public', so you must free it
	pub fn from_point_ptr(public: *const ec_point_st) -> PublicKey {
		assert!(!public.is_null());

		let key = PublicKey {
			ptr: key::new_empty_key()
		};

		let res = unsafe {
			// EC_KEY_set_public_key() copies 'public'
			EC_KEY_set_public_key(key.as_mut_key_ptr(), public)
		};
		assert!(res == 1);

		assert!(key.is_valid());
		key
	}

	pub fn from_vec(vec: &Vec<u8>) -> Result<PublicKey,()> {
		let key = PublicKey {
			ptr: key::new_empty_key()
		};
		let group = key.as_group_ptr();

		let mut v = vec.clone();
		v.push(0);

		let point = unsafe {
			EC_POINT_hex2point(group, v.as_ptr() as *mut i8,
				ptr::null_mut(), ptr::null_mut())
		};
		if point.is_null() {
			warn!("PublicKey::from_vec(): point is NULL (len={}).", vec.len());
			return Err(());
		}

		let res = unsafe {
			// EC_KEY_set_public_key() copies 'point'
			EC_KEY_set_public_key(key.as_mut_key_ptr(), point)
		};
		if res != 1 {
			warn!("PublicKey::from_vec(): EC_KEY_set_public_key() failed");
			return Err(());
		}

		unsafe { EC_POINT_free(point) };

		if key.is_valid() {
			Ok(key)
		} else {
			Err(())
		}
	}

	pub fn to_vec(&self) -> Vec<u8> {
		assert!(self.is_valid());

		let group = self.as_group_ptr();
		let point = self.as_point_ptr();

		unsafe {
			let form = POINT_CONVERSION_COMPRESSED.to_u32();
			let ptr = EC_POINT_point2hex(group, point, form, ptr::null_mut());
			assert!(!ptr.is_null());

			CStr::from_ptr(ptr as *const i8).to_bytes().to_vec()
		}
	}

	/// WARN: YOU must free the *mut evp_pkey_st!
	pub fn to_evp_pkey(&self) -> Result<*mut evp_pkey_st,()> {
		unsafe {
			let evp = EVP_PKEY_new();
			assert!(!evp.is_null());

	  		if EVP_PKEY_set1_EC_KEY(evp, self.ptr) != 1 {
	  			EVP_PKEY_free(evp);
	  			Err(())
	  		} else {
		  		Ok(evp)
	  		}
	  	}
	}
}

impl Drop for PublicKey {
	fn drop(&mut self) {
		self.key_drop()
	}
}
