use std::ptr;
use std::io;
use std::io::{Write,ErrorKind};
use libc;
use std::ffi::CStr;

use bindings_ecdh::ec_key_st;
use bindings_ecdh::evp_pkey_st;
use bindings_ecdh::ec_point_st;
use bindings_ecdh::bignum_st;
use bindings_ecdh::EVP_PKEY_new;
use bindings_ecdh::EVP_PKEY_free;
use bindings_ecdh::EVP_PKEY_assign_EC_KEY;
use bindings_ecdh::EVP_PKEY_set1_EC_KEY;
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
use bindings_ecdh::CRYPTO_free;
use bindings_ecdh::BIO_free;
use bindings_ecdh::BIO_read;
use bindings_ecdh::BIO_eof;
use bindings_ecdh::BIO_set_close;
use bindings_ecdh::BIO_new;
use bindings_ecdh::BIO_s_mem;

use bindings_ecdh::BIO_NOCLOSE;
use bindings_ecdh::PEM_write_bio_PrivateKey;

use public_key::PublicKey;
use group::Group;
use key;
use key::Key;
use big_number::BigNumber;
use std::mem;

pub struct PrivateKey {
	ptr: *mut ec_key_st
}

unsafe impl Send for PrivateKey {}
unsafe impl Sync for PrivateKey {}

impl key::Key for PrivateKey {
	fn as_mut_key_ptr(&self) -> *mut ec_key_st {
		assert!(!self.ptr.is_null());
		self.ptr
	}
}

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//		assert!(key.is_valid());
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

impl PrivateKey {
	pub fn generate() -> Result<PrivateKey,()> {
		let key = PrivateKey {
			ptr: key::new_empty_key()
		};
		
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

	pub fn to_pem<W>(&self, writer: &mut W) -> io::Result<usize> where W: Write {
		let evp = try!(self.to_evp_pkey()
			.map_err(|_| io::Error::new(ErrorKind::Other, "to_evp_pkey() failed")));

		// free evp, bio

		let bio = unsafe {
			let ptr = BIO_new(BIO_s_mem());
			assert!(!ptr.is_null());
			ptr
		};

		let res = unsafe {
			PEM_write_bio_PrivateKey(bio, evp, ptr::null_mut(),
			                         ptr::null_mut(), -1, ptr::null(), ptr::null_mut())
		};
		unsafe {
			EVP_PKEY_free(evp);
		};

		if res == 1 {
			let mut buf = vec![0u8; 4*1024];

			let len = unsafe {
				let len = BIO_read(bio, buf.as_mut_ptr() as *mut libc::c_void,
					buf.len() as libc::c_int);
				BIO_free(bio);
				len
			};

			if buf.len() > len as usize && len > 0 {
				buf.truncate(len as usize);
				let len = try!(writer.write(&buf[..]));
				try!(writer.flush());

				Ok(len)
			} else {
				Err(io::Error::new(ErrorKind::Other, "BIO_read() failed"))
			}
		}
		else {
			unsafe { BIO_free(bio) };
			Err(io::Error::new(ErrorKind::Other, "PEM_write_bio_PrivateKey() failed"))
		}
	}

	/// You must free this pointer!
	fn to_evp_pkey(&self) -> Result<*mut evp_pkey_st,()> {
		unsafe {
			let evp = EVP_PKEY_new();
			assert!(!evp.is_null());

	  		if EVP_PKEY_set1_EC_KEY(evp, self.ptr) == 1 {
		  		Ok(evp)
	  		} else {
	  			Err(())
	  		}
	  	}
	}

	pub fn from_vec(vec: &Vec<u8>) -> Result<PrivateKey,()> {
		let key = PrivateKey {
			ptr: key::new_empty_key()
		};
		let bn = try!(BigNumber::from_vec(vec));

		let res = unsafe {
			EC_KEY_set_private_key(key.as_mut_key_ptr(), bn.as_ptr())
		};

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
			// do not free the result of EC_KEY_get0_private_key()!
			let bn = EC_KEY_get0_private_key(self.as_mut_key_ptr());
			let group = self.as_group_ptr();

			let point = EC_POINT_new(group);
			assert!(!point.is_null());

			let res = EC_POINT_mul(group, point, bn,
				ptr::null_mut(), ptr::null(), ptr::null_mut());

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

	pub fn to_vec(&self) -> Vec<u8> {
		unsafe {
			// do not free the result of EC_KEY_get0_private_key()!
			let ptr = EC_KEY_get0_private_key(self.as_mut_key_ptr());
			let bn = BigNumber::from_ptr(ptr as *mut _);

			let vec = bn.to_vec();
			mem::forget(bn);

			vec
		}
	}

	pub fn get_public_key(&self) -> PublicKey {
		// Do not free this pointer
		let ptr = self.as_point_ptr();

		// Does not takes over ownership of 'ptr'
		PublicKey::from_point_ptr(ptr)
	}
}

impl Drop for PrivateKey {
	fn drop(&mut self) {
		self.key_drop();
	}
}
