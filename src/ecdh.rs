use std::ptr;
use libc;

use bindings_sha::SHA512_DIGEST_LENGTH;
use bindings_sha::SHA512;
use bindings_ecdh::ECDH_compute_key;
use bindings_ecdh::EC_KEY_get0_public_key;
use bindings_ecdh::ec_point_st;

use key::Key;

extern fn ecdh_key_derivation(
			input: *const libc::c_void,
			ilen: libc::c_ulong,
			output: *mut libc::c_void,
			olen: *mut libc::c_ulong)
	-> *mut libc::c_void
{
	unsafe {
		if *olen < KEY_LEN as u64 {
			return ptr::null_mut();
		}

		*olen = KEY_LEN as u64;
		let res = KEY_HASH(input as *const u8, ilen, output as *mut u8);
		res as *mut libc::c_void
	}
}

pub const KEY_LEN: usize = SHA512_DIGEST_LENGTH as usize;
pub const KEY_HASH: (unsafe extern "C" fn(*const u8, u64, *mut u8) -> *mut u8) = SHA512;

pub struct ECDH;

impl ECDH {
	pub fn compute_key(alice_private_key: &Key,
		               bob_public_key:    *const ec_point_st)
		-> Result<[u8; KEY_LEN], ()>
	{
		/* NOTE to self:
		 * This function does NOT ensure FORWARD SECURITY!
		 *
		 * But if we to use this function for temporary data only
		 * (ie. our current IP and port, which is kind of obvious anyway)
		 * it SHOULD be ok.
		 *
		 * We could use an ephemeral key for Alice, but what's the benefit?
		 * And when using Alice's real private key,
		 * we get authentication for free (no signature required).
		 */
		let mut key = [0 as u8; KEY_LEN];
		let expected_key_len = key.len() as u64;
	
		let actual_key_len = unsafe {
			let key_ptr = key.as_mut_ptr() as *mut libc::c_void;

			ECDH_compute_key(key_ptr, expected_key_len,
				bob_public_key, alice_private_key.as_mut_ptr(),
				Some(ecdh_key_derivation))
		} as u64;

		if actual_key_len== expected_key_len {
			Ok(key)
		} else {
			Err(())
		}
	}
}
