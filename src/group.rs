use std::ptr;

use bindings_ecdh::ec_group_st;
use bindings_ecdh::EC_GROUP_new_by_curve_name;
use bindings_ecdh::EC_GROUP_precompute_mult;
use bindings_ecdh::EC_GROUP_set_point_conversion_form;
use bindings_ecdh::EC_GROUP_free;
use bindings_ecdh::point_conversion_form_t::POINT_CONVERSION_COMPRESSED;

const NID_secp521r1:i32 = 716;

pub struct Group {
	ptr: *mut ec_group_st,
}

impl Group {
	pub fn new() -> Group {
		let group = unsafe {
			let grp = EC_GROUP_new_by_curve_name(NID_secp521r1);
			assert!(!grp.is_null());

			let res = EC_GROUP_precompute_mult(grp, ptr::null_mut());
			assert!(res == 1);

			EC_GROUP_set_point_conversion_form(grp, POINT_CONVERSION_COMPRESSED.to_u32());

			grp
		};

		Group { ptr: group }
	}

	pub fn as_ptr(&self) -> *const ec_group_st {
		assert!(!self.ptr.is_null());
		self.ptr as *const ec_group_st
	}

	pub fn as_mut_ptr(&self) -> *mut ec_group_st {
		assert!(!self.ptr.is_null());
		self.ptr
	}
}

impl Drop for Group {
	fn drop(&mut self) {
		unsafe {
			assert!(!self.as_ptr().is_null());
			
			EC_GROUP_free(self.as_mut_ptr());
		}
	}
}
