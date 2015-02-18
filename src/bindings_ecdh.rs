extern crate libc;
use std::mem;

type CRYPTO_dynlock_value = *mut i32;
/*
struct stack_st
		(int) num
		(char **) data
		(int) sorted
		(int) num_alloc
		(int (*)(const void *, const void *)) comp [int (*)(const void *, const void *)]
*/
#[repr(C)]
pub struct stack_st {
	num: libc::c_int,
	data: *mut *mut libc::c_char,
	sorted: libc::c_int,
	num_alloc: libc::c_int,
	comp: Option<extern fn(*const libc::c_void, *const libc::c_void) -> libc::c_int>,
}

/*
struct stack_st_OPENSSL_STRING
		(_STACK) stack [struct stack_st]
*/
#[repr(C)]
pub struct stack_st_OPENSSL_STRING {
	stack: stack_st,
}

/*
struct stack_st_OPENSSL_BLOCK
		(_STACK) stack [struct stack_st]
*/
#[repr(C)]
pub struct stack_st_OPENSSL_BLOCK {
	stack: stack_st,
}

/*
struct asn1_string_st
		(int) length
		(int) type
		(unsigned char *) data
		(long) flags
*/
#[repr(C)]
pub struct asn1_string_st {
	length: libc::c_int,
	type_: libc::c_int,
	data: *mut libc::c_uchar,
	flags: libc::c_long,
}

/*
struct ASN1_ITEM_st
*/
#[repr(C)]
pub struct ASN1_ITEM_st;

/*
struct asn1_pctx_st
*/
#[repr(C)]
pub struct asn1_pctx_st;

/*
struct bignum_st
		(unsigned long *) d
		(int) top
		(int) dmax
		(int) neg
		(int) flags
*/
#[repr(C)]
pub struct bignum_st {
	d: *mut libc::c_ulong,
	top: libc::c_int,
	dmax: libc::c_int,
	neg: libc::c_int,
	flags: libc::c_int,
}

/*
struct bignum_ctx
*/
#[repr(C)]
pub struct bignum_ctx;

/*
struct bn_blinding_st
*/
#[repr(C)]
pub struct bn_blinding_st;

/*
struct bn_mont_ctx_st
		(int) ri
		(BIGNUM) RR [struct bignum_st]
		(BIGNUM) N [struct bignum_st]
		(BIGNUM) Ni [struct bignum_st]
		(unsigned long [2]) n0
		(int) flags
*/
#[repr(C)]
pub struct bn_mont_ctx_st {
	ri: libc::c_int,
	RR: bignum_st,
	N: bignum_st,
	Ni: bignum_st,
	n0: [libc::c_ulong; 2],
	flags: libc::c_int,
}

/*
struct bn_recp_ctx_st
		(BIGNUM) N [struct bignum_st]
		(BIGNUM) Nr [struct bignum_st]
		(int) num_bits
		(int) shift
		(int) flags
*/
#[repr(C)]
pub struct bn_recp_ctx_st {
	N: bignum_st,
	Nr: bignum_st,
	num_bits: libc::c_int,
	shift: libc::c_int,
	flags: libc::c_int,
}

/*
struct bn_gencb_st
		(unsigned int) ver
		(void *) arg
		(union bn_gencb_st::(anonymous at /usr/include/openssl/bn.h:358:2)) 
		(union (anonymous union at /usr/include/openssl/bn.h:358:2)) cb [union bn_gencb_st::(anonymous at /usr/include/openssl/bn.h:358:2)]
*/
#[repr(C)]
pub struct bn_gencb_st {
	ver: libc::c_uint,
	arg: *mut libc::c_void,
//	_: union bn_gencb_st::(anonymous at /usr/include/openssl/bn.h:358:2),
//	cb: union bn_gencb_st::(anonymous at /usr/include/openssl/bn.h:358:2),
}

/*
struct buf_mem_st
*/
#[repr(C)]
pub struct buf_mem_st;

/*
struct evp_cipher_st
*/
#[repr(C)]
pub struct evp_cipher_st;

/*
struct evp_cipher_ctx_st
*/
#[repr(C)]
pub struct evp_cipher_ctx_st;

/*
struct env_md_st
*/
#[repr(C)]
pub struct env_md_st;

/*
struct env_md_ctx_st
*/
#[repr(C)]
pub struct env_md_ctx_st;

/*
struct evp_pkey_st
*/
#[repr(C)]
pub struct evp_pkey_st;

/*
struct evp_pkey_asn1_method_st
*/
#[repr(C)]
pub struct evp_pkey_asn1_method_st;

/*
struct evp_pkey_method_st
*/
#[repr(C)]
pub struct evp_pkey_method_st;

/*
struct evp_pkey_ctx_st
*/
#[repr(C)]
pub struct evp_pkey_ctx_st;

/*
struct dh_st
*/
#[repr(C)]
pub struct dh_st;

/*
struct dh_method
*/
#[repr(C)]
pub struct dh_method;

/*
struct dsa_st
*/
#[repr(C)]
pub struct dsa_st;

/*
struct dsa_method
*/
#[repr(C)]
pub struct dsa_method;

/*
struct rsa_st
*/
#[repr(C)]
pub struct rsa_st;

/*
struct rsa_meth_st
*/
#[repr(C)]
pub struct rsa_meth_st;

/*
struct rand_meth_st
*/
#[repr(C)]
pub struct rand_meth_st;

/*
struct ecdh_method
*/
#[repr(C)]
pub struct ecdh_method;

/*
struct ecdsa_method
*/
#[repr(C)]
pub struct ecdsa_method;

/*
struct x509_st
*/
#[repr(C)]
pub struct x509_st;

/*
struct X509_algor_st
*/
#[repr(C)]
pub struct X509_algor_st;

/*
struct X509_crl_st
*/
#[repr(C)]
pub struct X509_crl_st;

/*
struct x509_crl_method_st
*/
#[repr(C)]
pub struct x509_crl_method_st;

/*
struct x509_revoked_st
*/
#[repr(C)]
pub struct x509_revoked_st;

/*
struct X509_name_st
*/
#[repr(C)]
pub struct X509_name_st;

/*
struct X509_pubkey_st
*/
#[repr(C)]
pub struct X509_pubkey_st;

/*
struct x509_store_st
*/
#[repr(C)]
pub struct x509_store_st;

/*
struct x509_store_ctx_st
*/
#[repr(C)]
pub struct x509_store_ctx_st;

/*
struct pkcs8_priv_key_info_st
*/
#[repr(C)]
pub struct pkcs8_priv_key_info_st;

/*
struct v3_ext_ctx
*/
#[repr(C)]
pub struct v3_ext_ctx;

/*
struct conf_st
*/
#[repr(C)]
pub struct conf_st;

/*
struct store_st
*/
#[repr(C)]
pub struct store_st;

/*
struct store_method_st
*/
#[repr(C)]
pub struct store_method_st;

/*
struct ui_st
*/
#[repr(C)]
pub struct ui_st;

/*
struct ui_method_st
*/
#[repr(C)]
pub struct ui_method_st;

/*
struct st_ERR_FNS
*/
#[repr(C)]
pub struct st_ERR_FNS;

/*
struct engine_st
*/
#[repr(C)]
pub struct engine_st;

/*
struct ssl_st
*/
#[repr(C)]
pub struct ssl_st;

/*
struct ssl_ctx_st
*/
#[repr(C)]
pub struct ssl_ctx_st;

/*
struct X509_POLICY_NODE_st
*/
#[repr(C)]
pub struct X509_POLICY_NODE_st;

/*
struct X509_POLICY_LEVEL_st
*/
#[repr(C)]
pub struct X509_POLICY_LEVEL_st;

/*
struct X509_POLICY_TREE_st
*/
#[repr(C)]
pub struct X509_POLICY_TREE_st;

/*
struct X509_POLICY_CACHE_st
*/
#[repr(C)]
pub struct X509_POLICY_CACHE_st;

/*
struct AUTHORITY_KEYID_st
*/
#[repr(C)]
pub struct AUTHORITY_KEYID_st;

/*
struct DIST_POINT_st
*/
#[repr(C)]
pub struct DIST_POINT_st;

/*
struct ISSUING_DIST_POINT_st
*/
#[repr(C)]
pub struct ISSUING_DIST_POINT_st;

/*
struct NAME_CONSTRAINTS_st
*/
#[repr(C)]
pub struct NAME_CONSTRAINTS_st;

/*
struct crypto_ex_data_st
		(struct stack_st_void) stack_st_void
		(struct stack_st_void *) sk [struct stack_st_void *]
		(int) dummy
*/
#[repr(C)]
pub struct crypto_ex_data_st {
	stack_st_void: stack_st_void,
	sk: *mut stack_st_void,
	dummy: libc::c_int,
}

/*
struct ocsp_req_ctx_st
*/
#[repr(C)]
pub struct ocsp_req_ctx_st;

/*
struct ocsp_response_st
*/
#[repr(C)]
pub struct ocsp_response_st;

/*
struct ocsp_responder_id_st
*/
#[repr(C)]
pub struct ocsp_responder_id_st;

/*
struct openssl_item_st
		(int) code
		(void *) value
		(size_t) value_size [unsigned long]
		(size_t *) value_length [unsigned long *]
*/
#[repr(C)]
pub struct openssl_item_st {
	code: libc::c_int,
	value: *mut libc::c_void,
	value_size: libc::c_ulong,
	value_length: *mut libc::c_ulong,
}

/*
struct 
		(int) references
		(struct CRYPTO_dynlock_value) CRYPTO_dynlock_value
		(struct CRYPTO_dynlock_value *) data [struct CRYPTO_dynlock_value *]
#[repr(C)]
pub struct  {
	references: libc::c_int,
	CRYPTO_dynlock_value: CRYPTO_dynlock_value,
	data: *mut CRYPTO_dynlock_value,
}
*/

/*
struct bio_st
		(BIO_METHOD *) method [struct bio_method_st *]
		(long (*)(struct bio_st *, int, const char *, int, long, long)) callback [long (*)(struct bio_st *, int, const char *, int, long, long)]
		(char *) cb_arg
		(int) init
		(int) shutdown
		(int) flags
		(int) retry_reason
		(int) num
		(void *) ptr
		(struct bio_st *) next_bio [struct bio_st *]
		(struct bio_st *) prev_bio [struct bio_st *]
		(int) references
		(unsigned long) num_read
		(unsigned long) num_write
		(CRYPTO_EX_DATA) ex_data [struct crypto_ex_data_st]
*/
#[repr(C)]
pub struct bio_st {
	method: *mut bio_method_st,
	callback: Option<extern fn(*mut bio_st, libc::c_int, *const libc::c_char, libc::c_int, libc::c_long, libc::c_long) -> libc::c_long>,
	cb_arg: *mut libc::c_char,
	init: libc::c_int,
	shutdown: libc::c_int,
	flags: libc::c_int,
	retry_reason: libc::c_int,
	num: libc::c_int,
	ptr: *mut libc::c_void,
	next_bio: *mut bio_st,
	prev_bio: *mut bio_st,
	references: libc::c_int,
	num_read: libc::c_ulong,
	num_write: libc::c_ulong,
	ex_data: crypto_ex_data_st,
}

/*
struct stack_st_void
		(_STACK) stack [struct stack_st]
*/
#[repr(C)]
pub struct stack_st_void {
	stack: stack_st,
}

/*
struct crypto_ex_data_func_st
		(long) argl
		(void *) argp
		(CRYPTO_EX_new *) new_func [int (*)(void *, void *, struct crypto_ex_data_st *, int, long, void *)]
		(CRYPTO_EX_free *) free_func [void (*)(void *, void *, struct crypto_ex_data_st *, int, long, void *)]
		(CRYPTO_EX_dup *) dup_func [int (*)(struct crypto_ex_data_st *, struct crypto_ex_data_st *, void *, int, long, void *)]
*/
#[repr(C)]
pub struct crypto_ex_data_func_st {
	argl: libc::c_long,
	argp: *mut libc::c_void,
	new_func: Option<extern fn(*mut libc::c_void, *mut libc::c_void, *mut crypto_ex_data_st, libc::c_int, libc::c_long, *mut libc::c_void) -> libc::c_int>,
	free_func: Option<extern fn(*mut libc::c_void, *mut libc::c_void, *mut crypto_ex_data_st, libc::c_int, libc::c_long, *mut libc::c_void)>,
	dup_func: Option<extern fn(*mut crypto_ex_data_st, *mut crypto_ex_data_st, *mut libc::c_void, libc::c_int, libc::c_long, *mut libc::c_void) -> libc::c_int>,
}

/*
struct stack_st_CRYPTO_EX_DATA_FUNCS
		(_STACK) stack [struct stack_st]
*/
#[repr(C)]
pub struct stack_st_CRYPTO_EX_DATA_FUNCS {
	stack: stack_st,
}

/*
struct st_CRYPTO_EX_DATA_IMPL
*/
#[repr(C)]
pub struct st_CRYPTO_EX_DATA_IMPL;

/*
struct crypto_threadid_st
		(void *) ptr
		(unsigned long) val
*/
#[repr(C)]
pub struct crypto_threadid_st {
	ptr: *mut libc::c_void,
	val: libc::c_ulong,
}

/*
struct bio_method_st
		(int) type
		(const char *) name
		(int (*)(BIO *, const char *, int)) bwrite [int (*)(struct bio_st *, const char *, int)]
		(int (*)(BIO *, char *, int)) bread [int (*)(struct bio_st *, char *, int)]
		(int (*)(BIO *, const char *)) bputs [int (*)(struct bio_st *, const char *)]
		(int (*)(BIO *, char *, int)) bgets [int (*)(struct bio_st *, char *, int)]
		(long (*)(BIO *, int, long, void *)) ctrl [long (*)(struct bio_st *, int, long, void *)]
		(int (*)(BIO *)) create [int (*)(struct bio_st *)]
		(int (*)(BIO *)) destroy [int (*)(struct bio_st *)]
		(long (*)(BIO *, int, bio_info_cb *)) callback_ctrl [long (*)(struct bio_st *, int, void (*)(struct bio_st *, int, const char *, int, long, long))]
*/
#[repr(C)]
pub struct bio_method_st {
	type_: libc::c_int,
	name: *const libc::c_char,
	bwrite: Option<extern fn(*mut bio_st, *const libc::c_char, libc::c_int) -> libc::c_int>,
	bread: Option<extern fn(*mut bio_st, *mut libc::c_char, libc::c_int) -> libc::c_int>,
	bputs: Option<extern fn(*mut bio_st, *const libc::c_char) -> libc::c_int>,
	bgets: Option<extern fn(*mut bio_st, *mut libc::c_char, libc::c_int) -> libc::c_int>,
	ctrl: Option<extern fn(*mut bio_st, libc::c_int, libc::c_long, *mut libc::c_void) -> libc::c_long>,
	create: Option<extern fn(*mut bio_st) -> libc::c_int>,
	destroy: Option<extern fn(*mut bio_st) -> libc::c_int>,
	callback_ctrl: Option<extern fn(*mut bio_st, libc::c_int, Option<extern fn(*mut bio_st, libc::c_int, *const libc::c_char, libc::c_int, libc::c_long, libc::c_long)>) -> libc::c_long>,
}

/*
struct stack_st_BIO
		(_STACK) stack [struct stack_st]
*/
#[repr(C)]
pub struct stack_st_BIO {
	stack: stack_st,
}

/*
struct bio_f_buffer_ctx_struct
		(int) ibuf_size
		(int) obuf_size
		(char *) ibuf
		(int) ibuf_len
		(int) ibuf_off
		(char *) obuf
		(int) obuf_len
		(int) obuf_off
*/
#[repr(C)]
pub struct bio_f_buffer_ctx_struct {
	ibuf_size: libc::c_int,
	obuf_size: libc::c_int,
	ibuf: *mut libc::c_char,
	ibuf_len: libc::c_int,
	ibuf_off: libc::c_int,
	obuf: *mut libc::c_char,
	obuf_len: libc::c_int,
	obuf_off: libc::c_int,
}

/*
struct hostent
*/
#[repr(C)]
pub struct hostent;

/*
struct stack_st_X509_ALGOR
		(_STACK) stack [struct stack_st]
*/
#[repr(C)]
pub struct stack_st_X509_ALGOR {
	stack: stack_st,
}

/*
struct asn1_ctx_st
		(unsigned char *) p
		(int) eos
		(int) error
		(int) inf
		(int) tag
		(int) xclass
		(long) slen
		(unsigned char *) max
		(unsigned char *) q
		(unsigned char **) pp
		(int) line
*/
#[repr(C)]
pub struct asn1_ctx_st {
	p: *mut libc::c_uchar,
	eos: libc::c_int,
	error: libc::c_int,
	inf: libc::c_int,
	tag: libc::c_int,
	xclass: libc::c_int,
	slen: libc::c_long,
	max: *mut libc::c_uchar,
	q: *mut libc::c_uchar,
	pp: *mut *mut libc::c_uchar,
	line: libc::c_int,
}

/*
struct asn1_const_ctx_st
		(const unsigned char *) p
		(int) eos
		(int) error
		(int) inf
		(int) tag
		(int) xclass
		(long) slen
		(const unsigned char *) max
		(const unsigned char *) q
		(const unsigned char **) pp
		(int) line
*/
#[repr(C)]
pub struct asn1_const_ctx_st {
	p: *const libc::c_uchar,
	eos: libc::c_int,
	error: libc::c_int,
	inf: libc::c_int,
	tag: libc::c_int,
	xclass: libc::c_int,
	slen: libc::c_long,
	max: *const libc::c_uchar,
	q: *const libc::c_uchar,
	pp: *mut *const libc::c_uchar,
	line: libc::c_int,
}

/*
struct asn1_object_st
		(const char *) sn
		(const char *) ln
		(int) nid
		(int) length
		(const unsigned char *) data
		(int) flags
*/
#[repr(C)]
pub struct asn1_object_st {
	sn: *const libc::c_char,
	ln: *const libc::c_char,
	nid: libc::c_int,
	length: libc::c_int,
	data: *const libc::c_uchar,
	flags: libc::c_int,
}

/*
struct ASN1_ENCODING_st
		(unsigned char *) enc
		(long) len
		(int) modified
*/
#[repr(C)]
pub struct ASN1_ENCODING_st {
	enc: *mut libc::c_uchar,
	len: libc::c_long,
	modified: libc::c_int,
}

/*
struct asn1_string_table_st
		(int) nid
		(long) minsize
		(long) maxsize
		(unsigned long) mask
		(unsigned long) flags
*/
#[repr(C)]
pub struct asn1_string_table_st {
	nid: libc::c_int,
	minsize: libc::c_long,
	maxsize: libc::c_long,
	mask: libc::c_ulong,
	flags: libc::c_ulong,
}

/*
struct stack_st_ASN1_STRING_TABLE
		(_STACK) stack [struct stack_st]
*/
#[repr(C)]
pub struct stack_st_ASN1_STRING_TABLE {
	stack: stack_st,
}

/*
struct ASN1_TEMPLATE_st
*/
#[repr(C)]
pub struct ASN1_TEMPLATE_st;

/*
struct ASN1_TLC_st
*/
#[repr(C)]
pub struct ASN1_TLC_st;

/*
struct ASN1_VALUE_st
*/
#[repr(C)]
pub struct ASN1_VALUE_st;

/*
struct stack_st_ASN1_INTEGER
		(_STACK) stack [struct stack_st]
*/
#[repr(C)]
pub struct stack_st_ASN1_INTEGER {
	stack: stack_st,
}

/*
struct stack_st_ASN1_GENERALSTRING
		(_STACK) stack [struct stack_st]
*/
#[repr(C)]
pub struct stack_st_ASN1_GENERALSTRING {
	stack: stack_st,
}

/*
struct asn1_type_st
		(int) type
		(union asn1_type_st::(anonymous at /usr/include/openssl/asn1.h:524:2)) 
		(union (anonymous union at /usr/include/openssl/asn1.h:524:2)) value [union asn1_type_st::(anonymous at /usr/include/openssl/asn1.h:524:2)]
*/
#[repr(C)]
pub struct asn1_type_st {
	type_: libc::c_int,
//	_: union asn1_type_st::(anonymous at /usr/include/openssl/asn1.h:524:2),
//	value: union asn1_type_st::(anonymous at /usr/include/openssl/asn1.h:524:2),
}

/*
struct stack_st_ASN1_TYPE
		(_STACK) stack [struct stack_st]
*/
#[repr(C)]
pub struct stack_st_ASN1_TYPE {
	stack: stack_st,
}

/*
struct NETSCAPE_X509_st
		(ASN1_OCTET_STRING *) header [struct asn1_string_st *]
		(X509 *) cert [struct x509_st *]
*/
#[repr(C)]
pub struct NETSCAPE_X509_st {
	header: *mut asn1_string_st,
	cert: *mut x509_st,
}

/*
struct BIT_STRING_BITNAME_st
		(int) bitnum
		(const char *) lname
		(const char *) sname
*/
#[repr(C)]
pub struct BIT_STRING_BITNAME_st {
	bitnum: libc::c_int,
	lname: *const libc::c_char,
	sname: *const libc::c_char,
}

/*
struct stack_st_ASN1_OBJECT
		(_STACK) stack [struct stack_st]
*/
#[repr(C)]
pub struct stack_st_ASN1_OBJECT {
	stack: stack_st,
}

/*
struct ec_method_st
*/
#[repr(C)]
pub struct ec_method_st;

/*
struct ec_group_st
*/
#[repr(C)]
pub struct ec_group_st;

/*
struct ec_point_st
*/
#[repr(C)]
pub struct ec_point_st;

/*
struct 
		(int) nid
		(const char *) comment
#[repr(C)]
pub struct  {
	nid: libc::c_int,
	comment: *const libc::c_char,
}
*/

/*
struct ecpk_parameters_st
*/
#[repr(C)]
pub struct ecpk_parameters_st;

/*
struct ec_key_st
*/
#[repr(C)]
pub struct ec_key_st;

/*
struct _STACK
		(int) num
		(char **) data
		(int) sorted
		(int) num_alloc
		(int (*)(const void *, const void *)) comp [int (*)(const void *, const void *)]
*/
#[repr(C)]
pub struct _STACK {
	num: libc::c_int,
	data: *mut *mut libc::c_char,
	sorted: libc::c_int,
	num_alloc: libc::c_int,
	comp: Option<extern fn(*const libc::c_void, *const libc::c_void) -> libc::c_int>,
}

/*
struct CRYPTO_EX_DATA_IMPL
*/
#[repr(C)]
pub struct CRYPTO_EX_DATA_IMPL;

/*
struct CRYPTO_EX_DATA
		(struct stack_st_void) stack_st_void
		(struct stack_st_void *) sk [struct stack_st_void *]
		(int) dummy
*/
#[repr(C)]
pub struct CRYPTO_EX_DATA {
	stack_st_void: stack_st_void,
	sk: *mut stack_st_void,
	dummy: libc::c_int,
}

/*
struct CRYPTO_THREADID
		(void *) ptr
		(unsigned long) val
*/
#[repr(C)]
pub struct CRYPTO_THREADID {
	ptr: *mut libc::c_void,
	val: libc::c_ulong,
}

/*
struct FILE
		(int) _flags
		(char *) _IO_read_ptr
		(char *) _IO_read_end
		(char *) _IO_read_base
		(char *) _IO_write_base
		(char *) _IO_write_ptr
		(char *) _IO_write_end
		(char *) _IO_buf_base
		(char *) _IO_buf_end
		(char *) _IO_save_base
		(char *) _IO_backup_base
		(char *) _IO_save_end
		(struct _IO_marker *) _markers [struct _IO_marker *]
		(struct _IO_FILE *) _chain [struct _IO_FILE *]
		(int) _fileno
		(int) _flags2
		(__off_t) _old_offset [long]
		(unsigned short) _cur_column
		(signed char) _vtable_offset
		(char [1]) _shortbuf
		(_IO_lock_t *) _lock [void *]
		(__off64_t) _offset [long]
		(void *) __pad1
		(void *) __pad2
		(void *) __pad3
		(void *) __pad4
		(size_t) __pad5 [unsigned long]
		(int) _mode
		(char [20]) _unused2
*/
#[repr(C)]
pub struct FILE {
	_flags: libc::c_int,
	_IO_read_ptr: *mut libc::c_char,
	_IO_read_end: *mut libc::c_char,
	_IO_read_base: *mut libc::c_char,
	_IO_write_base: *mut libc::c_char,
	_IO_write_ptr: *mut libc::c_char,
	_IO_write_end: *mut libc::c_char,
	_IO_buf_base: *mut libc::c_char,
	_IO_buf_end: *mut libc::c_char,
	_IO_save_base: *mut libc::c_char,
	_IO_backup_base: *mut libc::c_char,
	_IO_save_end: *mut libc::c_char,
	//_markers: *mut _IO_marker,
	_chain: libc::c_int,
	_fileno: libc::c_int,
	_flags2: libc::c_int,
	_old_offset: libc::c_long,
	_cur_column: libc::c_ushort,
	_vtable_offset: libc::c_char,
	_shortbuf: [libc::c_char; 1],
	_lock: *mut libc::c_void,
	_offset: libc::c_long,
	__pad1: *mut libc::c_void,
	__pad2: *mut libc::c_void,
	__pad3: *mut libc::c_void,
	__pad4: *mut libc::c_void,
	__pad5: libc::c_ulong,
	_mode: libc::c_int,
	_unused2: [libc::c_char; 20],
}

/*
struct BIO
		(BIO_METHOD *) method [struct bio_method_st *]
		(long (*)(struct bio_st *, int, const char *, int, long, long)) callback [long (*)(struct bio_st *, int, const char *, int, long, long)]
		(char *) cb_arg
		(int) init
		(int) shutdown
		(int) flags
		(int) retry_reason
		(int) num
		(void *) ptr
		(struct bio_st *) next_bio [struct bio_st *]
		(struct bio_st *) prev_bio [struct bio_st *]
		(int) references
		(unsigned long) num_read
		(unsigned long) num_write
		(CRYPTO_EX_DATA) ex_data [struct crypto_ex_data_st]
*/
#[repr(C)]
pub struct BIO {
	method: *mut bio_method_st,
	callback: Option<extern fn(*mut bio_st, libc::c_int, *const libc::c_char, libc::c_int, libc::c_long, libc::c_long) -> libc::c_long>,
	cb_arg: *mut libc::c_char,
	init: libc::c_int,
	shutdown: libc::c_int,
	flags: libc::c_int,
	retry_reason: libc::c_int,
	num: libc::c_int,
	ptr: *mut libc::c_void,
	next_bio: *mut bio_st,
	prev_bio: *mut bio_st,
	references: libc::c_int,
	num_read: libc::c_ulong,
	num_write: libc::c_ulong,
	ex_data: crypto_ex_data_st,
}

/*
struct BIO_METHOD
		(int) type
		(const char *) name
		(int (*)(BIO *, const char *, int)) bwrite [int (*)(struct bio_st *, const char *, int)]
		(int (*)(BIO *, char *, int)) bread [int (*)(struct bio_st *, char *, int)]
		(int (*)(BIO *, const char *)) bputs [int (*)(struct bio_st *, const char *)]
		(int (*)(BIO *, char *, int)) bgets [int (*)(struct bio_st *, char *, int)]
		(long (*)(BIO *, int, long, void *)) ctrl [long (*)(struct bio_st *, int, long, void *)]
		(int (*)(BIO *)) create [int (*)(struct bio_st *)]
		(int (*)(BIO *)) destroy [int (*)(struct bio_st *)]
		(long (*)(BIO *, int, bio_info_cb *)) callback_ctrl [long (*)(struct bio_st *, int, void (*)(struct bio_st *, int, const char *, int, long, long))]
*/
#[repr(C)]
pub struct BIO_METHOD {
	type_: libc::c_int,
	name: *const libc::c_char,
	bwrite: Option<extern fn(*mut bio_st, *const libc::c_char, libc::c_int) -> libc::c_int>,
	bread: Option<extern fn(*mut bio_st, *mut libc::c_char, libc::c_int) -> libc::c_int>,
	bputs: Option<extern fn(*mut bio_st, *const libc::c_char) -> libc::c_int>,
	bgets: Option<extern fn(*mut bio_st, *mut libc::c_char, libc::c_int) -> libc::c_int>,
	ctrl: Option<extern fn(*mut bio_st, libc::c_int, libc::c_long, *mut libc::c_void) -> libc::c_long>,
	create: Option<extern fn(*mut bio_st) -> libc::c_int>,
	destroy: Option<extern fn(*mut bio_st) -> libc::c_int>,
	callback_ctrl: Option<extern fn(*mut bio_st, libc::c_int, Option<extern fn(*mut bio_st, libc::c_int, *const libc::c_char, libc::c_int, libc::c_long, libc::c_long)>) -> libc::c_long>,
}

/*
struct BN_GENCB
		(unsigned int) ver
		(void *) arg
		(union bn_gencb_st::(anonymous at /usr/include/openssl/bn.h:358:2)) 
		(union (anonymous union at /usr/include/openssl/bn.h:358:2)) cb [union bn_gencb_st::(anonymous at /usr/include/openssl/bn.h:358:2)]
*/
#[repr(C)]
pub struct BN_GENCB {
	ver: libc::c_uint,
	arg: *mut libc::c_void,
//	_: union bn_gencb_st::(anonymous at /usr/include/openssl/bn.h:358:2),
//	cb: union bn_gencb_st::(anonymous at /usr/include/openssl/bn.h:358:2),
}

/*
struct BN_CTX
*/
#[repr(C)]
pub struct BN_CTX;

/*
struct BIGNUM
		(unsigned long *) d
		(int) top
		(int) dmax
		(int) neg
		(int) flags
*/
#[repr(C)]
pub struct BIGNUM {
	d: *mut libc::c_ulong,
	top: libc::c_int,
	dmax: libc::c_int,
	neg: libc::c_int,
	flags: libc::c_int,
}

/*
struct BN_MONT_CTX
		(int) ri
		(BIGNUM) RR [struct bignum_st]
		(BIGNUM) N [struct bignum_st]
		(BIGNUM) Ni [struct bignum_st]
		(unsigned long [2]) n0
		(int) flags
*/
#[repr(C)]
pub struct BN_MONT_CTX {
	ri: libc::c_int,
	RR: bignum_st,
	N: bignum_st,
	Ni: bignum_st,
	n0: [libc::c_ulong; 2],
	flags: libc::c_int,
}

/*
struct BN_BLINDING
*/
#[repr(C)]
pub struct BN_BLINDING;

/*
struct BN_RECP_CTX
		(BIGNUM) N [struct bignum_st]
		(BIGNUM) Nr [struct bignum_st]
		(int) num_bits
		(int) shift
		(int) flags
*/
#[repr(C)]
pub struct BN_RECP_CTX {
	N: bignum_st,
	Nr: bignum_st,
	num_bits: libc::c_int,
	shift: libc::c_int,
	flags: libc::c_int,
}

/*
struct ASN1_SEQUENCE_ANY
		(_STACK) stack [struct stack_st]
*/
#[repr(C)]
pub struct ASN1_SEQUENCE_ANY {
	stack: stack_st,
}

/*
struct ASN1_TYPE
		(int) type
		(union asn1_type_st::(anonymous at /usr/include/openssl/asn1.h:524:2)) 
		(union (anonymous union at /usr/include/openssl/asn1.h:524:2)) value [union asn1_type_st::(anonymous at /usr/include/openssl/asn1.h:524:2)]
*/
#[repr(C)]
pub struct ASN1_TYPE {
	type_: libc::c_int,
//	_: union asn1_type_st::(anonymous at /usr/include/openssl/asn1.h:524:2),
//	value: union asn1_type_st::(anonymous at /usr/include/openssl/asn1.h:524:2),
}

/*
struct ASN1_OBJECT
		(const char *) sn
		(const char *) ln
		(int) nid
		(int) length
		(const unsigned char *) data
		(int) flags
*/
#[repr(C)]
pub struct ASN1_OBJECT {
	sn: *const libc::c_char,
	ln: *const libc::c_char,
	nid: libc::c_int,
	length: libc::c_int,
	data: *const libc::c_uchar,
	flags: libc::c_int,
}

/*
struct ASN1_STRING
		(int) length
		(int) type
		(unsigned char *) data
		(long) flags
*/
#[repr(C)]
pub struct ASN1_STRING {
	length: libc::c_int,
	type_: libc::c_int,
	data: *mut libc::c_uchar,
	flags: libc::c_long,
}

/*
struct ASN1_BIT_STRING
		(int) length
		(int) type
		(unsigned char *) data
		(long) flags
*/
#[repr(C)]
pub struct ASN1_BIT_STRING {
	length: libc::c_int,
	type_: libc::c_int,
	data: *mut libc::c_uchar,
	flags: libc::c_long,
}

/*
struct BIT_STRING_BITNAME
		(int) bitnum
		(const char *) lname
		(const char *) sname
*/
#[repr(C)]
pub struct BIT_STRING_BITNAME {
	bitnum: libc::c_int,
	lname: *const libc::c_char,
	sname: *const libc::c_char,
}

/*
struct ASN1_INTEGER
		(int) length
		(int) type
		(unsigned char *) data
		(long) flags
*/
#[repr(C)]
pub struct ASN1_INTEGER {
	length: libc::c_int,
	type_: libc::c_int,
	data: *mut libc::c_uchar,
	flags: libc::c_long,
}

/*
struct ASN1_ENUMERATED
		(int) length
		(int) type
		(unsigned char *) data
		(long) flags
*/
#[repr(C)]
pub struct ASN1_ENUMERATED {
	length: libc::c_int,
	type_: libc::c_int,
	data: *mut libc::c_uchar,
	flags: libc::c_long,
}

/*
struct ASN1_UTCTIME
		(int) length
		(int) type
		(unsigned char *) data
		(long) flags
*/
#[repr(C)]
pub struct ASN1_UTCTIME {
	length: libc::c_int,
	type_: libc::c_int,
	data: *mut libc::c_uchar,
	flags: libc::c_long,
}

/*
struct ASN1_GENERALIZEDTIME
		(int) length
		(int) type
		(unsigned char *) data
		(long) flags
*/
#[repr(C)]
pub struct ASN1_GENERALIZEDTIME {
	length: libc::c_int,
	type_: libc::c_int,
	data: *mut libc::c_uchar,
	flags: libc::c_long,
}

/*
struct ASN1_OCTET_STRING
		(int) length
		(int) type
		(unsigned char *) data
		(long) flags
*/
#[repr(C)]
pub struct ASN1_OCTET_STRING {
	length: libc::c_int,
	type_: libc::c_int,
	data: *mut libc::c_uchar,
	flags: libc::c_long,
}

/*
struct ASN1_VISIBLESTRING
		(int) length
		(int) type
		(unsigned char *) data
		(long) flags
*/
#[repr(C)]
pub struct ASN1_VISIBLESTRING {
	length: libc::c_int,
	type_: libc::c_int,
	data: *mut libc::c_uchar,
	flags: libc::c_long,
}

/*
struct ASN1_UNIVERSALSTRING
		(int) length
		(int) type
		(unsigned char *) data
		(long) flags
*/
#[repr(C)]
pub struct ASN1_UNIVERSALSTRING {
	length: libc::c_int,
	type_: libc::c_int,
	data: *mut libc::c_uchar,
	flags: libc::c_long,
}

/*
struct ASN1_UTF8STRING
		(int) length
		(int) type
		(unsigned char *) data
		(long) flags
*/
#[repr(C)]
pub struct ASN1_UTF8STRING {
	length: libc::c_int,
	type_: libc::c_int,
	data: *mut libc::c_uchar,
	flags: libc::c_long,
}

/*
struct ASN1_BMPSTRING
		(int) length
		(int) type
		(unsigned char *) data
		(long) flags
*/
#[repr(C)]
pub struct ASN1_BMPSTRING {
	length: libc::c_int,
	type_: libc::c_int,
	data: *mut libc::c_uchar,
	flags: libc::c_long,
}

/*
struct ASN1_PRINTABLESTRING
		(int) length
		(int) type
		(unsigned char *) data
		(long) flags
*/
#[repr(C)]
pub struct ASN1_PRINTABLESTRING {
	length: libc::c_int,
	type_: libc::c_int,
	data: *mut libc::c_uchar,
	flags: libc::c_long,
}

/*
struct ASN1_T61STRING
		(int) length
		(int) type
		(unsigned char *) data
		(long) flags
*/
#[repr(C)]
pub struct ASN1_T61STRING {
	length: libc::c_int,
	type_: libc::c_int,
	data: *mut libc::c_uchar,
	flags: libc::c_long,
}

/*
struct ASN1_IA5STRING
		(int) length
		(int) type
		(unsigned char *) data
		(long) flags
*/
#[repr(C)]
pub struct ASN1_IA5STRING {
	length: libc::c_int,
	type_: libc::c_int,
	data: *mut libc::c_uchar,
	flags: libc::c_long,
}

/*
struct ASN1_GENERALSTRING
		(int) length
		(int) type
		(unsigned char *) data
		(long) flags
*/
#[repr(C)]
pub struct ASN1_GENERALSTRING {
	length: libc::c_int,
	type_: libc::c_int,
	data: *mut libc::c_uchar,
	flags: libc::c_long,
}

/*
struct ASN1_TIME
		(int) length
		(int) type
		(unsigned char *) data
		(long) flags
*/
#[repr(C)]
pub struct ASN1_TIME {
	length: libc::c_int,
	type_: libc::c_int,
	data: *mut libc::c_uchar,
	flags: libc::c_long,
}

/*
struct ASN1_CTX
		(unsigned char *) p
		(int) eos
		(int) error
		(int) inf
		(int) tag
		(int) xclass
		(long) slen
		(unsigned char *) max
		(unsigned char *) q
		(unsigned char **) pp
		(int) line
*/
#[repr(C)]
pub struct ASN1_CTX {
	p: *mut libc::c_uchar,
	eos: libc::c_int,
	error: libc::c_int,
	inf: libc::c_int,
	tag: libc::c_int,
	xclass: libc::c_int,
	slen: libc::c_long,
	max: *mut libc::c_uchar,
	q: *mut libc::c_uchar,
	pp: *mut *mut libc::c_uchar,
	line: libc::c_int,
}

/*
struct ASN1_const_CTX
		(const unsigned char *) p
		(int) eos
		(int) error
		(int) inf
		(int) tag
		(int) xclass
		(long) slen
		(const unsigned char *) max
		(const unsigned char *) q
		(const unsigned char **) pp
		(int) line
*/
#[repr(C)]
pub struct ASN1_const_CTX {
	p: *const libc::c_uchar,
	eos: libc::c_int,
	error: libc::c_int,
	inf: libc::c_int,
	tag: libc::c_int,
	xclass: libc::c_int,
	slen: libc::c_long,
	max: *const libc::c_uchar,
	q: *const libc::c_uchar,
	pp: *mut *const libc::c_uchar,
	line: libc::c_int,
}

/*
struct ASN1_ITEM
*/
#[repr(C)]
pub struct ASN1_ITEM;

/*
struct NETSCAPE_X509
		(ASN1_OCTET_STRING *) header [struct asn1_string_st *]
		(X509 *) cert [struct x509_st *]
*/
#[repr(C)]
pub struct NETSCAPE_X509 {
	header: *mut asn1_string_st,
	cert: *mut x509_st,
}

/*
struct ASN1_VALUE
*/
#[repr(C)]
pub struct ASN1_VALUE;

/*
struct CONF
*/
#[repr(C)]
pub struct CONF;

/*
struct X509V3_CTX
*/
#[repr(C)]
pub struct X509V3_CTX;

/*
struct ASN1_PCTX
*/
#[repr(C)]
pub struct ASN1_PCTX;

/*
struct EC_METHOD
*/
#[repr(C)]
pub struct EC_METHOD;

/*
struct EC_GROUP
*/
#[repr(C)]
pub struct EC_GROUP;

/*
struct EC_POINT
*/
#[repr(C)]
pub struct EC_POINT;

/*
struct EC_builtin_curve
		(int) nid
		(const char *) comment
*/
#[repr(C)]
pub struct EC_builtin_curve {
	nid: libc::c_int,
	comment: *const libc::c_char,
}

/*
struct EC_KEY
*/
#[repr(C)]
pub struct EC_KEY;

/*
struct ECDH_METHOD
*/
#[repr(C)]
pub struct ECDH_METHOD;

/*
int sk_num()
	(const _STACK *)  [const struct stack_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_num(_: *const stack_st) -> libc::c_int;
}


/*
void * sk_value()
	(const _STACK *)  [const struct stack_st *]
	(int) 
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_value(_: *const stack_st, _: libc::c_int) -> *mut libc::c_void;
}


/*
void * sk_set()
	(_STACK *)  [struct stack_st *]
	(int) 
	(void *) 
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_set(_: *mut stack_st, _: libc::c_int, _: *mut libc::c_void) -> *mut libc::c_void;
}


/*
_STACK * sk_new() [struct stack_st *]
	(int (*)(const void *, const void *)) cmp [int (*)(const void *, const void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_new(cmp: Option<extern fn(*const libc::c_void, *const libc::c_void) -> libc::c_int>) -> *mut stack_st;
}


/*
_STACK * sk_new_null() [struct stack_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_new_null() -> *mut stack_st;
}


/*
void sk_free()
	(_STACK *)  [struct stack_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_free(_: *mut stack_st);
}


/*
void sk_pop_free()
	(_STACK *) st [struct stack_st *]
	(void (*)(void *)) func [void (*)(void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_pop_free(st: *mut stack_st, func: Option<extern fn(*mut libc::c_void)>);
}


/*
int sk_insert()
	(_STACK *) sk [struct stack_st *]
	(void *) data
	(int) where
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_insert(sk: *mut stack_st, data: *mut libc::c_void, where_: libc::c_int) -> libc::c_int;
}


/*
void * sk_delete()
	(_STACK *) st [struct stack_st *]
	(int) loc
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_delete(st: *mut stack_st, loc: libc::c_int) -> *mut libc::c_void;
}


/*
void * sk_delete_ptr()
	(_STACK *) st [struct stack_st *]
	(void *) p
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_delete_ptr(st: *mut stack_st, p: *mut libc::c_void) -> *mut libc::c_void;
}


/*
int sk_find()
	(_STACK *) st [struct stack_st *]
	(void *) data
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_find(st: *mut stack_st, data: *mut libc::c_void) -> libc::c_int;
}


/*
int sk_find_ex()
	(_STACK *) st [struct stack_st *]
	(void *) data
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_find_ex(st: *mut stack_st, data: *mut libc::c_void) -> libc::c_int;
}


/*
int sk_push()
	(_STACK *) st [struct stack_st *]
	(void *) data
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_push(st: *mut stack_st, data: *mut libc::c_void) -> libc::c_int;
}


/*
int sk_unshift()
	(_STACK *) st [struct stack_st *]
	(void *) data
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_unshift(st: *mut stack_st, data: *mut libc::c_void) -> libc::c_int;
}


/*
void * sk_shift()
	(_STACK *) st [struct stack_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_shift(st: *mut stack_st) -> *mut libc::c_void;
}


/*
void * sk_pop()
	(_STACK *) st [struct stack_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_pop(st: *mut stack_st) -> *mut libc::c_void;
}


/*
void sk_zero()
	(_STACK *) st [struct stack_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_zero(st: *mut stack_st);
}


/*
int (*)(const void *, const void *) sk_set_cmp_func() [int (*)(const void *, const void *)]
	(_STACK *) sk [struct stack_st *]
	(int (*)(const void *, const void *)) c [int (*)(const void *, const void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_set_cmp_func(sk: *mut stack_st, c: Option<extern fn(*const libc::c_void, *const libc::c_void) -> libc::c_int>) -> Option<extern fn(*const libc::c_void, *const libc::c_void) -> libc::c_int>;
}


/*
_STACK * sk_dup() [struct stack_st *]
	(_STACK *) st [struct stack_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_dup(st: *mut stack_st) -> *mut stack_st;
}


/*
void sk_sort()
	(_STACK *) st [struct stack_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_sort(st: *mut stack_st);
}


/*
int sk_is_sorted()
	(const _STACK *) st [const struct stack_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn sk_is_sorted(st: *const stack_st) -> libc::c_int;
}


/*
int CRYPTO_mem_ctrl()
	(int) mode
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_mem_ctrl(mode: libc::c_int) -> libc::c_int;
}


/*
int CRYPTO_is_mem_check_on()
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_is_mem_check_on() -> libc::c_int;
}


/*
const char * SSLeay_version()
	(int) type
*/
#[link(name="crypto")]
extern "C" {
	pub fn SSLeay_version(type_: libc::c_int) -> *const libc::c_char;
}


/*
unsigned long SSLeay()
*/
#[link(name="crypto")]
extern "C" {
	pub fn SSLeay() -> libc::c_ulong;
}


/*
int OPENSSL_issetugid()
*/
#[link(name="crypto")]
extern "C" {
	pub fn OPENSSL_issetugid() -> libc::c_int;
}


/*
const CRYPTO_EX_DATA_IMPL * CRYPTO_get_ex_data_implementation() [const struct st_CRYPTO_EX_DATA_IMPL *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_ex_data_implementation() -> *const st_CRYPTO_EX_DATA_IMPL;
}


/*
int CRYPTO_set_ex_data_implementation()
	(const CRYPTO_EX_DATA_IMPL *) i [const struct st_CRYPTO_EX_DATA_IMPL *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_set_ex_data_implementation(i: *const st_CRYPTO_EX_DATA_IMPL) -> libc::c_int;
}


/*
int CRYPTO_ex_data_new_class()
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_ex_data_new_class() -> libc::c_int;
}


/*
int CRYPTO_get_ex_new_index()
	(int) class_index
	(long) argl
	(void *) argp
	(CRYPTO_EX_new *) new_func [int (*)(void *, void *, struct crypto_ex_data_st *, int, long, void *)]
	(CRYPTO_EX_dup *) dup_func [int (*)(struct crypto_ex_data_st *, struct crypto_ex_data_st *, void *, int, long, void *)]
	(CRYPTO_EX_free *) free_func [void (*)(void *, void *, struct crypto_ex_data_st *, int, long, void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_ex_new_index(class_index: libc::c_int, argl: libc::c_long, argp: *mut libc::c_void, new_func: Option<extern fn(*mut libc::c_void, *mut libc::c_void, *mut crypto_ex_data_st, libc::c_int, libc::c_long, *mut libc::c_void) -> libc::c_int>, dup_func: Option<extern fn(*mut crypto_ex_data_st, *mut crypto_ex_data_st, *mut libc::c_void, libc::c_int, libc::c_long, *mut libc::c_void) -> libc::c_int>, free_func: Option<extern fn(*mut libc::c_void, *mut libc::c_void, *mut crypto_ex_data_st, libc::c_int, libc::c_long, *mut libc::c_void)>) -> libc::c_int;
}


/*
int CRYPTO_new_ex_data()
	(int) class_index
	(void *) obj
	(CRYPTO_EX_DATA *) ad [struct crypto_ex_data_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_new_ex_data(class_index: libc::c_int, obj: *mut libc::c_void, ad: *mut crypto_ex_data_st) -> libc::c_int;
}


/*
int CRYPTO_dup_ex_data()
	(int) class_index
	(CRYPTO_EX_DATA *) to [struct crypto_ex_data_st *]
	(CRYPTO_EX_DATA *) from [struct crypto_ex_data_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_dup_ex_data(class_index: libc::c_int, to: *mut crypto_ex_data_st, from: *mut crypto_ex_data_st) -> libc::c_int;
}


/*
void CRYPTO_free_ex_data()
	(int) class_index
	(void *) obj
	(CRYPTO_EX_DATA *) ad [struct crypto_ex_data_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_free_ex_data(class_index: libc::c_int, obj: *mut libc::c_void, ad: *mut crypto_ex_data_st);
}


/*
int CRYPTO_set_ex_data()
	(CRYPTO_EX_DATA *) ad [struct crypto_ex_data_st *]
	(int) idx
	(void *) val
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_set_ex_data(ad: *mut crypto_ex_data_st, idx: libc::c_int, val: *mut libc::c_void) -> libc::c_int;
}


/*
void * CRYPTO_get_ex_data()
	(const CRYPTO_EX_DATA *) ad [const struct crypto_ex_data_st *]
	(int) idx
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_ex_data(ad: *const crypto_ex_data_st, idx: libc::c_int) -> *mut libc::c_void;
}


/*
void CRYPTO_cleanup_all_ex_data()
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_cleanup_all_ex_data();
}


/*
int CRYPTO_get_new_lockid()
	(char *) name
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_new_lockid(name: *mut libc::c_char) -> libc::c_int;
}


/*
int CRYPTO_num_locks()
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_num_locks() -> libc::c_int;
}


/*
void CRYPTO_lock()
	(int) mode
	(int) type
	(const char *) file
	(int) line
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_lock(mode: libc::c_int, type_: libc::c_int, file: *const libc::c_char, line: libc::c_int);
}


/*
void CRYPTO_set_locking_callback()
	(void (*)(int, int, const char *, int)) func [void (*)(int, int, const char *, int)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_set_locking_callback(func: Option<extern fn(libc::c_int, libc::c_int, *const libc::c_char, libc::c_int)>);
}


/*
void (*)(int, int, const char *, int) CRYPTO_get_locking_callback() [void (*)(int, int, const char *, int)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_locking_callback() -> Option<extern fn(libc::c_int, libc::c_int, *const libc::c_char, libc::c_int)>;
}


/*
void CRYPTO_set_add_lock_callback()
	(int (*)(int *, int, int, const char *, int)) func [int (*)(int *, int, int, const char *, int)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_set_add_lock_callback(func: Option<extern fn(*mut libc::c_int, libc::c_int, libc::c_int, *const libc::c_char, libc::c_int) -> libc::c_int>);
}


/*
int (*)(int *, int, int, const char *, int) CRYPTO_get_add_lock_callback() [int (*)(int *, int, int, const char *, int)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_add_lock_callback() -> Option<extern fn(*mut libc::c_int, libc::c_int, libc::c_int, *const libc::c_char, libc::c_int) -> libc::c_int>;
}


/*
void CRYPTO_THREADID_set_numeric()
	(CRYPTO_THREADID *) id [struct crypto_threadid_st *]
	(unsigned long) val
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_THREADID_set_numeric(id: *mut crypto_threadid_st, val: libc::c_ulong);
}


/*
void CRYPTO_THREADID_set_pointer()
	(CRYPTO_THREADID *) id [struct crypto_threadid_st *]
	(void *) ptr
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_THREADID_set_pointer(id: *mut crypto_threadid_st, ptr: *mut libc::c_void);
}


/*
int CRYPTO_THREADID_set_callback()
	(void (*)(CRYPTO_THREADID *)) threadid_func [void (*)(struct crypto_threadid_st *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_THREADID_set_callback(threadid_func: Option<extern fn(*mut crypto_threadid_st)>) -> libc::c_int;
}


/*
void (*)(CRYPTO_THREADID *) CRYPTO_THREADID_get_callback() [void (*)(struct crypto_threadid_st *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_THREADID_get_callback() -> Option<extern fn(*mut crypto_threadid_st)>;
}


/*
void CRYPTO_THREADID_current()
	(CRYPTO_THREADID *) id [struct crypto_threadid_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_THREADID_current(id: *mut crypto_threadid_st);
}


/*
int CRYPTO_THREADID_cmp()
	(const CRYPTO_THREADID *) a [const struct crypto_threadid_st *]
	(const CRYPTO_THREADID *) b [const struct crypto_threadid_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_THREADID_cmp(a: *const crypto_threadid_st, b: *const crypto_threadid_st) -> libc::c_int;
}


/*
void CRYPTO_THREADID_cpy()
	(CRYPTO_THREADID *) dest [struct crypto_threadid_st *]
	(const CRYPTO_THREADID *) src [const struct crypto_threadid_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_THREADID_cpy(dest: *mut crypto_threadid_st, src: *const crypto_threadid_st);
}


/*
unsigned long CRYPTO_THREADID_hash()
	(const CRYPTO_THREADID *) id [const struct crypto_threadid_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_THREADID_hash(id: *const crypto_threadid_st) -> libc::c_ulong;
}


/*
void CRYPTO_set_id_callback()
	(unsigned long (*)(void)) func [unsigned long (*)(void)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_set_id_callback(func: Option<extern fn() -> libc::c_ulong>);
}


/*
unsigned long (*)(void) CRYPTO_get_id_callback() [unsigned long (*)(void)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_id_callback() -> Option<extern fn() -> libc::c_ulong>;
}


/*
unsigned long CRYPTO_thread_id()
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_thread_id() -> libc::c_ulong;
}


/*
const char * CRYPTO_get_lock_name()
	(int) type
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_lock_name(type_: libc::c_int) -> *const libc::c_char;
}


/*
int CRYPTO_add_lock()
	(int *) pointer
	(int) amount
	(int) type
	(const char *) file
	(int) line
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_add_lock(pointer: *mut libc::c_int, amount: libc::c_int, type_: libc::c_int, file: *const libc::c_char, line: libc::c_int) -> libc::c_int;
}


/*
int CRYPTO_get_new_dynlockid()
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_new_dynlockid() -> libc::c_int;
}


/*
void CRYPTO_destroy_dynlockid()
	(int) i
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_destroy_dynlockid(i: libc::c_int);
}


/*
struct CRYPTO_dynlock_value * CRYPTO_get_dynlock_value() [struct CRYPTO_dynlock_value *]
	(int) i
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_dynlock_value(i: libc::c_int) -> *mut CRYPTO_dynlock_value;
}


/*
void CRYPTO_set_dynlock_create_callback()
	(struct CRYPTO_dynlock_value *(*)(const char *, int)) dyn_create_function [struct CRYPTO_dynlock_value *(*)(const char *, int)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_set_dynlock_create_callback(dyn_create_function: Option<extern fn(*const libc::c_char, libc::c_int) -> *mut CRYPTO_dynlock_value>);
}


/*
void CRYPTO_set_dynlock_lock_callback()
	(void (*)(int, struct CRYPTO_dynlock_value *, const char *, int)) dyn_lock_function [void (*)(int, struct CRYPTO_dynlock_value *, const char *, int)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_set_dynlock_lock_callback(dyn_lock_function: Option<extern fn(libc::c_int, *mut CRYPTO_dynlock_value, *const libc::c_char, libc::c_int)>);
}


/*
void CRYPTO_set_dynlock_destroy_callback()
	(void (*)(struct CRYPTO_dynlock_value *, const char *, int)) dyn_destroy_function [void (*)(struct CRYPTO_dynlock_value *, const char *, int)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function: Option<extern fn(*mut CRYPTO_dynlock_value, *const libc::c_char, libc::c_int)>);
}


/*
struct CRYPTO_dynlock_value *(*)(const char *, int) CRYPTO_get_dynlock_create_callback() [struct CRYPTO_dynlock_value *(*)(const char *, int)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_dynlock_create_callback() -> Option<extern fn(*const libc::c_char, libc::c_int) -> *mut CRYPTO_dynlock_value>;
}


/*
void (*)(int, struct CRYPTO_dynlock_value *, const char *, int) CRYPTO_get_dynlock_lock_callback() [void (*)(int, struct CRYPTO_dynlock_value *, const char *, int)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_dynlock_lock_callback() -> Option<extern fn(libc::c_int, *mut CRYPTO_dynlock_value, *const libc::c_char, libc::c_int)>;
}


/*
void (*)(struct CRYPTO_dynlock_value *, const char *, int) CRYPTO_get_dynlock_destroy_callback() [void (*)(struct CRYPTO_dynlock_value *, const char *, int)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_dynlock_destroy_callback() -> Option<extern fn(*mut CRYPTO_dynlock_value, *const libc::c_char, libc::c_int)>;
}


/*
int CRYPTO_set_mem_functions()
	(void *(*)(size_t)) m [void *(*)(unsigned long)]
	(void *(*)(void *, size_t)) r [void *(*)(void *, unsigned long)]
	(void (*)(void *)) f [void (*)(void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_set_mem_functions(m: Option<extern fn(libc::c_ulong) -> *mut libc::c_void>, r: Option<extern fn(*mut libc::c_void, libc::c_ulong) -> *mut libc::c_void>, f: Option<extern fn(*mut libc::c_void)>) -> libc::c_int;
}


/*
int CRYPTO_set_locked_mem_functions()
	(void *(*)(size_t)) m [void *(*)(unsigned long)]
	(void (*)(void *)) free_func [void (*)(void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_set_locked_mem_functions(m: Option<extern fn(libc::c_ulong) -> *mut libc::c_void>, free_func: Option<extern fn(*mut libc::c_void)>) -> libc::c_int;
}


/*
int CRYPTO_set_mem_ex_functions()
	(void *(*)(size_t, const char *, int)) m [void *(*)(unsigned long, const char *, int)]
	(void *(*)(void *, size_t, const char *, int)) r [void *(*)(void *, unsigned long, const char *, int)]
	(void (*)(void *)) f [void (*)(void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_set_mem_ex_functions(m: Option<extern fn(libc::c_ulong, *const libc::c_char, libc::c_int) -> *mut libc::c_void>, r: Option<extern fn(*mut libc::c_void, libc::c_ulong, *const libc::c_char, libc::c_int) -> *mut libc::c_void>, f: Option<extern fn(*mut libc::c_void)>) -> libc::c_int;
}


/*
int CRYPTO_set_locked_mem_ex_functions()
	(void *(*)(size_t, const char *, int)) m [void *(*)(unsigned long, const char *, int)]
	(void (*)(void *)) free_func [void (*)(void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_set_locked_mem_ex_functions(m: Option<extern fn(libc::c_ulong, *const libc::c_char, libc::c_int) -> *mut libc::c_void>, free_func: Option<extern fn(*mut libc::c_void)>) -> libc::c_int;
}


/*
int CRYPTO_set_mem_debug_functions()
	(void (*)(void *, int, const char *, int, int)) m [void (*)(void *, int, const char *, int, int)]
	(void (*)(void *, void *, int, const char *, int, int)) r [void (*)(void *, void *, int, const char *, int, int)]
	(void (*)(void *, int)) f [void (*)(void *, int)]
	(void (*)(long)) so [void (*)(long)]
	(long (*)(void)) go [long (*)(void)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_set_mem_debug_functions(m: Option<extern fn(*mut libc::c_void, libc::c_int, *const libc::c_char, libc::c_int, libc::c_int)>, r: Option<extern fn(*mut libc::c_void, *mut libc::c_void, libc::c_int, *const libc::c_char, libc::c_int, libc::c_int)>, f: Option<extern fn(*mut libc::c_void, libc::c_int)>, so: Option<extern fn(libc::c_long)>, go: Option<extern fn() -> libc::c_long>) -> libc::c_int;
}


/*
void CRYPTO_get_mem_functions()
	(void *(**)(size_t)) m [void *(**)(unsigned long)]
	(void *(**)(void *, size_t)) r [void *(**)(void *, unsigned long)]
	(void (**)(void *)) f [void (**)(void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_mem_functions(m: *mut Option<extern fn(libc::c_ulong) -> *mut libc::c_void>, r: *mut Option<extern fn(*mut libc::c_void, libc::c_ulong) -> *mut libc::c_void>, f: *mut Option<extern fn(*mut libc::c_void)>);
}


/*
void CRYPTO_get_locked_mem_functions()
	(void *(**)(size_t)) m [void *(**)(unsigned long)]
	(void (**)(void *)) f [void (**)(void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_locked_mem_functions(m: *mut Option<extern fn(libc::c_ulong) -> *mut libc::c_void>, f: *mut Option<extern fn(*mut libc::c_void)>);
}


/*
void CRYPTO_get_mem_ex_functions()
	(void *(**)(size_t, const char *, int)) m [void *(**)(unsigned long, const char *, int)]
	(void *(**)(void *, size_t, const char *, int)) r [void *(**)(void *, unsigned long, const char *, int)]
	(void (**)(void *)) f [void (**)(void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_mem_ex_functions(m: *mut Option<extern fn(libc::c_ulong, *const libc::c_char, libc::c_int) -> *mut libc::c_void>, r: *mut Option<extern fn(*mut libc::c_void, libc::c_ulong, *const libc::c_char, libc::c_int) -> *mut libc::c_void>, f: *mut Option<extern fn(*mut libc::c_void)>);
}


/*
void CRYPTO_get_locked_mem_ex_functions()
	(void *(**)(size_t, const char *, int)) m [void *(**)(unsigned long, const char *, int)]
	(void (**)(void *)) f [void (**)(void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_locked_mem_ex_functions(m: *mut Option<extern fn(libc::c_ulong, *const libc::c_char, libc::c_int) -> *mut libc::c_void>, f: *mut Option<extern fn(*mut libc::c_void)>);
}


/*
void CRYPTO_get_mem_debug_functions()
	(void (**)(void *, int, const char *, int, int)) m [void (**)(void *, int, const char *, int, int)]
	(void (**)(void *, void *, int, const char *, int, int)) r [void (**)(void *, void *, int, const char *, int, int)]
	(void (**)(void *, int)) f [void (**)(void *, int)]
	(void (**)(long)) so [void (**)(long)]
	(long (**)(void)) go [long (**)(void)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_mem_debug_functions(m: *mut Option<extern fn(*mut libc::c_void, libc::c_int, *const libc::c_char, libc::c_int, libc::c_int)>, r: *mut Option<extern fn(*mut libc::c_void, *mut libc::c_void, libc::c_int, *const libc::c_char, libc::c_int, libc::c_int)>, f: *mut Option<extern fn(*mut libc::c_void, libc::c_int)>, so: *mut Option<extern fn(libc::c_long)>, go: *mut Option<extern fn() -> libc::c_long>);
}


/*
void * CRYPTO_malloc_locked()
	(int) num
	(const char *) file
	(int) line
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_malloc_locked(num: libc::c_int, file: *const libc::c_char, line: libc::c_int) -> *mut libc::c_void;
}


/*
void CRYPTO_free_locked()
	(void *) ptr
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_free_locked(ptr: *mut libc::c_void);
}


/*
void * CRYPTO_malloc()
	(int) num
	(const char *) file
	(int) line
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_malloc(num: libc::c_int, file: *const libc::c_char, line: libc::c_int) -> *mut libc::c_void;
}


/*
char * CRYPTO_strdup()
	(const char *) str
	(const char *) file
	(int) line
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_strdup(str: *const libc::c_char, file: *const libc::c_char, line: libc::c_int) -> *mut libc::c_char;
}


/*
void CRYPTO_free()
	(void *) ptr
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_free(ptr: *mut libc::c_void);
}


/*
void * CRYPTO_realloc()
	(void *) addr
	(int) num
	(const char *) file
	(int) line
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_realloc(addr: *mut libc::c_void, num: libc::c_int, file: *const libc::c_char, line: libc::c_int) -> *mut libc::c_void;
}


/*
void * CRYPTO_realloc_clean()
	(void *) addr
	(int) old_num
	(int) num
	(const char *) file
	(int) line
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_realloc_clean(addr: *mut libc::c_void, old_num: libc::c_int, num: libc::c_int, file: *const libc::c_char, line: libc::c_int) -> *mut libc::c_void;
}


/*
void * CRYPTO_remalloc()
	(void *) addr
	(int) num
	(const char *) file
	(int) line
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_remalloc(addr: *mut libc::c_void, num: libc::c_int, file: *const libc::c_char, line: libc::c_int) -> *mut libc::c_void;
}


/*
void OPENSSL_cleanse()
	(void *) ptr
	(size_t) len [unsigned long]
*/
#[link(name="crypto")]
extern "C" {
	pub fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: libc::c_ulong);
}


/*
void CRYPTO_set_mem_debug_options()
	(long) bits
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_set_mem_debug_options(bits: libc::c_long);
}


/*
long CRYPTO_get_mem_debug_options()
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_get_mem_debug_options() -> libc::c_long;
}


/*
int CRYPTO_push_info_()
	(const char *) info
	(const char *) file
	(int) line
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_push_info_(info: *const libc::c_char, file: *const libc::c_char, line: libc::c_int) -> libc::c_int;
}


/*
int CRYPTO_pop_info()
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_pop_info() -> libc::c_int;
}


/*
int CRYPTO_remove_all_info()
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_remove_all_info() -> libc::c_int;
}


/*
void CRYPTO_dbg_malloc()
	(void *) addr
	(int) num
	(const char *) file
	(int) line
	(int) before_p
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_dbg_malloc(addr: *mut libc::c_void, num: libc::c_int, file: *const libc::c_char, line: libc::c_int, before_p: libc::c_int);
}


/*
void CRYPTO_dbg_realloc()
	(void *) addr1
	(void *) addr2
	(int) num
	(const char *) file
	(int) line
	(int) before_p
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_dbg_realloc(addr1: *mut libc::c_void, addr2: *mut libc::c_void, num: libc::c_int, file: *const libc::c_char, line: libc::c_int, before_p: libc::c_int);
}


/*
void CRYPTO_dbg_free()
	(void *) addr
	(int) before_p
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_dbg_free(addr: *mut libc::c_void, before_p: libc::c_int);
}


/*
void CRYPTO_dbg_set_options()
	(long) bits
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_dbg_set_options(bits: libc::c_long);
}


/*
long CRYPTO_dbg_get_options()
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_dbg_get_options() -> libc::c_long;
}


/*
void CRYPTO_mem_leaks_fp()
	(FILE *)  [struct _IO_FILE *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_mem_leaks_fp(_: libc::c_int);
}


/*
void CRYPTO_mem_leaks()
	(struct bio_st *) bio [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_mem_leaks(bio: *mut bio_st);
}


/*
void CRYPTO_mem_leaks_cb()
	(CRYPTO_MEM_LEAK_CB *) cb [void *(*)(unsigned long, const char *, int, int, void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_mem_leaks_cb(cb: Option<extern fn(libc::c_ulong, *const libc::c_char, libc::c_int, libc::c_int, *mut libc::c_void) -> *mut libc::c_void>);
}


/*
void OpenSSLDie()
	(const char *) file
	(int) line
	(const char *) assertion
*/
#[link(name="crypto")]
extern "C" {
	pub fn OpenSSLDie(file: *const libc::c_char, line: libc::c_int, assertion: *const libc::c_char);
}


/*
unsigned long * OPENSSL_ia32cap_loc()
*/
#[link(name="crypto")]
extern "C" {
	pub fn OPENSSL_ia32cap_loc() -> *mut libc::c_ulong;
}


/*
int OPENSSL_isservice()
*/
#[link(name="crypto")]
extern "C" {
	pub fn OPENSSL_isservice() -> libc::c_int;
}


/*
int FIPS_mode()
*/
#[link(name="crypto")]
extern "C" {
	pub fn FIPS_mode() -> libc::c_int;
}


/*
int FIPS_mode_set()
	(int) r
*/
#[link(name="crypto")]
extern "C" {
	pub fn FIPS_mode_set(r: libc::c_int) -> libc::c_int;
}


/*
void OPENSSL_init()
*/
#[link(name="crypto")]
extern "C" {
	pub fn OPENSSL_init();
}


/*
int CRYPTO_memcmp()
	(const void *) a
	(const void *) b
	(size_t) len [unsigned long]
*/
#[link(name="crypto")]
extern "C" {
	pub fn CRYPTO_memcmp(a: *const libc::c_void, b: *const libc::c_void, len: libc::c_ulong) -> libc::c_int;
}


/*
void ERR_load_CRYPTO_strings()
*/
#[link(name="crypto")]
extern "C" {
	pub fn ERR_load_CRYPTO_strings();
}


/*
void BIO_set_flags()
	(BIO *) b [struct bio_st *]
	(int) flags
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_set_flags(b: *mut bio_st, flags: libc::c_int);
}


/*
int BIO_test_flags()
	(const BIO *) b [const struct bio_st *]
	(int) flags
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_test_flags(b: *const bio_st, flags: libc::c_int) -> libc::c_int;
}


/*
void BIO_clear_flags()
	(BIO *) b [struct bio_st *]
	(int) flags
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_clear_flags(b: *mut bio_st, flags: libc::c_int);
}


/*
long (*)(struct bio_st *, int, const char *, int, long, long) BIO_get_callback() [long (*)(struct bio_st *, int, const char *, int, long, long)]
	(const BIO *) b [const struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_get_callback(b: *const bio_st) -> Option<extern fn(*mut bio_st, libc::c_int, *const libc::c_char, libc::c_int, libc::c_long, libc::c_long) -> libc::c_long>;
}


/*
void BIO_set_callback()
	(BIO *) b [struct bio_st *]
	(long (*)(struct bio_st *, int, const char *, int, long, long)) callback [long (*)(struct bio_st *, int, const char *, int, long, long)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_set_callback(b: *mut bio_st, callback: Option<extern fn(*mut bio_st, libc::c_int, *const libc::c_char, libc::c_int, libc::c_long, libc::c_long) -> libc::c_long>);
}


/*
char * BIO_get_callback_arg()
	(const BIO *) b [const struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_get_callback_arg(b: *const bio_st) -> *mut libc::c_char;
}


/*
void BIO_set_callback_arg()
	(BIO *) b [struct bio_st *]
	(char *) arg
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_set_callback_arg(b: *mut bio_st, arg: *mut libc::c_char);
}


/*
const char * BIO_method_name()
	(const BIO *) b [const struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_method_name(b: *const bio_st) -> *const libc::c_char;
}


/*
int BIO_method_type()
	(const BIO *) b [const struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_method_type(b: *const bio_st) -> libc::c_int;
}


/*
size_t BIO_ctrl_pending() [unsigned long]
	(BIO *) b [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_ctrl_pending(b: *mut bio_st) -> libc::c_ulong;
}


/*
size_t BIO_ctrl_wpending() [unsigned long]
	(BIO *) b [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_ctrl_wpending(b: *mut bio_st) -> libc::c_ulong;
}


/*
size_t BIO_ctrl_get_write_guarantee() [unsigned long]
	(BIO *) b [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_ctrl_get_write_guarantee(b: *mut bio_st) -> libc::c_ulong;
}


/*
size_t BIO_ctrl_get_read_request() [unsigned long]
	(BIO *) b [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_ctrl_get_read_request(b: *mut bio_st) -> libc::c_ulong;
}


/*
int BIO_ctrl_reset_read_request()
	(BIO *) b [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_ctrl_reset_read_request(b: *mut bio_st) -> libc::c_int;
}


/*
int BIO_set_ex_data()
	(BIO *) bio [struct bio_st *]
	(int) idx
	(void *) data
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_set_ex_data(bio: *mut bio_st, idx: libc::c_int, data: *mut libc::c_void) -> libc::c_int;
}


/*
void * BIO_get_ex_data()
	(BIO *) bio [struct bio_st *]
	(int) idx
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_get_ex_data(bio: *mut bio_st, idx: libc::c_int) -> *mut libc::c_void;
}


/*
int BIO_get_ex_new_index()
	(long) argl
	(void *) argp
	(CRYPTO_EX_new *) new_func [int (*)(void *, void *, struct crypto_ex_data_st *, int, long, void *)]
	(CRYPTO_EX_dup *) dup_func [int (*)(struct crypto_ex_data_st *, struct crypto_ex_data_st *, void *, int, long, void *)]
	(CRYPTO_EX_free *) free_func [void (*)(void *, void *, struct crypto_ex_data_st *, int, long, void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_get_ex_new_index(argl: libc::c_long, argp: *mut libc::c_void, new_func: Option<extern fn(*mut libc::c_void, *mut libc::c_void, *mut crypto_ex_data_st, libc::c_int, libc::c_long, *mut libc::c_void) -> libc::c_int>, dup_func: Option<extern fn(*mut crypto_ex_data_st, *mut crypto_ex_data_st, *mut libc::c_void, libc::c_int, libc::c_long, *mut libc::c_void) -> libc::c_int>, free_func: Option<extern fn(*mut libc::c_void, *mut libc::c_void, *mut crypto_ex_data_st, libc::c_int, libc::c_long, *mut libc::c_void)>) -> libc::c_int;
}


/*
unsigned long BIO_number_read()
	(BIO *) bio [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_number_read(bio: *mut bio_st) -> libc::c_ulong;
}


/*
unsigned long BIO_number_written()
	(BIO *) bio [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_number_written(bio: *mut bio_st) -> libc::c_ulong;
}


/*
int BIO_asn1_set_prefix()
	(BIO *) b [struct bio_st *]
	(asn1_ps_func *) prefix [int (*)(struct bio_st *, unsigned char **, int *, void *)]
	(asn1_ps_func *) prefix_free [int (*)(struct bio_st *, unsigned char **, int *, void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_asn1_set_prefix(b: *mut bio_st, prefix: Option<extern fn(*mut bio_st, *mut *mut libc::c_uchar, *mut libc::c_int, *mut libc::c_void) -> libc::c_int>, prefix_free: Option<extern fn(*mut bio_st, *mut *mut libc::c_uchar, *mut libc::c_int, *mut libc::c_void) -> libc::c_int>) -> libc::c_int;
}


/*
int BIO_asn1_get_prefix()
	(BIO *) b [struct bio_st *]
	(asn1_ps_func **) pprefix [int (**)(struct bio_st *, unsigned char **, int *, void *)]
	(asn1_ps_func **) pprefix_free [int (**)(struct bio_st *, unsigned char **, int *, void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_asn1_get_prefix(b: *mut bio_st, pprefix: *mut Option<extern fn(*mut bio_st, *mut *mut libc::c_uchar, *mut libc::c_int, *mut libc::c_void) -> libc::c_int>, pprefix_free: *mut Option<extern fn(*mut bio_st, *mut *mut libc::c_uchar, *mut libc::c_int, *mut libc::c_void) -> libc::c_int>) -> libc::c_int;
}


/*
int BIO_asn1_set_suffix()
	(BIO *) b [struct bio_st *]
	(asn1_ps_func *) suffix [int (*)(struct bio_st *, unsigned char **, int *, void *)]
	(asn1_ps_func *) suffix_free [int (*)(struct bio_st *, unsigned char **, int *, void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_asn1_set_suffix(b: *mut bio_st, suffix: Option<extern fn(*mut bio_st, *mut *mut libc::c_uchar, *mut libc::c_int, *mut libc::c_void) -> libc::c_int>, suffix_free: Option<extern fn(*mut bio_st, *mut *mut libc::c_uchar, *mut libc::c_int, *mut libc::c_void) -> libc::c_int>) -> libc::c_int;
}


/*
int BIO_asn1_get_suffix()
	(BIO *) b [struct bio_st *]
	(asn1_ps_func **) psuffix [int (**)(struct bio_st *, unsigned char **, int *, void *)]
	(asn1_ps_func **) psuffix_free [int (**)(struct bio_st *, unsigned char **, int *, void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_asn1_get_suffix(b: *mut bio_st, psuffix: *mut Option<extern fn(*mut bio_st, *mut *mut libc::c_uchar, *mut libc::c_int, *mut libc::c_void) -> libc::c_int>, psuffix_free: *mut Option<extern fn(*mut bio_st, *mut *mut libc::c_uchar, *mut libc::c_int, *mut libc::c_void) -> libc::c_int>) -> libc::c_int;
}


/*
BIO_METHOD * BIO_s_file() [struct bio_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_s_file() -> *mut bio_method_st;
}


/*
BIO * BIO_new_file() [struct bio_st *]
	(const char *) filename
	(const char *) mode
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_new_file(filename: *const libc::c_char, mode: *const libc::c_char) -> *mut bio_st;
}


/*
BIO * BIO_new_fp() [struct bio_st *]
	(FILE *) stream [struct _IO_FILE *]
	(int) close_flag
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_new_fp(stream: libc::c_int, close_flag: libc::c_int) -> *mut bio_st;
}


/*
BIO * BIO_new() [struct bio_st *]
	(BIO_METHOD *) type [struct bio_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_new(type_: *mut bio_method_st) -> *mut bio_st;
}


/*
int BIO_set()
	(BIO *) a [struct bio_st *]
	(BIO_METHOD *) type [struct bio_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_set(a: *mut bio_st, type_: *mut bio_method_st) -> libc::c_int;
}


/*
int BIO_free()
	(BIO *) a [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_free(a: *mut bio_st) -> libc::c_int;
}


/*
void BIO_vfree()
	(BIO *) a [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_vfree(a: *mut bio_st);
}


/*
int BIO_read()
	(BIO *) b [struct bio_st *]
	(void *) data
	(int) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_read(b: *mut bio_st, data: *mut libc::c_void, len: libc::c_int) -> libc::c_int;
}


/*
int BIO_gets()
	(BIO *) bp [struct bio_st *]
	(char *) buf
	(int) size
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_gets(bp: *mut bio_st, buf: *mut libc::c_char, size: libc::c_int) -> libc::c_int;
}


/*
int BIO_write()
	(BIO *) b [struct bio_st *]
	(const void *) data
	(int) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_write(b: *mut bio_st, data: *const libc::c_void, len: libc::c_int) -> libc::c_int;
}


/*
int BIO_puts()
	(BIO *) bp [struct bio_st *]
	(const char *) buf
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_puts(bp: *mut bio_st, buf: *const libc::c_char) -> libc::c_int;
}


/*
int BIO_indent()
	(BIO *) b [struct bio_st *]
	(int) indent
	(int) max
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_indent(b: *mut bio_st, indent: libc::c_int, max: libc::c_int) -> libc::c_int;
}


/*
long BIO_ctrl()
	(BIO *) bp [struct bio_st *]
	(int) cmd
	(long) larg
	(void *) parg
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_ctrl(bp: *mut bio_st, cmd: libc::c_int, larg: libc::c_long, parg: *mut libc::c_void) -> libc::c_long;
}


/*
long BIO_callback_ctrl()
	(BIO *) b [struct bio_st *]
	(int) cmd
	(void (*)(struct bio_st *, int, const char *, int, long, long)) fp [void (*)(struct bio_st *, int, const char *, int, long, long)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_callback_ctrl(b: *mut bio_st, cmd: libc::c_int, fp: Option<extern fn(*mut bio_st, libc::c_int, *const libc::c_char, libc::c_int, libc::c_long, libc::c_long)>) -> libc::c_long;
}


/*
char * BIO_ptr_ctrl()
	(BIO *) bp [struct bio_st *]
	(int) cmd
	(long) larg
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_ptr_ctrl(bp: *mut bio_st, cmd: libc::c_int, larg: libc::c_long) -> *mut libc::c_char;
}


/*
long BIO_int_ctrl()
	(BIO *) bp [struct bio_st *]
	(int) cmd
	(long) larg
	(int) iarg
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_int_ctrl(bp: *mut bio_st, cmd: libc::c_int, larg: libc::c_long, iarg: libc::c_int) -> libc::c_long;
}


/*
BIO * BIO_push() [struct bio_st *]
	(BIO *) b [struct bio_st *]
	(BIO *) append [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_push(b: *mut bio_st, append: *mut bio_st) -> *mut bio_st;
}


/*
BIO * BIO_pop() [struct bio_st *]
	(BIO *) b [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_pop(b: *mut bio_st) -> *mut bio_st;
}


/*
void BIO_free_all()
	(BIO *) a [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_free_all(a: *mut bio_st);
}


/*
BIO * BIO_find_type() [struct bio_st *]
	(BIO *) b [struct bio_st *]
	(int) bio_type
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_find_type(b: *mut bio_st, bio_type: libc::c_int) -> *mut bio_st;
}


/*
BIO * BIO_next() [struct bio_st *]
	(BIO *) b [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_next(b: *mut bio_st) -> *mut bio_st;
}


/*
BIO * BIO_get_retry_BIO() [struct bio_st *]
	(BIO *) bio [struct bio_st *]
	(int *) reason
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_get_retry_BIO(bio: *mut bio_st, reason: *mut libc::c_int) -> *mut bio_st;
}


/*
int BIO_get_retry_reason()
	(BIO *) bio [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_get_retry_reason(bio: *mut bio_st) -> libc::c_int;
}


/*
BIO * BIO_dup_chain() [struct bio_st *]
	(BIO *) in [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_dup_chain(in_: *mut bio_st) -> *mut bio_st;
}


/*
int BIO_nread0()
	(BIO *) bio [struct bio_st *]
	(char **) buf
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_nread0(bio: *mut bio_st, buf: *mut *mut libc::c_char) -> libc::c_int;
}


/*
int BIO_nread()
	(BIO *) bio [struct bio_st *]
	(char **) buf
	(int) num
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_nread(bio: *mut bio_st, buf: *mut *mut libc::c_char, num: libc::c_int) -> libc::c_int;
}


/*
int BIO_nwrite0()
	(BIO *) bio [struct bio_st *]
	(char **) buf
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_nwrite0(bio: *mut bio_st, buf: *mut *mut libc::c_char) -> libc::c_int;
}


/*
int BIO_nwrite()
	(BIO *) bio [struct bio_st *]
	(char **) buf
	(int) num
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_nwrite(bio: *mut bio_st, buf: *mut *mut libc::c_char, num: libc::c_int) -> libc::c_int;
}


/*
long BIO_debug_callback()
	(BIO *) bio [struct bio_st *]
	(int) cmd
	(const char *) argp
	(int) argi
	(long) argl
	(long) ret
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_debug_callback(bio: *mut bio_st, cmd: libc::c_int, argp: *const libc::c_char, argi: libc::c_int, argl: libc::c_long, ret: libc::c_long) -> libc::c_long;
}


/*
BIO_METHOD * BIO_s_mem() [struct bio_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_s_mem() -> *mut bio_method_st;
}


/*
BIO * BIO_new_mem_buf() [struct bio_st *]
	(void *) buf
	(int) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_new_mem_buf(buf: *mut libc::c_void, len: libc::c_int) -> *mut bio_st;
}


/*
BIO_METHOD * BIO_s_socket() [struct bio_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_s_socket() -> *mut bio_method_st;
}


/*
BIO_METHOD * BIO_s_connect() [struct bio_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_s_connect() -> *mut bio_method_st;
}


/*
BIO_METHOD * BIO_s_accept() [struct bio_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_s_accept() -> *mut bio_method_st;
}


/*
BIO_METHOD * BIO_s_fd() [struct bio_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_s_fd() -> *mut bio_method_st;
}


/*
BIO_METHOD * BIO_s_log() [struct bio_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_s_log() -> *mut bio_method_st;
}


/*
BIO_METHOD * BIO_s_bio() [struct bio_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_s_bio() -> *mut bio_method_st;
}


/*
BIO_METHOD * BIO_s_null() [struct bio_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_s_null() -> *mut bio_method_st;
}


/*
BIO_METHOD * BIO_f_null() [struct bio_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_f_null() -> *mut bio_method_st;
}


/*
BIO_METHOD * BIO_f_buffer() [struct bio_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_f_buffer() -> *mut bio_method_st;
}


/*
BIO_METHOD * BIO_f_nbio_test() [struct bio_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_f_nbio_test() -> *mut bio_method_st;
}


/*
BIO_METHOD * BIO_s_datagram() [struct bio_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_s_datagram() -> *mut bio_method_st;
}


/*
int BIO_sock_should_retry()
	(int) i
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_sock_should_retry(i: libc::c_int) -> libc::c_int;
}


/*
int BIO_sock_non_fatal_error()
	(int) error
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_sock_non_fatal_error(error: libc::c_int) -> libc::c_int;
}


/*
int BIO_dgram_non_fatal_error()
	(int) error
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_dgram_non_fatal_error(error: libc::c_int) -> libc::c_int;
}


/*
int BIO_fd_should_retry()
	(int) i
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_fd_should_retry(i: libc::c_int) -> libc::c_int;
}


/*
int BIO_fd_non_fatal_error()
	(int) error
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_fd_non_fatal_error(error: libc::c_int) -> libc::c_int;
}


/*
int BIO_dump_cb()
	(int (*)(const void *, size_t, void *)) cb [int (*)(const void *, unsigned long, void *)]
	(void *) u
	(const char *) s
	(int) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_dump_cb(cb: Option<extern fn(*const libc::c_void, libc::c_ulong, *mut libc::c_void) -> libc::c_int>, u: *mut libc::c_void, s: *const libc::c_char, len: libc::c_int) -> libc::c_int;
}


/*
int BIO_dump_indent_cb()
	(int (*)(const void *, size_t, void *)) cb [int (*)(const void *, unsigned long, void *)]
	(void *) u
	(const char *) s
	(int) len
	(int) indent
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_dump_indent_cb(cb: Option<extern fn(*const libc::c_void, libc::c_ulong, *mut libc::c_void) -> libc::c_int>, u: *mut libc::c_void, s: *const libc::c_char, len: libc::c_int, indent: libc::c_int) -> libc::c_int;
}


/*
int BIO_dump()
	(BIO *) b [struct bio_st *]
	(const char *) bytes
	(int) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_dump(b: *mut bio_st, bytes: *const libc::c_char, len: libc::c_int) -> libc::c_int;
}


/*
int BIO_dump_indent()
	(BIO *) b [struct bio_st *]
	(const char *) bytes
	(int) len
	(int) indent
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_dump_indent(b: *mut bio_st, bytes: *const libc::c_char, len: libc::c_int, indent: libc::c_int) -> libc::c_int;
}


/*
int BIO_dump_fp()
	(FILE *) fp [struct _IO_FILE *]
	(const char *) s
	(int) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_dump_fp(fp: libc::c_int, s: *const libc::c_char, len: libc::c_int) -> libc::c_int;
}


/*
int BIO_dump_indent_fp()
	(FILE *) fp [struct _IO_FILE *]
	(const char *) s
	(int) len
	(int) indent
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_dump_indent_fp(fp: libc::c_int, s: *const libc::c_char, len: libc::c_int, indent: libc::c_int) -> libc::c_int;
}


/*
struct hostent * BIO_gethostbyname() [struct hostent *]
	(const char *) name
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_gethostbyname(name: *const libc::c_char) -> *mut hostent;
}


/*
int BIO_sock_error()
	(int) sock
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_sock_error(sock: libc::c_int) -> libc::c_int;
}


/*
int BIO_socket_ioctl()
	(int) fd
	(long) type
	(void *) arg
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_socket_ioctl(fd: libc::c_int, type_: libc::c_long, arg: *mut libc::c_void) -> libc::c_int;
}


/*
int BIO_socket_nbio()
	(int) fd
	(int) mode
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_socket_nbio(fd: libc::c_int, mode: libc::c_int) -> libc::c_int;
}


/*
int BIO_get_port()
	(const char *) str
	(unsigned short *) port_ptr
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_get_port(str: *const libc::c_char, port_ptr: *mut libc::c_ushort) -> libc::c_int;
}


/*
int BIO_get_host_ip()
	(const char *) str
	(unsigned char *) ip
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_get_host_ip(str: *const libc::c_char, ip: *mut libc::c_uchar) -> libc::c_int;
}


/*
int BIO_get_accept_socket()
	(char *) host_port
	(int) mode
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_get_accept_socket(host_port: *mut libc::c_char, mode: libc::c_int) -> libc::c_int;
}


/*
int BIO_accept()
	(int) sock
	(char **) ip_port
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_accept(sock: libc::c_int, ip_port: *mut *mut libc::c_char) -> libc::c_int;
}


/*
int BIO_sock_init()
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_sock_init() -> libc::c_int;
}


/*
void BIO_sock_cleanup()
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_sock_cleanup();
}


/*
int BIO_set_tcp_ndelay()
	(int) sock
	(int) turn_on
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_set_tcp_ndelay(sock: libc::c_int, turn_on: libc::c_int) -> libc::c_int;
}


/*
BIO * BIO_new_socket() [struct bio_st *]
	(int) sock
	(int) close_flag
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_new_socket(sock: libc::c_int, close_flag: libc::c_int) -> *mut bio_st;
}


/*
BIO * BIO_new_dgram() [struct bio_st *]
	(int) fd
	(int) close_flag
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_new_dgram(fd: libc::c_int, close_flag: libc::c_int) -> *mut bio_st;
}


/*
BIO * BIO_new_fd() [struct bio_st *]
	(int) fd
	(int) close_flag
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_new_fd(fd: libc::c_int, close_flag: libc::c_int) -> *mut bio_st;
}


/*
BIO * BIO_new_connect() [struct bio_st *]
	(char *) host_port
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_new_connect(host_port: *mut libc::c_char) -> *mut bio_st;
}


/*
BIO * BIO_new_accept() [struct bio_st *]
	(char *) host_port
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_new_accept(host_port: *mut libc::c_char) -> *mut bio_st;
}


/*
int BIO_new_bio_pair()
	(BIO **) bio1 [struct bio_st **]
	(size_t) writebuf1 [unsigned long]
	(BIO **) bio2 [struct bio_st **]
	(size_t) writebuf2 [unsigned long]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_new_bio_pair(bio1: *mut *mut bio_st, writebuf1: libc::c_ulong, bio2: *mut *mut bio_st, writebuf2: libc::c_ulong) -> libc::c_int;
}


/*
void BIO_copy_next_retry()
	(BIO *) b [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_copy_next_retry(b: *mut bio_st);
}


/*
int BIO_printf()
	(BIO *) bio [struct bio_st *]
	(const char *) format
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_printf(bio: *mut bio_st, format: *const libc::c_char) -> libc::c_int;
}


/*
int BIO_vprintf()
	(BIO *) bio [struct bio_st *]
	(const char *) format
	(va_list) args [struct __va_list_tag [1]]
#[link(name="crypto")]
extern "C" {
	pub fn BIO_vprintf(bio: *mut bio_st, format: *const libc::c_char, args: [__va_list_tag; 1]) -> libc::c_int;
}
*/


/*
int BIO_snprintf()
	(char *) buf
	(size_t) n [unsigned long]
	(const char *) format
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_snprintf(buf: *mut libc::c_char, n: libc::c_ulong, format: *const libc::c_char) -> libc::c_int;
}


/*
int BIO_vsnprintf()
	(char *) buf
	(size_t) n [unsigned long]
	(const char *) format
	(va_list) args [struct __va_list_tag [1]]
#[link(name="crypto")]
extern "C" {
	pub fn BIO_vsnprintf(buf: *mut libc::c_char, n: libc::c_ulong, format: *const libc::c_char, args: [__va_list_tag; 1]) -> libc::c_int;
}
*/


/*
void ERR_load_BIO_strings()
*/
#[link(name="crypto")]
extern "C" {
	pub fn ERR_load_BIO_strings();
}


/*
int BN_GENCB_call()
	(BN_GENCB *) cb [struct bn_gencb_st *]
	(int) a
	(int) b
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GENCB_call(cb: *mut bn_gencb_st, a: libc::c_int, b: libc::c_int) -> libc::c_int;
}


/*
const BIGNUM * BN_value_one() [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_value_one() -> *const bignum_st;
}


/*
char * BN_options()
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_options() -> *mut libc::c_char;
}


/*
BN_CTX * BN_CTX_new() [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_CTX_new() -> *mut bignum_ctx;
}


/*
void BN_CTX_init()
	(BN_CTX *) c [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_CTX_init(c: *mut bignum_ctx);
}


/*
void BN_CTX_free()
	(BN_CTX *) c [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_CTX_free(c: *mut bignum_ctx);
}


/*
void BN_CTX_start()
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_CTX_start(ctx: *mut bignum_ctx);
}


/*
BIGNUM * BN_CTX_get() [struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_CTX_get(ctx: *mut bignum_ctx) -> *mut bignum_st;
}


/*
void BN_CTX_end()
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_CTX_end(ctx: *mut bignum_ctx);
}


/*
int BN_rand()
	(BIGNUM *) rnd [struct bignum_st *]
	(int) bits
	(int) top
	(int) bottom
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_rand(rnd: *mut bignum_st, bits: libc::c_int, top: libc::c_int, bottom: libc::c_int) -> libc::c_int;
}


/*
int BN_pseudo_rand()
	(BIGNUM *) rnd [struct bignum_st *]
	(int) bits
	(int) top
	(int) bottom
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_pseudo_rand(rnd: *mut bignum_st, bits: libc::c_int, top: libc::c_int, bottom: libc::c_int) -> libc::c_int;
}


/*
int BN_rand_range()
	(BIGNUM *) rnd [struct bignum_st *]
	(const BIGNUM *) range [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_rand_range(rnd: *mut bignum_st, range: *const bignum_st) -> libc::c_int;
}


/*
int BN_pseudo_rand_range()
	(BIGNUM *) rnd [struct bignum_st *]
	(const BIGNUM *) range [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_pseudo_rand_range(rnd: *mut bignum_st, range: *const bignum_st) -> libc::c_int;
}


/*
int BN_num_bits()
	(const BIGNUM *) a [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_num_bits(a: *const bignum_st) -> libc::c_int;
}


/*
int BN_num_bits_word()
	(unsigned long) 
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_num_bits_word(_: libc::c_ulong) -> libc::c_int;
}


/*
BIGNUM * BN_new() [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_new() -> *mut bignum_st;
}


/*
void BN_init()
	(BIGNUM *)  [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_init(_: *mut bignum_st);
}


/*
void BN_clear_free()
	(BIGNUM *) a [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_clear_free(a: *mut bignum_st);
}


/*
BIGNUM * BN_copy() [struct bignum_st *]
	(BIGNUM *) a [struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_copy(a: *mut bignum_st, b: *const bignum_st) -> *mut bignum_st;
}


/*
void BN_swap()
	(BIGNUM *) a [struct bignum_st *]
	(BIGNUM *) b [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_swap(a: *mut bignum_st, b: *mut bignum_st);
}


/*
BIGNUM * BN_bin2bn() [struct bignum_st *]
	(const unsigned char *) s
	(int) len
	(BIGNUM *) ret [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_bin2bn(s: *const libc::c_uchar, len: libc::c_int, ret: *mut bignum_st) -> *mut bignum_st;
}


/*
int BN_bn2bin()
	(const BIGNUM *) a [const struct bignum_st *]
	(unsigned char *) to
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_bn2bin(a: *const bignum_st, to: *mut libc::c_uchar) -> libc::c_int;
}


/*
BIGNUM * BN_mpi2bn() [struct bignum_st *]
	(const unsigned char *) s
	(int) len
	(BIGNUM *) ret [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mpi2bn(s: *const libc::c_uchar, len: libc::c_int, ret: *mut bignum_st) -> *mut bignum_st;
}


/*
int BN_bn2mpi()
	(const BIGNUM *) a [const struct bignum_st *]
	(unsigned char *) to
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_bn2mpi(a: *const bignum_st, to: *mut libc::c_uchar) -> libc::c_int;
}


/*
int BN_sub()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_sub(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st) -> libc::c_int;
}


/*
int BN_usub()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_usub(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st) -> libc::c_int;
}


/*
int BN_uadd()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_uadd(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st) -> libc::c_int;
}


/*
int BN_add()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_add(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st) -> libc::c_int;
}


/*
int BN_mul()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mul(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_sqr()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_sqr(r: *mut bignum_st, a: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
void BN_set_negative()
	(BIGNUM *) b [struct bignum_st *]
	(int) n
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_set_negative(b: *mut bignum_st, n: libc::c_int);
}


/*
int BN_div()
	(BIGNUM *) dv [struct bignum_st *]
	(BIGNUM *) rem [struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
	(const BIGNUM *) d [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_div(dv: *mut bignum_st, rem: *mut bignum_st, m: *const bignum_st, d: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_nnmod()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
	(const BIGNUM *) d [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_nnmod(r: *mut bignum_st, m: *const bignum_st, d: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_mod_add()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_add(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st, m: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_mod_add_quick()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_add_quick(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st, m: *const bignum_st) -> libc::c_int;
}


/*
int BN_mod_sub()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_sub(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st, m: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_mod_sub_quick()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_sub_quick(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st, m: *const bignum_st) -> libc::c_int;
}


/*
int BN_mod_mul()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_mul(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st, m: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_mod_sqr()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_sqr(r: *mut bignum_st, a: *const bignum_st, m: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_mod_lshift1()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_lshift1(r: *mut bignum_st, a: *const bignum_st, m: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_mod_lshift1_quick()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_lshift1_quick(r: *mut bignum_st, a: *const bignum_st, m: *const bignum_st) -> libc::c_int;
}


/*
int BN_mod_lshift()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(int) n
	(const BIGNUM *) m [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_lshift(r: *mut bignum_st, a: *const bignum_st, n: libc::c_int, m: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_mod_lshift_quick()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(int) n
	(const BIGNUM *) m [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_lshift_quick(r: *mut bignum_st, a: *const bignum_st, n: libc::c_int, m: *const bignum_st) -> libc::c_int;
}


/*
unsigned long BN_mod_word()
	(const BIGNUM *) a [const struct bignum_st *]
	(unsigned long) w
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_word(a: *const bignum_st, w: libc::c_ulong) -> libc::c_ulong;
}


/*
unsigned long BN_div_word()
	(BIGNUM *) a [struct bignum_st *]
	(unsigned long) w
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_div_word(a: *mut bignum_st, w: libc::c_ulong) -> libc::c_ulong;
}


/*
int BN_mul_word()
	(BIGNUM *) a [struct bignum_st *]
	(unsigned long) w
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mul_word(a: *mut bignum_st, w: libc::c_ulong) -> libc::c_int;
}


/*
int BN_add_word()
	(BIGNUM *) a [struct bignum_st *]
	(unsigned long) w
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_add_word(a: *mut bignum_st, w: libc::c_ulong) -> libc::c_int;
}


/*
int BN_sub_word()
	(BIGNUM *) a [struct bignum_st *]
	(unsigned long) w
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_sub_word(a: *mut bignum_st, w: libc::c_ulong) -> libc::c_int;
}


/*
int BN_set_word()
	(BIGNUM *) a [struct bignum_st *]
	(unsigned long) w
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_set_word(a: *mut bignum_st, w: libc::c_ulong) -> libc::c_int;
}


/*
unsigned long BN_get_word()
	(const BIGNUM *) a [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_get_word(a: *const bignum_st) -> libc::c_ulong;
}


/*
int BN_cmp()
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_cmp(a: *const bignum_st, b: *const bignum_st) -> libc::c_int;
}


/*
void BN_free()
	(BIGNUM *) a [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_free(a: *mut bignum_st);
}


/*
int BN_is_bit_set()
	(const BIGNUM *) a [const struct bignum_st *]
	(int) n
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_is_bit_set(a: *const bignum_st, n: libc::c_int) -> libc::c_int;
}


/*
int BN_lshift()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(int) n
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_lshift(r: *mut bignum_st, a: *const bignum_st, n: libc::c_int) -> libc::c_int;
}


/*
int BN_lshift1()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_lshift1(r: *mut bignum_st, a: *const bignum_st) -> libc::c_int;
}


/*
int BN_exp()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_exp(r: *mut bignum_st, a: *const bignum_st, p: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_mod_exp()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_exp(r: *mut bignum_st, a: *const bignum_st, p: *const bignum_st, m: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_mod_exp_mont()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
	(BN_MONT_CTX *) m_ctx [struct bn_mont_ctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_exp_mont(r: *mut bignum_st, a: *const bignum_st, p: *const bignum_st, m: *const bignum_st, ctx: *mut bignum_ctx, m_ctx: *mut bn_mont_ctx_st) -> libc::c_int;
}


/*
int BN_mod_exp_mont_consttime()
	(BIGNUM *) rr [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
	(BN_MONT_CTX *) in_mont [struct bn_mont_ctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_exp_mont_consttime(rr: *mut bignum_st, a: *const bignum_st, p: *const bignum_st, m: *const bignum_st, ctx: *mut bignum_ctx, in_mont: *mut bn_mont_ctx_st) -> libc::c_int;
}


/*
int BN_mod_exp_mont_word()
	(BIGNUM *) r [struct bignum_st *]
	(unsigned long) a
	(const BIGNUM *) p [const struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
	(BN_MONT_CTX *) m_ctx [struct bn_mont_ctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_exp_mont_word(r: *mut bignum_st, a: libc::c_ulong, p: *const bignum_st, m: *const bignum_st, ctx: *mut bignum_ctx, m_ctx: *mut bn_mont_ctx_st) -> libc::c_int;
}


/*
int BN_mod_exp2_mont()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a1 [const struct bignum_st *]
	(const BIGNUM *) p1 [const struct bignum_st *]
	(const BIGNUM *) a2 [const struct bignum_st *]
	(const BIGNUM *) p2 [const struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
	(BN_MONT_CTX *) m_ctx [struct bn_mont_ctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_exp2_mont(r: *mut bignum_st, a1: *const bignum_st, p1: *const bignum_st, a2: *const bignum_st, p2: *const bignum_st, m: *const bignum_st, ctx: *mut bignum_ctx, m_ctx: *mut bn_mont_ctx_st) -> libc::c_int;
}


/*
int BN_mod_exp_simple()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_exp_simple(r: *mut bignum_st, a: *const bignum_st, p: *const bignum_st, m: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_mask_bits()
	(BIGNUM *) a [struct bignum_st *]
	(int) n
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mask_bits(a: *mut bignum_st, n: libc::c_int) -> libc::c_int;
}


/*
int BN_print_fp()
	(FILE *) fp [struct _IO_FILE *]
	(const BIGNUM *) a [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_print_fp(fp: libc::c_int, a: *const bignum_st) -> libc::c_int;
}


/*
int BN_print()
	(BIO *) fp [struct bio_st *]
	(const BIGNUM *) a [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_print(fp: *mut bio_st, a: *const bignum_st) -> libc::c_int;
}


/*
int BN_reciprocal()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
	(int) len
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_reciprocal(r: *mut bignum_st, m: *const bignum_st, len: libc::c_int, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_rshift()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(int) n
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_rshift(r: *mut bignum_st, a: *const bignum_st, n: libc::c_int) -> libc::c_int;
}


/*
int BN_rshift1()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_rshift1(r: *mut bignum_st, a: *const bignum_st) -> libc::c_int;
}


/*
void BN_clear()
	(BIGNUM *) a [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_clear(a: *mut bignum_st);
}


/*
BIGNUM * BN_dup() [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_dup(a: *const bignum_st) -> *mut bignum_st;
}


/*
int BN_ucmp()
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_ucmp(a: *const bignum_st, b: *const bignum_st) -> libc::c_int;
}


/*
int BN_set_bit()
	(BIGNUM *) a [struct bignum_st *]
	(int) n
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_set_bit(a: *mut bignum_st, n: libc::c_int) -> libc::c_int;
}


/*
int BN_clear_bit()
	(BIGNUM *) a [struct bignum_st *]
	(int) n
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_clear_bit(a: *mut bignum_st, n: libc::c_int) -> libc::c_int;
}


/*
char * BN_bn2hex()
	(const BIGNUM *) a [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_bn2hex(a: *const bignum_st) -> *mut libc::c_char;
}


/*
char * BN_bn2dec()
	(const BIGNUM *) a [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_bn2dec(a: *const bignum_st) -> *mut libc::c_char;
}


/*
int BN_hex2bn()
	(BIGNUM **) a [struct bignum_st **]
	(const char *) str
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_hex2bn(a: *mut *mut bignum_st, str: *const libc::c_char) -> libc::c_int;
}


/*
int BN_dec2bn()
	(BIGNUM **) a [struct bignum_st **]
	(const char *) str
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_dec2bn(a: *mut *mut bignum_st, str: *const libc::c_char) -> libc::c_int;
}


/*
int BN_asc2bn()
	(BIGNUM **) a [struct bignum_st **]
	(const char *) str
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_asc2bn(a: *mut *mut bignum_st, str: *const libc::c_char) -> libc::c_int;
}


/*
int BN_gcd()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_gcd(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_kronecker()
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_kronecker(a: *const bignum_st, b: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
BIGNUM * BN_mod_inverse() [struct bignum_st *]
	(BIGNUM *) ret [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) n [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_inverse(ret: *mut bignum_st, a: *const bignum_st, n: *const bignum_st, ctx: *mut bignum_ctx) -> *mut bignum_st;
}


/*
BIGNUM * BN_mod_sqrt() [struct bignum_st *]
	(BIGNUM *) ret [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) n [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_sqrt(ret: *mut bignum_st, a: *const bignum_st, n: *const bignum_st, ctx: *mut bignum_ctx) -> *mut bignum_st;
}


/*
void BN_consttime_swap()
	(unsigned long) swap
	(BIGNUM *) a [struct bignum_st *]
	(BIGNUM *) b [struct bignum_st *]
	(int) nwords
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_consttime_swap(swap: libc::c_ulong, a: *mut bignum_st, b: *mut bignum_st, nwords: libc::c_int);
}


/*
BIGNUM * BN_generate_prime() [struct bignum_st *]
	(BIGNUM *) ret [struct bignum_st *]
	(int) bits
	(int) safe
	(const BIGNUM *) add [const struct bignum_st *]
	(const BIGNUM *) rem [const struct bignum_st *]
	(void (*)(int, int, void *)) callback [void (*)(int, int, void *)]
	(void *) cb_arg
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_generate_prime(ret: *mut bignum_st, bits: libc::c_int, safe: libc::c_int, add: *const bignum_st, rem: *const bignum_st, callback: Option<extern fn(libc::c_int, libc::c_int, *mut libc::c_void)>, cb_arg: *mut libc::c_void) -> *mut bignum_st;
}


/*
int BN_is_prime()
	(const BIGNUM *) p [const struct bignum_st *]
	(int) nchecks
	(void (*)(int, int, void *)) callback [void (*)(int, int, void *)]
	(BN_CTX *) ctx [struct bignum_ctx *]
	(void *) cb_arg
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_is_prime(p: *const bignum_st, nchecks: libc::c_int, callback: Option<extern fn(libc::c_int, libc::c_int, *mut libc::c_void)>, ctx: *mut bignum_ctx, cb_arg: *mut libc::c_void) -> libc::c_int;
}


/*
int BN_is_prime_fasttest()
	(const BIGNUM *) p [const struct bignum_st *]
	(int) nchecks
	(void (*)(int, int, void *)) callback [void (*)(int, int, void *)]
	(BN_CTX *) ctx [struct bignum_ctx *]
	(void *) cb_arg
	(int) do_trial_division
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_is_prime_fasttest(p: *const bignum_st, nchecks: libc::c_int, callback: Option<extern fn(libc::c_int, libc::c_int, *mut libc::c_void)>, ctx: *mut bignum_ctx, cb_arg: *mut libc::c_void, do_trial_division: libc::c_int) -> libc::c_int;
}


/*
int BN_generate_prime_ex()
	(BIGNUM *) ret [struct bignum_st *]
	(int) bits
	(int) safe
	(const BIGNUM *) add [const struct bignum_st *]
	(const BIGNUM *) rem [const struct bignum_st *]
	(BN_GENCB *) cb [struct bn_gencb_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_generate_prime_ex(ret: *mut bignum_st, bits: libc::c_int, safe: libc::c_int, add: *const bignum_st, rem: *const bignum_st, cb: *mut bn_gencb_st) -> libc::c_int;
}


/*
int BN_is_prime_ex()
	(const BIGNUM *) p [const struct bignum_st *]
	(int) nchecks
	(BN_CTX *) ctx [struct bignum_ctx *]
	(BN_GENCB *) cb [struct bn_gencb_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_is_prime_ex(p: *const bignum_st, nchecks: libc::c_int, ctx: *mut bignum_ctx, cb: *mut bn_gencb_st) -> libc::c_int;
}


/*
int BN_is_prime_fasttest_ex()
	(const BIGNUM *) p [const struct bignum_st *]
	(int) nchecks
	(BN_CTX *) ctx [struct bignum_ctx *]
	(int) do_trial_division
	(BN_GENCB *) cb [struct bn_gencb_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_is_prime_fasttest_ex(p: *const bignum_st, nchecks: libc::c_int, ctx: *mut bignum_ctx, do_trial_division: libc::c_int, cb: *mut bn_gencb_st) -> libc::c_int;
}


/*
int BN_X931_generate_Xpq()
	(BIGNUM *) Xp [struct bignum_st *]
	(BIGNUM *) Xq [struct bignum_st *]
	(int) nbits
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_X931_generate_Xpq(Xp: *mut bignum_st, Xq: *mut bignum_st, nbits: libc::c_int, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_X931_derive_prime_ex()
	(BIGNUM *) p [struct bignum_st *]
	(BIGNUM *) p1 [struct bignum_st *]
	(BIGNUM *) p2 [struct bignum_st *]
	(const BIGNUM *) Xp [const struct bignum_st *]
	(const BIGNUM *) Xp1 [const struct bignum_st *]
	(const BIGNUM *) Xp2 [const struct bignum_st *]
	(const BIGNUM *) e [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
	(BN_GENCB *) cb [struct bn_gencb_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_X931_derive_prime_ex(p: *mut bignum_st, p1: *mut bignum_st, p2: *mut bignum_st, Xp: *const bignum_st, Xp1: *const bignum_st, Xp2: *const bignum_st, e: *const bignum_st, ctx: *mut bignum_ctx, cb: *mut bn_gencb_st) -> libc::c_int;
}


/*
int BN_X931_generate_prime_ex()
	(BIGNUM *) p [struct bignum_st *]
	(BIGNUM *) p1 [struct bignum_st *]
	(BIGNUM *) p2 [struct bignum_st *]
	(BIGNUM *) Xp1 [struct bignum_st *]
	(BIGNUM *) Xp2 [struct bignum_st *]
	(const BIGNUM *) Xp [const struct bignum_st *]
	(const BIGNUM *) e [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
	(BN_GENCB *) cb [struct bn_gencb_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_X931_generate_prime_ex(p: *mut bignum_st, p1: *mut bignum_st, p2: *mut bignum_st, Xp1: *mut bignum_st, Xp2: *mut bignum_st, Xp: *const bignum_st, e: *const bignum_st, ctx: *mut bignum_ctx, cb: *mut bn_gencb_st) -> libc::c_int;
}


/*
BN_MONT_CTX * BN_MONT_CTX_new() [struct bn_mont_ctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_MONT_CTX_new() -> *mut bn_mont_ctx_st;
}


/*
void BN_MONT_CTX_init()
	(BN_MONT_CTX *) ctx [struct bn_mont_ctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_MONT_CTX_init(ctx: *mut bn_mont_ctx_st);
}


/*
int BN_mod_mul_montgomery()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(BN_MONT_CTX *) mont [struct bn_mont_ctx_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_mul_montgomery(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st, mont: *mut bn_mont_ctx_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_from_montgomery()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(BN_MONT_CTX *) mont [struct bn_mont_ctx_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_from_montgomery(r: *mut bignum_st, a: *const bignum_st, mont: *mut bn_mont_ctx_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
void BN_MONT_CTX_free()
	(BN_MONT_CTX *) mont [struct bn_mont_ctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_MONT_CTX_free(mont: *mut bn_mont_ctx_st);
}


/*
int BN_MONT_CTX_set()
	(BN_MONT_CTX *) mont [struct bn_mont_ctx_st *]
	(const BIGNUM *) mod [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_MONT_CTX_set(mont: *mut bn_mont_ctx_st, mod_: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
BN_MONT_CTX * BN_MONT_CTX_copy() [struct bn_mont_ctx_st *]
	(BN_MONT_CTX *) to [struct bn_mont_ctx_st *]
	(BN_MONT_CTX *) from [struct bn_mont_ctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_MONT_CTX_copy(to: *mut bn_mont_ctx_st, from: *mut bn_mont_ctx_st) -> *mut bn_mont_ctx_st;
}


/*
BN_MONT_CTX * BN_MONT_CTX_set_locked() [struct bn_mont_ctx_st *]
	(BN_MONT_CTX **) pmont [struct bn_mont_ctx_st **]
	(int) lock
	(const BIGNUM *) mod [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_MONT_CTX_set_locked(pmont: *mut *mut bn_mont_ctx_st, lock: libc::c_int, mod_: *const bignum_st, ctx: *mut bignum_ctx) -> *mut bn_mont_ctx_st;
}


/*
BN_BLINDING * BN_BLINDING_new() [struct bn_blinding_st *]
	(const BIGNUM *) A [const struct bignum_st *]
	(const BIGNUM *) Ai [const struct bignum_st *]
	(BIGNUM *) mod [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_BLINDING_new(A: *const bignum_st, Ai: *const bignum_st, mod_: *mut bignum_st) -> *mut bn_blinding_st;
}


/*
void BN_BLINDING_free()
	(BN_BLINDING *) b [struct bn_blinding_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_BLINDING_free(b: *mut bn_blinding_st);
}


/*
int BN_BLINDING_update()
	(BN_BLINDING *) b [struct bn_blinding_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_BLINDING_update(b: *mut bn_blinding_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_BLINDING_convert()
	(BIGNUM *) n [struct bignum_st *]
	(BN_BLINDING *) b [struct bn_blinding_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_BLINDING_convert(n: *mut bignum_st, b: *mut bn_blinding_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_BLINDING_invert()
	(BIGNUM *) n [struct bignum_st *]
	(BN_BLINDING *) b [struct bn_blinding_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_BLINDING_invert(n: *mut bignum_st, b: *mut bn_blinding_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_BLINDING_convert_ex()
	(BIGNUM *) n [struct bignum_st *]
	(BIGNUM *) r [struct bignum_st *]
	(BN_BLINDING *) b [struct bn_blinding_st *]
	(BN_CTX *)  [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_BLINDING_convert_ex(n: *mut bignum_st, r: *mut bignum_st, b: *mut bn_blinding_st, _: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_BLINDING_invert_ex()
	(BIGNUM *) n [struct bignum_st *]
	(const BIGNUM *) r [const struct bignum_st *]
	(BN_BLINDING *) b [struct bn_blinding_st *]
	(BN_CTX *)  [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_BLINDING_invert_ex(n: *mut bignum_st, r: *const bignum_st, b: *mut bn_blinding_st, _: *mut bignum_ctx) -> libc::c_int;
}


/*
unsigned long BN_BLINDING_get_thread_id()
	(const BN_BLINDING *)  [const struct bn_blinding_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_BLINDING_get_thread_id(_: *const bn_blinding_st) -> libc::c_ulong;
}


/*
void BN_BLINDING_set_thread_id()
	(BN_BLINDING *)  [struct bn_blinding_st *]
	(unsigned long) 
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_BLINDING_set_thread_id(_: *mut bn_blinding_st, _: libc::c_ulong);
}


/*
CRYPTO_THREADID * BN_BLINDING_thread_id() [struct crypto_threadid_st *]
	(BN_BLINDING *)  [struct bn_blinding_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_BLINDING_thread_id(_: *mut bn_blinding_st) -> *mut crypto_threadid_st;
}


/*
unsigned long BN_BLINDING_get_flags()
	(const BN_BLINDING *)  [const struct bn_blinding_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_BLINDING_get_flags(_: *const bn_blinding_st) -> libc::c_ulong;
}


/*
void BN_BLINDING_set_flags()
	(BN_BLINDING *)  [struct bn_blinding_st *]
	(unsigned long) 
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_BLINDING_set_flags(_: *mut bn_blinding_st, _: libc::c_ulong);
}


/*
BN_BLINDING * BN_BLINDING_create_param() [struct bn_blinding_st *]
	(BN_BLINDING *) b [struct bn_blinding_st *]
	(const BIGNUM *) e [const struct bignum_st *]
	(BIGNUM *) m [struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
	(int (*)(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, BN_MONT_CTX *)) bn_mod_exp [int (*)(struct bignum_st *, const struct bignum_st *, const struct bignum_st *, const struct bignum_st *, struct bignum_ctx *, struct bn_mont_ctx_st *)]
	(BN_MONT_CTX *) m_ctx [struct bn_mont_ctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_BLINDING_create_param(b: *mut bn_blinding_st, e: *const bignum_st, m: *mut bignum_st, ctx: *mut bignum_ctx, bn_mod_exp: Option<extern fn(*mut bignum_st, *const bignum_st, *const bignum_st, *const bignum_st, *mut bignum_ctx, *mut bn_mont_ctx_st) -> libc::c_int>, m_ctx: *mut bn_mont_ctx_st) -> *mut bn_blinding_st;
}


/*
void BN_set_params()
	(int) mul
	(int) high
	(int) low
	(int) mont
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_set_params(mul: libc::c_int, high: libc::c_int, low: libc::c_int, mont: libc::c_int);
}


/*
int BN_get_params()
	(int) which
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_get_params(which: libc::c_int) -> libc::c_int;
}


/*
void BN_RECP_CTX_init()
	(BN_RECP_CTX *) recp [struct bn_recp_ctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_RECP_CTX_init(recp: *mut bn_recp_ctx_st);
}


/*
BN_RECP_CTX * BN_RECP_CTX_new() [struct bn_recp_ctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_RECP_CTX_new() -> *mut bn_recp_ctx_st;
}


/*
void BN_RECP_CTX_free()
	(BN_RECP_CTX *) recp [struct bn_recp_ctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_RECP_CTX_free(recp: *mut bn_recp_ctx_st);
}


/*
int BN_RECP_CTX_set()
	(BN_RECP_CTX *) recp [struct bn_recp_ctx_st *]
	(const BIGNUM *) rdiv [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_RECP_CTX_set(recp: *mut bn_recp_ctx_st, rdiv: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_mod_mul_reciprocal()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) x [const struct bignum_st *]
	(const BIGNUM *) y [const struct bignum_st *]
	(BN_RECP_CTX *) recp [struct bn_recp_ctx_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_mul_reciprocal(r: *mut bignum_st, x: *const bignum_st, y: *const bignum_st, recp: *mut bn_recp_ctx_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_mod_exp_recp()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_mod_exp_recp(r: *mut bignum_st, a: *const bignum_st, p: *const bignum_st, m: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_div_recp()
	(BIGNUM *) dv [struct bignum_st *]
	(BIGNUM *) rem [struct bignum_st *]
	(const BIGNUM *) m [const struct bignum_st *]
	(BN_RECP_CTX *) recp [struct bn_recp_ctx_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_div_recp(dv: *mut bignum_st, rem: *mut bignum_st, m: *const bignum_st, recp: *mut bn_recp_ctx_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_GF2m_add()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_add(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st) -> libc::c_int;
}


/*
int BN_GF2m_mod()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_mod(r: *mut bignum_st, a: *const bignum_st, p: *const bignum_st) -> libc::c_int;
}


/*
int BN_GF2m_mod_mul()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_mod_mul(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st, p: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_GF2m_mod_sqr()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_mod_sqr(r: *mut bignum_st, a: *const bignum_st, p: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_GF2m_mod_inv()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_mod_inv(r: *mut bignum_st, b: *const bignum_st, p: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_GF2m_mod_div()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_mod_div(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st, p: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_GF2m_mod_exp()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_mod_exp(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st, p: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_GF2m_mod_sqrt()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_mod_sqrt(r: *mut bignum_st, a: *const bignum_st, p: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_GF2m_mod_solve_quad()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_mod_solve_quad(r: *mut bignum_st, a: *const bignum_st, p: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_GF2m_mod_arr()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const int []) p [int const[]]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_mod_arr(r: *mut bignum_st, a: *const bignum_st, p: *mut libc::c_int /* INCOMPLETEARRAY */) -> libc::c_int;
}


/*
int BN_GF2m_mod_mul_arr()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(const int []) p [int const[]]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_mod_mul_arr(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st, p: *mut libc::c_int /* INCOMPLETEARRAY */, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_GF2m_mod_sqr_arr()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const int []) p [int const[]]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_mod_sqr_arr(r: *mut bignum_st, a: *const bignum_st, p: *mut libc::c_int /* INCOMPLETEARRAY */, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_GF2m_mod_inv_arr()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(const int []) p [int const[]]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_mod_inv_arr(r: *mut bignum_st, b: *const bignum_st, p: *mut libc::c_int /* INCOMPLETEARRAY */, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_GF2m_mod_div_arr()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(const int []) p [int const[]]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_mod_div_arr(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st, p: *mut libc::c_int /* INCOMPLETEARRAY */, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_GF2m_mod_exp_arr()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(const int []) p [int const[]]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_mod_exp_arr(r: *mut bignum_st, a: *const bignum_st, b: *const bignum_st, p: *mut libc::c_int /* INCOMPLETEARRAY */, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_GF2m_mod_sqrt_arr()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const int []) p [int const[]]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_mod_sqrt_arr(r: *mut bignum_st, a: *const bignum_st, p: *mut libc::c_int /* INCOMPLETEARRAY */, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_GF2m_mod_solve_quad_arr()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const int []) p [int const[]]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_mod_solve_quad_arr(r: *mut bignum_st, a: *const bignum_st, p: *mut libc::c_int /* INCOMPLETEARRAY */, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_GF2m_poly2arr()
	(const BIGNUM *) a [const struct bignum_st *]
	(int []) p
	(int) max
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_poly2arr(a: *const bignum_st, p: *mut libc::c_int /* INCOMPLETEARRAY */, max: libc::c_int) -> libc::c_int;
}


/*
int BN_GF2m_arr2poly()
	(const int []) p [int const[]]
	(BIGNUM *) a [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_GF2m_arr2poly(p: *mut libc::c_int /* INCOMPLETEARRAY */, a: *mut bignum_st) -> libc::c_int;
}


/*
int BN_nist_mod_192()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_nist_mod_192(r: *mut bignum_st, a: *const bignum_st, p: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_nist_mod_224()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_nist_mod_224(r: *mut bignum_st, a: *const bignum_st, p: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_nist_mod_256()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_nist_mod_256(r: *mut bignum_st, a: *const bignum_st, p: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_nist_mod_384()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_nist_mod_384(r: *mut bignum_st, a: *const bignum_st, p: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int BN_nist_mod_521()
	(BIGNUM *) r [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_nist_mod_521(r: *mut bignum_st, a: *const bignum_st, p: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
const BIGNUM * BN_get0_nist_prime_192() [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_get0_nist_prime_192() -> *const bignum_st;
}


/*
const BIGNUM * BN_get0_nist_prime_224() [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_get0_nist_prime_224() -> *const bignum_st;
}


/*
const BIGNUM * BN_get0_nist_prime_256() [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_get0_nist_prime_256() -> *const bignum_st;
}


/*
const BIGNUM * BN_get0_nist_prime_384() [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_get0_nist_prime_384() -> *const bignum_st;
}


/*
const BIGNUM * BN_get0_nist_prime_521() [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_get0_nist_prime_521() -> *const bignum_st;
}


/*
BIGNUM * bn_expand2() [struct bignum_st *]
	(BIGNUM *) a [struct bignum_st *]
	(int) words
*/
#[link(name="crypto")]
extern "C" {
	pub fn bn_expand2(a: *mut bignum_st, words: libc::c_int) -> *mut bignum_st;
}


/*
BIGNUM * bn_dup_expand() [struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(int) words
*/
#[link(name="crypto")]
extern "C" {
	pub fn bn_dup_expand(a: *const bignum_st, words: libc::c_int) -> *mut bignum_st;
}


/*
unsigned long bn_mul_add_words()
	(unsigned long *) rp
	(const unsigned long *) ap
	(int) num
	(unsigned long) w
*/
#[link(name="crypto")]
extern "C" {
	pub fn bn_mul_add_words(rp: *mut libc::c_ulong, ap: *const libc::c_ulong, num: libc::c_int, w: libc::c_ulong) -> libc::c_ulong;
}


/*
unsigned long bn_mul_words()
	(unsigned long *) rp
	(const unsigned long *) ap
	(int) num
	(unsigned long) w
*/
#[link(name="crypto")]
extern "C" {
	pub fn bn_mul_words(rp: *mut libc::c_ulong, ap: *const libc::c_ulong, num: libc::c_int, w: libc::c_ulong) -> libc::c_ulong;
}


/*
void bn_sqr_words()
	(unsigned long *) rp
	(const unsigned long *) ap
	(int) num
*/
#[link(name="crypto")]
extern "C" {
	pub fn bn_sqr_words(rp: *mut libc::c_ulong, ap: *const libc::c_ulong, num: libc::c_int);
}


/*
unsigned long bn_div_words()
	(unsigned long) h
	(unsigned long) l
	(unsigned long) d
*/
#[link(name="crypto")]
extern "C" {
	pub fn bn_div_words(h: libc::c_ulong, l: libc::c_ulong, d: libc::c_ulong) -> libc::c_ulong;
}


/*
unsigned long bn_add_words()
	(unsigned long *) rp
	(const unsigned long *) ap
	(const unsigned long *) bp
	(int) num
*/
#[link(name="crypto")]
extern "C" {
	pub fn bn_add_words(rp: *mut libc::c_ulong, ap: *const libc::c_ulong, bp: *const libc::c_ulong, num: libc::c_int) -> libc::c_ulong;
}


/*
unsigned long bn_sub_words()
	(unsigned long *) rp
	(const unsigned long *) ap
	(const unsigned long *) bp
	(int) num
*/
#[link(name="crypto")]
extern "C" {
	pub fn bn_sub_words(rp: *mut libc::c_ulong, ap: *const libc::c_ulong, bp: *const libc::c_ulong, num: libc::c_int) -> libc::c_ulong;
}


/*
BIGNUM * get_rfc2409_prime_768() [struct bignum_st *]
	(BIGNUM *) bn [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn get_rfc2409_prime_768(bn: *mut bignum_st) -> *mut bignum_st;
}


/*
BIGNUM * get_rfc2409_prime_1024() [struct bignum_st *]
	(BIGNUM *) bn [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn get_rfc2409_prime_1024(bn: *mut bignum_st) -> *mut bignum_st;
}


/*
BIGNUM * get_rfc3526_prime_1536() [struct bignum_st *]
	(BIGNUM *) bn [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn get_rfc3526_prime_1536(bn: *mut bignum_st) -> *mut bignum_st;
}


/*
BIGNUM * get_rfc3526_prime_2048() [struct bignum_st *]
	(BIGNUM *) bn [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn get_rfc3526_prime_2048(bn: *mut bignum_st) -> *mut bignum_st;
}


/*
BIGNUM * get_rfc3526_prime_3072() [struct bignum_st *]
	(BIGNUM *) bn [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn get_rfc3526_prime_3072(bn: *mut bignum_st) -> *mut bignum_st;
}


/*
BIGNUM * get_rfc3526_prime_4096() [struct bignum_st *]
	(BIGNUM *) bn [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn get_rfc3526_prime_4096(bn: *mut bignum_st) -> *mut bignum_st;
}


/*
BIGNUM * get_rfc3526_prime_6144() [struct bignum_st *]
	(BIGNUM *) bn [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn get_rfc3526_prime_6144(bn: *mut bignum_st) -> *mut bignum_st;
}


/*
BIGNUM * get_rfc3526_prime_8192() [struct bignum_st *]
	(BIGNUM *) bn [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn get_rfc3526_prime_8192(bn: *mut bignum_st) -> *mut bignum_st;
}


/*
int BN_bntest_rand()
	(BIGNUM *) rnd [struct bignum_st *]
	(int) bits
	(int) top
	(int) bottom
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_bntest_rand(rnd: *mut bignum_st, bits: libc::c_int, top: libc::c_int, bottom: libc::c_int) -> libc::c_int;
}


/*
void ERR_load_BN_strings()
*/
#[link(name="crypto")]
extern "C" {
	pub fn ERR_load_BN_strings();
}


/*
ASN1_SEQUENCE_ANY * d2i_ASN1_SEQUENCE_ANY() [struct stack_st_ASN1_TYPE *]
	(ASN1_SEQUENCE_ANY **) a [struct stack_st_ASN1_TYPE **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_SEQUENCE_ANY(a: *mut *mut stack_st_ASN1_TYPE, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut stack_st_ASN1_TYPE;
}


/*
int i2d_ASN1_SEQUENCE_ANY()
	(const ASN1_SEQUENCE_ANY *) a [const struct stack_st_ASN1_TYPE *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_SEQUENCE_ANY(a: *const stack_st_ASN1_TYPE, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_SEQUENCE_ANY * d2i_ASN1_SET_ANY() [struct stack_st_ASN1_TYPE *]
	(ASN1_SEQUENCE_ANY **) a [struct stack_st_ASN1_TYPE **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_SET_ANY(a: *mut *mut stack_st_ASN1_TYPE, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut stack_st_ASN1_TYPE;
}


/*
int i2d_ASN1_SET_ANY()
	(const ASN1_SEQUENCE_ANY *) a [const struct stack_st_ASN1_TYPE *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_SET_ANY(a: *const stack_st_ASN1_TYPE, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_TYPE * ASN1_TYPE_new() [struct asn1_type_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TYPE_new() -> *mut asn1_type_st;
}


/*
void ASN1_TYPE_free()
	(ASN1_TYPE *) a [struct asn1_type_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TYPE_free(a: *mut asn1_type_st);
}


/*
ASN1_TYPE * d2i_ASN1_TYPE() [struct asn1_type_st *]
	(ASN1_TYPE **) a [struct asn1_type_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_TYPE(a: *mut *mut asn1_type_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_type_st;
}


/*
int i2d_ASN1_TYPE()
	(ASN1_TYPE *) a [struct asn1_type_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_TYPE(a: *mut asn1_type_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
int ASN1_TYPE_get()
	(ASN1_TYPE *) a [struct asn1_type_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TYPE_get(a: *mut asn1_type_st) -> libc::c_int;
}


/*
void ASN1_TYPE_set()
	(ASN1_TYPE *) a [struct asn1_type_st *]
	(int) type
	(void *) value
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TYPE_set(a: *mut asn1_type_st, type_: libc::c_int, value: *mut libc::c_void);
}


/*
int ASN1_TYPE_set1()
	(ASN1_TYPE *) a [struct asn1_type_st *]
	(int) type
	(const void *) value
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TYPE_set1(a: *mut asn1_type_st, type_: libc::c_int, value: *const libc::c_void) -> libc::c_int;
}


/*
int ASN1_TYPE_cmp()
	(const ASN1_TYPE *) a [const struct asn1_type_st *]
	(const ASN1_TYPE *) b [const struct asn1_type_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TYPE_cmp(a: *const asn1_type_st, b: *const asn1_type_st) -> libc::c_int;
}


/*
ASN1_OBJECT * ASN1_OBJECT_new() [struct asn1_object_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_OBJECT_new() -> *mut asn1_object_st;
}


/*
void ASN1_OBJECT_free()
	(ASN1_OBJECT *) a [struct asn1_object_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_OBJECT_free(a: *mut asn1_object_st);
}


/*
int i2d_ASN1_OBJECT()
	(ASN1_OBJECT *) a [struct asn1_object_st *]
	(unsigned char **) pp
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_OBJECT(a: *mut asn1_object_st, pp: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_OBJECT * c2i_ASN1_OBJECT() [struct asn1_object_st *]
	(ASN1_OBJECT **) a [struct asn1_object_st **]
	(const unsigned char **) pp
	(long) length
*/
#[link(name="crypto")]
extern "C" {
	pub fn c2i_ASN1_OBJECT(a: *mut *mut asn1_object_st, pp: *mut *const libc::c_uchar, length: libc::c_long) -> *mut asn1_object_st;
}


/*
ASN1_OBJECT * d2i_ASN1_OBJECT() [struct asn1_object_st *]
	(ASN1_OBJECT **) a [struct asn1_object_st **]
	(const unsigned char **) pp
	(long) length
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_OBJECT(a: *mut *mut asn1_object_st, pp: *mut *const libc::c_uchar, length: libc::c_long) -> *mut asn1_object_st;
}


/*
ASN1_STRING * ASN1_STRING_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_new() -> *mut asn1_string_st;
}


/*
void ASN1_STRING_free()
	(ASN1_STRING *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_free(a: *mut asn1_string_st);
}


/*
int ASN1_STRING_copy()
	(ASN1_STRING *) dst [struct asn1_string_st *]
	(const ASN1_STRING *) str [const struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_copy(dst: *mut asn1_string_st, str: *const asn1_string_st) -> libc::c_int;
}


/*
ASN1_STRING * ASN1_STRING_dup() [struct asn1_string_st *]
	(const ASN1_STRING *) a [const struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_dup(a: *const asn1_string_st) -> *mut asn1_string_st;
}


/*
ASN1_STRING * ASN1_STRING_type_new() [struct asn1_string_st *]
	(int) type
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_type_new(type_: libc::c_int) -> *mut asn1_string_st;
}


/*
int ASN1_STRING_cmp()
	(const ASN1_STRING *) a [const struct asn1_string_st *]
	(const ASN1_STRING *) b [const struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_cmp(a: *const asn1_string_st, b: *const asn1_string_st) -> libc::c_int;
}


/*
int ASN1_STRING_set()
	(ASN1_STRING *) str [struct asn1_string_st *]
	(const void *) data
	(int) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_set(str: *mut asn1_string_st, data: *const libc::c_void, len: libc::c_int) -> libc::c_int;
}


/*
void ASN1_STRING_set0()
	(ASN1_STRING *) str [struct asn1_string_st *]
	(void *) data
	(int) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_set0(str: *mut asn1_string_st, data: *mut libc::c_void, len: libc::c_int);
}


/*
int ASN1_STRING_length()
	(const ASN1_STRING *) x [const struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_length(x: *const asn1_string_st) -> libc::c_int;
}


/*
void ASN1_STRING_length_set()
	(ASN1_STRING *) x [struct asn1_string_st *]
	(int) n
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_length_set(x: *mut asn1_string_st, n: libc::c_int);
}


/*
int ASN1_STRING_type()
	(ASN1_STRING *) x [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_type(x: *mut asn1_string_st) -> libc::c_int;
}


/*
unsigned char * ASN1_STRING_data()
	(ASN1_STRING *) x [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_data(x: *mut asn1_string_st) -> *mut libc::c_uchar;
}


/*
ASN1_BIT_STRING * ASN1_BIT_STRING_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_BIT_STRING_new() -> *mut asn1_string_st;
}


/*
void ASN1_BIT_STRING_free()
	(ASN1_BIT_STRING *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_BIT_STRING_free(a: *mut asn1_string_st);
}


/*
ASN1_BIT_STRING * d2i_ASN1_BIT_STRING() [struct asn1_string_st *]
	(ASN1_BIT_STRING **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_BIT_STRING(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_ASN1_BIT_STRING()
	(ASN1_BIT_STRING *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_BIT_STRING(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
int i2c_ASN1_BIT_STRING()
	(ASN1_BIT_STRING *) a [struct asn1_string_st *]
	(unsigned char **) pp
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2c_ASN1_BIT_STRING(a: *mut asn1_string_st, pp: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_BIT_STRING * c2i_ASN1_BIT_STRING() [struct asn1_string_st *]
	(ASN1_BIT_STRING **) a [struct asn1_string_st **]
	(const unsigned char **) pp
	(long) length
*/
#[link(name="crypto")]
extern "C" {
	pub fn c2i_ASN1_BIT_STRING(a: *mut *mut asn1_string_st, pp: *mut *const libc::c_uchar, length: libc::c_long) -> *mut asn1_string_st;
}


/*
int ASN1_BIT_STRING_set()
	(ASN1_BIT_STRING *) a [struct asn1_string_st *]
	(unsigned char *) d
	(int) length
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_BIT_STRING_set(a: *mut asn1_string_st, d: *mut libc::c_uchar, length: libc::c_int) -> libc::c_int;
}


/*
int ASN1_BIT_STRING_set_bit()
	(ASN1_BIT_STRING *) a [struct asn1_string_st *]
	(int) n
	(int) value
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_BIT_STRING_set_bit(a: *mut asn1_string_st, n: libc::c_int, value: libc::c_int) -> libc::c_int;
}


/*
int ASN1_BIT_STRING_get_bit()
	(ASN1_BIT_STRING *) a [struct asn1_string_st *]
	(int) n
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_BIT_STRING_get_bit(a: *mut asn1_string_st, n: libc::c_int) -> libc::c_int;
}


/*
int ASN1_BIT_STRING_check()
	(ASN1_BIT_STRING *) a [struct asn1_string_st *]
	(unsigned char *) flags
	(int) flags_len
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_BIT_STRING_check(a: *mut asn1_string_st, flags: *mut libc::c_uchar, flags_len: libc::c_int) -> libc::c_int;
}


/*
int ASN1_BIT_STRING_name_print()
	(BIO *) out [struct bio_st *]
	(ASN1_BIT_STRING *) bs [struct asn1_string_st *]
	(BIT_STRING_BITNAME *) tbl [struct BIT_STRING_BITNAME_st *]
	(int) indent
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_BIT_STRING_name_print(out: *mut bio_st, bs: *mut asn1_string_st, tbl: *mut BIT_STRING_BITNAME_st, indent: libc::c_int) -> libc::c_int;
}


/*
int ASN1_BIT_STRING_num_asc()
	(char *) name
	(BIT_STRING_BITNAME *) tbl [struct BIT_STRING_BITNAME_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_BIT_STRING_num_asc(name: *mut libc::c_char, tbl: *mut BIT_STRING_BITNAME_st) -> libc::c_int;
}


/*
int ASN1_BIT_STRING_set_asc()
	(ASN1_BIT_STRING *) bs [struct asn1_string_st *]
	(char *) name
	(int) value
	(BIT_STRING_BITNAME *) tbl [struct BIT_STRING_BITNAME_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_BIT_STRING_set_asc(bs: *mut asn1_string_st, name: *mut libc::c_char, value: libc::c_int, tbl: *mut BIT_STRING_BITNAME_st) -> libc::c_int;
}


/*
int i2d_ASN1_BOOLEAN()
	(int) a
	(unsigned char **) pp
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_BOOLEAN(a: libc::c_int, pp: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
int d2i_ASN1_BOOLEAN()
	(int *) a
	(const unsigned char **) pp
	(long) length
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_BOOLEAN(a: *mut libc::c_int, pp: *mut *const libc::c_uchar, length: libc::c_long) -> libc::c_int;
}


/*
ASN1_INTEGER * ASN1_INTEGER_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_INTEGER_new() -> *mut asn1_string_st;
}


/*
void ASN1_INTEGER_free()
	(ASN1_INTEGER *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_INTEGER_free(a: *mut asn1_string_st);
}


/*
ASN1_INTEGER * d2i_ASN1_INTEGER() [struct asn1_string_st *]
	(ASN1_INTEGER **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_INTEGER(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_ASN1_INTEGER()
	(ASN1_INTEGER *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_INTEGER(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
int i2c_ASN1_INTEGER()
	(ASN1_INTEGER *) a [struct asn1_string_st *]
	(unsigned char **) pp
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2c_ASN1_INTEGER(a: *mut asn1_string_st, pp: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_INTEGER * c2i_ASN1_INTEGER() [struct asn1_string_st *]
	(ASN1_INTEGER **) a [struct asn1_string_st **]
	(const unsigned char **) pp
	(long) length
*/
#[link(name="crypto")]
extern "C" {
	pub fn c2i_ASN1_INTEGER(a: *mut *mut asn1_string_st, pp: *mut *const libc::c_uchar, length: libc::c_long) -> *mut asn1_string_st;
}


/*
ASN1_INTEGER * d2i_ASN1_UINTEGER() [struct asn1_string_st *]
	(ASN1_INTEGER **) a [struct asn1_string_st **]
	(const unsigned char **) pp
	(long) length
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_UINTEGER(a: *mut *mut asn1_string_st, pp: *mut *const libc::c_uchar, length: libc::c_long) -> *mut asn1_string_st;
}


/*
ASN1_INTEGER * ASN1_INTEGER_dup() [struct asn1_string_st *]
	(const ASN1_INTEGER *) x [const struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_INTEGER_dup(x: *const asn1_string_st) -> *mut asn1_string_st;
}


/*
int ASN1_INTEGER_cmp()
	(const ASN1_INTEGER *) x [const struct asn1_string_st *]
	(const ASN1_INTEGER *) y [const struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_INTEGER_cmp(x: *const asn1_string_st, y: *const asn1_string_st) -> libc::c_int;
}


/*
ASN1_ENUMERATED * ASN1_ENUMERATED_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_ENUMERATED_new() -> *mut asn1_string_st;
}


/*
void ASN1_ENUMERATED_free()
	(ASN1_ENUMERATED *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_ENUMERATED_free(a: *mut asn1_string_st);
}


/*
ASN1_ENUMERATED * d2i_ASN1_ENUMERATED() [struct asn1_string_st *]
	(ASN1_ENUMERATED **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_ENUMERATED(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_ASN1_ENUMERATED()
	(ASN1_ENUMERATED *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_ENUMERATED(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
int ASN1_UTCTIME_check()
	(ASN1_UTCTIME *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_UTCTIME_check(a: *mut asn1_string_st) -> libc::c_int;
}


/*
ASN1_UTCTIME * ASN1_UTCTIME_set() [struct asn1_string_st *]
	(ASN1_UTCTIME *) s [struct asn1_string_st *]
	(time_t) t [long]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_UTCTIME_set(s: *mut asn1_string_st, t: libc::c_long) -> *mut asn1_string_st;
}


/*
ASN1_UTCTIME * ASN1_UTCTIME_adj() [struct asn1_string_st *]
	(ASN1_UTCTIME *) s [struct asn1_string_st *]
	(time_t) t [long]
	(int) offset_day
	(long) offset_sec
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_UTCTIME_adj(s: *mut asn1_string_st, t: libc::c_long, offset_day: libc::c_int, offset_sec: libc::c_long) -> *mut asn1_string_st;
}


/*
int ASN1_UTCTIME_set_string()
	(ASN1_UTCTIME *) s [struct asn1_string_st *]
	(const char *) str
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_UTCTIME_set_string(s: *mut asn1_string_st, str: *const libc::c_char) -> libc::c_int;
}


/*
int ASN1_UTCTIME_cmp_time_t()
	(const ASN1_UTCTIME *) s [const struct asn1_string_st *]
	(time_t) t [long]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_UTCTIME_cmp_time_t(s: *const asn1_string_st, t: libc::c_long) -> libc::c_int;
}


/*
int ASN1_GENERALIZEDTIME_check()
	(ASN1_GENERALIZEDTIME *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_GENERALIZEDTIME_check(a: *mut asn1_string_st) -> libc::c_int;
}


/*
ASN1_GENERALIZEDTIME * ASN1_GENERALIZEDTIME_set() [struct asn1_string_st *]
	(ASN1_GENERALIZEDTIME *) s [struct asn1_string_st *]
	(time_t) t [long]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_GENERALIZEDTIME_set(s: *mut asn1_string_st, t: libc::c_long) -> *mut asn1_string_st;
}


/*
ASN1_GENERALIZEDTIME * ASN1_GENERALIZEDTIME_adj() [struct asn1_string_st *]
	(ASN1_GENERALIZEDTIME *) s [struct asn1_string_st *]
	(time_t) t [long]
	(int) offset_day
	(long) offset_sec
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_GENERALIZEDTIME_adj(s: *mut asn1_string_st, t: libc::c_long, offset_day: libc::c_int, offset_sec: libc::c_long) -> *mut asn1_string_st;
}


/*
int ASN1_GENERALIZEDTIME_set_string()
	(ASN1_GENERALIZEDTIME *) s [struct asn1_string_st *]
	(const char *) str
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_GENERALIZEDTIME_set_string(s: *mut asn1_string_st, str: *const libc::c_char) -> libc::c_int;
}


/*
ASN1_OCTET_STRING * ASN1_OCTET_STRING_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_OCTET_STRING_new() -> *mut asn1_string_st;
}


/*
void ASN1_OCTET_STRING_free()
	(ASN1_OCTET_STRING *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_OCTET_STRING_free(a: *mut asn1_string_st);
}


/*
ASN1_OCTET_STRING * d2i_ASN1_OCTET_STRING() [struct asn1_string_st *]
	(ASN1_OCTET_STRING **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_OCTET_STRING(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_ASN1_OCTET_STRING()
	(ASN1_OCTET_STRING *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_OCTET_STRING(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_OCTET_STRING * ASN1_OCTET_STRING_dup() [struct asn1_string_st *]
	(const ASN1_OCTET_STRING *) a [const struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_OCTET_STRING_dup(a: *const asn1_string_st) -> *mut asn1_string_st;
}


/*
int ASN1_OCTET_STRING_cmp()
	(const ASN1_OCTET_STRING *) a [const struct asn1_string_st *]
	(const ASN1_OCTET_STRING *) b [const struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_OCTET_STRING_cmp(a: *const asn1_string_st, b: *const asn1_string_st) -> libc::c_int;
}


/*
int ASN1_OCTET_STRING_set()
	(ASN1_OCTET_STRING *) str [struct asn1_string_st *]
	(const unsigned char *) data
	(int) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_OCTET_STRING_set(str: *mut asn1_string_st, data: *const libc::c_uchar, len: libc::c_int) -> libc::c_int;
}


/*
ASN1_VISIBLESTRING * ASN1_VISIBLESTRING_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_VISIBLESTRING_new() -> *mut asn1_string_st;
}


/*
void ASN1_VISIBLESTRING_free()
	(ASN1_VISIBLESTRING *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_VISIBLESTRING_free(a: *mut asn1_string_st);
}


/*
ASN1_VISIBLESTRING * d2i_ASN1_VISIBLESTRING() [struct asn1_string_st *]
	(ASN1_VISIBLESTRING **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_VISIBLESTRING(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_ASN1_VISIBLESTRING()
	(ASN1_VISIBLESTRING *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_VISIBLESTRING(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_UNIVERSALSTRING * ASN1_UNIVERSALSTRING_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_UNIVERSALSTRING_new() -> *mut asn1_string_st;
}


/*
void ASN1_UNIVERSALSTRING_free()
	(ASN1_UNIVERSALSTRING *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_UNIVERSALSTRING_free(a: *mut asn1_string_st);
}


/*
ASN1_UNIVERSALSTRING * d2i_ASN1_UNIVERSALSTRING() [struct asn1_string_st *]
	(ASN1_UNIVERSALSTRING **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_UNIVERSALSTRING(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_ASN1_UNIVERSALSTRING()
	(ASN1_UNIVERSALSTRING *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_UNIVERSALSTRING(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_UTF8STRING * ASN1_UTF8STRING_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_UTF8STRING_new() -> *mut asn1_string_st;
}


/*
void ASN1_UTF8STRING_free()
	(ASN1_UTF8STRING *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_UTF8STRING_free(a: *mut asn1_string_st);
}


/*
ASN1_UTF8STRING * d2i_ASN1_UTF8STRING() [struct asn1_string_st *]
	(ASN1_UTF8STRING **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_UTF8STRING(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_ASN1_UTF8STRING()
	(ASN1_UTF8STRING *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_UTF8STRING(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_NULL * ASN1_NULL_new() [int *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_NULL_new() -> *mut libc::c_int;
}


/*
void ASN1_NULL_free()
	(ASN1_NULL *) a [int *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_NULL_free(a: *mut libc::c_int);
}


/*
ASN1_NULL * d2i_ASN1_NULL() [int *]
	(ASN1_NULL **) a [int **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_NULL(a: *mut *mut libc::c_int, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut libc::c_int;
}


/*
int i2d_ASN1_NULL()
	(ASN1_NULL *) a [int *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_NULL(a: *mut libc::c_int, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_BMPSTRING * ASN1_BMPSTRING_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_BMPSTRING_new() -> *mut asn1_string_st;
}


/*
void ASN1_BMPSTRING_free()
	(ASN1_BMPSTRING *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_BMPSTRING_free(a: *mut asn1_string_st);
}


/*
ASN1_BMPSTRING * d2i_ASN1_BMPSTRING() [struct asn1_string_st *]
	(ASN1_BMPSTRING **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_BMPSTRING(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_ASN1_BMPSTRING()
	(ASN1_BMPSTRING *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_BMPSTRING(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
int UTF8_getc()
	(const unsigned char *) str
	(int) len
	(unsigned long *) val
*/
#[link(name="crypto")]
extern "C" {
	pub fn UTF8_getc(str: *const libc::c_uchar, len: libc::c_int, val: *mut libc::c_ulong) -> libc::c_int;
}


/*
int UTF8_putc()
	(unsigned char *) str
	(int) len
	(unsigned long) value
*/
#[link(name="crypto")]
extern "C" {
	pub fn UTF8_putc(str: *mut libc::c_uchar, len: libc::c_int, value: libc::c_ulong) -> libc::c_int;
}


/*
ASN1_STRING * ASN1_PRINTABLE_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_PRINTABLE_new() -> *mut asn1_string_st;
}


/*
void ASN1_PRINTABLE_free()
	(ASN1_STRING *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_PRINTABLE_free(a: *mut asn1_string_st);
}


/*
ASN1_STRING * d2i_ASN1_PRINTABLE() [struct asn1_string_st *]
	(ASN1_STRING **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_PRINTABLE(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_ASN1_PRINTABLE()
	(ASN1_STRING *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_PRINTABLE(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_STRING * DIRECTORYSTRING_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn DIRECTORYSTRING_new() -> *mut asn1_string_st;
}


/*
void DIRECTORYSTRING_free()
	(ASN1_STRING *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn DIRECTORYSTRING_free(a: *mut asn1_string_st);
}


/*
ASN1_STRING * d2i_DIRECTORYSTRING() [struct asn1_string_st *]
	(ASN1_STRING **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_DIRECTORYSTRING(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_DIRECTORYSTRING()
	(ASN1_STRING *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_DIRECTORYSTRING(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_STRING * DISPLAYTEXT_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn DISPLAYTEXT_new() -> *mut asn1_string_st;
}


/*
void DISPLAYTEXT_free()
	(ASN1_STRING *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn DISPLAYTEXT_free(a: *mut asn1_string_st);
}


/*
ASN1_STRING * d2i_DISPLAYTEXT() [struct asn1_string_st *]
	(ASN1_STRING **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_DISPLAYTEXT(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_DISPLAYTEXT()
	(ASN1_STRING *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_DISPLAYTEXT(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_PRINTABLESTRING * ASN1_PRINTABLESTRING_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_PRINTABLESTRING_new() -> *mut asn1_string_st;
}


/*
void ASN1_PRINTABLESTRING_free()
	(ASN1_PRINTABLESTRING *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_PRINTABLESTRING_free(a: *mut asn1_string_st);
}


/*
ASN1_PRINTABLESTRING * d2i_ASN1_PRINTABLESTRING() [struct asn1_string_st *]
	(ASN1_PRINTABLESTRING **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_PRINTABLESTRING(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_ASN1_PRINTABLESTRING()
	(ASN1_PRINTABLESTRING *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_PRINTABLESTRING(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_T61STRING * ASN1_T61STRING_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_T61STRING_new() -> *mut asn1_string_st;
}


/*
void ASN1_T61STRING_free()
	(ASN1_T61STRING *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_T61STRING_free(a: *mut asn1_string_st);
}


/*
ASN1_T61STRING * d2i_ASN1_T61STRING() [struct asn1_string_st *]
	(ASN1_T61STRING **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_T61STRING(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_ASN1_T61STRING()
	(ASN1_T61STRING *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_T61STRING(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_IA5STRING * ASN1_IA5STRING_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_IA5STRING_new() -> *mut asn1_string_st;
}


/*
void ASN1_IA5STRING_free()
	(ASN1_IA5STRING *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_IA5STRING_free(a: *mut asn1_string_st);
}


/*
ASN1_IA5STRING * d2i_ASN1_IA5STRING() [struct asn1_string_st *]
	(ASN1_IA5STRING **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_IA5STRING(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_ASN1_IA5STRING()
	(ASN1_IA5STRING *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_IA5STRING(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_GENERALSTRING * ASN1_GENERALSTRING_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_GENERALSTRING_new() -> *mut asn1_string_st;
}


/*
void ASN1_GENERALSTRING_free()
	(ASN1_GENERALSTRING *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_GENERALSTRING_free(a: *mut asn1_string_st);
}


/*
ASN1_GENERALSTRING * d2i_ASN1_GENERALSTRING() [struct asn1_string_st *]
	(ASN1_GENERALSTRING **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_GENERALSTRING(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_ASN1_GENERALSTRING()
	(ASN1_GENERALSTRING *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_GENERALSTRING(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_UTCTIME * ASN1_UTCTIME_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_UTCTIME_new() -> *mut asn1_string_st;
}


/*
void ASN1_UTCTIME_free()
	(ASN1_UTCTIME *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_UTCTIME_free(a: *mut asn1_string_st);
}


/*
ASN1_UTCTIME * d2i_ASN1_UTCTIME() [struct asn1_string_st *]
	(ASN1_UTCTIME **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_UTCTIME(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_ASN1_UTCTIME()
	(ASN1_UTCTIME *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_UTCTIME(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_GENERALIZEDTIME * ASN1_GENERALIZEDTIME_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_GENERALIZEDTIME_new() -> *mut asn1_string_st;
}


/*
void ASN1_GENERALIZEDTIME_free()
	(ASN1_GENERALIZEDTIME *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_GENERALIZEDTIME_free(a: *mut asn1_string_st);
}


/*
ASN1_GENERALIZEDTIME * d2i_ASN1_GENERALIZEDTIME() [struct asn1_string_st *]
	(ASN1_GENERALIZEDTIME **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_GENERALIZEDTIME(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_ASN1_GENERALIZEDTIME()
	(ASN1_GENERALIZEDTIME *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_GENERALIZEDTIME(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_TIME * ASN1_TIME_new() [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TIME_new() -> *mut asn1_string_st;
}


/*
void ASN1_TIME_free()
	(ASN1_TIME *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TIME_free(a: *mut asn1_string_st);
}


/*
ASN1_TIME * d2i_ASN1_TIME() [struct asn1_string_st *]
	(ASN1_TIME **) a [struct asn1_string_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_TIME(a: *mut *mut asn1_string_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut asn1_string_st;
}


/*
int i2d_ASN1_TIME()
	(ASN1_TIME *) a [struct asn1_string_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_TIME(a: *mut asn1_string_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
ASN1_TIME * ASN1_TIME_set() [struct asn1_string_st *]
	(ASN1_TIME *) s [struct asn1_string_st *]
	(time_t) t [long]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TIME_set(s: *mut asn1_string_st, t: libc::c_long) -> *mut asn1_string_st;
}


/*
ASN1_TIME * ASN1_TIME_adj() [struct asn1_string_st *]
	(ASN1_TIME *) s [struct asn1_string_st *]
	(time_t) t [long]
	(int) offset_day
	(long) offset_sec
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TIME_adj(s: *mut asn1_string_st, t: libc::c_long, offset_day: libc::c_int, offset_sec: libc::c_long) -> *mut asn1_string_st;
}


/*
int ASN1_TIME_check()
	(ASN1_TIME *) t [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TIME_check(t: *mut asn1_string_st) -> libc::c_int;
}


/*
ASN1_GENERALIZEDTIME * ASN1_TIME_to_generalizedtime() [struct asn1_string_st *]
	(ASN1_TIME *) t [struct asn1_string_st *]
	(ASN1_GENERALIZEDTIME **) out [struct asn1_string_st **]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TIME_to_generalizedtime(t: *mut asn1_string_st, out: *mut *mut asn1_string_st) -> *mut asn1_string_st;
}


/*
int ASN1_TIME_set_string()
	(ASN1_TIME *) s [struct asn1_string_st *]
	(const char *) str
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TIME_set_string(s: *mut asn1_string_st, str: *const libc::c_char) -> libc::c_int;
}


/*
int i2d_ASN1_SET()
	(struct stack_st_OPENSSL_BLOCK *) a [struct stack_st_OPENSSL_BLOCK *]
	(unsigned char **) pp
	(i2d_of_void *) i2d [int (*)(void *, unsigned char **)]
	(int) ex_tag
	(int) ex_class
	(int) is_set
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_SET(a: *mut stack_st_OPENSSL_BLOCK, pp: *mut *mut libc::c_uchar, i2d: Option<extern fn(*mut libc::c_void, *mut *mut libc::c_uchar) -> libc::c_int>, ex_tag: libc::c_int, ex_class: libc::c_int, is_set: libc::c_int) -> libc::c_int;
}


/*
struct stack_st_OPENSSL_BLOCK * d2i_ASN1_SET() [struct stack_st_OPENSSL_BLOCK *]
	(struct stack_st_OPENSSL_BLOCK **) a [struct stack_st_OPENSSL_BLOCK **]
	(const unsigned char **) pp
	(long) length
	(d2i_of_void *) d2i [void *(*)(void **, const unsigned char **, long)]
	(void (*)(OPENSSL_BLOCK)) free_func [void (*)(void *)]
	(int) ex_tag
	(int) ex_class
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_SET(a: *mut *mut stack_st_OPENSSL_BLOCK, pp: *mut *const libc::c_uchar, length: libc::c_long, d2i: Option<extern fn(*mut *mut libc::c_void, *mut *const libc::c_uchar, libc::c_long) -> *mut libc::c_void>, free_func: Option<extern fn(*mut libc::c_void)>, ex_tag: libc::c_int, ex_class: libc::c_int) -> *mut stack_st_OPENSSL_BLOCK;
}


/*
int i2a_ASN1_INTEGER()
	(BIO *) bp [struct bio_st *]
	(ASN1_INTEGER *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2a_ASN1_INTEGER(bp: *mut bio_st, a: *mut asn1_string_st) -> libc::c_int;
}


/*
int a2i_ASN1_INTEGER()
	(BIO *) bp [struct bio_st *]
	(ASN1_INTEGER *) bs [struct asn1_string_st *]
	(char *) buf
	(int) size
*/
#[link(name="crypto")]
extern "C" {
	pub fn a2i_ASN1_INTEGER(bp: *mut bio_st, bs: *mut asn1_string_st, buf: *mut libc::c_char, size: libc::c_int) -> libc::c_int;
}


/*
int i2a_ASN1_ENUMERATED()
	(BIO *) bp [struct bio_st *]
	(ASN1_ENUMERATED *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2a_ASN1_ENUMERATED(bp: *mut bio_st, a: *mut asn1_string_st) -> libc::c_int;
}


/*
int a2i_ASN1_ENUMERATED()
	(BIO *) bp [struct bio_st *]
	(ASN1_ENUMERATED *) bs [struct asn1_string_st *]
	(char *) buf
	(int) size
*/
#[link(name="crypto")]
extern "C" {
	pub fn a2i_ASN1_ENUMERATED(bp: *mut bio_st, bs: *mut asn1_string_st, buf: *mut libc::c_char, size: libc::c_int) -> libc::c_int;
}


/*
int i2a_ASN1_OBJECT()
	(BIO *) bp [struct bio_st *]
	(ASN1_OBJECT *) a [struct asn1_object_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2a_ASN1_OBJECT(bp: *mut bio_st, a: *mut asn1_object_st) -> libc::c_int;
}


/*
int a2i_ASN1_STRING()
	(BIO *) bp [struct bio_st *]
	(ASN1_STRING *) bs [struct asn1_string_st *]
	(char *) buf
	(int) size
*/
#[link(name="crypto")]
extern "C" {
	pub fn a2i_ASN1_STRING(bp: *mut bio_st, bs: *mut asn1_string_st, buf: *mut libc::c_char, size: libc::c_int) -> libc::c_int;
}


/*
int i2a_ASN1_STRING()
	(BIO *) bp [struct bio_st *]
	(ASN1_STRING *) a [struct asn1_string_st *]
	(int) type
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2a_ASN1_STRING(bp: *mut bio_st, a: *mut asn1_string_st, type_: libc::c_int) -> libc::c_int;
}


/*
int i2t_ASN1_OBJECT()
	(char *) buf
	(int) buf_len
	(ASN1_OBJECT *) a [struct asn1_object_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2t_ASN1_OBJECT(buf: *mut libc::c_char, buf_len: libc::c_int, a: *mut asn1_object_st) -> libc::c_int;
}


/*
int a2d_ASN1_OBJECT()
	(unsigned char *) out
	(int) olen
	(const char *) buf
	(int) num
*/
#[link(name="crypto")]
extern "C" {
	pub fn a2d_ASN1_OBJECT(out: *mut libc::c_uchar, olen: libc::c_int, buf: *const libc::c_char, num: libc::c_int) -> libc::c_int;
}


/*
ASN1_OBJECT * ASN1_OBJECT_create() [struct asn1_object_st *]
	(int) nid
	(unsigned char *) data
	(int) len
	(const char *) sn
	(const char *) ln
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_OBJECT_create(nid: libc::c_int, data: *mut libc::c_uchar, len: libc::c_int, sn: *const libc::c_char, ln: *const libc::c_char) -> *mut asn1_object_st;
}


/*
int ASN1_INTEGER_set()
	(ASN1_INTEGER *) a [struct asn1_string_st *]
	(long) v
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_INTEGER_set(a: *mut asn1_string_st, v: libc::c_long) -> libc::c_int;
}


/*
long ASN1_INTEGER_get()
	(const ASN1_INTEGER *) a [const struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_INTEGER_get(a: *const asn1_string_st) -> libc::c_long;
}


/*
ASN1_INTEGER * BN_to_ASN1_INTEGER() [struct asn1_string_st *]
	(const BIGNUM *) bn [const struct bignum_st *]
	(ASN1_INTEGER *) ai [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_to_ASN1_INTEGER(bn: *const bignum_st, ai: *mut asn1_string_st) -> *mut asn1_string_st;
}


/*
BIGNUM * ASN1_INTEGER_to_BN() [struct bignum_st *]
	(const ASN1_INTEGER *) ai [const struct asn1_string_st *]
	(BIGNUM *) bn [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_INTEGER_to_BN(ai: *const asn1_string_st, bn: *mut bignum_st) -> *mut bignum_st;
}


/*
int ASN1_ENUMERATED_set()
	(ASN1_ENUMERATED *) a [struct asn1_string_st *]
	(long) v
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_ENUMERATED_set(a: *mut asn1_string_st, v: libc::c_long) -> libc::c_int;
}


/*
long ASN1_ENUMERATED_get()
	(ASN1_ENUMERATED *) a [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_ENUMERATED_get(a: *mut asn1_string_st) -> libc::c_long;
}


/*
ASN1_ENUMERATED * BN_to_ASN1_ENUMERATED() [struct asn1_string_st *]
	(BIGNUM *) bn [struct bignum_st *]
	(ASN1_ENUMERATED *) ai [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BN_to_ASN1_ENUMERATED(bn: *mut bignum_st, ai: *mut asn1_string_st) -> *mut asn1_string_st;
}


/*
BIGNUM * ASN1_ENUMERATED_to_BN() [struct bignum_st *]
	(ASN1_ENUMERATED *) ai [struct asn1_string_st *]
	(BIGNUM *) bn [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_ENUMERATED_to_BN(ai: *mut asn1_string_st, bn: *mut bignum_st) -> *mut bignum_st;
}


/*
int ASN1_PRINTABLE_type()
	(const unsigned char *) s
	(int) max
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_PRINTABLE_type(s: *const libc::c_uchar, max: libc::c_int) -> libc::c_int;
}


/*
int i2d_ASN1_bytes()
	(ASN1_STRING *) a [struct asn1_string_st *]
	(unsigned char **) pp
	(int) tag
	(int) xclass
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_bytes(a: *mut asn1_string_st, pp: *mut *mut libc::c_uchar, tag: libc::c_int, xclass: libc::c_int) -> libc::c_int;
}


/*
ASN1_STRING * d2i_ASN1_bytes() [struct asn1_string_st *]
	(ASN1_STRING **) a [struct asn1_string_st **]
	(const unsigned char **) pp
	(long) length
	(int) Ptag
	(int) Pclass
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_bytes(a: *mut *mut asn1_string_st, pp: *mut *const libc::c_uchar, length: libc::c_long, Ptag: libc::c_int, Pclass: libc::c_int) -> *mut asn1_string_st;
}


/*
unsigned long ASN1_tag2bit()
	(int) tag
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_tag2bit(tag: libc::c_int) -> libc::c_ulong;
}


/*
ASN1_STRING * d2i_ASN1_type_bytes() [struct asn1_string_st *]
	(ASN1_STRING **) a [struct asn1_string_st **]
	(const unsigned char **) pp
	(long) length
	(int) type
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ASN1_type_bytes(a: *mut *mut asn1_string_st, pp: *mut *const libc::c_uchar, length: libc::c_long, type_: libc::c_int) -> *mut asn1_string_st;
}


/*
int asn1_Finish()
	(ASN1_CTX *) c [struct asn1_ctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn asn1_Finish(c: *mut asn1_ctx_st) -> libc::c_int;
}


/*
int asn1_const_Finish()
	(ASN1_const_CTX *) c [struct asn1_const_ctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn asn1_const_Finish(c: *mut asn1_const_ctx_st) -> libc::c_int;
}


/*
int ASN1_get_object()
	(const unsigned char **) pp
	(long *) plength
	(int *) ptag
	(int *) pclass
	(long) omax
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_get_object(pp: *mut *const libc::c_uchar, plength: *mut libc::c_long, ptag: *mut libc::c_int, pclass: *mut libc::c_int, omax: libc::c_long) -> libc::c_int;
}


/*
int ASN1_check_infinite_end()
	(unsigned char **) p
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_check_infinite_end(p: *mut *mut libc::c_uchar, len: libc::c_long) -> libc::c_int;
}


/*
int ASN1_const_check_infinite_end()
	(const unsigned char **) p
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_const_check_infinite_end(p: *mut *const libc::c_uchar, len: libc::c_long) -> libc::c_int;
}


/*
void ASN1_put_object()
	(unsigned char **) pp
	(int) constructed
	(int) length
	(int) tag
	(int) xclass
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_put_object(pp: *mut *mut libc::c_uchar, constructed: libc::c_int, length: libc::c_int, tag: libc::c_int, xclass: libc::c_int);
}


/*
int ASN1_put_eoc()
	(unsigned char **) pp
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_put_eoc(pp: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
int ASN1_object_size()
	(int) constructed
	(int) length
	(int) tag
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_object_size(constructed: libc::c_int, length: libc::c_int, tag: libc::c_int) -> libc::c_int;
}


/*
void * ASN1_dup()
	(i2d_of_void *) i2d [int (*)(void *, unsigned char **)]
	(d2i_of_void *) d2i [void *(*)(void **, const unsigned char **, long)]
	(void *) x
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_dup(i2d: Option<extern fn(*mut libc::c_void, *mut *mut libc::c_uchar) -> libc::c_int>, d2i: Option<extern fn(*mut *mut libc::c_void, *mut *const libc::c_uchar, libc::c_long) -> *mut libc::c_void>, x: *mut libc::c_void) -> *mut libc::c_void;
}


/*
void * ASN1_item_dup()
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
	(void *) x
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_item_dup(it: *const ASN1_ITEM_st, x: *mut libc::c_void) -> *mut libc::c_void;
}


/*
void * ASN1_d2i_fp()
	(void *(*)(void)) xnew [void *(*)(void)]
	(d2i_of_void *) d2i [void *(*)(void **, const unsigned char **, long)]
	(FILE *) in [struct _IO_FILE *]
	(void **) x
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_d2i_fp(xnew: Option<extern fn() -> *mut libc::c_void>, d2i: Option<extern fn(*mut *mut libc::c_void, *mut *const libc::c_uchar, libc::c_long) -> *mut libc::c_void>, in_: libc::c_int, x: *mut *mut libc::c_void) -> *mut libc::c_void;
}


/*
void * ASN1_item_d2i_fp()
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
	(FILE *) in [struct _IO_FILE *]
	(void *) x
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_item_d2i_fp(it: *const ASN1_ITEM_st, in_: libc::c_int, x: *mut libc::c_void) -> *mut libc::c_void;
}


/*
int ASN1_i2d_fp()
	(i2d_of_void *) i2d [int (*)(void *, unsigned char **)]
	(FILE *) out [struct _IO_FILE *]
	(void *) x
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_i2d_fp(i2d: Option<extern fn(*mut libc::c_void, *mut *mut libc::c_uchar) -> libc::c_int>, out: libc::c_int, x: *mut libc::c_void) -> libc::c_int;
}


/*
int ASN1_item_i2d_fp()
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
	(FILE *) out [struct _IO_FILE *]
	(void *) x
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_item_i2d_fp(it: *const ASN1_ITEM_st, out: libc::c_int, x: *mut libc::c_void) -> libc::c_int;
}


/*
int ASN1_STRING_print_ex_fp()
	(FILE *) fp [struct _IO_FILE *]
	(ASN1_STRING *) str [struct asn1_string_st *]
	(unsigned long) flags
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_print_ex_fp(fp: libc::c_int, str: *mut asn1_string_st, flags: libc::c_ulong) -> libc::c_int;
}


/*
int ASN1_STRING_to_UTF8()
	(unsigned char **) out
	(ASN1_STRING *) in [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_to_UTF8(out: *mut *mut libc::c_uchar, in_: *mut asn1_string_st) -> libc::c_int;
}


/*
void * ASN1_d2i_bio()
	(void *(*)(void)) xnew [void *(*)(void)]
	(d2i_of_void *) d2i [void *(*)(void **, const unsigned char **, long)]
	(BIO *) in [struct bio_st *]
	(void **) x
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_d2i_bio(xnew: Option<extern fn() -> *mut libc::c_void>, d2i: Option<extern fn(*mut *mut libc::c_void, *mut *const libc::c_uchar, libc::c_long) -> *mut libc::c_void>, in_: *mut bio_st, x: *mut *mut libc::c_void) -> *mut libc::c_void;
}


/*
void * ASN1_item_d2i_bio()
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
	(BIO *) in [struct bio_st *]
	(void *) x
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_item_d2i_bio(it: *const ASN1_ITEM_st, in_: *mut bio_st, x: *mut libc::c_void) -> *mut libc::c_void;
}


/*
int ASN1_i2d_bio()
	(i2d_of_void *) i2d [int (*)(void *, unsigned char **)]
	(BIO *) out [struct bio_st *]
	(unsigned char *) x
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_i2d_bio(i2d: Option<extern fn(*mut libc::c_void, *mut *mut libc::c_uchar) -> libc::c_int>, out: *mut bio_st, x: *mut libc::c_uchar) -> libc::c_int;
}


/*
int ASN1_item_i2d_bio()
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
	(BIO *) out [struct bio_st *]
	(void *) x
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_item_i2d_bio(it: *const ASN1_ITEM_st, out: *mut bio_st, x: *mut libc::c_void) -> libc::c_int;
}


/*
int ASN1_UTCTIME_print()
	(BIO *) fp [struct bio_st *]
	(const ASN1_UTCTIME *) a [const struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_UTCTIME_print(fp: *mut bio_st, a: *const asn1_string_st) -> libc::c_int;
}


/*
int ASN1_GENERALIZEDTIME_print()
	(BIO *) fp [struct bio_st *]
	(const ASN1_GENERALIZEDTIME *) a [const struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_GENERALIZEDTIME_print(fp: *mut bio_st, a: *const asn1_string_st) -> libc::c_int;
}


/*
int ASN1_TIME_print()
	(BIO *) fp [struct bio_st *]
	(const ASN1_TIME *) a [const struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TIME_print(fp: *mut bio_st, a: *const asn1_string_st) -> libc::c_int;
}


/*
int ASN1_STRING_print()
	(BIO *) bp [struct bio_st *]
	(const ASN1_STRING *) v [const struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_print(bp: *mut bio_st, v: *const asn1_string_st) -> libc::c_int;
}


/*
int ASN1_STRING_print_ex()
	(BIO *) out [struct bio_st *]
	(ASN1_STRING *) str [struct asn1_string_st *]
	(unsigned long) flags
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_print_ex(out: *mut bio_st, str: *mut asn1_string_st, flags: libc::c_ulong) -> libc::c_int;
}


/*
int ASN1_bn_print()
	(BIO *) bp [struct bio_st *]
	(const char *) number
	(const BIGNUM *) num [const struct bignum_st *]
	(unsigned char *) buf
	(int) off
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_bn_print(bp: *mut bio_st, number: *const libc::c_char, num: *const bignum_st, buf: *mut libc::c_uchar, off: libc::c_int) -> libc::c_int;
}


/*
int ASN1_parse()
	(BIO *) bp [struct bio_st *]
	(const unsigned char *) pp
	(long) len
	(int) indent
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_parse(bp: *mut bio_st, pp: *const libc::c_uchar, len: libc::c_long, indent: libc::c_int) -> libc::c_int;
}


/*
int ASN1_parse_dump()
	(BIO *) bp [struct bio_st *]
	(const unsigned char *) pp
	(long) len
	(int) indent
	(int) dump
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_parse_dump(bp: *mut bio_st, pp: *const libc::c_uchar, len: libc::c_long, indent: libc::c_int, dump: libc::c_int) -> libc::c_int;
}


/*
const char * ASN1_tag2str()
	(int) tag
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_tag2str(tag: libc::c_int) -> *const libc::c_char;
}


/*
NETSCAPE_X509 * NETSCAPE_X509_new() [struct NETSCAPE_X509_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn NETSCAPE_X509_new() -> *mut NETSCAPE_X509_st;
}


/*
void NETSCAPE_X509_free()
	(NETSCAPE_X509 *) a [struct NETSCAPE_X509_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn NETSCAPE_X509_free(a: *mut NETSCAPE_X509_st);
}


/*
NETSCAPE_X509 * d2i_NETSCAPE_X509() [struct NETSCAPE_X509_st *]
	(NETSCAPE_X509 **) a [struct NETSCAPE_X509_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_NETSCAPE_X509(a: *mut *mut NETSCAPE_X509_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut NETSCAPE_X509_st;
}


/*
int i2d_NETSCAPE_X509()
	(NETSCAPE_X509 *) a [struct NETSCAPE_X509_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_NETSCAPE_X509(a: *mut NETSCAPE_X509_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
int ASN1_UNIVERSALSTRING_to_string()
	(ASN1_UNIVERSALSTRING *) s [struct asn1_string_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_UNIVERSALSTRING_to_string(s: *mut asn1_string_st) -> libc::c_int;
}


/*
int ASN1_TYPE_set_octetstring()
	(ASN1_TYPE *) a [struct asn1_type_st *]
	(unsigned char *) data
	(int) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TYPE_set_octetstring(a: *mut asn1_type_st, data: *mut libc::c_uchar, len: libc::c_int) -> libc::c_int;
}


/*
int ASN1_TYPE_get_octetstring()
	(ASN1_TYPE *) a [struct asn1_type_st *]
	(unsigned char *) data
	(int) max_len
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TYPE_get_octetstring(a: *mut asn1_type_st, data: *mut libc::c_uchar, max_len: libc::c_int) -> libc::c_int;
}


/*
int ASN1_TYPE_set_int_octetstring()
	(ASN1_TYPE *) a [struct asn1_type_st *]
	(long) num
	(unsigned char *) data
	(int) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TYPE_set_int_octetstring(a: *mut asn1_type_st, num: libc::c_long, data: *mut libc::c_uchar, len: libc::c_int) -> libc::c_int;
}


/*
int ASN1_TYPE_get_int_octetstring()
	(ASN1_TYPE *) a [struct asn1_type_st *]
	(long *) num
	(unsigned char *) data
	(int) max_len
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_TYPE_get_int_octetstring(a: *mut asn1_type_st, num: *mut libc::c_long, data: *mut libc::c_uchar, max_len: libc::c_int) -> libc::c_int;
}


/*
struct stack_st_OPENSSL_BLOCK * ASN1_seq_unpack() [struct stack_st_OPENSSL_BLOCK *]
	(const unsigned char *) buf
	(int) len
	(d2i_of_void *) d2i [void *(*)(void **, const unsigned char **, long)]
	(void (*)(OPENSSL_BLOCK)) free_func [void (*)(void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_seq_unpack(buf: *const libc::c_uchar, len: libc::c_int, d2i: Option<extern fn(*mut *mut libc::c_void, *mut *const libc::c_uchar, libc::c_long) -> *mut libc::c_void>, free_func: Option<extern fn(*mut libc::c_void)>) -> *mut stack_st_OPENSSL_BLOCK;
}


/*
unsigned char * ASN1_seq_pack()
	(struct stack_st_OPENSSL_BLOCK *) safes [struct stack_st_OPENSSL_BLOCK *]
	(i2d_of_void *) i2d [int (*)(void *, unsigned char **)]
	(unsigned char **) buf
	(int *) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_seq_pack(safes: *mut stack_st_OPENSSL_BLOCK, i2d: Option<extern fn(*mut libc::c_void, *mut *mut libc::c_uchar) -> libc::c_int>, buf: *mut *mut libc::c_uchar, len: *mut libc::c_int) -> *mut libc::c_uchar;
}


/*
void * ASN1_unpack_string()
	(ASN1_STRING *) oct [struct asn1_string_st *]
	(d2i_of_void *) d2i [void *(*)(void **, const unsigned char **, long)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_unpack_string(oct: *mut asn1_string_st, d2i: Option<extern fn(*mut *mut libc::c_void, *mut *const libc::c_uchar, libc::c_long) -> *mut libc::c_void>) -> *mut libc::c_void;
}


/*
void * ASN1_item_unpack()
	(ASN1_STRING *) oct [struct asn1_string_st *]
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_item_unpack(oct: *mut asn1_string_st, it: *const ASN1_ITEM_st) -> *mut libc::c_void;
}


/*
ASN1_STRING * ASN1_pack_string() [struct asn1_string_st *]
	(void *) obj
	(i2d_of_void *) i2d [int (*)(void *, unsigned char **)]
	(ASN1_OCTET_STRING **) oct [struct asn1_string_st **]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_pack_string(obj: *mut libc::c_void, i2d: Option<extern fn(*mut libc::c_void, *mut *mut libc::c_uchar) -> libc::c_int>, oct: *mut *mut asn1_string_st) -> *mut asn1_string_st;
}


/*
ASN1_STRING * ASN1_item_pack() [struct asn1_string_st *]
	(void *) obj
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
	(ASN1_OCTET_STRING **) oct [struct asn1_string_st **]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_item_pack(obj: *mut libc::c_void, it: *const ASN1_ITEM_st, oct: *mut *mut asn1_string_st) -> *mut asn1_string_st;
}


/*
void ASN1_STRING_set_default_mask()
	(unsigned long) mask
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_set_default_mask(mask: libc::c_ulong);
}


/*
int ASN1_STRING_set_default_mask_asc()
	(const char *) p
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_set_default_mask_asc(p: *const libc::c_char) -> libc::c_int;
}


/*
unsigned long ASN1_STRING_get_default_mask()
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_get_default_mask() -> libc::c_ulong;
}


/*
int ASN1_mbstring_copy()
	(ASN1_STRING **) out [struct asn1_string_st **]
	(const unsigned char *) in
	(int) len
	(int) inform
	(unsigned long) mask
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_mbstring_copy(out: *mut *mut asn1_string_st, in_: *const libc::c_uchar, len: libc::c_int, inform: libc::c_int, mask: libc::c_ulong) -> libc::c_int;
}


/*
int ASN1_mbstring_ncopy()
	(ASN1_STRING **) out [struct asn1_string_st **]
	(const unsigned char *) in
	(int) len
	(int) inform
	(unsigned long) mask
	(long) minsize
	(long) maxsize
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_mbstring_ncopy(out: *mut *mut asn1_string_st, in_: *const libc::c_uchar, len: libc::c_int, inform: libc::c_int, mask: libc::c_ulong, minsize: libc::c_long, maxsize: libc::c_long) -> libc::c_int;
}


/*
ASN1_STRING * ASN1_STRING_set_by_NID() [struct asn1_string_st *]
	(ASN1_STRING **) out [struct asn1_string_st **]
	(const unsigned char *) in
	(int) inlen
	(int) inform
	(int) nid
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_set_by_NID(out: *mut *mut asn1_string_st, in_: *const libc::c_uchar, inlen: libc::c_int, inform: libc::c_int, nid: libc::c_int) -> *mut asn1_string_st;
}


/*
ASN1_STRING_TABLE * ASN1_STRING_TABLE_get() [struct asn1_string_table_st *]
	(int) nid
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_TABLE_get(nid: libc::c_int) -> *mut asn1_string_table_st;
}


/*
int ASN1_STRING_TABLE_add()
	(int) 
	(long) 
	(long) 
	(unsigned long) 
	(unsigned long) 
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_TABLE_add(_: libc::c_int, _: libc::c_long, _: libc::c_long, _: libc::c_ulong, _: libc::c_ulong) -> libc::c_int;
}


/*
void ASN1_STRING_TABLE_cleanup()
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_STRING_TABLE_cleanup();
}


/*
ASN1_VALUE * ASN1_item_new() [struct ASN1_VALUE_st *]
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_item_new(it: *const ASN1_ITEM_st) -> *mut ASN1_VALUE_st;
}


/*
void ASN1_item_free()
	(ASN1_VALUE *) val [struct ASN1_VALUE_st *]
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_item_free(val: *mut ASN1_VALUE_st, it: *const ASN1_ITEM_st);
}


/*
ASN1_VALUE * ASN1_item_d2i() [struct ASN1_VALUE_st *]
	(ASN1_VALUE **) val [struct ASN1_VALUE_st **]
	(const unsigned char **) in
	(long) len
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_item_d2i(val: *mut *mut ASN1_VALUE_st, in_: *mut *const libc::c_uchar, len: libc::c_long, it: *const ASN1_ITEM_st) -> *mut ASN1_VALUE_st;
}


/*
int ASN1_item_i2d()
	(ASN1_VALUE *) val [struct ASN1_VALUE_st *]
	(unsigned char **) out
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_item_i2d(val: *mut ASN1_VALUE_st, out: *mut *mut libc::c_uchar, it: *const ASN1_ITEM_st) -> libc::c_int;
}


/*
int ASN1_item_ndef_i2d()
	(ASN1_VALUE *) val [struct ASN1_VALUE_st *]
	(unsigned char **) out
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_item_ndef_i2d(val: *mut ASN1_VALUE_st, out: *mut *mut libc::c_uchar, it: *const ASN1_ITEM_st) -> libc::c_int;
}


/*
void ASN1_add_oid_module()
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_add_oid_module();
}


/*
ASN1_TYPE * ASN1_generate_nconf() [struct asn1_type_st *]
	(char *) str
	(CONF *) nconf [struct conf_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_generate_nconf(str: *mut libc::c_char, nconf: *mut conf_st) -> *mut asn1_type_st;
}


/*
ASN1_TYPE * ASN1_generate_v3() [struct asn1_type_st *]
	(char *) str
	(X509V3_CTX *) cnf [struct v3_ext_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_generate_v3(str: *mut libc::c_char, cnf: *mut v3_ext_ctx) -> *mut asn1_type_st;
}


/*
int ASN1_item_print()
	(BIO *) out [struct bio_st *]
	(ASN1_VALUE *) ifld [struct ASN1_VALUE_st *]
	(int) indent
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
	(const ASN1_PCTX *) pctx [const struct asn1_pctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_item_print(out: *mut bio_st, ifld: *mut ASN1_VALUE_st, indent: libc::c_int, it: *const ASN1_ITEM_st, pctx: *const asn1_pctx_st) -> libc::c_int;
}


/*
ASN1_PCTX * ASN1_PCTX_new() [struct asn1_pctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_PCTX_new() -> *mut asn1_pctx_st;
}


/*
void ASN1_PCTX_free()
	(ASN1_PCTX *) p [struct asn1_pctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_PCTX_free(p: *mut asn1_pctx_st);
}


/*
unsigned long ASN1_PCTX_get_flags()
	(ASN1_PCTX *) p [struct asn1_pctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_PCTX_get_flags(p: *mut asn1_pctx_st) -> libc::c_ulong;
}


/*
void ASN1_PCTX_set_flags()
	(ASN1_PCTX *) p [struct asn1_pctx_st *]
	(unsigned long) flags
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_PCTX_set_flags(p: *mut asn1_pctx_st, flags: libc::c_ulong);
}


/*
unsigned long ASN1_PCTX_get_nm_flags()
	(ASN1_PCTX *) p [struct asn1_pctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_PCTX_get_nm_flags(p: *mut asn1_pctx_st) -> libc::c_ulong;
}


/*
void ASN1_PCTX_set_nm_flags()
	(ASN1_PCTX *) p [struct asn1_pctx_st *]
	(unsigned long) flags
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_PCTX_set_nm_flags(p: *mut asn1_pctx_st, flags: libc::c_ulong);
}


/*
unsigned long ASN1_PCTX_get_cert_flags()
	(ASN1_PCTX *) p [struct asn1_pctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_PCTX_get_cert_flags(p: *mut asn1_pctx_st) -> libc::c_ulong;
}


/*
void ASN1_PCTX_set_cert_flags()
	(ASN1_PCTX *) p [struct asn1_pctx_st *]
	(unsigned long) flags
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_PCTX_set_cert_flags(p: *mut asn1_pctx_st, flags: libc::c_ulong);
}


/*
unsigned long ASN1_PCTX_get_oid_flags()
	(ASN1_PCTX *) p [struct asn1_pctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_PCTX_get_oid_flags(p: *mut asn1_pctx_st) -> libc::c_ulong;
}


/*
void ASN1_PCTX_set_oid_flags()
	(ASN1_PCTX *) p [struct asn1_pctx_st *]
	(unsigned long) flags
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_PCTX_set_oid_flags(p: *mut asn1_pctx_st, flags: libc::c_ulong);
}


/*
unsigned long ASN1_PCTX_get_str_flags()
	(ASN1_PCTX *) p [struct asn1_pctx_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_PCTX_get_str_flags(p: *mut asn1_pctx_st) -> libc::c_ulong;
}


/*
void ASN1_PCTX_set_str_flags()
	(ASN1_PCTX *) p [struct asn1_pctx_st *]
	(unsigned long) flags
*/
#[link(name="crypto")]
extern "C" {
	pub fn ASN1_PCTX_set_str_flags(p: *mut asn1_pctx_st, flags: libc::c_ulong);
}


/*
BIO_METHOD * BIO_f_asn1() [struct bio_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_f_asn1() -> *mut bio_method_st;
}


/*
BIO * BIO_new_NDEF() [struct bio_st *]
	(BIO *) out [struct bio_st *]
	(ASN1_VALUE *) val [struct ASN1_VALUE_st *]
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn BIO_new_NDEF(out: *mut bio_st, val: *mut ASN1_VALUE_st, it: *const ASN1_ITEM_st) -> *mut bio_st;
}


/*
int i2d_ASN1_bio_stream()
	(BIO *) out [struct bio_st *]
	(ASN1_VALUE *) val [struct ASN1_VALUE_st *]
	(BIO *) in [struct bio_st *]
	(int) flags
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ASN1_bio_stream(out: *mut bio_st, val: *mut ASN1_VALUE_st, in_: *mut bio_st, flags: libc::c_int, it: *const ASN1_ITEM_st) -> libc::c_int;
}


/*
int PEM_write_bio_ASN1_stream()
	(BIO *) out [struct bio_st *]
	(ASN1_VALUE *) val [struct ASN1_VALUE_st *]
	(BIO *) in [struct bio_st *]
	(int) flags
	(const char *) hdr
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn PEM_write_bio_ASN1_stream(out: *mut bio_st, val: *mut ASN1_VALUE_st, in_: *mut bio_st, flags: libc::c_int, hdr: *const libc::c_char, it: *const ASN1_ITEM_st) -> libc::c_int;
}


/*
int SMIME_write_ASN1()
	(BIO *) bio [struct bio_st *]
	(ASN1_VALUE *) val [struct ASN1_VALUE_st *]
	(BIO *) data [struct bio_st *]
	(int) flags
	(int) ctype_nid
	(int) econt_nid
	(struct stack_st_X509_ALGOR *) mdalgs [struct stack_st_X509_ALGOR *]
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SMIME_write_ASN1(bio: *mut bio_st, val: *mut ASN1_VALUE_st, data: *mut bio_st, flags: libc::c_int, ctype_nid: libc::c_int, econt_nid: libc::c_int, mdalgs: *mut stack_st_X509_ALGOR, it: *const ASN1_ITEM_st) -> libc::c_int;
}


/*
ASN1_VALUE * SMIME_read_ASN1() [struct ASN1_VALUE_st *]
	(BIO *) bio [struct bio_st *]
	(BIO **) bcont [struct bio_st **]
	(const ASN1_ITEM *) it [const struct ASN1_ITEM_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SMIME_read_ASN1(bio: *mut bio_st, bcont: *mut *mut bio_st, it: *const ASN1_ITEM_st) -> *mut ASN1_VALUE_st;
}


/*
int SMIME_crlf_copy()
	(BIO *) in [struct bio_st *]
	(BIO *) out [struct bio_st *]
	(int) flags
*/
#[link(name="crypto")]
extern "C" {
	pub fn SMIME_crlf_copy(in_: *mut bio_st, out: *mut bio_st, flags: libc::c_int) -> libc::c_int;
}


/*
int SMIME_text()
	(BIO *) in [struct bio_st *]
	(BIO *) out [struct bio_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SMIME_text(in_: *mut bio_st, out: *mut bio_st) -> libc::c_int;
}


/*
void ERR_load_ASN1_strings()
*/
#[link(name="crypto")]
extern "C" {
	pub fn ERR_load_ASN1_strings();
}


/*
const EC_METHOD * EC_GFp_simple_method() [const struct ec_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GFp_simple_method() -> *const ec_method_st;
}


/*
const EC_METHOD * EC_GFp_mont_method() [const struct ec_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GFp_mont_method() -> *const ec_method_st;
}


/*
const EC_METHOD * EC_GFp_nist_method() [const struct ec_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GFp_nist_method() -> *const ec_method_st;
}


/*
const EC_METHOD * EC_GFp_nistp224_method() [const struct ec_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GFp_nistp224_method() -> *const ec_method_st;
}


/*
const EC_METHOD * EC_GFp_nistp256_method() [const struct ec_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GFp_nistp256_method() -> *const ec_method_st;
}


/*
const EC_METHOD * EC_GFp_nistp521_method() [const struct ec_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GFp_nistp521_method() -> *const ec_method_st;
}


/*
const EC_METHOD * EC_GF2m_simple_method() [const struct ec_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GF2m_simple_method() -> *const ec_method_st;
}


/*
EC_GROUP * EC_GROUP_new() [struct ec_group_st *]
	(const EC_METHOD *) meth [const struct ec_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_new(meth: *const ec_method_st) -> *mut ec_group_st;
}


/*
void EC_GROUP_free()
	(EC_GROUP *) group [struct ec_group_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_free(group: *mut ec_group_st);
}


/*
void EC_GROUP_clear_free()
	(EC_GROUP *) group [struct ec_group_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_clear_free(group: *mut ec_group_st);
}


/*
int EC_GROUP_copy()
	(EC_GROUP *) dst [struct ec_group_st *]
	(const EC_GROUP *) src [const struct ec_group_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_copy(dst: *mut ec_group_st, src: *const ec_group_st) -> libc::c_int;
}


/*
EC_GROUP * EC_GROUP_dup() [struct ec_group_st *]
	(const EC_GROUP *) src [const struct ec_group_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_dup(src: *const ec_group_st) -> *mut ec_group_st;
}


/*
const EC_METHOD * EC_GROUP_method_of() [const struct ec_method_st *]
	(const EC_GROUP *) group [const struct ec_group_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_method_of(group: *const ec_group_st) -> *const ec_method_st;
}


/*
int EC_METHOD_get_field_type()
	(const EC_METHOD *) meth [const struct ec_method_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_METHOD_get_field_type(meth: *const ec_method_st) -> libc::c_int;
}


/*
int EC_GROUP_set_generator()
	(EC_GROUP *) group [struct ec_group_st *]
	(const EC_POINT *) generator [const struct ec_point_st *]
	(const BIGNUM *) order [const struct bignum_st *]
	(const BIGNUM *) cofactor [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_set_generator(group: *mut ec_group_st, generator: *const ec_point_st, order: *const bignum_st, cofactor: *const bignum_st) -> libc::c_int;
}


/*
const EC_POINT * EC_GROUP_get0_generator() [const struct ec_point_st *]
	(const EC_GROUP *) group [const struct ec_group_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_get0_generator(group: *const ec_group_st) -> *const ec_point_st;
}


/*
int EC_GROUP_get_order()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(BIGNUM *) order [struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_get_order(group: *const ec_group_st, order: *mut bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_GROUP_get_cofactor()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(BIGNUM *) cofactor [struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_get_cofactor(group: *const ec_group_st, cofactor: *mut bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
void EC_GROUP_set_curve_name()
	(EC_GROUP *) group [struct ec_group_st *]
	(int) nid
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_set_curve_name(group: *mut ec_group_st, nid: libc::c_int);
}


/*
int EC_GROUP_get_curve_name()
	(const EC_GROUP *) group [const struct ec_group_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_get_curve_name(group: *const ec_group_st) -> libc::c_int;
}


/*
void EC_GROUP_set_asn1_flag()
	(EC_GROUP *) group [struct ec_group_st *]
	(int) flag
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_set_asn1_flag(group: *mut ec_group_st, flag: libc::c_int);
}


/*
int EC_GROUP_get_asn1_flag()
	(const EC_GROUP *) group [const struct ec_group_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_get_asn1_flag(group: *const ec_group_st) -> libc::c_int;
}


/*
void EC_GROUP_set_point_conversion_form()
	(EC_GROUP *) group [struct ec_group_st *]
	(point_conversion_form_t) form [point_conversion_form_t]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_set_point_conversion_form(group: *mut ec_group_st, form: libc::c_uint);
}


/*
point_conversion_form_t EC_GROUP_get_point_conversion_form() [point_conversion_form_t]
	(const EC_GROUP *)  [const struct ec_group_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_get_point_conversion_form(_: *const ec_group_st) -> libc::c_uint;
}


/*
unsigned char * EC_GROUP_get0_seed()
	(const EC_GROUP *) x [const struct ec_group_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_get0_seed(x: *const ec_group_st) -> *mut libc::c_uchar;
}


/*
size_t EC_GROUP_get_seed_len() [unsigned long]
	(const EC_GROUP *)  [const struct ec_group_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_get_seed_len(_: *const ec_group_st) -> libc::c_ulong;
}


/*
size_t EC_GROUP_set_seed() [unsigned long]
	(EC_GROUP *)  [struct ec_group_st *]
	(const unsigned char *) 
	(size_t) len [unsigned long]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_set_seed(_: *mut ec_group_st, _: *const libc::c_uchar, len: libc::c_ulong) -> libc::c_ulong;
}


/*
int EC_GROUP_set_curve_GFp()
	(EC_GROUP *) group [struct ec_group_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_set_curve_GFp(group: *mut ec_group_st, p: *const bignum_st, a: *const bignum_st, b: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_GROUP_get_curve_GFp()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(BIGNUM *) p [struct bignum_st *]
	(BIGNUM *) a [struct bignum_st *]
	(BIGNUM *) b [struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_get_curve_GFp(group: *const ec_group_st, p: *mut bignum_st, a: *mut bignum_st, b: *mut bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_GROUP_set_curve_GF2m()
	(EC_GROUP *) group [struct ec_group_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_set_curve_GF2m(group: *mut ec_group_st, p: *const bignum_st, a: *const bignum_st, b: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_GROUP_get_curve_GF2m()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(BIGNUM *) p [struct bignum_st *]
	(BIGNUM *) a [struct bignum_st *]
	(BIGNUM *) b [struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_get_curve_GF2m(group: *const ec_group_st, p: *mut bignum_st, a: *mut bignum_st, b: *mut bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_GROUP_get_degree()
	(const EC_GROUP *) group [const struct ec_group_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_get_degree(group: *const ec_group_st) -> libc::c_int;
}


/*
int EC_GROUP_check()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_check(group: *const ec_group_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_GROUP_check_discriminant()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_check_discriminant(group: *const ec_group_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_GROUP_cmp()
	(const EC_GROUP *) a [const struct ec_group_st *]
	(const EC_GROUP *) b [const struct ec_group_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_cmp(a: *const ec_group_st, b: *const ec_group_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
EC_GROUP * EC_GROUP_new_curve_GFp() [struct ec_group_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_new_curve_GFp(p: *const bignum_st, a: *const bignum_st, b: *const bignum_st, ctx: *mut bignum_ctx) -> *mut ec_group_st;
}


/*
EC_GROUP * EC_GROUP_new_curve_GF2m() [struct ec_group_st *]
	(const BIGNUM *) p [const struct bignum_st *]
	(const BIGNUM *) a [const struct bignum_st *]
	(const BIGNUM *) b [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_new_curve_GF2m(p: *const bignum_st, a: *const bignum_st, b: *const bignum_st, ctx: *mut bignum_ctx) -> *mut ec_group_st;
}


/*
EC_GROUP * EC_GROUP_new_by_curve_name() [struct ec_group_st *]
	(int) nid
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_new_by_curve_name(nid: libc::c_int) -> *mut ec_group_st;
}


/*
size_t EC_get_builtin_curves() [unsigned long]
	(EC_builtin_curve *) r [EC_builtin_curve *]
	(size_t) nitems [unsigned long]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_get_builtin_curves(r: *mut EC_builtin_curve, nitems: libc::c_ulong) -> libc::c_ulong;
}


/*
EC_POINT * EC_POINT_new() [struct ec_point_st *]
	(const EC_GROUP *) group [const struct ec_group_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_new(group: *const ec_group_st) -> *mut ec_point_st;
}


/*
void EC_POINT_free()
	(EC_POINT *) point [struct ec_point_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_free(point: *mut ec_point_st);
}


/*
void EC_POINT_clear_free()
	(EC_POINT *) point [struct ec_point_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_clear_free(point: *mut ec_point_st);
}


/*
int EC_POINT_copy()
	(EC_POINT *) dst [struct ec_point_st *]
	(const EC_POINT *) src [const struct ec_point_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_copy(dst: *mut ec_point_st, src: *const ec_point_st) -> libc::c_int;
}


/*
EC_POINT * EC_POINT_dup() [struct ec_point_st *]
	(const EC_POINT *) src [const struct ec_point_st *]
	(const EC_GROUP *) group [const struct ec_group_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_dup(src: *const ec_point_st, group: *const ec_group_st) -> *mut ec_point_st;
}


/*
const EC_METHOD * EC_POINT_method_of() [const struct ec_method_st *]
	(const EC_POINT *) point [const struct ec_point_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_method_of(point: *const ec_point_st) -> *const ec_method_st;
}


/*
int EC_POINT_set_to_infinity()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(EC_POINT *) point [struct ec_point_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_set_to_infinity(group: *const ec_group_st, point: *mut ec_point_st) -> libc::c_int;
}


/*
int EC_POINT_set_Jprojective_coordinates_GFp()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(EC_POINT *) p [struct ec_point_st *]
	(const BIGNUM *) x [const struct bignum_st *]
	(const BIGNUM *) y [const struct bignum_st *]
	(const BIGNUM *) z [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_set_Jprojective_coordinates_GFp(group: *const ec_group_st, p: *mut ec_point_st, x: *const bignum_st, y: *const bignum_st, z: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_POINT_get_Jprojective_coordinates_GFp()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(const EC_POINT *) p [const struct ec_point_st *]
	(BIGNUM *) x [struct bignum_st *]
	(BIGNUM *) y [struct bignum_st *]
	(BIGNUM *) z [struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_get_Jprojective_coordinates_GFp(group: *const ec_group_st, p: *const ec_point_st, x: *mut bignum_st, y: *mut bignum_st, z: *mut bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_POINT_set_affine_coordinates_GFp()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(EC_POINT *) p [struct ec_point_st *]
	(const BIGNUM *) x [const struct bignum_st *]
	(const BIGNUM *) y [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_set_affine_coordinates_GFp(group: *const ec_group_st, p: *mut ec_point_st, x: *const bignum_st, y: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_POINT_get_affine_coordinates_GFp()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(const EC_POINT *) p [const struct ec_point_st *]
	(BIGNUM *) x [struct bignum_st *]
	(BIGNUM *) y [struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_get_affine_coordinates_GFp(group: *const ec_group_st, p: *const ec_point_st, x: *mut bignum_st, y: *mut bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_POINT_set_compressed_coordinates_GFp()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(EC_POINT *) p [struct ec_point_st *]
	(const BIGNUM *) x [const struct bignum_st *]
	(int) y_bit
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_set_compressed_coordinates_GFp(group: *const ec_group_st, p: *mut ec_point_st, x: *const bignum_st, y_bit: libc::c_int, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_POINT_set_affine_coordinates_GF2m()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(EC_POINT *) p [struct ec_point_st *]
	(const BIGNUM *) x [const struct bignum_st *]
	(const BIGNUM *) y [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_set_affine_coordinates_GF2m(group: *const ec_group_st, p: *mut ec_point_st, x: *const bignum_st, y: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_POINT_get_affine_coordinates_GF2m()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(const EC_POINT *) p [const struct ec_point_st *]
	(BIGNUM *) x [struct bignum_st *]
	(BIGNUM *) y [struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_get_affine_coordinates_GF2m(group: *const ec_group_st, p: *const ec_point_st, x: *mut bignum_st, y: *mut bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_POINT_set_compressed_coordinates_GF2m()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(EC_POINT *) p [struct ec_point_st *]
	(const BIGNUM *) x [const struct bignum_st *]
	(int) y_bit
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_set_compressed_coordinates_GF2m(group: *const ec_group_st, p: *mut ec_point_st, x: *const bignum_st, y_bit: libc::c_int, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
size_t EC_POINT_point2oct() [unsigned long]
	(const EC_GROUP *) group [const struct ec_group_st *]
	(const EC_POINT *) p [const struct ec_point_st *]
	(point_conversion_form_t) form [point_conversion_form_t]
	(unsigned char *) buf
	(size_t) len [unsigned long]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_point2oct(group: *const ec_group_st, p: *const ec_point_st, form: libc::c_uint, buf: *mut libc::c_uchar, len: libc::c_ulong, ctx: *mut bignum_ctx) -> libc::c_ulong;
}


/*
int EC_POINT_oct2point()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(EC_POINT *) p [struct ec_point_st *]
	(const unsigned char *) buf
	(size_t) len [unsigned long]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_oct2point(group: *const ec_group_st, p: *mut ec_point_st, buf: *const libc::c_uchar, len: libc::c_ulong, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
BIGNUM * EC_POINT_point2bn() [struct bignum_st *]
	(const EC_GROUP *)  [const struct ec_group_st *]
	(const EC_POINT *)  [const struct ec_point_st *]
	(point_conversion_form_t) form [point_conversion_form_t]
	(BIGNUM *)  [struct bignum_st *]
	(BN_CTX *)  [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_point2bn(_: *const ec_group_st, _: *const ec_point_st, form: libc::c_uint, _: *mut bignum_st, _: *mut bignum_ctx) -> *mut bignum_st;
}


/*
EC_POINT * EC_POINT_bn2point() [struct ec_point_st *]
	(const EC_GROUP *)  [const struct ec_group_st *]
	(const BIGNUM *)  [const struct bignum_st *]
	(EC_POINT *)  [struct ec_point_st *]
	(BN_CTX *)  [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_bn2point(_: *const ec_group_st, _: *const bignum_st, _: *mut ec_point_st, _: *mut bignum_ctx) -> *mut ec_point_st;
}


/*
char * EC_POINT_point2hex()
	(const EC_GROUP *)  [const struct ec_group_st *]
	(const EC_POINT *)  [const struct ec_point_st *]
	(point_conversion_form_t) form [point_conversion_form_t]
	(BN_CTX *)  [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_point2hex(_: *const ec_group_st, _: *const ec_point_st, form: libc::c_uint, _: *mut bignum_ctx) -> *mut libc::c_char;
}


/*
EC_POINT * EC_POINT_hex2point() [struct ec_point_st *]
	(const EC_GROUP *)  [const struct ec_group_st *]
	(const char *) 
	(EC_POINT *)  [struct ec_point_st *]
	(BN_CTX *)  [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_hex2point(_: *const ec_group_st, _: *const libc::c_char, _: *mut ec_point_st, _: *mut bignum_ctx) -> *mut ec_point_st;
}


/*
int EC_POINT_add()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(EC_POINT *) r [struct ec_point_st *]
	(const EC_POINT *) a [const struct ec_point_st *]
	(const EC_POINT *) b [const struct ec_point_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_add(group: *const ec_group_st, r: *mut ec_point_st, a: *const ec_point_st, b: *const ec_point_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_POINT_dbl()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(EC_POINT *) r [struct ec_point_st *]
	(const EC_POINT *) a [const struct ec_point_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_dbl(group: *const ec_group_st, r: *mut ec_point_st, a: *const ec_point_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_POINT_invert()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(EC_POINT *) a [struct ec_point_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_invert(group: *const ec_group_st, a: *mut ec_point_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_POINT_is_at_infinity()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(const EC_POINT *) p [const struct ec_point_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_is_at_infinity(group: *const ec_group_st, p: *const ec_point_st) -> libc::c_int;
}


/*
int EC_POINT_is_on_curve()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(const EC_POINT *) point [const struct ec_point_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_is_on_curve(group: *const ec_group_st, point: *const ec_point_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_POINT_cmp()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(const EC_POINT *) a [const struct ec_point_st *]
	(const EC_POINT *) b [const struct ec_point_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_cmp(group: *const ec_group_st, a: *const ec_point_st, b: *const ec_point_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_POINT_make_affine()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(EC_POINT *) point [struct ec_point_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_make_affine(group: *const ec_group_st, point: *mut ec_point_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_POINTs_make_affine()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(size_t) num [unsigned long]
	(EC_POINT *[]) points [struct ec_point_st *[]]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINTs_make_affine(group: *const ec_group_st, num: libc::c_ulong, points: *mut *mut ec_point_st /* INCOMPLETEARRAY */, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_POINTs_mul()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(EC_POINT *) r [struct ec_point_st *]
	(const BIGNUM *) n [const struct bignum_st *]
	(size_t) num [unsigned long]
	(const EC_POINT *[]) p [const struct ec_point_st *[]]
	(const BIGNUM *[]) m [const struct bignum_st *[]]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINTs_mul(group: *const ec_group_st, r: *mut ec_point_st, n: *const bignum_st, num: libc::c_ulong, p: *mut *const ec_point_st /* INCOMPLETEARRAY */, m: *mut *const bignum_st /* INCOMPLETEARRAY */, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_POINT_mul()
	(const EC_GROUP *) group [const struct ec_group_st *]
	(EC_POINT *) r [struct ec_point_st *]
	(const BIGNUM *) n [const struct bignum_st *]
	(const EC_POINT *) q [const struct ec_point_st *]
	(const BIGNUM *) m [const struct bignum_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_POINT_mul(group: *const ec_group_st, r: *mut ec_point_st, n: *const bignum_st, q: *const ec_point_st, m: *const bignum_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_GROUP_precompute_mult()
	(EC_GROUP *) group [struct ec_group_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_precompute_mult(group: *mut ec_group_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_GROUP_have_precompute_mult()
	(const EC_GROUP *) group [const struct ec_group_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_have_precompute_mult(group: *const ec_group_st) -> libc::c_int;
}


/*
int EC_GROUP_get_basis_type()
	(const EC_GROUP *)  [const struct ec_group_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_get_basis_type(_: *const ec_group_st) -> libc::c_int;
}


/*
int EC_GROUP_get_trinomial_basis()
	(const EC_GROUP *)  [const struct ec_group_st *]
	(unsigned int *) k
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_get_trinomial_basis(_: *const ec_group_st, k: *mut libc::c_uint) -> libc::c_int;
}


/*
int EC_GROUP_get_pentanomial_basis()
	(const EC_GROUP *)  [const struct ec_group_st *]
	(unsigned int *) k1
	(unsigned int *) k2
	(unsigned int *) k3
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_GROUP_get_pentanomial_basis(_: *const ec_group_st, k1: *mut libc::c_uint, k2: *mut libc::c_uint, k3: *mut libc::c_uint) -> libc::c_int;
}


/*
EC_GROUP * d2i_ECPKParameters() [struct ec_group_st *]
	(EC_GROUP **)  [struct ec_group_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ECPKParameters(_: *mut *mut ec_group_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut ec_group_st;
}


/*
int i2d_ECPKParameters()
	(const EC_GROUP *)  [const struct ec_group_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ECPKParameters(_: *const ec_group_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
int ECPKParameters_print()
	(BIO *) bp [struct bio_st *]
	(const EC_GROUP *) x [const struct ec_group_st *]
	(int) off
*/
#[link(name="crypto")]
extern "C" {
	pub fn ECPKParameters_print(bp: *mut bio_st, x: *const ec_group_st, off: libc::c_int) -> libc::c_int;
}


/*
int ECPKParameters_print_fp()
	(FILE *) fp [struct _IO_FILE *]
	(const EC_GROUP *) x [const struct ec_group_st *]
	(int) off
*/
#[link(name="crypto")]
extern "C" {
	pub fn ECPKParameters_print_fp(fp: libc::c_int, x: *const ec_group_st, off: libc::c_int) -> libc::c_int;
}


/*
EC_KEY * EC_KEY_new() [struct ec_key_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_new() -> *mut ec_key_st;
}


/*
int EC_KEY_get_flags()
	(const EC_KEY *) key [const struct ec_key_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_get_flags(key: *const ec_key_st) -> libc::c_int;
}


/*
void EC_KEY_set_flags()
	(EC_KEY *) key [struct ec_key_st *]
	(int) flags
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_set_flags(key: *mut ec_key_st, flags: libc::c_int);
}


/*
void EC_KEY_clear_flags()
	(EC_KEY *) key [struct ec_key_st *]
	(int) flags
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_clear_flags(key: *mut ec_key_st, flags: libc::c_int);
}


/*
EC_KEY * EC_KEY_new_by_curve_name() [struct ec_key_st *]
	(int) nid
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_new_by_curve_name(nid: libc::c_int) -> *mut ec_key_st;
}


/*
void EC_KEY_free()
	(EC_KEY *) key [struct ec_key_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_free(key: *mut ec_key_st);
}


/*
EC_KEY * EC_KEY_copy() [struct ec_key_st *]
	(EC_KEY *) dst [struct ec_key_st *]
	(const EC_KEY *) src [const struct ec_key_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_copy(dst: *mut ec_key_st, src: *const ec_key_st) -> *mut ec_key_st;
}


/*
EC_KEY * EC_KEY_dup() [struct ec_key_st *]
	(const EC_KEY *) src [const struct ec_key_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_dup(src: *const ec_key_st) -> *mut ec_key_st;
}


/*
int EC_KEY_up_ref()
	(EC_KEY *) key [struct ec_key_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_up_ref(key: *mut ec_key_st) -> libc::c_int;
}


/*
const EC_GROUP * EC_KEY_get0_group() [const struct ec_group_st *]
	(const EC_KEY *) key [const struct ec_key_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_get0_group(key: *const ec_key_st) -> *const ec_group_st;
}


/*
int EC_KEY_set_group()
	(EC_KEY *) key [struct ec_key_st *]
	(const EC_GROUP *) group [const struct ec_group_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_set_group(key: *mut ec_key_st, group: *const ec_group_st) -> libc::c_int;
}


/*
const BIGNUM * EC_KEY_get0_private_key() [const struct bignum_st *]
	(const EC_KEY *) key [const struct ec_key_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_get0_private_key(key: *const ec_key_st) -> *const bignum_st;
}


/*
int EC_KEY_set_private_key()
	(EC_KEY *) key [struct ec_key_st *]
	(const BIGNUM *) prv [const struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_set_private_key(key: *mut ec_key_st, prv: *const bignum_st) -> libc::c_int;
}


/*
const EC_POINT * EC_KEY_get0_public_key() [const struct ec_point_st *]
	(const EC_KEY *) key [const struct ec_key_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_get0_public_key(key: *const ec_key_st) -> *const ec_point_st;
}


/*
int EC_KEY_set_public_key()
	(EC_KEY *) key [struct ec_key_st *]
	(const EC_POINT *) pub [const struct ec_point_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_set_public_key(key: *mut ec_key_st, pub_: *const ec_point_st) -> libc::c_int;
}


/*
unsigned int EC_KEY_get_enc_flags()
	(const EC_KEY *) key [const struct ec_key_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_get_enc_flags(key: *const ec_key_st) -> libc::c_uint;
}


/*
void EC_KEY_set_enc_flags()
	(EC_KEY *) eckey [struct ec_key_st *]
	(unsigned int) flags
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_set_enc_flags(eckey: *mut ec_key_st, flags: libc::c_uint);
}


/*
point_conversion_form_t EC_KEY_get_conv_form() [point_conversion_form_t]
	(const EC_KEY *) key [const struct ec_key_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_get_conv_form(key: *const ec_key_st) -> libc::c_uint;
}


/*
void EC_KEY_set_conv_form()
	(EC_KEY *) eckey [struct ec_key_st *]
	(point_conversion_form_t) cform [point_conversion_form_t]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_set_conv_form(eckey: *mut ec_key_st, cform: libc::c_uint);
}


/*
void * EC_KEY_get_key_method_data()
	(EC_KEY *) key [struct ec_key_st *]
	(void *(*)(void *)) dup_func [void *(*)(void *)]
	(void (*)(void *)) free_func [void (*)(void *)]
	(void (*)(void *)) clear_free_func [void (*)(void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_get_key_method_data(key: *mut ec_key_st, dup_func: Option<extern fn(*mut libc::c_void) -> *mut libc::c_void>, free_func: Option<extern fn(*mut libc::c_void)>, clear_free_func: Option<extern fn(*mut libc::c_void)>) -> *mut libc::c_void;
}


/*
void * EC_KEY_insert_key_method_data()
	(EC_KEY *) key [struct ec_key_st *]
	(void *) data
	(void *(*)(void *)) dup_func [void *(*)(void *)]
	(void (*)(void *)) free_func [void (*)(void *)]
	(void (*)(void *)) clear_free_func [void (*)(void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_insert_key_method_data(key: *mut ec_key_st, data: *mut libc::c_void, dup_func: Option<extern fn(*mut libc::c_void) -> *mut libc::c_void>, free_func: Option<extern fn(*mut libc::c_void)>, clear_free_func: Option<extern fn(*mut libc::c_void)>) -> *mut libc::c_void;
}


/*
void EC_KEY_set_asn1_flag()
	(EC_KEY *) eckey [struct ec_key_st *]
	(int) asn1_flag
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_set_asn1_flag(eckey: *mut ec_key_st, asn1_flag: libc::c_int);
}


/*
int EC_KEY_precompute_mult()
	(EC_KEY *) key [struct ec_key_st *]
	(BN_CTX *) ctx [struct bignum_ctx *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_precompute_mult(key: *mut ec_key_st, ctx: *mut bignum_ctx) -> libc::c_int;
}


/*
int EC_KEY_generate_key()
	(EC_KEY *) key [struct ec_key_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_generate_key(key: *mut ec_key_st) -> libc::c_int;
}


/*
int EC_KEY_check_key()
	(const EC_KEY *) key [const struct ec_key_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_check_key(key: *const ec_key_st) -> libc::c_int;
}


/*
int EC_KEY_set_public_key_affine_coordinates()
	(EC_KEY *) key [struct ec_key_st *]
	(BIGNUM *) x [struct bignum_st *]
	(BIGNUM *) y [struct bignum_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_set_public_key_affine_coordinates(key: *mut ec_key_st, x: *mut bignum_st, y: *mut bignum_st) -> libc::c_int;
}


/*
EC_KEY * d2i_ECPrivateKey() [struct ec_key_st *]
	(EC_KEY **) key [struct ec_key_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ECPrivateKey(key: *mut *mut ec_key_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut ec_key_st;
}


/*
int i2d_ECPrivateKey()
	(EC_KEY *) key [struct ec_key_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ECPrivateKey(key: *mut ec_key_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
EC_KEY * d2i_ECParameters() [struct ec_key_st *]
	(EC_KEY **) key [struct ec_key_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn d2i_ECParameters(key: *mut *mut ec_key_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut ec_key_st;
}


/*
int i2d_ECParameters()
	(EC_KEY *) key [struct ec_key_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2d_ECParameters(key: *mut ec_key_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
EC_KEY * o2i_ECPublicKey() [struct ec_key_st *]
	(EC_KEY **) key [struct ec_key_st **]
	(const unsigned char **) in
	(long) len
*/
#[link(name="crypto")]
extern "C" {
	pub fn o2i_ECPublicKey(key: *mut *mut ec_key_st, in_: *mut *const libc::c_uchar, len: libc::c_long) -> *mut ec_key_st;
}


/*
int i2o_ECPublicKey()
	(EC_KEY *) key [struct ec_key_st *]
	(unsigned char **) out
*/
#[link(name="crypto")]
extern "C" {
	pub fn i2o_ECPublicKey(key: *mut ec_key_st, out: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
int ECParameters_print()
	(BIO *) bp [struct bio_st *]
	(const EC_KEY *) key [const struct ec_key_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ECParameters_print(bp: *mut bio_st, key: *const ec_key_st) -> libc::c_int;
}


/*
int EC_KEY_print()
	(BIO *) bp [struct bio_st *]
	(const EC_KEY *) key [const struct ec_key_st *]
	(int) off
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_print(bp: *mut bio_st, key: *const ec_key_st, off: libc::c_int) -> libc::c_int;
}


/*
int ECParameters_print_fp()
	(FILE *) fp [struct _IO_FILE *]
	(const EC_KEY *) key [const struct ec_key_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ECParameters_print_fp(fp: libc::c_int, key: *const ec_key_st) -> libc::c_int;
}


/*
int EC_KEY_print_fp()
	(FILE *) fp [struct _IO_FILE *]
	(const EC_KEY *) key [const struct ec_key_st *]
	(int) off
*/
#[link(name="crypto")]
extern "C" {
	pub fn EC_KEY_print_fp(fp: libc::c_int, key: *const ec_key_st, off: libc::c_int) -> libc::c_int;
}


/*
void ERR_load_EC_strings()
*/
#[link(name="crypto")]
extern "C" {
	pub fn ERR_load_EC_strings();
}


/*
const ECDH_METHOD * ECDH_OpenSSL() [const struct ecdh_method *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ECDH_OpenSSL() -> *const ecdh_method;
}


/*
void ECDH_set_default_method()
	(const ECDH_METHOD *)  [const struct ecdh_method *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ECDH_set_default_method(_: *const ecdh_method);
}


/*
const ECDH_METHOD * ECDH_get_default_method() [const struct ecdh_method *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ECDH_get_default_method() -> *const ecdh_method;
}


/*
int ECDH_set_method()
	(EC_KEY *)  [struct ec_key_st *]
	(const ECDH_METHOD *)  [const struct ecdh_method *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ECDH_set_method(_: *mut ec_key_st, _: *const ecdh_method) -> libc::c_int;
}


/*
int ECDH_compute_key()
	(void *) out
	(size_t) outlen [unsigned long]
	(const EC_POINT *) pub_key [const struct ec_point_st *]
	(EC_KEY *) ecdh [struct ec_key_st *]
	(void *(*)(const void *, size_t, void *, size_t *)) KDF [void *(*)(const void *, unsigned long, void *, unsigned long *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ECDH_compute_key(out: *mut libc::c_void, outlen: libc::c_ulong, pub_key: *const ec_point_st, ecdh: *mut ec_key_st, KDF: Option<extern fn(*const libc::c_void, libc::c_ulong, *mut libc::c_void, *mut libc::c_ulong) -> *mut libc::c_void>) -> libc::c_int;
}


/*
int ECDH_get_ex_new_index()
	(long) argl
	(void *) argp
	(CRYPTO_EX_new *) new_func [int (*)(void *, void *, struct crypto_ex_data_st *, int, long, void *)]
	(CRYPTO_EX_dup *) dup_func [int (*)(struct crypto_ex_data_st *, struct crypto_ex_data_st *, void *, int, long, void *)]
	(CRYPTO_EX_free *) free_func [void (*)(void *, void *, struct crypto_ex_data_st *, int, long, void *)]
*/
#[link(name="crypto")]
extern "C" {
	pub fn ECDH_get_ex_new_index(argl: libc::c_long, argp: *mut libc::c_void, new_func: Option<extern fn(*mut libc::c_void, *mut libc::c_void, *mut crypto_ex_data_st, libc::c_int, libc::c_long, *mut libc::c_void) -> libc::c_int>, dup_func: Option<extern fn(*mut crypto_ex_data_st, *mut crypto_ex_data_st, *mut libc::c_void, libc::c_int, libc::c_long, *mut libc::c_void) -> libc::c_int>, free_func: Option<extern fn(*mut libc::c_void, *mut libc::c_void, *mut crypto_ex_data_st, libc::c_int, libc::c_long, *mut libc::c_void)>) -> libc::c_int;
}


/*
int ECDH_set_ex_data()
	(EC_KEY *) d [struct ec_key_st *]
	(int) idx
	(void *) arg
*/
#[link(name="crypto")]
extern "C" {
	pub fn ECDH_set_ex_data(d: *mut ec_key_st, idx: libc::c_int, arg: *mut libc::c_void) -> libc::c_int;
}


/*
void * ECDH_get_ex_data()
	(EC_KEY *) d [struct ec_key_st *]
	(int) idx
*/
#[link(name="crypto")]
extern "C" {
	pub fn ECDH_get_ex_data(d: *mut ec_key_st, idx: libc::c_int) -> *mut libc::c_void;
}


/*
void ERR_load_ECDH_strings()
*/
#[link(name="crypto")]
extern "C" {
	pub fn ERR_load_ECDH_strings();
}


/*
enum  {
	POINT_CONVERSION_COMPRESSED =	0x00000002 (2)
	POINT_CONVERSION_UNCOMPRESSED =	0x00000004 (4)
	POINT_CONVERSION_HYBRID =	0x00000006 (6)
}
*/
#[derive(Copy, PartialEq, Debug)]
#[repr(u32)]
pub enum point_conversion_form_t {
	POINT_CONVERSION_COMPRESSED =	2 as u32,
	POINT_CONVERSION_UNCOMPRESSED =	4 as u32,
	POINT_CONVERSION_HYBRID =	6 as u32,
}

impl point_conversion_form_t {
	pub fn to_u32(&self) -> libc::c_uint {
		*self as libc::c_uint
	}

	pub fn from_u32(v: libc::c_uint) -> point_conversion_form_t {
		unsafe { mem::transmute(v) }
	}
}

/* HEADER_ECDH_H # */

/* OPENSSL_NO_GMP # */

/* OPENSSL_NO_IDEA # */

/* OPENSSL_NO_JPAKE # */

/* OPENSSL_NO_KRB5 # */

/* OPENSSL_NO_MD2 # */

/* OPENSSL_NO_MDC2 # */

/* OPENSSL_NO_RC5 # */

/* OPENSSL_NO_RFC3779 # */

/* OPENSSL_NO_SCTP # */

/* OPENSSL_NO_SSL2 # */

/* OPENSSL_NO_STORE # */

/* OPENSSL_THREADS # */

/* OPENSSL_NO_STATIC_ENGINE # */

/* OPENSSL_CPUID_OBJ /* crypto/opensslconf.h.in */ */

/* OPENSSL_UNISTD < unistd . h > # */

/* HEADER_EC_H # */

/* OPENSSL_CPUID_OBJ /* crypto/opensslconf.h.in */ */

/* OPENSSL_UNISTD < unistd . h > # */

/* HEADER_ASN1_H # */

/* OPENSSL_CPUID_OBJ /* crypto/opensslconf.h.in */ */

/* OPENSSL_UNISTD < unistd . h > # */

/* HEADER_E_OS2_H # */

/* OPENSSL_SYS_UNIX /* ----------------------- Macintosh, before MacOS X ----------------------- */ */

/* OPENSSL_SYS_LINUX # */

/* OPENSSL_UNISTD_IO OPENSSL_UNISTD # */

/* OPENSSL_DECLARE_EXIT /* declared in unistd.h */ */

/* OPENSSL_EXPORT extern # */

/* OPENSSL_IMPORT extern # */

/* OPENSSL_GLOBAL # */

/* OPENSSL_EXTERN OPENSSL_IMPORT /* Macros to allow global variables to be reached through function calls when
   required (if a shared library version requires it, for example.
   The way it's done allows definitions like this:

	// in foobar.c
	OPENSSL_IMPLEMENT_GLOBAL(int,foobar,0)
	// in foobar.h
	OPENSSL_DECLARE_GLOBAL(int,foobar);
	#define foobar OPENSSL_GLOBAL_REF(foobar)
*/ */

/* OPENSSL_IMPLEMENT_GLOBAL ( type , name , value ) OPENSSL_GLOBAL type _shadow_ ## name = value ; # */

/* OPENSSL_DECLARE_GLOBAL ( type , name ) OPENSSL_EXPORT type _shadow_ ## name # */

/* OPENSSL_GLOBAL_REF ( name ) _shadow_ ## name # */

/* ossl_ssize_t ssize_t # */

/* HEADER_BIO_H # */

/* OPENSSL_CPUID_OBJ /* crypto/opensslconf.h.in */ */

/* OPENSSL_UNISTD < unistd . h > # */

/* HEADER_CRYPTO_H # */

/* OPENSSL_CPUID_OBJ /* crypto/opensslconf.h.in */ */

/* OPENSSL_UNISTD < unistd . h > # */

/* HEADER_STACK_H # */

/* M_sk_num ( sk ) ( ( sk ) ? ( sk ) -> num : - 1 ) # */

/* M_sk_value ( sk , n ) ( ( sk ) ? ( sk ) -> data [ n ] : NULL ) int */

/* HEADER_SAFESTACK_H # */

/* CHECKED_PTR_OF ( type , p ) ( ( void * ) ( 1 ? p : ( type * ) 0 ) ) # */

/* CHECKED_STACK_OF ( type , p ) ( ( _STACK * ) ( 1 ? p : ( STACK_OF ( type ) * ) 0 ) ) # */

/* CHECKED_SK_FREE_FUNC ( type , p ) ( ( void ( * ) ( void * ) ) ( ( 1 ? p : ( void ( * ) ( type * ) ) 0 ) ) ) # */

/* CHECKED_SK_FREE_FUNC2 ( type , p ) ( ( void ( * ) ( void * ) ) ( ( 1 ? p : ( void ( * ) ( type ) ) 0 ) ) ) # */

/* CHECKED_SK_CMP_FUNC ( type , p ) ( ( int ( * ) ( const void * , const void * ) ) ( ( 1 ? p : ( int ( * ) ( const type * const * , const type * const * ) ) 0 ) ) ) # */

/* STACK_OF ( type ) struct stack_st_ ## type # */

/* PREDECLARE_STACK_OF ( type ) STACK_OF ( type ) ; # */

/* DECLARE_STACK_OF ( type ) STACK_OF ( type ) { _STACK stack ; } ; # */

/* DECLARE_SPECIAL_STACK_OF ( type , type2 ) STACK_OF ( type ) { _STACK stack ; } ; # */

/* IMPLEMENT_STACK_OF ( type ) /* nada (obsolete in new safestack approach)*/ */

/* SKM_sk_new ( type , cmp ) ( ( STACK_OF ( type ) * ) sk_new ( CHECKED_SK_CMP_FUNC ( type , cmp ) ) ) # */

/* SKM_sk_new_null ( type ) ( ( STACK_OF ( type ) * ) sk_new_null ( ) ) # */

/* SKM_sk_free ( type , st ) sk_free ( CHECKED_STACK_OF ( type , st ) ) # */

/* SKM_sk_num ( type , st ) sk_num ( CHECKED_STACK_OF ( type , st ) ) # */

/* SKM_sk_value ( type , st , i ) ( ( type * ) sk_value ( CHECKED_STACK_OF ( type , st ) , i ) ) # */

/* SKM_sk_set ( type , st , i , val ) sk_set ( CHECKED_STACK_OF ( type , st ) , i , CHECKED_PTR_OF ( type , val ) ) # */

/* SKM_sk_zero ( type , st ) sk_zero ( CHECKED_STACK_OF ( type , st ) ) # */

/* SKM_sk_push ( type , st , val ) sk_push ( CHECKED_STACK_OF ( type , st ) , CHECKED_PTR_OF ( type , val ) ) # */

/* SKM_sk_unshift ( type , st , val ) sk_unshift ( CHECKED_STACK_OF ( type , st ) , CHECKED_PTR_OF ( type , val ) ) # */

/* SKM_sk_find ( type , st , val ) sk_find ( CHECKED_STACK_OF ( type , st ) , CHECKED_PTR_OF ( type , val ) ) # */

/* SKM_sk_find_ex ( type , st , val ) sk_find_ex ( CHECKED_STACK_OF ( type , st ) , CHECKED_PTR_OF ( type , val ) ) # */

/* SKM_sk_delete ( type , st , i ) ( type * ) sk_delete ( CHECKED_STACK_OF ( type , st ) , i ) # */

/* SKM_sk_delete_ptr ( type , st , ptr ) ( type * ) sk_delete_ptr ( CHECKED_STACK_OF ( type , st ) , CHECKED_PTR_OF ( type , ptr ) ) # */

/* SKM_sk_insert ( type , st , val , i ) sk_insert ( CHECKED_STACK_OF ( type , st ) , CHECKED_PTR_OF ( type , val ) , i ) # */

/* SKM_sk_set_cmp_func ( type , st , cmp ) ( ( int ( * ) ( const type * const * , const type * const * ) ) sk_set_cmp_func ( CHECKED_STACK_OF ( type , st ) , CHECKED_SK_CMP_FUNC ( type , cmp ) ) ) # */

/* SKM_sk_dup ( type , st ) ( STACK_OF ( type ) * ) sk_dup ( CHECKED_STACK_OF ( type , st ) ) # */

/* SKM_sk_pop_free ( type , st , free_func ) sk_pop_free ( CHECKED_STACK_OF ( type , st ) , CHECKED_SK_FREE_FUNC ( type , free_func ) ) # */

/* SKM_sk_shift ( type , st ) ( type * ) sk_shift ( CHECKED_STACK_OF ( type , st ) ) # */

/* SKM_sk_pop ( type , st ) ( type * ) sk_pop ( CHECKED_STACK_OF ( type , st ) ) # */

/* SKM_sk_sort ( type , st ) sk_sort ( CHECKED_STACK_OF ( type , st ) ) # */

/* SKM_sk_is_sorted ( type , st ) sk_is_sorted ( CHECKED_STACK_OF ( type , st ) ) # */

/* SKM_ASN1_SET_OF_d2i ( type , st , pp , length , d2i_func , free_func , ex_tag , ex_class ) ( STACK_OF ( type ) * ) d2i_ASN1_SET ( ( STACK_OF ( OPENSSL_BLOCK ) * * ) CHECKED_PTR_OF ( STACK_OF ( type ) * , st ) , pp , length , CHECKED_D2I_OF ( type , d2i_func ) , CHECKED_SK_FREE_FUNC ( type , free_func ) , ex_tag , ex_class ) # */

/* SKM_ASN1_SET_OF_i2d ( type , st , pp , i2d_func , ex_tag , ex_class , is_set ) i2d_ASN1_SET ( ( STACK_OF ( OPENSSL_BLOCK ) * ) CHECKED_STACK_OF ( type , st ) , pp , CHECKED_I2D_OF ( type , i2d_func ) , ex_tag , ex_class , is_set ) # */

/* SKM_ASN1_seq_pack ( type , st , i2d_func , buf , len ) ASN1_seq_pack ( CHECKED_PTR_OF ( STACK_OF ( type ) , st ) , CHECKED_I2D_OF ( type , i2d_func ) , buf , len ) # */

/* SKM_ASN1_seq_unpack ( type , buf , len , d2i_func , free_func ) ( STACK_OF ( type ) * ) ASN1_seq_unpack ( buf , len , CHECKED_D2I_OF ( type , d2i_func ) , CHECKED_SK_FREE_FUNC ( type , free_func ) ) # */

/* SKM_PKCS12_decrypt_d2i ( type , algor , d2i_func , free_func , pass , passlen , oct , seq ) ( STACK_OF ( type ) * ) PKCS12_decrypt_d2i ( algor , CHECKED_D2I_OF ( type , d2i_func ) , CHECKED_SK_FREE_FUNC ( type , free_func ) , pass , passlen , oct , seq ) /* This block of defines is updated by util/mkstack.pl, please do not touch! */ */

/* sk_ACCESS_DESCRIPTION_new ( cmp ) SKM_sk_new ( ACCESS_DESCRIPTION , ( cmp ) ) # */

/* sk_ACCESS_DESCRIPTION_new_null ( ) SKM_sk_new_null ( ACCESS_DESCRIPTION ) # */

/* sk_ACCESS_DESCRIPTION_free ( st ) SKM_sk_free ( ACCESS_DESCRIPTION , ( st ) ) # */

/* sk_ACCESS_DESCRIPTION_num ( st ) SKM_sk_num ( ACCESS_DESCRIPTION , ( st ) ) # */

/* sk_ACCESS_DESCRIPTION_value ( st , i ) SKM_sk_value ( ACCESS_DESCRIPTION , ( st ) , ( i ) ) # */

/* sk_ACCESS_DESCRIPTION_set ( st , i , val ) SKM_sk_set ( ACCESS_DESCRIPTION , ( st ) , ( i ) , ( val ) ) # */

/* sk_ACCESS_DESCRIPTION_zero ( st ) SKM_sk_zero ( ACCESS_DESCRIPTION , ( st ) ) # */

/* sk_ACCESS_DESCRIPTION_push ( st , val ) SKM_sk_push ( ACCESS_DESCRIPTION , ( st ) , ( val ) ) # */

/* sk_ACCESS_DESCRIPTION_unshift ( st , val ) SKM_sk_unshift ( ACCESS_DESCRIPTION , ( st ) , ( val ) ) # */

/* sk_ACCESS_DESCRIPTION_find ( st , val ) SKM_sk_find ( ACCESS_DESCRIPTION , ( st ) , ( val ) ) # */

/* sk_ACCESS_DESCRIPTION_find_ex ( st , val ) SKM_sk_find_ex ( ACCESS_DESCRIPTION , ( st ) , ( val ) ) # */

/* sk_ACCESS_DESCRIPTION_delete ( st , i ) SKM_sk_delete ( ACCESS_DESCRIPTION , ( st ) , ( i ) ) # */

/* sk_ACCESS_DESCRIPTION_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( ACCESS_DESCRIPTION , ( st ) , ( ptr ) ) # */

/* sk_ACCESS_DESCRIPTION_insert ( st , val , i ) SKM_sk_insert ( ACCESS_DESCRIPTION , ( st ) , ( val ) , ( i ) ) # */

/* sk_ACCESS_DESCRIPTION_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( ACCESS_DESCRIPTION , ( st ) , ( cmp ) ) # */

/* sk_ACCESS_DESCRIPTION_dup ( st ) SKM_sk_dup ( ACCESS_DESCRIPTION , st ) # */

/* sk_ACCESS_DESCRIPTION_pop_free ( st , free_func ) SKM_sk_pop_free ( ACCESS_DESCRIPTION , ( st ) , ( free_func ) ) # */

/* sk_ACCESS_DESCRIPTION_shift ( st ) SKM_sk_shift ( ACCESS_DESCRIPTION , ( st ) ) # */

/* sk_ACCESS_DESCRIPTION_pop ( st ) SKM_sk_pop ( ACCESS_DESCRIPTION , ( st ) ) # */

/* sk_ACCESS_DESCRIPTION_sort ( st ) SKM_sk_sort ( ACCESS_DESCRIPTION , ( st ) ) # */

/* sk_ACCESS_DESCRIPTION_is_sorted ( st ) SKM_sk_is_sorted ( ACCESS_DESCRIPTION , ( st ) ) # */

/* sk_ASIdOrRange_new ( cmp ) SKM_sk_new ( ASIdOrRange , ( cmp ) ) # */

/* sk_ASIdOrRange_new_null ( ) SKM_sk_new_null ( ASIdOrRange ) # */

/* sk_ASIdOrRange_free ( st ) SKM_sk_free ( ASIdOrRange , ( st ) ) # */

/* sk_ASIdOrRange_num ( st ) SKM_sk_num ( ASIdOrRange , ( st ) ) # */

/* sk_ASIdOrRange_value ( st , i ) SKM_sk_value ( ASIdOrRange , ( st ) , ( i ) ) # */

/* sk_ASIdOrRange_set ( st , i , val ) SKM_sk_set ( ASIdOrRange , ( st ) , ( i ) , ( val ) ) # */

/* sk_ASIdOrRange_zero ( st ) SKM_sk_zero ( ASIdOrRange , ( st ) ) # */

/* sk_ASIdOrRange_push ( st , val ) SKM_sk_push ( ASIdOrRange , ( st ) , ( val ) ) # */

/* sk_ASIdOrRange_unshift ( st , val ) SKM_sk_unshift ( ASIdOrRange , ( st ) , ( val ) ) # */

/* sk_ASIdOrRange_find ( st , val ) SKM_sk_find ( ASIdOrRange , ( st ) , ( val ) ) # */

/* sk_ASIdOrRange_find_ex ( st , val ) SKM_sk_find_ex ( ASIdOrRange , ( st ) , ( val ) ) # */

/* sk_ASIdOrRange_delete ( st , i ) SKM_sk_delete ( ASIdOrRange , ( st ) , ( i ) ) # */

/* sk_ASIdOrRange_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( ASIdOrRange , ( st ) , ( ptr ) ) # */

/* sk_ASIdOrRange_insert ( st , val , i ) SKM_sk_insert ( ASIdOrRange , ( st ) , ( val ) , ( i ) ) # */

/* sk_ASIdOrRange_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( ASIdOrRange , ( st ) , ( cmp ) ) # */

/* sk_ASIdOrRange_dup ( st ) SKM_sk_dup ( ASIdOrRange , st ) # */

/* sk_ASIdOrRange_pop_free ( st , free_func ) SKM_sk_pop_free ( ASIdOrRange , ( st ) , ( free_func ) ) # */

/* sk_ASIdOrRange_shift ( st ) SKM_sk_shift ( ASIdOrRange , ( st ) ) # */

/* sk_ASIdOrRange_pop ( st ) SKM_sk_pop ( ASIdOrRange , ( st ) ) # */

/* sk_ASIdOrRange_sort ( st ) SKM_sk_sort ( ASIdOrRange , ( st ) ) # */

/* sk_ASIdOrRange_is_sorted ( st ) SKM_sk_is_sorted ( ASIdOrRange , ( st ) ) # */

/* sk_ASN1_GENERALSTRING_new ( cmp ) SKM_sk_new ( ASN1_GENERALSTRING , ( cmp ) ) # */

/* sk_ASN1_GENERALSTRING_new_null ( ) SKM_sk_new_null ( ASN1_GENERALSTRING ) # */

/* sk_ASN1_GENERALSTRING_free ( st ) SKM_sk_free ( ASN1_GENERALSTRING , ( st ) ) # */

/* sk_ASN1_GENERALSTRING_num ( st ) SKM_sk_num ( ASN1_GENERALSTRING , ( st ) ) # */

/* sk_ASN1_GENERALSTRING_value ( st , i ) SKM_sk_value ( ASN1_GENERALSTRING , ( st ) , ( i ) ) # */

/* sk_ASN1_GENERALSTRING_set ( st , i , val ) SKM_sk_set ( ASN1_GENERALSTRING , ( st ) , ( i ) , ( val ) ) # */

/* sk_ASN1_GENERALSTRING_zero ( st ) SKM_sk_zero ( ASN1_GENERALSTRING , ( st ) ) # */

/* sk_ASN1_GENERALSTRING_push ( st , val ) SKM_sk_push ( ASN1_GENERALSTRING , ( st ) , ( val ) ) # */

/* sk_ASN1_GENERALSTRING_unshift ( st , val ) SKM_sk_unshift ( ASN1_GENERALSTRING , ( st ) , ( val ) ) # */

/* sk_ASN1_GENERALSTRING_find ( st , val ) SKM_sk_find ( ASN1_GENERALSTRING , ( st ) , ( val ) ) # */

/* sk_ASN1_GENERALSTRING_find_ex ( st , val ) SKM_sk_find_ex ( ASN1_GENERALSTRING , ( st ) , ( val ) ) # */

/* sk_ASN1_GENERALSTRING_delete ( st , i ) SKM_sk_delete ( ASN1_GENERALSTRING , ( st ) , ( i ) ) # */

/* sk_ASN1_GENERALSTRING_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( ASN1_GENERALSTRING , ( st ) , ( ptr ) ) # */

/* sk_ASN1_GENERALSTRING_insert ( st , val , i ) SKM_sk_insert ( ASN1_GENERALSTRING , ( st ) , ( val ) , ( i ) ) # */

/* sk_ASN1_GENERALSTRING_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( ASN1_GENERALSTRING , ( st ) , ( cmp ) ) # */

/* sk_ASN1_GENERALSTRING_dup ( st ) SKM_sk_dup ( ASN1_GENERALSTRING , st ) # */

/* sk_ASN1_GENERALSTRING_pop_free ( st , free_func ) SKM_sk_pop_free ( ASN1_GENERALSTRING , ( st ) , ( free_func ) ) # */

/* sk_ASN1_GENERALSTRING_shift ( st ) SKM_sk_shift ( ASN1_GENERALSTRING , ( st ) ) # */

/* sk_ASN1_GENERALSTRING_pop ( st ) SKM_sk_pop ( ASN1_GENERALSTRING , ( st ) ) # */

/* sk_ASN1_GENERALSTRING_sort ( st ) SKM_sk_sort ( ASN1_GENERALSTRING , ( st ) ) # */

/* sk_ASN1_GENERALSTRING_is_sorted ( st ) SKM_sk_is_sorted ( ASN1_GENERALSTRING , ( st ) ) # */

/* sk_ASN1_INTEGER_new ( cmp ) SKM_sk_new ( ASN1_INTEGER , ( cmp ) ) # */

/* sk_ASN1_INTEGER_new_null ( ) SKM_sk_new_null ( ASN1_INTEGER ) # */

/* sk_ASN1_INTEGER_free ( st ) SKM_sk_free ( ASN1_INTEGER , ( st ) ) # */

/* sk_ASN1_INTEGER_num ( st ) SKM_sk_num ( ASN1_INTEGER , ( st ) ) # */

/* sk_ASN1_INTEGER_value ( st , i ) SKM_sk_value ( ASN1_INTEGER , ( st ) , ( i ) ) # */

/* sk_ASN1_INTEGER_set ( st , i , val ) SKM_sk_set ( ASN1_INTEGER , ( st ) , ( i ) , ( val ) ) # */

/* sk_ASN1_INTEGER_zero ( st ) SKM_sk_zero ( ASN1_INTEGER , ( st ) ) # */

/* sk_ASN1_INTEGER_push ( st , val ) SKM_sk_push ( ASN1_INTEGER , ( st ) , ( val ) ) # */

/* sk_ASN1_INTEGER_unshift ( st , val ) SKM_sk_unshift ( ASN1_INTEGER , ( st ) , ( val ) ) # */

/* sk_ASN1_INTEGER_find ( st , val ) SKM_sk_find ( ASN1_INTEGER , ( st ) , ( val ) ) # */

/* sk_ASN1_INTEGER_find_ex ( st , val ) SKM_sk_find_ex ( ASN1_INTEGER , ( st ) , ( val ) ) # */

/* sk_ASN1_INTEGER_delete ( st , i ) SKM_sk_delete ( ASN1_INTEGER , ( st ) , ( i ) ) # */

/* sk_ASN1_INTEGER_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( ASN1_INTEGER , ( st ) , ( ptr ) ) # */

/* sk_ASN1_INTEGER_insert ( st , val , i ) SKM_sk_insert ( ASN1_INTEGER , ( st ) , ( val ) , ( i ) ) # */

/* sk_ASN1_INTEGER_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( ASN1_INTEGER , ( st ) , ( cmp ) ) # */

/* sk_ASN1_INTEGER_dup ( st ) SKM_sk_dup ( ASN1_INTEGER , st ) # */

/* sk_ASN1_INTEGER_pop_free ( st , free_func ) SKM_sk_pop_free ( ASN1_INTEGER , ( st ) , ( free_func ) ) # */

/* sk_ASN1_INTEGER_shift ( st ) SKM_sk_shift ( ASN1_INTEGER , ( st ) ) # */

/* sk_ASN1_INTEGER_pop ( st ) SKM_sk_pop ( ASN1_INTEGER , ( st ) ) # */

/* sk_ASN1_INTEGER_sort ( st ) SKM_sk_sort ( ASN1_INTEGER , ( st ) ) # */

/* sk_ASN1_INTEGER_is_sorted ( st ) SKM_sk_is_sorted ( ASN1_INTEGER , ( st ) ) # */

/* sk_ASN1_OBJECT_new ( cmp ) SKM_sk_new ( ASN1_OBJECT , ( cmp ) ) # */

/* sk_ASN1_OBJECT_new_null ( ) SKM_sk_new_null ( ASN1_OBJECT ) # */

/* sk_ASN1_OBJECT_free ( st ) SKM_sk_free ( ASN1_OBJECT , ( st ) ) # */

/* sk_ASN1_OBJECT_num ( st ) SKM_sk_num ( ASN1_OBJECT , ( st ) ) # */

/* sk_ASN1_OBJECT_value ( st , i ) SKM_sk_value ( ASN1_OBJECT , ( st ) , ( i ) ) # */

/* sk_ASN1_OBJECT_set ( st , i , val ) SKM_sk_set ( ASN1_OBJECT , ( st ) , ( i ) , ( val ) ) # */

/* sk_ASN1_OBJECT_zero ( st ) SKM_sk_zero ( ASN1_OBJECT , ( st ) ) # */

/* sk_ASN1_OBJECT_push ( st , val ) SKM_sk_push ( ASN1_OBJECT , ( st ) , ( val ) ) # */

/* sk_ASN1_OBJECT_unshift ( st , val ) SKM_sk_unshift ( ASN1_OBJECT , ( st ) , ( val ) ) # */

/* sk_ASN1_OBJECT_find ( st , val ) SKM_sk_find ( ASN1_OBJECT , ( st ) , ( val ) ) # */

/* sk_ASN1_OBJECT_find_ex ( st , val ) SKM_sk_find_ex ( ASN1_OBJECT , ( st ) , ( val ) ) # */

/* sk_ASN1_OBJECT_delete ( st , i ) SKM_sk_delete ( ASN1_OBJECT , ( st ) , ( i ) ) # */

/* sk_ASN1_OBJECT_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( ASN1_OBJECT , ( st ) , ( ptr ) ) # */

/* sk_ASN1_OBJECT_insert ( st , val , i ) SKM_sk_insert ( ASN1_OBJECT , ( st ) , ( val ) , ( i ) ) # */

/* sk_ASN1_OBJECT_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( ASN1_OBJECT , ( st ) , ( cmp ) ) # */

/* sk_ASN1_OBJECT_dup ( st ) SKM_sk_dup ( ASN1_OBJECT , st ) # */

/* sk_ASN1_OBJECT_pop_free ( st , free_func ) SKM_sk_pop_free ( ASN1_OBJECT , ( st ) , ( free_func ) ) # */

/* sk_ASN1_OBJECT_shift ( st ) SKM_sk_shift ( ASN1_OBJECT , ( st ) ) # */

/* sk_ASN1_OBJECT_pop ( st ) SKM_sk_pop ( ASN1_OBJECT , ( st ) ) # */

/* sk_ASN1_OBJECT_sort ( st ) SKM_sk_sort ( ASN1_OBJECT , ( st ) ) # */

/* sk_ASN1_OBJECT_is_sorted ( st ) SKM_sk_is_sorted ( ASN1_OBJECT , ( st ) ) # */

/* sk_ASN1_STRING_TABLE_new ( cmp ) SKM_sk_new ( ASN1_STRING_TABLE , ( cmp ) ) # */

/* sk_ASN1_STRING_TABLE_new_null ( ) SKM_sk_new_null ( ASN1_STRING_TABLE ) # */

/* sk_ASN1_STRING_TABLE_free ( st ) SKM_sk_free ( ASN1_STRING_TABLE , ( st ) ) # */

/* sk_ASN1_STRING_TABLE_num ( st ) SKM_sk_num ( ASN1_STRING_TABLE , ( st ) ) # */

/* sk_ASN1_STRING_TABLE_value ( st , i ) SKM_sk_value ( ASN1_STRING_TABLE , ( st ) , ( i ) ) # */

/* sk_ASN1_STRING_TABLE_set ( st , i , val ) SKM_sk_set ( ASN1_STRING_TABLE , ( st ) , ( i ) , ( val ) ) # */

/* sk_ASN1_STRING_TABLE_zero ( st ) SKM_sk_zero ( ASN1_STRING_TABLE , ( st ) ) # */

/* sk_ASN1_STRING_TABLE_push ( st , val ) SKM_sk_push ( ASN1_STRING_TABLE , ( st ) , ( val ) ) # */

/* sk_ASN1_STRING_TABLE_unshift ( st , val ) SKM_sk_unshift ( ASN1_STRING_TABLE , ( st ) , ( val ) ) # */

/* sk_ASN1_STRING_TABLE_find ( st , val ) SKM_sk_find ( ASN1_STRING_TABLE , ( st ) , ( val ) ) # */

/* sk_ASN1_STRING_TABLE_find_ex ( st , val ) SKM_sk_find_ex ( ASN1_STRING_TABLE , ( st ) , ( val ) ) # */

/* sk_ASN1_STRING_TABLE_delete ( st , i ) SKM_sk_delete ( ASN1_STRING_TABLE , ( st ) , ( i ) ) # */

/* sk_ASN1_STRING_TABLE_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( ASN1_STRING_TABLE , ( st ) , ( ptr ) ) # */

/* sk_ASN1_STRING_TABLE_insert ( st , val , i ) SKM_sk_insert ( ASN1_STRING_TABLE , ( st ) , ( val ) , ( i ) ) # */

/* sk_ASN1_STRING_TABLE_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( ASN1_STRING_TABLE , ( st ) , ( cmp ) ) # */

/* sk_ASN1_STRING_TABLE_dup ( st ) SKM_sk_dup ( ASN1_STRING_TABLE , st ) # */

/* sk_ASN1_STRING_TABLE_pop_free ( st , free_func ) SKM_sk_pop_free ( ASN1_STRING_TABLE , ( st ) , ( free_func ) ) # */

/* sk_ASN1_STRING_TABLE_shift ( st ) SKM_sk_shift ( ASN1_STRING_TABLE , ( st ) ) # */

/* sk_ASN1_STRING_TABLE_pop ( st ) SKM_sk_pop ( ASN1_STRING_TABLE , ( st ) ) # */

/* sk_ASN1_STRING_TABLE_sort ( st ) SKM_sk_sort ( ASN1_STRING_TABLE , ( st ) ) # */

/* sk_ASN1_STRING_TABLE_is_sorted ( st ) SKM_sk_is_sorted ( ASN1_STRING_TABLE , ( st ) ) # */

/* sk_ASN1_TYPE_new ( cmp ) SKM_sk_new ( ASN1_TYPE , ( cmp ) ) # */

/* sk_ASN1_TYPE_new_null ( ) SKM_sk_new_null ( ASN1_TYPE ) # */

/* sk_ASN1_TYPE_free ( st ) SKM_sk_free ( ASN1_TYPE , ( st ) ) # */

/* sk_ASN1_TYPE_num ( st ) SKM_sk_num ( ASN1_TYPE , ( st ) ) # */

/* sk_ASN1_TYPE_value ( st , i ) SKM_sk_value ( ASN1_TYPE , ( st ) , ( i ) ) # */

/* sk_ASN1_TYPE_set ( st , i , val ) SKM_sk_set ( ASN1_TYPE , ( st ) , ( i ) , ( val ) ) # */

/* sk_ASN1_TYPE_zero ( st ) SKM_sk_zero ( ASN1_TYPE , ( st ) ) # */

/* sk_ASN1_TYPE_push ( st , val ) SKM_sk_push ( ASN1_TYPE , ( st ) , ( val ) ) # */

/* sk_ASN1_TYPE_unshift ( st , val ) SKM_sk_unshift ( ASN1_TYPE , ( st ) , ( val ) ) # */

/* sk_ASN1_TYPE_find ( st , val ) SKM_sk_find ( ASN1_TYPE , ( st ) , ( val ) ) # */

/* sk_ASN1_TYPE_find_ex ( st , val ) SKM_sk_find_ex ( ASN1_TYPE , ( st ) , ( val ) ) # */

/* sk_ASN1_TYPE_delete ( st , i ) SKM_sk_delete ( ASN1_TYPE , ( st ) , ( i ) ) # */

/* sk_ASN1_TYPE_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( ASN1_TYPE , ( st ) , ( ptr ) ) # */

/* sk_ASN1_TYPE_insert ( st , val , i ) SKM_sk_insert ( ASN1_TYPE , ( st ) , ( val ) , ( i ) ) # */

/* sk_ASN1_TYPE_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( ASN1_TYPE , ( st ) , ( cmp ) ) # */

/* sk_ASN1_TYPE_dup ( st ) SKM_sk_dup ( ASN1_TYPE , st ) # */

/* sk_ASN1_TYPE_pop_free ( st , free_func ) SKM_sk_pop_free ( ASN1_TYPE , ( st ) , ( free_func ) ) # */

/* sk_ASN1_TYPE_shift ( st ) SKM_sk_shift ( ASN1_TYPE , ( st ) ) # */

/* sk_ASN1_TYPE_pop ( st ) SKM_sk_pop ( ASN1_TYPE , ( st ) ) # */

/* sk_ASN1_TYPE_sort ( st ) SKM_sk_sort ( ASN1_TYPE , ( st ) ) # */

/* sk_ASN1_TYPE_is_sorted ( st ) SKM_sk_is_sorted ( ASN1_TYPE , ( st ) ) # */

/* sk_ASN1_UTF8STRING_new ( cmp ) SKM_sk_new ( ASN1_UTF8STRING , ( cmp ) ) # */

/* sk_ASN1_UTF8STRING_new_null ( ) SKM_sk_new_null ( ASN1_UTF8STRING ) # */

/* sk_ASN1_UTF8STRING_free ( st ) SKM_sk_free ( ASN1_UTF8STRING , ( st ) ) # */

/* sk_ASN1_UTF8STRING_num ( st ) SKM_sk_num ( ASN1_UTF8STRING , ( st ) ) # */

/* sk_ASN1_UTF8STRING_value ( st , i ) SKM_sk_value ( ASN1_UTF8STRING , ( st ) , ( i ) ) # */

/* sk_ASN1_UTF8STRING_set ( st , i , val ) SKM_sk_set ( ASN1_UTF8STRING , ( st ) , ( i ) , ( val ) ) # */

/* sk_ASN1_UTF8STRING_zero ( st ) SKM_sk_zero ( ASN1_UTF8STRING , ( st ) ) # */

/* sk_ASN1_UTF8STRING_push ( st , val ) SKM_sk_push ( ASN1_UTF8STRING , ( st ) , ( val ) ) # */

/* sk_ASN1_UTF8STRING_unshift ( st , val ) SKM_sk_unshift ( ASN1_UTF8STRING , ( st ) , ( val ) ) # */

/* sk_ASN1_UTF8STRING_find ( st , val ) SKM_sk_find ( ASN1_UTF8STRING , ( st ) , ( val ) ) # */

/* sk_ASN1_UTF8STRING_find_ex ( st , val ) SKM_sk_find_ex ( ASN1_UTF8STRING , ( st ) , ( val ) ) # */

/* sk_ASN1_UTF8STRING_delete ( st , i ) SKM_sk_delete ( ASN1_UTF8STRING , ( st ) , ( i ) ) # */

/* sk_ASN1_UTF8STRING_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( ASN1_UTF8STRING , ( st ) , ( ptr ) ) # */

/* sk_ASN1_UTF8STRING_insert ( st , val , i ) SKM_sk_insert ( ASN1_UTF8STRING , ( st ) , ( val ) , ( i ) ) # */

/* sk_ASN1_UTF8STRING_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( ASN1_UTF8STRING , ( st ) , ( cmp ) ) # */

/* sk_ASN1_UTF8STRING_dup ( st ) SKM_sk_dup ( ASN1_UTF8STRING , st ) # */

/* sk_ASN1_UTF8STRING_pop_free ( st , free_func ) SKM_sk_pop_free ( ASN1_UTF8STRING , ( st ) , ( free_func ) ) # */

/* sk_ASN1_UTF8STRING_shift ( st ) SKM_sk_shift ( ASN1_UTF8STRING , ( st ) ) # */

/* sk_ASN1_UTF8STRING_pop ( st ) SKM_sk_pop ( ASN1_UTF8STRING , ( st ) ) # */

/* sk_ASN1_UTF8STRING_sort ( st ) SKM_sk_sort ( ASN1_UTF8STRING , ( st ) ) # */

/* sk_ASN1_UTF8STRING_is_sorted ( st ) SKM_sk_is_sorted ( ASN1_UTF8STRING , ( st ) ) # */

/* sk_ASN1_VALUE_new ( cmp ) SKM_sk_new ( ASN1_VALUE , ( cmp ) ) # */

/* sk_ASN1_VALUE_new_null ( ) SKM_sk_new_null ( ASN1_VALUE ) # */

/* sk_ASN1_VALUE_free ( st ) SKM_sk_free ( ASN1_VALUE , ( st ) ) # */

/* sk_ASN1_VALUE_num ( st ) SKM_sk_num ( ASN1_VALUE , ( st ) ) # */

/* sk_ASN1_VALUE_value ( st , i ) SKM_sk_value ( ASN1_VALUE , ( st ) , ( i ) ) # */

/* sk_ASN1_VALUE_set ( st , i , val ) SKM_sk_set ( ASN1_VALUE , ( st ) , ( i ) , ( val ) ) # */

/* sk_ASN1_VALUE_zero ( st ) SKM_sk_zero ( ASN1_VALUE , ( st ) ) # */

/* sk_ASN1_VALUE_push ( st , val ) SKM_sk_push ( ASN1_VALUE , ( st ) , ( val ) ) # */

/* sk_ASN1_VALUE_unshift ( st , val ) SKM_sk_unshift ( ASN1_VALUE , ( st ) , ( val ) ) # */

/* sk_ASN1_VALUE_find ( st , val ) SKM_sk_find ( ASN1_VALUE , ( st ) , ( val ) ) # */

/* sk_ASN1_VALUE_find_ex ( st , val ) SKM_sk_find_ex ( ASN1_VALUE , ( st ) , ( val ) ) # */

/* sk_ASN1_VALUE_delete ( st , i ) SKM_sk_delete ( ASN1_VALUE , ( st ) , ( i ) ) # */

/* sk_ASN1_VALUE_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( ASN1_VALUE , ( st ) , ( ptr ) ) # */

/* sk_ASN1_VALUE_insert ( st , val , i ) SKM_sk_insert ( ASN1_VALUE , ( st ) , ( val ) , ( i ) ) # */

/* sk_ASN1_VALUE_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( ASN1_VALUE , ( st ) , ( cmp ) ) # */

/* sk_ASN1_VALUE_dup ( st ) SKM_sk_dup ( ASN1_VALUE , st ) # */

/* sk_ASN1_VALUE_pop_free ( st , free_func ) SKM_sk_pop_free ( ASN1_VALUE , ( st ) , ( free_func ) ) # */

/* sk_ASN1_VALUE_shift ( st ) SKM_sk_shift ( ASN1_VALUE , ( st ) ) # */

/* sk_ASN1_VALUE_pop ( st ) SKM_sk_pop ( ASN1_VALUE , ( st ) ) # */

/* sk_ASN1_VALUE_sort ( st ) SKM_sk_sort ( ASN1_VALUE , ( st ) ) # */

/* sk_ASN1_VALUE_is_sorted ( st ) SKM_sk_is_sorted ( ASN1_VALUE , ( st ) ) # */

/* sk_BIO_new ( cmp ) SKM_sk_new ( BIO , ( cmp ) ) # */

/* sk_BIO_new_null ( ) SKM_sk_new_null ( BIO ) # */

/* sk_BIO_free ( st ) SKM_sk_free ( BIO , ( st ) ) # */

/* sk_BIO_num ( st ) SKM_sk_num ( BIO , ( st ) ) # */

/* sk_BIO_value ( st , i ) SKM_sk_value ( BIO , ( st ) , ( i ) ) # */

/* sk_BIO_set ( st , i , val ) SKM_sk_set ( BIO , ( st ) , ( i ) , ( val ) ) # */

/* sk_BIO_zero ( st ) SKM_sk_zero ( BIO , ( st ) ) # */

/* sk_BIO_push ( st , val ) SKM_sk_push ( BIO , ( st ) , ( val ) ) # */

/* sk_BIO_unshift ( st , val ) SKM_sk_unshift ( BIO , ( st ) , ( val ) ) # */

/* sk_BIO_find ( st , val ) SKM_sk_find ( BIO , ( st ) , ( val ) ) # */

/* sk_BIO_find_ex ( st , val ) SKM_sk_find_ex ( BIO , ( st ) , ( val ) ) # */

/* sk_BIO_delete ( st , i ) SKM_sk_delete ( BIO , ( st ) , ( i ) ) # */

/* sk_BIO_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( BIO , ( st ) , ( ptr ) ) # */

/* sk_BIO_insert ( st , val , i ) SKM_sk_insert ( BIO , ( st ) , ( val ) , ( i ) ) # */

/* sk_BIO_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( BIO , ( st ) , ( cmp ) ) # */

/* sk_BIO_dup ( st ) SKM_sk_dup ( BIO , st ) # */

/* sk_BIO_pop_free ( st , free_func ) SKM_sk_pop_free ( BIO , ( st ) , ( free_func ) ) # */

/* sk_BIO_shift ( st ) SKM_sk_shift ( BIO , ( st ) ) # */

/* sk_BIO_pop ( st ) SKM_sk_pop ( BIO , ( st ) ) # */

/* sk_BIO_sort ( st ) SKM_sk_sort ( BIO , ( st ) ) # */

/* sk_BIO_is_sorted ( st ) SKM_sk_is_sorted ( BIO , ( st ) ) # */

/* sk_BY_DIR_ENTRY_new ( cmp ) SKM_sk_new ( BY_DIR_ENTRY , ( cmp ) ) # */

/* sk_BY_DIR_ENTRY_new_null ( ) SKM_sk_new_null ( BY_DIR_ENTRY ) # */

/* sk_BY_DIR_ENTRY_free ( st ) SKM_sk_free ( BY_DIR_ENTRY , ( st ) ) # */

/* sk_BY_DIR_ENTRY_num ( st ) SKM_sk_num ( BY_DIR_ENTRY , ( st ) ) # */

/* sk_BY_DIR_ENTRY_value ( st , i ) SKM_sk_value ( BY_DIR_ENTRY , ( st ) , ( i ) ) # */

/* sk_BY_DIR_ENTRY_set ( st , i , val ) SKM_sk_set ( BY_DIR_ENTRY , ( st ) , ( i ) , ( val ) ) # */

/* sk_BY_DIR_ENTRY_zero ( st ) SKM_sk_zero ( BY_DIR_ENTRY , ( st ) ) # */

/* sk_BY_DIR_ENTRY_push ( st , val ) SKM_sk_push ( BY_DIR_ENTRY , ( st ) , ( val ) ) # */

/* sk_BY_DIR_ENTRY_unshift ( st , val ) SKM_sk_unshift ( BY_DIR_ENTRY , ( st ) , ( val ) ) # */

/* sk_BY_DIR_ENTRY_find ( st , val ) SKM_sk_find ( BY_DIR_ENTRY , ( st ) , ( val ) ) # */

/* sk_BY_DIR_ENTRY_find_ex ( st , val ) SKM_sk_find_ex ( BY_DIR_ENTRY , ( st ) , ( val ) ) # */

/* sk_BY_DIR_ENTRY_delete ( st , i ) SKM_sk_delete ( BY_DIR_ENTRY , ( st ) , ( i ) ) # */

/* sk_BY_DIR_ENTRY_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( BY_DIR_ENTRY , ( st ) , ( ptr ) ) # */

/* sk_BY_DIR_ENTRY_insert ( st , val , i ) SKM_sk_insert ( BY_DIR_ENTRY , ( st ) , ( val ) , ( i ) ) # */

/* sk_BY_DIR_ENTRY_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( BY_DIR_ENTRY , ( st ) , ( cmp ) ) # */

/* sk_BY_DIR_ENTRY_dup ( st ) SKM_sk_dup ( BY_DIR_ENTRY , st ) # */

/* sk_BY_DIR_ENTRY_pop_free ( st , free_func ) SKM_sk_pop_free ( BY_DIR_ENTRY , ( st ) , ( free_func ) ) # */

/* sk_BY_DIR_ENTRY_shift ( st ) SKM_sk_shift ( BY_DIR_ENTRY , ( st ) ) # */

/* sk_BY_DIR_ENTRY_pop ( st ) SKM_sk_pop ( BY_DIR_ENTRY , ( st ) ) # */

/* sk_BY_DIR_ENTRY_sort ( st ) SKM_sk_sort ( BY_DIR_ENTRY , ( st ) ) # */

/* sk_BY_DIR_ENTRY_is_sorted ( st ) SKM_sk_is_sorted ( BY_DIR_ENTRY , ( st ) ) # */

/* sk_BY_DIR_HASH_new ( cmp ) SKM_sk_new ( BY_DIR_HASH , ( cmp ) ) # */

/* sk_BY_DIR_HASH_new_null ( ) SKM_sk_new_null ( BY_DIR_HASH ) # */

/* sk_BY_DIR_HASH_free ( st ) SKM_sk_free ( BY_DIR_HASH , ( st ) ) # */

/* sk_BY_DIR_HASH_num ( st ) SKM_sk_num ( BY_DIR_HASH , ( st ) ) # */

/* sk_BY_DIR_HASH_value ( st , i ) SKM_sk_value ( BY_DIR_HASH , ( st ) , ( i ) ) # */

/* sk_BY_DIR_HASH_set ( st , i , val ) SKM_sk_set ( BY_DIR_HASH , ( st ) , ( i ) , ( val ) ) # */

/* sk_BY_DIR_HASH_zero ( st ) SKM_sk_zero ( BY_DIR_HASH , ( st ) ) # */

/* sk_BY_DIR_HASH_push ( st , val ) SKM_sk_push ( BY_DIR_HASH , ( st ) , ( val ) ) # */

/* sk_BY_DIR_HASH_unshift ( st , val ) SKM_sk_unshift ( BY_DIR_HASH , ( st ) , ( val ) ) # */

/* sk_BY_DIR_HASH_find ( st , val ) SKM_sk_find ( BY_DIR_HASH , ( st ) , ( val ) ) # */

/* sk_BY_DIR_HASH_find_ex ( st , val ) SKM_sk_find_ex ( BY_DIR_HASH , ( st ) , ( val ) ) # */

/* sk_BY_DIR_HASH_delete ( st , i ) SKM_sk_delete ( BY_DIR_HASH , ( st ) , ( i ) ) # */

/* sk_BY_DIR_HASH_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( BY_DIR_HASH , ( st ) , ( ptr ) ) # */

/* sk_BY_DIR_HASH_insert ( st , val , i ) SKM_sk_insert ( BY_DIR_HASH , ( st ) , ( val ) , ( i ) ) # */

/* sk_BY_DIR_HASH_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( BY_DIR_HASH , ( st ) , ( cmp ) ) # */

/* sk_BY_DIR_HASH_dup ( st ) SKM_sk_dup ( BY_DIR_HASH , st ) # */

/* sk_BY_DIR_HASH_pop_free ( st , free_func ) SKM_sk_pop_free ( BY_DIR_HASH , ( st ) , ( free_func ) ) # */

/* sk_BY_DIR_HASH_shift ( st ) SKM_sk_shift ( BY_DIR_HASH , ( st ) ) # */

/* sk_BY_DIR_HASH_pop ( st ) SKM_sk_pop ( BY_DIR_HASH , ( st ) ) # */

/* sk_BY_DIR_HASH_sort ( st ) SKM_sk_sort ( BY_DIR_HASH , ( st ) ) # */

/* sk_BY_DIR_HASH_is_sorted ( st ) SKM_sk_is_sorted ( BY_DIR_HASH , ( st ) ) # */

/* sk_CMS_CertificateChoices_new ( cmp ) SKM_sk_new ( CMS_CertificateChoices , ( cmp ) ) # */

/* sk_CMS_CertificateChoices_new_null ( ) SKM_sk_new_null ( CMS_CertificateChoices ) # */

/* sk_CMS_CertificateChoices_free ( st ) SKM_sk_free ( CMS_CertificateChoices , ( st ) ) # */

/* sk_CMS_CertificateChoices_num ( st ) SKM_sk_num ( CMS_CertificateChoices , ( st ) ) # */

/* sk_CMS_CertificateChoices_value ( st , i ) SKM_sk_value ( CMS_CertificateChoices , ( st ) , ( i ) ) # */

/* sk_CMS_CertificateChoices_set ( st , i , val ) SKM_sk_set ( CMS_CertificateChoices , ( st ) , ( i ) , ( val ) ) # */

/* sk_CMS_CertificateChoices_zero ( st ) SKM_sk_zero ( CMS_CertificateChoices , ( st ) ) # */

/* sk_CMS_CertificateChoices_push ( st , val ) SKM_sk_push ( CMS_CertificateChoices , ( st ) , ( val ) ) # */

/* sk_CMS_CertificateChoices_unshift ( st , val ) SKM_sk_unshift ( CMS_CertificateChoices , ( st ) , ( val ) ) # */

/* sk_CMS_CertificateChoices_find ( st , val ) SKM_sk_find ( CMS_CertificateChoices , ( st ) , ( val ) ) # */

/* sk_CMS_CertificateChoices_find_ex ( st , val ) SKM_sk_find_ex ( CMS_CertificateChoices , ( st ) , ( val ) ) # */

/* sk_CMS_CertificateChoices_delete ( st , i ) SKM_sk_delete ( CMS_CertificateChoices , ( st ) , ( i ) ) # */

/* sk_CMS_CertificateChoices_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( CMS_CertificateChoices , ( st ) , ( ptr ) ) # */

/* sk_CMS_CertificateChoices_insert ( st , val , i ) SKM_sk_insert ( CMS_CertificateChoices , ( st ) , ( val ) , ( i ) ) # */

/* sk_CMS_CertificateChoices_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( CMS_CertificateChoices , ( st ) , ( cmp ) ) # */

/* sk_CMS_CertificateChoices_dup ( st ) SKM_sk_dup ( CMS_CertificateChoices , st ) # */

/* sk_CMS_CertificateChoices_pop_free ( st , free_func ) SKM_sk_pop_free ( CMS_CertificateChoices , ( st ) , ( free_func ) ) # */

/* sk_CMS_CertificateChoices_shift ( st ) SKM_sk_shift ( CMS_CertificateChoices , ( st ) ) # */

/* sk_CMS_CertificateChoices_pop ( st ) SKM_sk_pop ( CMS_CertificateChoices , ( st ) ) # */

/* sk_CMS_CertificateChoices_sort ( st ) SKM_sk_sort ( CMS_CertificateChoices , ( st ) ) # */

/* sk_CMS_CertificateChoices_is_sorted ( st ) SKM_sk_is_sorted ( CMS_CertificateChoices , ( st ) ) # */

/* sk_CMS_RecipientInfo_new ( cmp ) SKM_sk_new ( CMS_RecipientInfo , ( cmp ) ) # */

/* sk_CMS_RecipientInfo_new_null ( ) SKM_sk_new_null ( CMS_RecipientInfo ) # */

/* sk_CMS_RecipientInfo_free ( st ) SKM_sk_free ( CMS_RecipientInfo , ( st ) ) # */

/* sk_CMS_RecipientInfo_num ( st ) SKM_sk_num ( CMS_RecipientInfo , ( st ) ) # */

/* sk_CMS_RecipientInfo_value ( st , i ) SKM_sk_value ( CMS_RecipientInfo , ( st ) , ( i ) ) # */

/* sk_CMS_RecipientInfo_set ( st , i , val ) SKM_sk_set ( CMS_RecipientInfo , ( st ) , ( i ) , ( val ) ) # */

/* sk_CMS_RecipientInfo_zero ( st ) SKM_sk_zero ( CMS_RecipientInfo , ( st ) ) # */

/* sk_CMS_RecipientInfo_push ( st , val ) SKM_sk_push ( CMS_RecipientInfo , ( st ) , ( val ) ) # */

/* sk_CMS_RecipientInfo_unshift ( st , val ) SKM_sk_unshift ( CMS_RecipientInfo , ( st ) , ( val ) ) # */

/* sk_CMS_RecipientInfo_find ( st , val ) SKM_sk_find ( CMS_RecipientInfo , ( st ) , ( val ) ) # */

/* sk_CMS_RecipientInfo_find_ex ( st , val ) SKM_sk_find_ex ( CMS_RecipientInfo , ( st ) , ( val ) ) # */

/* sk_CMS_RecipientInfo_delete ( st , i ) SKM_sk_delete ( CMS_RecipientInfo , ( st ) , ( i ) ) # */

/* sk_CMS_RecipientInfo_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( CMS_RecipientInfo , ( st ) , ( ptr ) ) # */

/* sk_CMS_RecipientInfo_insert ( st , val , i ) SKM_sk_insert ( CMS_RecipientInfo , ( st ) , ( val ) , ( i ) ) # */

/* sk_CMS_RecipientInfo_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( CMS_RecipientInfo , ( st ) , ( cmp ) ) # */

/* sk_CMS_RecipientInfo_dup ( st ) SKM_sk_dup ( CMS_RecipientInfo , st ) # */

/* sk_CMS_RecipientInfo_pop_free ( st , free_func ) SKM_sk_pop_free ( CMS_RecipientInfo , ( st ) , ( free_func ) ) # */

/* sk_CMS_RecipientInfo_shift ( st ) SKM_sk_shift ( CMS_RecipientInfo , ( st ) ) # */

/* sk_CMS_RecipientInfo_pop ( st ) SKM_sk_pop ( CMS_RecipientInfo , ( st ) ) # */

/* sk_CMS_RecipientInfo_sort ( st ) SKM_sk_sort ( CMS_RecipientInfo , ( st ) ) # */

/* sk_CMS_RecipientInfo_is_sorted ( st ) SKM_sk_is_sorted ( CMS_RecipientInfo , ( st ) ) # */

/* sk_CMS_RevocationInfoChoice_new ( cmp ) SKM_sk_new ( CMS_RevocationInfoChoice , ( cmp ) ) # */

/* sk_CMS_RevocationInfoChoice_new_null ( ) SKM_sk_new_null ( CMS_RevocationInfoChoice ) # */

/* sk_CMS_RevocationInfoChoice_free ( st ) SKM_sk_free ( CMS_RevocationInfoChoice , ( st ) ) # */

/* sk_CMS_RevocationInfoChoice_num ( st ) SKM_sk_num ( CMS_RevocationInfoChoice , ( st ) ) # */

/* sk_CMS_RevocationInfoChoice_value ( st , i ) SKM_sk_value ( CMS_RevocationInfoChoice , ( st ) , ( i ) ) # */

/* sk_CMS_RevocationInfoChoice_set ( st , i , val ) SKM_sk_set ( CMS_RevocationInfoChoice , ( st ) , ( i ) , ( val ) ) # */

/* sk_CMS_RevocationInfoChoice_zero ( st ) SKM_sk_zero ( CMS_RevocationInfoChoice , ( st ) ) # */

/* sk_CMS_RevocationInfoChoice_push ( st , val ) SKM_sk_push ( CMS_RevocationInfoChoice , ( st ) , ( val ) ) # */

/* sk_CMS_RevocationInfoChoice_unshift ( st , val ) SKM_sk_unshift ( CMS_RevocationInfoChoice , ( st ) , ( val ) ) # */

/* sk_CMS_RevocationInfoChoice_find ( st , val ) SKM_sk_find ( CMS_RevocationInfoChoice , ( st ) , ( val ) ) # */

/* sk_CMS_RevocationInfoChoice_find_ex ( st , val ) SKM_sk_find_ex ( CMS_RevocationInfoChoice , ( st ) , ( val ) ) # */

/* sk_CMS_RevocationInfoChoice_delete ( st , i ) SKM_sk_delete ( CMS_RevocationInfoChoice , ( st ) , ( i ) ) # */

/* sk_CMS_RevocationInfoChoice_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( CMS_RevocationInfoChoice , ( st ) , ( ptr ) ) # */

/* sk_CMS_RevocationInfoChoice_insert ( st , val , i ) SKM_sk_insert ( CMS_RevocationInfoChoice , ( st ) , ( val ) , ( i ) ) # */

/* sk_CMS_RevocationInfoChoice_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( CMS_RevocationInfoChoice , ( st ) , ( cmp ) ) # */

/* sk_CMS_RevocationInfoChoice_dup ( st ) SKM_sk_dup ( CMS_RevocationInfoChoice , st ) # */

/* sk_CMS_RevocationInfoChoice_pop_free ( st , free_func ) SKM_sk_pop_free ( CMS_RevocationInfoChoice , ( st ) , ( free_func ) ) # */

/* sk_CMS_RevocationInfoChoice_shift ( st ) SKM_sk_shift ( CMS_RevocationInfoChoice , ( st ) ) # */

/* sk_CMS_RevocationInfoChoice_pop ( st ) SKM_sk_pop ( CMS_RevocationInfoChoice , ( st ) ) # */

/* sk_CMS_RevocationInfoChoice_sort ( st ) SKM_sk_sort ( CMS_RevocationInfoChoice , ( st ) ) # */

/* sk_CMS_RevocationInfoChoice_is_sorted ( st ) SKM_sk_is_sorted ( CMS_RevocationInfoChoice , ( st ) ) # */

/* sk_CMS_SignerInfo_new ( cmp ) SKM_sk_new ( CMS_SignerInfo , ( cmp ) ) # */

/* sk_CMS_SignerInfo_new_null ( ) SKM_sk_new_null ( CMS_SignerInfo ) # */

/* sk_CMS_SignerInfo_free ( st ) SKM_sk_free ( CMS_SignerInfo , ( st ) ) # */

/* sk_CMS_SignerInfo_num ( st ) SKM_sk_num ( CMS_SignerInfo , ( st ) ) # */

/* sk_CMS_SignerInfo_value ( st , i ) SKM_sk_value ( CMS_SignerInfo , ( st ) , ( i ) ) # */

/* sk_CMS_SignerInfo_set ( st , i , val ) SKM_sk_set ( CMS_SignerInfo , ( st ) , ( i ) , ( val ) ) # */

/* sk_CMS_SignerInfo_zero ( st ) SKM_sk_zero ( CMS_SignerInfo , ( st ) ) # */

/* sk_CMS_SignerInfo_push ( st , val ) SKM_sk_push ( CMS_SignerInfo , ( st ) , ( val ) ) # */

/* sk_CMS_SignerInfo_unshift ( st , val ) SKM_sk_unshift ( CMS_SignerInfo , ( st ) , ( val ) ) # */

/* sk_CMS_SignerInfo_find ( st , val ) SKM_sk_find ( CMS_SignerInfo , ( st ) , ( val ) ) # */

/* sk_CMS_SignerInfo_find_ex ( st , val ) SKM_sk_find_ex ( CMS_SignerInfo , ( st ) , ( val ) ) # */

/* sk_CMS_SignerInfo_delete ( st , i ) SKM_sk_delete ( CMS_SignerInfo , ( st ) , ( i ) ) # */

/* sk_CMS_SignerInfo_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( CMS_SignerInfo , ( st ) , ( ptr ) ) # */

/* sk_CMS_SignerInfo_insert ( st , val , i ) SKM_sk_insert ( CMS_SignerInfo , ( st ) , ( val ) , ( i ) ) # */

/* sk_CMS_SignerInfo_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( CMS_SignerInfo , ( st ) , ( cmp ) ) # */

/* sk_CMS_SignerInfo_dup ( st ) SKM_sk_dup ( CMS_SignerInfo , st ) # */

/* sk_CMS_SignerInfo_pop_free ( st , free_func ) SKM_sk_pop_free ( CMS_SignerInfo , ( st ) , ( free_func ) ) # */

/* sk_CMS_SignerInfo_shift ( st ) SKM_sk_shift ( CMS_SignerInfo , ( st ) ) # */

/* sk_CMS_SignerInfo_pop ( st ) SKM_sk_pop ( CMS_SignerInfo , ( st ) ) # */

/* sk_CMS_SignerInfo_sort ( st ) SKM_sk_sort ( CMS_SignerInfo , ( st ) ) # */

/* sk_CMS_SignerInfo_is_sorted ( st ) SKM_sk_is_sorted ( CMS_SignerInfo , ( st ) ) # */

/* sk_CONF_IMODULE_new ( cmp ) SKM_sk_new ( CONF_IMODULE , ( cmp ) ) # */

/* sk_CONF_IMODULE_new_null ( ) SKM_sk_new_null ( CONF_IMODULE ) # */

/* sk_CONF_IMODULE_free ( st ) SKM_sk_free ( CONF_IMODULE , ( st ) ) # */

/* sk_CONF_IMODULE_num ( st ) SKM_sk_num ( CONF_IMODULE , ( st ) ) # */

/* sk_CONF_IMODULE_value ( st , i ) SKM_sk_value ( CONF_IMODULE , ( st ) , ( i ) ) # */

/* sk_CONF_IMODULE_set ( st , i , val ) SKM_sk_set ( CONF_IMODULE , ( st ) , ( i ) , ( val ) ) # */

/* sk_CONF_IMODULE_zero ( st ) SKM_sk_zero ( CONF_IMODULE , ( st ) ) # */

/* sk_CONF_IMODULE_push ( st , val ) SKM_sk_push ( CONF_IMODULE , ( st ) , ( val ) ) # */

/* sk_CONF_IMODULE_unshift ( st , val ) SKM_sk_unshift ( CONF_IMODULE , ( st ) , ( val ) ) # */

/* sk_CONF_IMODULE_find ( st , val ) SKM_sk_find ( CONF_IMODULE , ( st ) , ( val ) ) # */

/* sk_CONF_IMODULE_find_ex ( st , val ) SKM_sk_find_ex ( CONF_IMODULE , ( st ) , ( val ) ) # */

/* sk_CONF_IMODULE_delete ( st , i ) SKM_sk_delete ( CONF_IMODULE , ( st ) , ( i ) ) # */

/* sk_CONF_IMODULE_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( CONF_IMODULE , ( st ) , ( ptr ) ) # */

/* sk_CONF_IMODULE_insert ( st , val , i ) SKM_sk_insert ( CONF_IMODULE , ( st ) , ( val ) , ( i ) ) # */

/* sk_CONF_IMODULE_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( CONF_IMODULE , ( st ) , ( cmp ) ) # */

/* sk_CONF_IMODULE_dup ( st ) SKM_sk_dup ( CONF_IMODULE , st ) # */

/* sk_CONF_IMODULE_pop_free ( st , free_func ) SKM_sk_pop_free ( CONF_IMODULE , ( st ) , ( free_func ) ) # */

/* sk_CONF_IMODULE_shift ( st ) SKM_sk_shift ( CONF_IMODULE , ( st ) ) # */

/* sk_CONF_IMODULE_pop ( st ) SKM_sk_pop ( CONF_IMODULE , ( st ) ) # */

/* sk_CONF_IMODULE_sort ( st ) SKM_sk_sort ( CONF_IMODULE , ( st ) ) # */

/* sk_CONF_IMODULE_is_sorted ( st ) SKM_sk_is_sorted ( CONF_IMODULE , ( st ) ) # */

/* sk_CONF_MODULE_new ( cmp ) SKM_sk_new ( CONF_MODULE , ( cmp ) ) # */

/* sk_CONF_MODULE_new_null ( ) SKM_sk_new_null ( CONF_MODULE ) # */

/* sk_CONF_MODULE_free ( st ) SKM_sk_free ( CONF_MODULE , ( st ) ) # */

/* sk_CONF_MODULE_num ( st ) SKM_sk_num ( CONF_MODULE , ( st ) ) # */

/* sk_CONF_MODULE_value ( st , i ) SKM_sk_value ( CONF_MODULE , ( st ) , ( i ) ) # */

/* sk_CONF_MODULE_set ( st , i , val ) SKM_sk_set ( CONF_MODULE , ( st ) , ( i ) , ( val ) ) # */

/* sk_CONF_MODULE_zero ( st ) SKM_sk_zero ( CONF_MODULE , ( st ) ) # */

/* sk_CONF_MODULE_push ( st , val ) SKM_sk_push ( CONF_MODULE , ( st ) , ( val ) ) # */

/* sk_CONF_MODULE_unshift ( st , val ) SKM_sk_unshift ( CONF_MODULE , ( st ) , ( val ) ) # */

/* sk_CONF_MODULE_find ( st , val ) SKM_sk_find ( CONF_MODULE , ( st ) , ( val ) ) # */

/* sk_CONF_MODULE_find_ex ( st , val ) SKM_sk_find_ex ( CONF_MODULE , ( st ) , ( val ) ) # */

/* sk_CONF_MODULE_delete ( st , i ) SKM_sk_delete ( CONF_MODULE , ( st ) , ( i ) ) # */

/* sk_CONF_MODULE_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( CONF_MODULE , ( st ) , ( ptr ) ) # */

/* sk_CONF_MODULE_insert ( st , val , i ) SKM_sk_insert ( CONF_MODULE , ( st ) , ( val ) , ( i ) ) # */

/* sk_CONF_MODULE_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( CONF_MODULE , ( st ) , ( cmp ) ) # */

/* sk_CONF_MODULE_dup ( st ) SKM_sk_dup ( CONF_MODULE , st ) # */

/* sk_CONF_MODULE_pop_free ( st , free_func ) SKM_sk_pop_free ( CONF_MODULE , ( st ) , ( free_func ) ) # */

/* sk_CONF_MODULE_shift ( st ) SKM_sk_shift ( CONF_MODULE , ( st ) ) # */

/* sk_CONF_MODULE_pop ( st ) SKM_sk_pop ( CONF_MODULE , ( st ) ) # */

/* sk_CONF_MODULE_sort ( st ) SKM_sk_sort ( CONF_MODULE , ( st ) ) # */

/* sk_CONF_MODULE_is_sorted ( st ) SKM_sk_is_sorted ( CONF_MODULE , ( st ) ) # */

/* sk_CONF_VALUE_new ( cmp ) SKM_sk_new ( CONF_VALUE , ( cmp ) ) # */

/* sk_CONF_VALUE_new_null ( ) SKM_sk_new_null ( CONF_VALUE ) # */

/* sk_CONF_VALUE_free ( st ) SKM_sk_free ( CONF_VALUE , ( st ) ) # */

/* sk_CONF_VALUE_num ( st ) SKM_sk_num ( CONF_VALUE , ( st ) ) # */

/* sk_CONF_VALUE_value ( st , i ) SKM_sk_value ( CONF_VALUE , ( st ) , ( i ) ) # */

/* sk_CONF_VALUE_set ( st , i , val ) SKM_sk_set ( CONF_VALUE , ( st ) , ( i ) , ( val ) ) # */

/* sk_CONF_VALUE_zero ( st ) SKM_sk_zero ( CONF_VALUE , ( st ) ) # */

/* sk_CONF_VALUE_push ( st , val ) SKM_sk_push ( CONF_VALUE , ( st ) , ( val ) ) # */

/* sk_CONF_VALUE_unshift ( st , val ) SKM_sk_unshift ( CONF_VALUE , ( st ) , ( val ) ) # */

/* sk_CONF_VALUE_find ( st , val ) SKM_sk_find ( CONF_VALUE , ( st ) , ( val ) ) # */

/* sk_CONF_VALUE_find_ex ( st , val ) SKM_sk_find_ex ( CONF_VALUE , ( st ) , ( val ) ) # */

/* sk_CONF_VALUE_delete ( st , i ) SKM_sk_delete ( CONF_VALUE , ( st ) , ( i ) ) # */

/* sk_CONF_VALUE_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( CONF_VALUE , ( st ) , ( ptr ) ) # */

/* sk_CONF_VALUE_insert ( st , val , i ) SKM_sk_insert ( CONF_VALUE , ( st ) , ( val ) , ( i ) ) # */

/* sk_CONF_VALUE_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( CONF_VALUE , ( st ) , ( cmp ) ) # */

/* sk_CONF_VALUE_dup ( st ) SKM_sk_dup ( CONF_VALUE , st ) # */

/* sk_CONF_VALUE_pop_free ( st , free_func ) SKM_sk_pop_free ( CONF_VALUE , ( st ) , ( free_func ) ) # */

/* sk_CONF_VALUE_shift ( st ) SKM_sk_shift ( CONF_VALUE , ( st ) ) # */

/* sk_CONF_VALUE_pop ( st ) SKM_sk_pop ( CONF_VALUE , ( st ) ) # */

/* sk_CONF_VALUE_sort ( st ) SKM_sk_sort ( CONF_VALUE , ( st ) ) # */

/* sk_CONF_VALUE_is_sorted ( st ) SKM_sk_is_sorted ( CONF_VALUE , ( st ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_new ( cmp ) SKM_sk_new ( CRYPTO_EX_DATA_FUNCS , ( cmp ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_new_null ( ) SKM_sk_new_null ( CRYPTO_EX_DATA_FUNCS ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_free ( st ) SKM_sk_free ( CRYPTO_EX_DATA_FUNCS , ( st ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_num ( st ) SKM_sk_num ( CRYPTO_EX_DATA_FUNCS , ( st ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_value ( st , i ) SKM_sk_value ( CRYPTO_EX_DATA_FUNCS , ( st ) , ( i ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_set ( st , i , val ) SKM_sk_set ( CRYPTO_EX_DATA_FUNCS , ( st ) , ( i ) , ( val ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_zero ( st ) SKM_sk_zero ( CRYPTO_EX_DATA_FUNCS , ( st ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_push ( st , val ) SKM_sk_push ( CRYPTO_EX_DATA_FUNCS , ( st ) , ( val ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_unshift ( st , val ) SKM_sk_unshift ( CRYPTO_EX_DATA_FUNCS , ( st ) , ( val ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_find ( st , val ) SKM_sk_find ( CRYPTO_EX_DATA_FUNCS , ( st ) , ( val ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_find_ex ( st , val ) SKM_sk_find_ex ( CRYPTO_EX_DATA_FUNCS , ( st ) , ( val ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_delete ( st , i ) SKM_sk_delete ( CRYPTO_EX_DATA_FUNCS , ( st ) , ( i ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( CRYPTO_EX_DATA_FUNCS , ( st ) , ( ptr ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_insert ( st , val , i ) SKM_sk_insert ( CRYPTO_EX_DATA_FUNCS , ( st ) , ( val ) , ( i ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( CRYPTO_EX_DATA_FUNCS , ( st ) , ( cmp ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_dup ( st ) SKM_sk_dup ( CRYPTO_EX_DATA_FUNCS , st ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_pop_free ( st , free_func ) SKM_sk_pop_free ( CRYPTO_EX_DATA_FUNCS , ( st ) , ( free_func ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_shift ( st ) SKM_sk_shift ( CRYPTO_EX_DATA_FUNCS , ( st ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_pop ( st ) SKM_sk_pop ( CRYPTO_EX_DATA_FUNCS , ( st ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_sort ( st ) SKM_sk_sort ( CRYPTO_EX_DATA_FUNCS , ( st ) ) # */

/* sk_CRYPTO_EX_DATA_FUNCS_is_sorted ( st ) SKM_sk_is_sorted ( CRYPTO_EX_DATA_FUNCS , ( st ) ) # */

/* sk_CRYPTO_dynlock_new ( cmp ) SKM_sk_new ( CRYPTO_dynlock , ( cmp ) ) # */

/* sk_CRYPTO_dynlock_new_null ( ) SKM_sk_new_null ( CRYPTO_dynlock ) # */

/* sk_CRYPTO_dynlock_free ( st ) SKM_sk_free ( CRYPTO_dynlock , ( st ) ) # */

/* sk_CRYPTO_dynlock_num ( st ) SKM_sk_num ( CRYPTO_dynlock , ( st ) ) # */

/* sk_CRYPTO_dynlock_value ( st , i ) SKM_sk_value ( CRYPTO_dynlock , ( st ) , ( i ) ) # */

/* sk_CRYPTO_dynlock_set ( st , i , val ) SKM_sk_set ( CRYPTO_dynlock , ( st ) , ( i ) , ( val ) ) # */

/* sk_CRYPTO_dynlock_zero ( st ) SKM_sk_zero ( CRYPTO_dynlock , ( st ) ) # */

/* sk_CRYPTO_dynlock_push ( st , val ) SKM_sk_push ( CRYPTO_dynlock , ( st ) , ( val ) ) # */

/* sk_CRYPTO_dynlock_unshift ( st , val ) SKM_sk_unshift ( CRYPTO_dynlock , ( st ) , ( val ) ) # */

/* sk_CRYPTO_dynlock_find ( st , val ) SKM_sk_find ( CRYPTO_dynlock , ( st ) , ( val ) ) # */

/* sk_CRYPTO_dynlock_find_ex ( st , val ) SKM_sk_find_ex ( CRYPTO_dynlock , ( st ) , ( val ) ) # */

/* sk_CRYPTO_dynlock_delete ( st , i ) SKM_sk_delete ( CRYPTO_dynlock , ( st ) , ( i ) ) # */

/* sk_CRYPTO_dynlock_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( CRYPTO_dynlock , ( st ) , ( ptr ) ) # */

/* sk_CRYPTO_dynlock_insert ( st , val , i ) SKM_sk_insert ( CRYPTO_dynlock , ( st ) , ( val ) , ( i ) ) # */

/* sk_CRYPTO_dynlock_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( CRYPTO_dynlock , ( st ) , ( cmp ) ) # */

/* sk_CRYPTO_dynlock_dup ( st ) SKM_sk_dup ( CRYPTO_dynlock , st ) # */

/* sk_CRYPTO_dynlock_pop_free ( st , free_func ) SKM_sk_pop_free ( CRYPTO_dynlock , ( st ) , ( free_func ) ) # */

/* sk_CRYPTO_dynlock_shift ( st ) SKM_sk_shift ( CRYPTO_dynlock , ( st ) ) # */

/* sk_CRYPTO_dynlock_pop ( st ) SKM_sk_pop ( CRYPTO_dynlock , ( st ) ) # */

/* sk_CRYPTO_dynlock_sort ( st ) SKM_sk_sort ( CRYPTO_dynlock , ( st ) ) # */

/* sk_CRYPTO_dynlock_is_sorted ( st ) SKM_sk_is_sorted ( CRYPTO_dynlock , ( st ) ) # */

/* sk_DIST_POINT_new ( cmp ) SKM_sk_new ( DIST_POINT , ( cmp ) ) # */

/* sk_DIST_POINT_new_null ( ) SKM_sk_new_null ( DIST_POINT ) # */

/* sk_DIST_POINT_free ( st ) SKM_sk_free ( DIST_POINT , ( st ) ) # */

/* sk_DIST_POINT_num ( st ) SKM_sk_num ( DIST_POINT , ( st ) ) # */

/* sk_DIST_POINT_value ( st , i ) SKM_sk_value ( DIST_POINT , ( st ) , ( i ) ) # */

/* sk_DIST_POINT_set ( st , i , val ) SKM_sk_set ( DIST_POINT , ( st ) , ( i ) , ( val ) ) # */

/* sk_DIST_POINT_zero ( st ) SKM_sk_zero ( DIST_POINT , ( st ) ) # */

/* sk_DIST_POINT_push ( st , val ) SKM_sk_push ( DIST_POINT , ( st ) , ( val ) ) # */

/* sk_DIST_POINT_unshift ( st , val ) SKM_sk_unshift ( DIST_POINT , ( st ) , ( val ) ) # */

/* sk_DIST_POINT_find ( st , val ) SKM_sk_find ( DIST_POINT , ( st ) , ( val ) ) # */

/* sk_DIST_POINT_find_ex ( st , val ) SKM_sk_find_ex ( DIST_POINT , ( st ) , ( val ) ) # */

/* sk_DIST_POINT_delete ( st , i ) SKM_sk_delete ( DIST_POINT , ( st ) , ( i ) ) # */

/* sk_DIST_POINT_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( DIST_POINT , ( st ) , ( ptr ) ) # */

/* sk_DIST_POINT_insert ( st , val , i ) SKM_sk_insert ( DIST_POINT , ( st ) , ( val ) , ( i ) ) # */

/* sk_DIST_POINT_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( DIST_POINT , ( st ) , ( cmp ) ) # */

/* sk_DIST_POINT_dup ( st ) SKM_sk_dup ( DIST_POINT , st ) # */

/* sk_DIST_POINT_pop_free ( st , free_func ) SKM_sk_pop_free ( DIST_POINT , ( st ) , ( free_func ) ) # */

/* sk_DIST_POINT_shift ( st ) SKM_sk_shift ( DIST_POINT , ( st ) ) # */

/* sk_DIST_POINT_pop ( st ) SKM_sk_pop ( DIST_POINT , ( st ) ) # */

/* sk_DIST_POINT_sort ( st ) SKM_sk_sort ( DIST_POINT , ( st ) ) # */

/* sk_DIST_POINT_is_sorted ( st ) SKM_sk_is_sorted ( DIST_POINT , ( st ) ) # */

/* sk_ENGINE_new ( cmp ) SKM_sk_new ( ENGINE , ( cmp ) ) # */

/* sk_ENGINE_new_null ( ) SKM_sk_new_null ( ENGINE ) # */

/* sk_ENGINE_free ( st ) SKM_sk_free ( ENGINE , ( st ) ) # */

/* sk_ENGINE_num ( st ) SKM_sk_num ( ENGINE , ( st ) ) # */

/* sk_ENGINE_value ( st , i ) SKM_sk_value ( ENGINE , ( st ) , ( i ) ) # */

/* sk_ENGINE_set ( st , i , val ) SKM_sk_set ( ENGINE , ( st ) , ( i ) , ( val ) ) # */

/* sk_ENGINE_zero ( st ) SKM_sk_zero ( ENGINE , ( st ) ) # */

/* sk_ENGINE_push ( st , val ) SKM_sk_push ( ENGINE , ( st ) , ( val ) ) # */

/* sk_ENGINE_unshift ( st , val ) SKM_sk_unshift ( ENGINE , ( st ) , ( val ) ) # */

/* sk_ENGINE_find ( st , val ) SKM_sk_find ( ENGINE , ( st ) , ( val ) ) # */

/* sk_ENGINE_find_ex ( st , val ) SKM_sk_find_ex ( ENGINE , ( st ) , ( val ) ) # */

/* sk_ENGINE_delete ( st , i ) SKM_sk_delete ( ENGINE , ( st ) , ( i ) ) # */

/* sk_ENGINE_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( ENGINE , ( st ) , ( ptr ) ) # */

/* sk_ENGINE_insert ( st , val , i ) SKM_sk_insert ( ENGINE , ( st ) , ( val ) , ( i ) ) # */

/* sk_ENGINE_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( ENGINE , ( st ) , ( cmp ) ) # */

/* sk_ENGINE_dup ( st ) SKM_sk_dup ( ENGINE , st ) # */

/* sk_ENGINE_pop_free ( st , free_func ) SKM_sk_pop_free ( ENGINE , ( st ) , ( free_func ) ) # */

/* sk_ENGINE_shift ( st ) SKM_sk_shift ( ENGINE , ( st ) ) # */

/* sk_ENGINE_pop ( st ) SKM_sk_pop ( ENGINE , ( st ) ) # */

/* sk_ENGINE_sort ( st ) SKM_sk_sort ( ENGINE , ( st ) ) # */

/* sk_ENGINE_is_sorted ( st ) SKM_sk_is_sorted ( ENGINE , ( st ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_new ( cmp ) SKM_sk_new ( ENGINE_CLEANUP_ITEM , ( cmp ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_new_null ( ) SKM_sk_new_null ( ENGINE_CLEANUP_ITEM ) # */

/* sk_ENGINE_CLEANUP_ITEM_free ( st ) SKM_sk_free ( ENGINE_CLEANUP_ITEM , ( st ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_num ( st ) SKM_sk_num ( ENGINE_CLEANUP_ITEM , ( st ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_value ( st , i ) SKM_sk_value ( ENGINE_CLEANUP_ITEM , ( st ) , ( i ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_set ( st , i , val ) SKM_sk_set ( ENGINE_CLEANUP_ITEM , ( st ) , ( i ) , ( val ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_zero ( st ) SKM_sk_zero ( ENGINE_CLEANUP_ITEM , ( st ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_push ( st , val ) SKM_sk_push ( ENGINE_CLEANUP_ITEM , ( st ) , ( val ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_unshift ( st , val ) SKM_sk_unshift ( ENGINE_CLEANUP_ITEM , ( st ) , ( val ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_find ( st , val ) SKM_sk_find ( ENGINE_CLEANUP_ITEM , ( st ) , ( val ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_find_ex ( st , val ) SKM_sk_find_ex ( ENGINE_CLEANUP_ITEM , ( st ) , ( val ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_delete ( st , i ) SKM_sk_delete ( ENGINE_CLEANUP_ITEM , ( st ) , ( i ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( ENGINE_CLEANUP_ITEM , ( st ) , ( ptr ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_insert ( st , val , i ) SKM_sk_insert ( ENGINE_CLEANUP_ITEM , ( st ) , ( val ) , ( i ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( ENGINE_CLEANUP_ITEM , ( st ) , ( cmp ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_dup ( st ) SKM_sk_dup ( ENGINE_CLEANUP_ITEM , st ) # */

/* sk_ENGINE_CLEANUP_ITEM_pop_free ( st , free_func ) SKM_sk_pop_free ( ENGINE_CLEANUP_ITEM , ( st ) , ( free_func ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_shift ( st ) SKM_sk_shift ( ENGINE_CLEANUP_ITEM , ( st ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_pop ( st ) SKM_sk_pop ( ENGINE_CLEANUP_ITEM , ( st ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_sort ( st ) SKM_sk_sort ( ENGINE_CLEANUP_ITEM , ( st ) ) # */

/* sk_ENGINE_CLEANUP_ITEM_is_sorted ( st ) SKM_sk_is_sorted ( ENGINE_CLEANUP_ITEM , ( st ) ) # */

/* sk_ESS_CERT_ID_new ( cmp ) SKM_sk_new ( ESS_CERT_ID , ( cmp ) ) # */

/* sk_ESS_CERT_ID_new_null ( ) SKM_sk_new_null ( ESS_CERT_ID ) # */

/* sk_ESS_CERT_ID_free ( st ) SKM_sk_free ( ESS_CERT_ID , ( st ) ) # */

/* sk_ESS_CERT_ID_num ( st ) SKM_sk_num ( ESS_CERT_ID , ( st ) ) # */

/* sk_ESS_CERT_ID_value ( st , i ) SKM_sk_value ( ESS_CERT_ID , ( st ) , ( i ) ) # */

/* sk_ESS_CERT_ID_set ( st , i , val ) SKM_sk_set ( ESS_CERT_ID , ( st ) , ( i ) , ( val ) ) # */

/* sk_ESS_CERT_ID_zero ( st ) SKM_sk_zero ( ESS_CERT_ID , ( st ) ) # */

/* sk_ESS_CERT_ID_push ( st , val ) SKM_sk_push ( ESS_CERT_ID , ( st ) , ( val ) ) # */

/* sk_ESS_CERT_ID_unshift ( st , val ) SKM_sk_unshift ( ESS_CERT_ID , ( st ) , ( val ) ) # */

/* sk_ESS_CERT_ID_find ( st , val ) SKM_sk_find ( ESS_CERT_ID , ( st ) , ( val ) ) # */

/* sk_ESS_CERT_ID_find_ex ( st , val ) SKM_sk_find_ex ( ESS_CERT_ID , ( st ) , ( val ) ) # */

/* sk_ESS_CERT_ID_delete ( st , i ) SKM_sk_delete ( ESS_CERT_ID , ( st ) , ( i ) ) # */

/* sk_ESS_CERT_ID_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( ESS_CERT_ID , ( st ) , ( ptr ) ) # */

/* sk_ESS_CERT_ID_insert ( st , val , i ) SKM_sk_insert ( ESS_CERT_ID , ( st ) , ( val ) , ( i ) ) # */

/* sk_ESS_CERT_ID_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( ESS_CERT_ID , ( st ) , ( cmp ) ) # */

/* sk_ESS_CERT_ID_dup ( st ) SKM_sk_dup ( ESS_CERT_ID , st ) # */

/* sk_ESS_CERT_ID_pop_free ( st , free_func ) SKM_sk_pop_free ( ESS_CERT_ID , ( st ) , ( free_func ) ) # */

/* sk_ESS_CERT_ID_shift ( st ) SKM_sk_shift ( ESS_CERT_ID , ( st ) ) # */

/* sk_ESS_CERT_ID_pop ( st ) SKM_sk_pop ( ESS_CERT_ID , ( st ) ) # */

/* sk_ESS_CERT_ID_sort ( st ) SKM_sk_sort ( ESS_CERT_ID , ( st ) ) # */

/* sk_ESS_CERT_ID_is_sorted ( st ) SKM_sk_is_sorted ( ESS_CERT_ID , ( st ) ) # */

/* sk_EVP_MD_new ( cmp ) SKM_sk_new ( EVP_MD , ( cmp ) ) # */

/* sk_EVP_MD_new_null ( ) SKM_sk_new_null ( EVP_MD ) # */

/* sk_EVP_MD_free ( st ) SKM_sk_free ( EVP_MD , ( st ) ) # */

/* sk_EVP_MD_num ( st ) SKM_sk_num ( EVP_MD , ( st ) ) # */

/* sk_EVP_MD_value ( st , i ) SKM_sk_value ( EVP_MD , ( st ) , ( i ) ) # */

/* sk_EVP_MD_set ( st , i , val ) SKM_sk_set ( EVP_MD , ( st ) , ( i ) , ( val ) ) # */

/* sk_EVP_MD_zero ( st ) SKM_sk_zero ( EVP_MD , ( st ) ) # */

/* sk_EVP_MD_push ( st , val ) SKM_sk_push ( EVP_MD , ( st ) , ( val ) ) # */

/* sk_EVP_MD_unshift ( st , val ) SKM_sk_unshift ( EVP_MD , ( st ) , ( val ) ) # */

/* sk_EVP_MD_find ( st , val ) SKM_sk_find ( EVP_MD , ( st ) , ( val ) ) # */

/* sk_EVP_MD_find_ex ( st , val ) SKM_sk_find_ex ( EVP_MD , ( st ) , ( val ) ) # */

/* sk_EVP_MD_delete ( st , i ) SKM_sk_delete ( EVP_MD , ( st ) , ( i ) ) # */

/* sk_EVP_MD_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( EVP_MD , ( st ) , ( ptr ) ) # */

/* sk_EVP_MD_insert ( st , val , i ) SKM_sk_insert ( EVP_MD , ( st ) , ( val ) , ( i ) ) # */

/* sk_EVP_MD_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( EVP_MD , ( st ) , ( cmp ) ) # */

/* sk_EVP_MD_dup ( st ) SKM_sk_dup ( EVP_MD , st ) # */

/* sk_EVP_MD_pop_free ( st , free_func ) SKM_sk_pop_free ( EVP_MD , ( st ) , ( free_func ) ) # */

/* sk_EVP_MD_shift ( st ) SKM_sk_shift ( EVP_MD , ( st ) ) # */

/* sk_EVP_MD_pop ( st ) SKM_sk_pop ( EVP_MD , ( st ) ) # */

/* sk_EVP_MD_sort ( st ) SKM_sk_sort ( EVP_MD , ( st ) ) # */

/* sk_EVP_MD_is_sorted ( st ) SKM_sk_is_sorted ( EVP_MD , ( st ) ) # */

/* sk_EVP_PBE_CTL_new ( cmp ) SKM_sk_new ( EVP_PBE_CTL , ( cmp ) ) # */

/* sk_EVP_PBE_CTL_new_null ( ) SKM_sk_new_null ( EVP_PBE_CTL ) # */

/* sk_EVP_PBE_CTL_free ( st ) SKM_sk_free ( EVP_PBE_CTL , ( st ) ) # */

/* sk_EVP_PBE_CTL_num ( st ) SKM_sk_num ( EVP_PBE_CTL , ( st ) ) # */

/* sk_EVP_PBE_CTL_value ( st , i ) SKM_sk_value ( EVP_PBE_CTL , ( st ) , ( i ) ) # */

/* sk_EVP_PBE_CTL_set ( st , i , val ) SKM_sk_set ( EVP_PBE_CTL , ( st ) , ( i ) , ( val ) ) # */

/* sk_EVP_PBE_CTL_zero ( st ) SKM_sk_zero ( EVP_PBE_CTL , ( st ) ) # */

/* sk_EVP_PBE_CTL_push ( st , val ) SKM_sk_push ( EVP_PBE_CTL , ( st ) , ( val ) ) # */

/* sk_EVP_PBE_CTL_unshift ( st , val ) SKM_sk_unshift ( EVP_PBE_CTL , ( st ) , ( val ) ) # */

/* sk_EVP_PBE_CTL_find ( st , val ) SKM_sk_find ( EVP_PBE_CTL , ( st ) , ( val ) ) # */

/* sk_EVP_PBE_CTL_find_ex ( st , val ) SKM_sk_find_ex ( EVP_PBE_CTL , ( st ) , ( val ) ) # */

/* sk_EVP_PBE_CTL_delete ( st , i ) SKM_sk_delete ( EVP_PBE_CTL , ( st ) , ( i ) ) # */

/* sk_EVP_PBE_CTL_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( EVP_PBE_CTL , ( st ) , ( ptr ) ) # */

/* sk_EVP_PBE_CTL_insert ( st , val , i ) SKM_sk_insert ( EVP_PBE_CTL , ( st ) , ( val ) , ( i ) ) # */

/* sk_EVP_PBE_CTL_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( EVP_PBE_CTL , ( st ) , ( cmp ) ) # */

/* sk_EVP_PBE_CTL_dup ( st ) SKM_sk_dup ( EVP_PBE_CTL , st ) # */

/* sk_EVP_PBE_CTL_pop_free ( st , free_func ) SKM_sk_pop_free ( EVP_PBE_CTL , ( st ) , ( free_func ) ) # */

/* sk_EVP_PBE_CTL_shift ( st ) SKM_sk_shift ( EVP_PBE_CTL , ( st ) ) # */

/* sk_EVP_PBE_CTL_pop ( st ) SKM_sk_pop ( EVP_PBE_CTL , ( st ) ) # */

/* sk_EVP_PBE_CTL_sort ( st ) SKM_sk_sort ( EVP_PBE_CTL , ( st ) ) # */

/* sk_EVP_PBE_CTL_is_sorted ( st ) SKM_sk_is_sorted ( EVP_PBE_CTL , ( st ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_new ( cmp ) SKM_sk_new ( EVP_PKEY_ASN1_METHOD , ( cmp ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_new_null ( ) SKM_sk_new_null ( EVP_PKEY_ASN1_METHOD ) # */

/* sk_EVP_PKEY_ASN1_METHOD_free ( st ) SKM_sk_free ( EVP_PKEY_ASN1_METHOD , ( st ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_num ( st ) SKM_sk_num ( EVP_PKEY_ASN1_METHOD , ( st ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_value ( st , i ) SKM_sk_value ( EVP_PKEY_ASN1_METHOD , ( st ) , ( i ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_set ( st , i , val ) SKM_sk_set ( EVP_PKEY_ASN1_METHOD , ( st ) , ( i ) , ( val ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_zero ( st ) SKM_sk_zero ( EVP_PKEY_ASN1_METHOD , ( st ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_push ( st , val ) SKM_sk_push ( EVP_PKEY_ASN1_METHOD , ( st ) , ( val ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_unshift ( st , val ) SKM_sk_unshift ( EVP_PKEY_ASN1_METHOD , ( st ) , ( val ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_find ( st , val ) SKM_sk_find ( EVP_PKEY_ASN1_METHOD , ( st ) , ( val ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_find_ex ( st , val ) SKM_sk_find_ex ( EVP_PKEY_ASN1_METHOD , ( st ) , ( val ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_delete ( st , i ) SKM_sk_delete ( EVP_PKEY_ASN1_METHOD , ( st ) , ( i ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( EVP_PKEY_ASN1_METHOD , ( st ) , ( ptr ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_insert ( st , val , i ) SKM_sk_insert ( EVP_PKEY_ASN1_METHOD , ( st ) , ( val ) , ( i ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( EVP_PKEY_ASN1_METHOD , ( st ) , ( cmp ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_dup ( st ) SKM_sk_dup ( EVP_PKEY_ASN1_METHOD , st ) # */

/* sk_EVP_PKEY_ASN1_METHOD_pop_free ( st , free_func ) SKM_sk_pop_free ( EVP_PKEY_ASN1_METHOD , ( st ) , ( free_func ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_shift ( st ) SKM_sk_shift ( EVP_PKEY_ASN1_METHOD , ( st ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_pop ( st ) SKM_sk_pop ( EVP_PKEY_ASN1_METHOD , ( st ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_sort ( st ) SKM_sk_sort ( EVP_PKEY_ASN1_METHOD , ( st ) ) # */

/* sk_EVP_PKEY_ASN1_METHOD_is_sorted ( st ) SKM_sk_is_sorted ( EVP_PKEY_ASN1_METHOD , ( st ) ) # */

/* sk_EVP_PKEY_METHOD_new ( cmp ) SKM_sk_new ( EVP_PKEY_METHOD , ( cmp ) ) # */

/* sk_EVP_PKEY_METHOD_new_null ( ) SKM_sk_new_null ( EVP_PKEY_METHOD ) # */

/* sk_EVP_PKEY_METHOD_free ( st ) SKM_sk_free ( EVP_PKEY_METHOD , ( st ) ) # */

/* sk_EVP_PKEY_METHOD_num ( st ) SKM_sk_num ( EVP_PKEY_METHOD , ( st ) ) # */

/* sk_EVP_PKEY_METHOD_value ( st , i ) SKM_sk_value ( EVP_PKEY_METHOD , ( st ) , ( i ) ) # */

/* sk_EVP_PKEY_METHOD_set ( st , i , val ) SKM_sk_set ( EVP_PKEY_METHOD , ( st ) , ( i ) , ( val ) ) # */

/* sk_EVP_PKEY_METHOD_zero ( st ) SKM_sk_zero ( EVP_PKEY_METHOD , ( st ) ) # */

/* sk_EVP_PKEY_METHOD_push ( st , val ) SKM_sk_push ( EVP_PKEY_METHOD , ( st ) , ( val ) ) # */

/* sk_EVP_PKEY_METHOD_unshift ( st , val ) SKM_sk_unshift ( EVP_PKEY_METHOD , ( st ) , ( val ) ) # */

/* sk_EVP_PKEY_METHOD_find ( st , val ) SKM_sk_find ( EVP_PKEY_METHOD , ( st ) , ( val ) ) # */

/* sk_EVP_PKEY_METHOD_find_ex ( st , val ) SKM_sk_find_ex ( EVP_PKEY_METHOD , ( st ) , ( val ) ) # */

/* sk_EVP_PKEY_METHOD_delete ( st , i ) SKM_sk_delete ( EVP_PKEY_METHOD , ( st ) , ( i ) ) # */

/* sk_EVP_PKEY_METHOD_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( EVP_PKEY_METHOD , ( st ) , ( ptr ) ) # */

/* sk_EVP_PKEY_METHOD_insert ( st , val , i ) SKM_sk_insert ( EVP_PKEY_METHOD , ( st ) , ( val ) , ( i ) ) # */

/* sk_EVP_PKEY_METHOD_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( EVP_PKEY_METHOD , ( st ) , ( cmp ) ) # */

/* sk_EVP_PKEY_METHOD_dup ( st ) SKM_sk_dup ( EVP_PKEY_METHOD , st ) # */

/* sk_EVP_PKEY_METHOD_pop_free ( st , free_func ) SKM_sk_pop_free ( EVP_PKEY_METHOD , ( st ) , ( free_func ) ) # */

/* sk_EVP_PKEY_METHOD_shift ( st ) SKM_sk_shift ( EVP_PKEY_METHOD , ( st ) ) # */

/* sk_EVP_PKEY_METHOD_pop ( st ) SKM_sk_pop ( EVP_PKEY_METHOD , ( st ) ) # */

/* sk_EVP_PKEY_METHOD_sort ( st ) SKM_sk_sort ( EVP_PKEY_METHOD , ( st ) ) # */

/* sk_EVP_PKEY_METHOD_is_sorted ( st ) SKM_sk_is_sorted ( EVP_PKEY_METHOD , ( st ) ) # */

/* sk_GENERAL_NAME_new ( cmp ) SKM_sk_new ( GENERAL_NAME , ( cmp ) ) # */

/* sk_GENERAL_NAME_new_null ( ) SKM_sk_new_null ( GENERAL_NAME ) # */

/* sk_GENERAL_NAME_free ( st ) SKM_sk_free ( GENERAL_NAME , ( st ) ) # */

/* sk_GENERAL_NAME_num ( st ) SKM_sk_num ( GENERAL_NAME , ( st ) ) # */

/* sk_GENERAL_NAME_value ( st , i ) SKM_sk_value ( GENERAL_NAME , ( st ) , ( i ) ) # */

/* sk_GENERAL_NAME_set ( st , i , val ) SKM_sk_set ( GENERAL_NAME , ( st ) , ( i ) , ( val ) ) # */

/* sk_GENERAL_NAME_zero ( st ) SKM_sk_zero ( GENERAL_NAME , ( st ) ) # */

/* sk_GENERAL_NAME_push ( st , val ) SKM_sk_push ( GENERAL_NAME , ( st ) , ( val ) ) # */

/* sk_GENERAL_NAME_unshift ( st , val ) SKM_sk_unshift ( GENERAL_NAME , ( st ) , ( val ) ) # */

/* sk_GENERAL_NAME_find ( st , val ) SKM_sk_find ( GENERAL_NAME , ( st ) , ( val ) ) # */

/* sk_GENERAL_NAME_find_ex ( st , val ) SKM_sk_find_ex ( GENERAL_NAME , ( st ) , ( val ) ) # */

/* sk_GENERAL_NAME_delete ( st , i ) SKM_sk_delete ( GENERAL_NAME , ( st ) , ( i ) ) # */

/* sk_GENERAL_NAME_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( GENERAL_NAME , ( st ) , ( ptr ) ) # */

/* sk_GENERAL_NAME_insert ( st , val , i ) SKM_sk_insert ( GENERAL_NAME , ( st ) , ( val ) , ( i ) ) # */

/* sk_GENERAL_NAME_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( GENERAL_NAME , ( st ) , ( cmp ) ) # */

/* sk_GENERAL_NAME_dup ( st ) SKM_sk_dup ( GENERAL_NAME , st ) # */

/* sk_GENERAL_NAME_pop_free ( st , free_func ) SKM_sk_pop_free ( GENERAL_NAME , ( st ) , ( free_func ) ) # */

/* sk_GENERAL_NAME_shift ( st ) SKM_sk_shift ( GENERAL_NAME , ( st ) ) # */

/* sk_GENERAL_NAME_pop ( st ) SKM_sk_pop ( GENERAL_NAME , ( st ) ) # */

/* sk_GENERAL_NAME_sort ( st ) SKM_sk_sort ( GENERAL_NAME , ( st ) ) # */

/* sk_GENERAL_NAME_is_sorted ( st ) SKM_sk_is_sorted ( GENERAL_NAME , ( st ) ) # */

/* sk_GENERAL_NAMES_new ( cmp ) SKM_sk_new ( GENERAL_NAMES , ( cmp ) ) # */

/* sk_GENERAL_NAMES_new_null ( ) SKM_sk_new_null ( GENERAL_NAMES ) # */

/* sk_GENERAL_NAMES_free ( st ) SKM_sk_free ( GENERAL_NAMES , ( st ) ) # */

/* sk_GENERAL_NAMES_num ( st ) SKM_sk_num ( GENERAL_NAMES , ( st ) ) # */

/* sk_GENERAL_NAMES_value ( st , i ) SKM_sk_value ( GENERAL_NAMES , ( st ) , ( i ) ) # */

/* sk_GENERAL_NAMES_set ( st , i , val ) SKM_sk_set ( GENERAL_NAMES , ( st ) , ( i ) , ( val ) ) # */

/* sk_GENERAL_NAMES_zero ( st ) SKM_sk_zero ( GENERAL_NAMES , ( st ) ) # */

/* sk_GENERAL_NAMES_push ( st , val ) SKM_sk_push ( GENERAL_NAMES , ( st ) , ( val ) ) # */

/* sk_GENERAL_NAMES_unshift ( st , val ) SKM_sk_unshift ( GENERAL_NAMES , ( st ) , ( val ) ) # */

/* sk_GENERAL_NAMES_find ( st , val ) SKM_sk_find ( GENERAL_NAMES , ( st ) , ( val ) ) # */

/* sk_GENERAL_NAMES_find_ex ( st , val ) SKM_sk_find_ex ( GENERAL_NAMES , ( st ) , ( val ) ) # */

/* sk_GENERAL_NAMES_delete ( st , i ) SKM_sk_delete ( GENERAL_NAMES , ( st ) , ( i ) ) # */

/* sk_GENERAL_NAMES_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( GENERAL_NAMES , ( st ) , ( ptr ) ) # */

/* sk_GENERAL_NAMES_insert ( st , val , i ) SKM_sk_insert ( GENERAL_NAMES , ( st ) , ( val ) , ( i ) ) # */

/* sk_GENERAL_NAMES_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( GENERAL_NAMES , ( st ) , ( cmp ) ) # */

/* sk_GENERAL_NAMES_dup ( st ) SKM_sk_dup ( GENERAL_NAMES , st ) # */

/* sk_GENERAL_NAMES_pop_free ( st , free_func ) SKM_sk_pop_free ( GENERAL_NAMES , ( st ) , ( free_func ) ) # */

/* sk_GENERAL_NAMES_shift ( st ) SKM_sk_shift ( GENERAL_NAMES , ( st ) ) # */

/* sk_GENERAL_NAMES_pop ( st ) SKM_sk_pop ( GENERAL_NAMES , ( st ) ) # */

/* sk_GENERAL_NAMES_sort ( st ) SKM_sk_sort ( GENERAL_NAMES , ( st ) ) # */

/* sk_GENERAL_NAMES_is_sorted ( st ) SKM_sk_is_sorted ( GENERAL_NAMES , ( st ) ) # */

/* sk_GENERAL_SUBTREE_new ( cmp ) SKM_sk_new ( GENERAL_SUBTREE , ( cmp ) ) # */

/* sk_GENERAL_SUBTREE_new_null ( ) SKM_sk_new_null ( GENERAL_SUBTREE ) # */

/* sk_GENERAL_SUBTREE_free ( st ) SKM_sk_free ( GENERAL_SUBTREE , ( st ) ) # */

/* sk_GENERAL_SUBTREE_num ( st ) SKM_sk_num ( GENERAL_SUBTREE , ( st ) ) # */

/* sk_GENERAL_SUBTREE_value ( st , i ) SKM_sk_value ( GENERAL_SUBTREE , ( st ) , ( i ) ) # */

/* sk_GENERAL_SUBTREE_set ( st , i , val ) SKM_sk_set ( GENERAL_SUBTREE , ( st ) , ( i ) , ( val ) ) # */

/* sk_GENERAL_SUBTREE_zero ( st ) SKM_sk_zero ( GENERAL_SUBTREE , ( st ) ) # */

/* sk_GENERAL_SUBTREE_push ( st , val ) SKM_sk_push ( GENERAL_SUBTREE , ( st ) , ( val ) ) # */

/* sk_GENERAL_SUBTREE_unshift ( st , val ) SKM_sk_unshift ( GENERAL_SUBTREE , ( st ) , ( val ) ) # */

/* sk_GENERAL_SUBTREE_find ( st , val ) SKM_sk_find ( GENERAL_SUBTREE , ( st ) , ( val ) ) # */

/* sk_GENERAL_SUBTREE_find_ex ( st , val ) SKM_sk_find_ex ( GENERAL_SUBTREE , ( st ) , ( val ) ) # */

/* sk_GENERAL_SUBTREE_delete ( st , i ) SKM_sk_delete ( GENERAL_SUBTREE , ( st ) , ( i ) ) # */

/* sk_GENERAL_SUBTREE_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( GENERAL_SUBTREE , ( st ) , ( ptr ) ) # */

/* sk_GENERAL_SUBTREE_insert ( st , val , i ) SKM_sk_insert ( GENERAL_SUBTREE , ( st ) , ( val ) , ( i ) ) # */

/* sk_GENERAL_SUBTREE_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( GENERAL_SUBTREE , ( st ) , ( cmp ) ) # */

/* sk_GENERAL_SUBTREE_dup ( st ) SKM_sk_dup ( GENERAL_SUBTREE , st ) # */

/* sk_GENERAL_SUBTREE_pop_free ( st , free_func ) SKM_sk_pop_free ( GENERAL_SUBTREE , ( st ) , ( free_func ) ) # */

/* sk_GENERAL_SUBTREE_shift ( st ) SKM_sk_shift ( GENERAL_SUBTREE , ( st ) ) # */

/* sk_GENERAL_SUBTREE_pop ( st ) SKM_sk_pop ( GENERAL_SUBTREE , ( st ) ) # */

/* sk_GENERAL_SUBTREE_sort ( st ) SKM_sk_sort ( GENERAL_SUBTREE , ( st ) ) # */

/* sk_GENERAL_SUBTREE_is_sorted ( st ) SKM_sk_is_sorted ( GENERAL_SUBTREE , ( st ) ) # */

/* sk_IPAddressFamily_new ( cmp ) SKM_sk_new ( IPAddressFamily , ( cmp ) ) # */

/* sk_IPAddressFamily_new_null ( ) SKM_sk_new_null ( IPAddressFamily ) # */

/* sk_IPAddressFamily_free ( st ) SKM_sk_free ( IPAddressFamily , ( st ) ) # */

/* sk_IPAddressFamily_num ( st ) SKM_sk_num ( IPAddressFamily , ( st ) ) # */

/* sk_IPAddressFamily_value ( st , i ) SKM_sk_value ( IPAddressFamily , ( st ) , ( i ) ) # */

/* sk_IPAddressFamily_set ( st , i , val ) SKM_sk_set ( IPAddressFamily , ( st ) , ( i ) , ( val ) ) # */

/* sk_IPAddressFamily_zero ( st ) SKM_sk_zero ( IPAddressFamily , ( st ) ) # */

/* sk_IPAddressFamily_push ( st , val ) SKM_sk_push ( IPAddressFamily , ( st ) , ( val ) ) # */

/* sk_IPAddressFamily_unshift ( st , val ) SKM_sk_unshift ( IPAddressFamily , ( st ) , ( val ) ) # */

/* sk_IPAddressFamily_find ( st , val ) SKM_sk_find ( IPAddressFamily , ( st ) , ( val ) ) # */

/* sk_IPAddressFamily_find_ex ( st , val ) SKM_sk_find_ex ( IPAddressFamily , ( st ) , ( val ) ) # */

/* sk_IPAddressFamily_delete ( st , i ) SKM_sk_delete ( IPAddressFamily , ( st ) , ( i ) ) # */

/* sk_IPAddressFamily_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( IPAddressFamily , ( st ) , ( ptr ) ) # */

/* sk_IPAddressFamily_insert ( st , val , i ) SKM_sk_insert ( IPAddressFamily , ( st ) , ( val ) , ( i ) ) # */

/* sk_IPAddressFamily_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( IPAddressFamily , ( st ) , ( cmp ) ) # */

/* sk_IPAddressFamily_dup ( st ) SKM_sk_dup ( IPAddressFamily , st ) # */

/* sk_IPAddressFamily_pop_free ( st , free_func ) SKM_sk_pop_free ( IPAddressFamily , ( st ) , ( free_func ) ) # */

/* sk_IPAddressFamily_shift ( st ) SKM_sk_shift ( IPAddressFamily , ( st ) ) # */

/* sk_IPAddressFamily_pop ( st ) SKM_sk_pop ( IPAddressFamily , ( st ) ) # */

/* sk_IPAddressFamily_sort ( st ) SKM_sk_sort ( IPAddressFamily , ( st ) ) # */

/* sk_IPAddressFamily_is_sorted ( st ) SKM_sk_is_sorted ( IPAddressFamily , ( st ) ) # */

/* sk_IPAddressOrRange_new ( cmp ) SKM_sk_new ( IPAddressOrRange , ( cmp ) ) # */

/* sk_IPAddressOrRange_new_null ( ) SKM_sk_new_null ( IPAddressOrRange ) # */

/* sk_IPAddressOrRange_free ( st ) SKM_sk_free ( IPAddressOrRange , ( st ) ) # */

/* sk_IPAddressOrRange_num ( st ) SKM_sk_num ( IPAddressOrRange , ( st ) ) # */

/* sk_IPAddressOrRange_value ( st , i ) SKM_sk_value ( IPAddressOrRange , ( st ) , ( i ) ) # */

/* sk_IPAddressOrRange_set ( st , i , val ) SKM_sk_set ( IPAddressOrRange , ( st ) , ( i ) , ( val ) ) # */

/* sk_IPAddressOrRange_zero ( st ) SKM_sk_zero ( IPAddressOrRange , ( st ) ) # */

/* sk_IPAddressOrRange_push ( st , val ) SKM_sk_push ( IPAddressOrRange , ( st ) , ( val ) ) # */

/* sk_IPAddressOrRange_unshift ( st , val ) SKM_sk_unshift ( IPAddressOrRange , ( st ) , ( val ) ) # */

/* sk_IPAddressOrRange_find ( st , val ) SKM_sk_find ( IPAddressOrRange , ( st ) , ( val ) ) # */

/* sk_IPAddressOrRange_find_ex ( st , val ) SKM_sk_find_ex ( IPAddressOrRange , ( st ) , ( val ) ) # */

/* sk_IPAddressOrRange_delete ( st , i ) SKM_sk_delete ( IPAddressOrRange , ( st ) , ( i ) ) # */

/* sk_IPAddressOrRange_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( IPAddressOrRange , ( st ) , ( ptr ) ) # */

/* sk_IPAddressOrRange_insert ( st , val , i ) SKM_sk_insert ( IPAddressOrRange , ( st ) , ( val ) , ( i ) ) # */

/* sk_IPAddressOrRange_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( IPAddressOrRange , ( st ) , ( cmp ) ) # */

/* sk_IPAddressOrRange_dup ( st ) SKM_sk_dup ( IPAddressOrRange , st ) # */

/* sk_IPAddressOrRange_pop_free ( st , free_func ) SKM_sk_pop_free ( IPAddressOrRange , ( st ) , ( free_func ) ) # */

/* sk_IPAddressOrRange_shift ( st ) SKM_sk_shift ( IPAddressOrRange , ( st ) ) # */

/* sk_IPAddressOrRange_pop ( st ) SKM_sk_pop ( IPAddressOrRange , ( st ) ) # */

/* sk_IPAddressOrRange_sort ( st ) SKM_sk_sort ( IPAddressOrRange , ( st ) ) # */

/* sk_IPAddressOrRange_is_sorted ( st ) SKM_sk_is_sorted ( IPAddressOrRange , ( st ) ) # */

/* sk_KRB5_APREQBODY_new ( cmp ) SKM_sk_new ( KRB5_APREQBODY , ( cmp ) ) # */

/* sk_KRB5_APREQBODY_new_null ( ) SKM_sk_new_null ( KRB5_APREQBODY ) # */

/* sk_KRB5_APREQBODY_free ( st ) SKM_sk_free ( KRB5_APREQBODY , ( st ) ) # */

/* sk_KRB5_APREQBODY_num ( st ) SKM_sk_num ( KRB5_APREQBODY , ( st ) ) # */

/* sk_KRB5_APREQBODY_value ( st , i ) SKM_sk_value ( KRB5_APREQBODY , ( st ) , ( i ) ) # */

/* sk_KRB5_APREQBODY_set ( st , i , val ) SKM_sk_set ( KRB5_APREQBODY , ( st ) , ( i ) , ( val ) ) # */

/* sk_KRB5_APREQBODY_zero ( st ) SKM_sk_zero ( KRB5_APREQBODY , ( st ) ) # */

/* sk_KRB5_APREQBODY_push ( st , val ) SKM_sk_push ( KRB5_APREQBODY , ( st ) , ( val ) ) # */

/* sk_KRB5_APREQBODY_unshift ( st , val ) SKM_sk_unshift ( KRB5_APREQBODY , ( st ) , ( val ) ) # */

/* sk_KRB5_APREQBODY_find ( st , val ) SKM_sk_find ( KRB5_APREQBODY , ( st ) , ( val ) ) # */

/* sk_KRB5_APREQBODY_find_ex ( st , val ) SKM_sk_find_ex ( KRB5_APREQBODY , ( st ) , ( val ) ) # */

/* sk_KRB5_APREQBODY_delete ( st , i ) SKM_sk_delete ( KRB5_APREQBODY , ( st ) , ( i ) ) # */

/* sk_KRB5_APREQBODY_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( KRB5_APREQBODY , ( st ) , ( ptr ) ) # */

/* sk_KRB5_APREQBODY_insert ( st , val , i ) SKM_sk_insert ( KRB5_APREQBODY , ( st ) , ( val ) , ( i ) ) # */

/* sk_KRB5_APREQBODY_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( KRB5_APREQBODY , ( st ) , ( cmp ) ) # */

/* sk_KRB5_APREQBODY_dup ( st ) SKM_sk_dup ( KRB5_APREQBODY , st ) # */

/* sk_KRB5_APREQBODY_pop_free ( st , free_func ) SKM_sk_pop_free ( KRB5_APREQBODY , ( st ) , ( free_func ) ) # */

/* sk_KRB5_APREQBODY_shift ( st ) SKM_sk_shift ( KRB5_APREQBODY , ( st ) ) # */

/* sk_KRB5_APREQBODY_pop ( st ) SKM_sk_pop ( KRB5_APREQBODY , ( st ) ) # */

/* sk_KRB5_APREQBODY_sort ( st ) SKM_sk_sort ( KRB5_APREQBODY , ( st ) ) # */

/* sk_KRB5_APREQBODY_is_sorted ( st ) SKM_sk_is_sorted ( KRB5_APREQBODY , ( st ) ) # */

/* sk_KRB5_AUTHDATA_new ( cmp ) SKM_sk_new ( KRB5_AUTHDATA , ( cmp ) ) # */

/* sk_KRB5_AUTHDATA_new_null ( ) SKM_sk_new_null ( KRB5_AUTHDATA ) # */

/* sk_KRB5_AUTHDATA_free ( st ) SKM_sk_free ( KRB5_AUTHDATA , ( st ) ) # */

/* sk_KRB5_AUTHDATA_num ( st ) SKM_sk_num ( KRB5_AUTHDATA , ( st ) ) # */

/* sk_KRB5_AUTHDATA_value ( st , i ) SKM_sk_value ( KRB5_AUTHDATA , ( st ) , ( i ) ) # */

/* sk_KRB5_AUTHDATA_set ( st , i , val ) SKM_sk_set ( KRB5_AUTHDATA , ( st ) , ( i ) , ( val ) ) # */

/* sk_KRB5_AUTHDATA_zero ( st ) SKM_sk_zero ( KRB5_AUTHDATA , ( st ) ) # */

/* sk_KRB5_AUTHDATA_push ( st , val ) SKM_sk_push ( KRB5_AUTHDATA , ( st ) , ( val ) ) # */

/* sk_KRB5_AUTHDATA_unshift ( st , val ) SKM_sk_unshift ( KRB5_AUTHDATA , ( st ) , ( val ) ) # */

/* sk_KRB5_AUTHDATA_find ( st , val ) SKM_sk_find ( KRB5_AUTHDATA , ( st ) , ( val ) ) # */

/* sk_KRB5_AUTHDATA_find_ex ( st , val ) SKM_sk_find_ex ( KRB5_AUTHDATA , ( st ) , ( val ) ) # */

/* sk_KRB5_AUTHDATA_delete ( st , i ) SKM_sk_delete ( KRB5_AUTHDATA , ( st ) , ( i ) ) # */

/* sk_KRB5_AUTHDATA_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( KRB5_AUTHDATA , ( st ) , ( ptr ) ) # */

/* sk_KRB5_AUTHDATA_insert ( st , val , i ) SKM_sk_insert ( KRB5_AUTHDATA , ( st ) , ( val ) , ( i ) ) # */

/* sk_KRB5_AUTHDATA_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( KRB5_AUTHDATA , ( st ) , ( cmp ) ) # */

/* sk_KRB5_AUTHDATA_dup ( st ) SKM_sk_dup ( KRB5_AUTHDATA , st ) # */

/* sk_KRB5_AUTHDATA_pop_free ( st , free_func ) SKM_sk_pop_free ( KRB5_AUTHDATA , ( st ) , ( free_func ) ) # */

/* sk_KRB5_AUTHDATA_shift ( st ) SKM_sk_shift ( KRB5_AUTHDATA , ( st ) ) # */

/* sk_KRB5_AUTHDATA_pop ( st ) SKM_sk_pop ( KRB5_AUTHDATA , ( st ) ) # */

/* sk_KRB5_AUTHDATA_sort ( st ) SKM_sk_sort ( KRB5_AUTHDATA , ( st ) ) # */

/* sk_KRB5_AUTHDATA_is_sorted ( st ) SKM_sk_is_sorted ( KRB5_AUTHDATA , ( st ) ) # */

/* sk_KRB5_AUTHENTBODY_new ( cmp ) SKM_sk_new ( KRB5_AUTHENTBODY , ( cmp ) ) # */

/* sk_KRB5_AUTHENTBODY_new_null ( ) SKM_sk_new_null ( KRB5_AUTHENTBODY ) # */

/* sk_KRB5_AUTHENTBODY_free ( st ) SKM_sk_free ( KRB5_AUTHENTBODY , ( st ) ) # */

/* sk_KRB5_AUTHENTBODY_num ( st ) SKM_sk_num ( KRB5_AUTHENTBODY , ( st ) ) # */

/* sk_KRB5_AUTHENTBODY_value ( st , i ) SKM_sk_value ( KRB5_AUTHENTBODY , ( st ) , ( i ) ) # */

/* sk_KRB5_AUTHENTBODY_set ( st , i , val ) SKM_sk_set ( KRB5_AUTHENTBODY , ( st ) , ( i ) , ( val ) ) # */

/* sk_KRB5_AUTHENTBODY_zero ( st ) SKM_sk_zero ( KRB5_AUTHENTBODY , ( st ) ) # */

/* sk_KRB5_AUTHENTBODY_push ( st , val ) SKM_sk_push ( KRB5_AUTHENTBODY , ( st ) , ( val ) ) # */

/* sk_KRB5_AUTHENTBODY_unshift ( st , val ) SKM_sk_unshift ( KRB5_AUTHENTBODY , ( st ) , ( val ) ) # */

/* sk_KRB5_AUTHENTBODY_find ( st , val ) SKM_sk_find ( KRB5_AUTHENTBODY , ( st ) , ( val ) ) # */

/* sk_KRB5_AUTHENTBODY_find_ex ( st , val ) SKM_sk_find_ex ( KRB5_AUTHENTBODY , ( st ) , ( val ) ) # */

/* sk_KRB5_AUTHENTBODY_delete ( st , i ) SKM_sk_delete ( KRB5_AUTHENTBODY , ( st ) , ( i ) ) # */

/* sk_KRB5_AUTHENTBODY_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( KRB5_AUTHENTBODY , ( st ) , ( ptr ) ) # */

/* sk_KRB5_AUTHENTBODY_insert ( st , val , i ) SKM_sk_insert ( KRB5_AUTHENTBODY , ( st ) , ( val ) , ( i ) ) # */

/* sk_KRB5_AUTHENTBODY_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( KRB5_AUTHENTBODY , ( st ) , ( cmp ) ) # */

/* sk_KRB5_AUTHENTBODY_dup ( st ) SKM_sk_dup ( KRB5_AUTHENTBODY , st ) # */

/* sk_KRB5_AUTHENTBODY_pop_free ( st , free_func ) SKM_sk_pop_free ( KRB5_AUTHENTBODY , ( st ) , ( free_func ) ) # */

/* sk_KRB5_AUTHENTBODY_shift ( st ) SKM_sk_shift ( KRB5_AUTHENTBODY , ( st ) ) # */

/* sk_KRB5_AUTHENTBODY_pop ( st ) SKM_sk_pop ( KRB5_AUTHENTBODY , ( st ) ) # */

/* sk_KRB5_AUTHENTBODY_sort ( st ) SKM_sk_sort ( KRB5_AUTHENTBODY , ( st ) ) # */

/* sk_KRB5_AUTHENTBODY_is_sorted ( st ) SKM_sk_is_sorted ( KRB5_AUTHENTBODY , ( st ) ) # */

/* sk_KRB5_CHECKSUM_new ( cmp ) SKM_sk_new ( KRB5_CHECKSUM , ( cmp ) ) # */

/* sk_KRB5_CHECKSUM_new_null ( ) SKM_sk_new_null ( KRB5_CHECKSUM ) # */

/* sk_KRB5_CHECKSUM_free ( st ) SKM_sk_free ( KRB5_CHECKSUM , ( st ) ) # */

/* sk_KRB5_CHECKSUM_num ( st ) SKM_sk_num ( KRB5_CHECKSUM , ( st ) ) # */

/* sk_KRB5_CHECKSUM_value ( st , i ) SKM_sk_value ( KRB5_CHECKSUM , ( st ) , ( i ) ) # */

/* sk_KRB5_CHECKSUM_set ( st , i , val ) SKM_sk_set ( KRB5_CHECKSUM , ( st ) , ( i ) , ( val ) ) # */

/* sk_KRB5_CHECKSUM_zero ( st ) SKM_sk_zero ( KRB5_CHECKSUM , ( st ) ) # */

/* sk_KRB5_CHECKSUM_push ( st , val ) SKM_sk_push ( KRB5_CHECKSUM , ( st ) , ( val ) ) # */

/* sk_KRB5_CHECKSUM_unshift ( st , val ) SKM_sk_unshift ( KRB5_CHECKSUM , ( st ) , ( val ) ) # */

/* sk_KRB5_CHECKSUM_find ( st , val ) SKM_sk_find ( KRB5_CHECKSUM , ( st ) , ( val ) ) # */

/* sk_KRB5_CHECKSUM_find_ex ( st , val ) SKM_sk_find_ex ( KRB5_CHECKSUM , ( st ) , ( val ) ) # */

/* sk_KRB5_CHECKSUM_delete ( st , i ) SKM_sk_delete ( KRB5_CHECKSUM , ( st ) , ( i ) ) # */

/* sk_KRB5_CHECKSUM_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( KRB5_CHECKSUM , ( st ) , ( ptr ) ) # */

/* sk_KRB5_CHECKSUM_insert ( st , val , i ) SKM_sk_insert ( KRB5_CHECKSUM , ( st ) , ( val ) , ( i ) ) # */

/* sk_KRB5_CHECKSUM_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( KRB5_CHECKSUM , ( st ) , ( cmp ) ) # */

/* sk_KRB5_CHECKSUM_dup ( st ) SKM_sk_dup ( KRB5_CHECKSUM , st ) # */

/* sk_KRB5_CHECKSUM_pop_free ( st , free_func ) SKM_sk_pop_free ( KRB5_CHECKSUM , ( st ) , ( free_func ) ) # */

/* sk_KRB5_CHECKSUM_shift ( st ) SKM_sk_shift ( KRB5_CHECKSUM , ( st ) ) # */

/* sk_KRB5_CHECKSUM_pop ( st ) SKM_sk_pop ( KRB5_CHECKSUM , ( st ) ) # */

/* sk_KRB5_CHECKSUM_sort ( st ) SKM_sk_sort ( KRB5_CHECKSUM , ( st ) ) # */

/* sk_KRB5_CHECKSUM_is_sorted ( st ) SKM_sk_is_sorted ( KRB5_CHECKSUM , ( st ) ) # */

/* sk_KRB5_ENCDATA_new ( cmp ) SKM_sk_new ( KRB5_ENCDATA , ( cmp ) ) # */

/* sk_KRB5_ENCDATA_new_null ( ) SKM_sk_new_null ( KRB5_ENCDATA ) # */

/* sk_KRB5_ENCDATA_free ( st ) SKM_sk_free ( KRB5_ENCDATA , ( st ) ) # */

/* sk_KRB5_ENCDATA_num ( st ) SKM_sk_num ( KRB5_ENCDATA , ( st ) ) # */

/* sk_KRB5_ENCDATA_value ( st , i ) SKM_sk_value ( KRB5_ENCDATA , ( st ) , ( i ) ) # */

/* sk_KRB5_ENCDATA_set ( st , i , val ) SKM_sk_set ( KRB5_ENCDATA , ( st ) , ( i ) , ( val ) ) # */

/* sk_KRB5_ENCDATA_zero ( st ) SKM_sk_zero ( KRB5_ENCDATA , ( st ) ) # */

/* sk_KRB5_ENCDATA_push ( st , val ) SKM_sk_push ( KRB5_ENCDATA , ( st ) , ( val ) ) # */

/* sk_KRB5_ENCDATA_unshift ( st , val ) SKM_sk_unshift ( KRB5_ENCDATA , ( st ) , ( val ) ) # */

/* sk_KRB5_ENCDATA_find ( st , val ) SKM_sk_find ( KRB5_ENCDATA , ( st ) , ( val ) ) # */

/* sk_KRB5_ENCDATA_find_ex ( st , val ) SKM_sk_find_ex ( KRB5_ENCDATA , ( st ) , ( val ) ) # */

/* sk_KRB5_ENCDATA_delete ( st , i ) SKM_sk_delete ( KRB5_ENCDATA , ( st ) , ( i ) ) # */

/* sk_KRB5_ENCDATA_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( KRB5_ENCDATA , ( st ) , ( ptr ) ) # */

/* sk_KRB5_ENCDATA_insert ( st , val , i ) SKM_sk_insert ( KRB5_ENCDATA , ( st ) , ( val ) , ( i ) ) # */

/* sk_KRB5_ENCDATA_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( KRB5_ENCDATA , ( st ) , ( cmp ) ) # */

/* sk_KRB5_ENCDATA_dup ( st ) SKM_sk_dup ( KRB5_ENCDATA , st ) # */

/* sk_KRB5_ENCDATA_pop_free ( st , free_func ) SKM_sk_pop_free ( KRB5_ENCDATA , ( st ) , ( free_func ) ) # */

/* sk_KRB5_ENCDATA_shift ( st ) SKM_sk_shift ( KRB5_ENCDATA , ( st ) ) # */

/* sk_KRB5_ENCDATA_pop ( st ) SKM_sk_pop ( KRB5_ENCDATA , ( st ) ) # */

/* sk_KRB5_ENCDATA_sort ( st ) SKM_sk_sort ( KRB5_ENCDATA , ( st ) ) # */

/* sk_KRB5_ENCDATA_is_sorted ( st ) SKM_sk_is_sorted ( KRB5_ENCDATA , ( st ) ) # */

/* sk_KRB5_ENCKEY_new ( cmp ) SKM_sk_new ( KRB5_ENCKEY , ( cmp ) ) # */

/* sk_KRB5_ENCKEY_new_null ( ) SKM_sk_new_null ( KRB5_ENCKEY ) # */

/* sk_KRB5_ENCKEY_free ( st ) SKM_sk_free ( KRB5_ENCKEY , ( st ) ) # */

/* sk_KRB5_ENCKEY_num ( st ) SKM_sk_num ( KRB5_ENCKEY , ( st ) ) # */

/* sk_KRB5_ENCKEY_value ( st , i ) SKM_sk_value ( KRB5_ENCKEY , ( st ) , ( i ) ) # */

/* sk_KRB5_ENCKEY_set ( st , i , val ) SKM_sk_set ( KRB5_ENCKEY , ( st ) , ( i ) , ( val ) ) # */

/* sk_KRB5_ENCKEY_zero ( st ) SKM_sk_zero ( KRB5_ENCKEY , ( st ) ) # */

/* sk_KRB5_ENCKEY_push ( st , val ) SKM_sk_push ( KRB5_ENCKEY , ( st ) , ( val ) ) # */

/* sk_KRB5_ENCKEY_unshift ( st , val ) SKM_sk_unshift ( KRB5_ENCKEY , ( st ) , ( val ) ) # */

/* sk_KRB5_ENCKEY_find ( st , val ) SKM_sk_find ( KRB5_ENCKEY , ( st ) , ( val ) ) # */

/* sk_KRB5_ENCKEY_find_ex ( st , val ) SKM_sk_find_ex ( KRB5_ENCKEY , ( st ) , ( val ) ) # */

/* sk_KRB5_ENCKEY_delete ( st , i ) SKM_sk_delete ( KRB5_ENCKEY , ( st ) , ( i ) ) # */

/* sk_KRB5_ENCKEY_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( KRB5_ENCKEY , ( st ) , ( ptr ) ) # */

/* sk_KRB5_ENCKEY_insert ( st , val , i ) SKM_sk_insert ( KRB5_ENCKEY , ( st ) , ( val ) , ( i ) ) # */

/* sk_KRB5_ENCKEY_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( KRB5_ENCKEY , ( st ) , ( cmp ) ) # */

/* sk_KRB5_ENCKEY_dup ( st ) SKM_sk_dup ( KRB5_ENCKEY , st ) # */

/* sk_KRB5_ENCKEY_pop_free ( st , free_func ) SKM_sk_pop_free ( KRB5_ENCKEY , ( st ) , ( free_func ) ) # */

/* sk_KRB5_ENCKEY_shift ( st ) SKM_sk_shift ( KRB5_ENCKEY , ( st ) ) # */

/* sk_KRB5_ENCKEY_pop ( st ) SKM_sk_pop ( KRB5_ENCKEY , ( st ) ) # */

/* sk_KRB5_ENCKEY_sort ( st ) SKM_sk_sort ( KRB5_ENCKEY , ( st ) ) # */

/* sk_KRB5_ENCKEY_is_sorted ( st ) SKM_sk_is_sorted ( KRB5_ENCKEY , ( st ) ) # */

/* sk_KRB5_PRINCNAME_new ( cmp ) SKM_sk_new ( KRB5_PRINCNAME , ( cmp ) ) # */

/* sk_KRB5_PRINCNAME_new_null ( ) SKM_sk_new_null ( KRB5_PRINCNAME ) # */

/* sk_KRB5_PRINCNAME_free ( st ) SKM_sk_free ( KRB5_PRINCNAME , ( st ) ) # */

/* sk_KRB5_PRINCNAME_num ( st ) SKM_sk_num ( KRB5_PRINCNAME , ( st ) ) # */

/* sk_KRB5_PRINCNAME_value ( st , i ) SKM_sk_value ( KRB5_PRINCNAME , ( st ) , ( i ) ) # */

/* sk_KRB5_PRINCNAME_set ( st , i , val ) SKM_sk_set ( KRB5_PRINCNAME , ( st ) , ( i ) , ( val ) ) # */

/* sk_KRB5_PRINCNAME_zero ( st ) SKM_sk_zero ( KRB5_PRINCNAME , ( st ) ) # */

/* sk_KRB5_PRINCNAME_push ( st , val ) SKM_sk_push ( KRB5_PRINCNAME , ( st ) , ( val ) ) # */

/* sk_KRB5_PRINCNAME_unshift ( st , val ) SKM_sk_unshift ( KRB5_PRINCNAME , ( st ) , ( val ) ) # */

/* sk_KRB5_PRINCNAME_find ( st , val ) SKM_sk_find ( KRB5_PRINCNAME , ( st ) , ( val ) ) # */

/* sk_KRB5_PRINCNAME_find_ex ( st , val ) SKM_sk_find_ex ( KRB5_PRINCNAME , ( st ) , ( val ) ) # */

/* sk_KRB5_PRINCNAME_delete ( st , i ) SKM_sk_delete ( KRB5_PRINCNAME , ( st ) , ( i ) ) # */

/* sk_KRB5_PRINCNAME_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( KRB5_PRINCNAME , ( st ) , ( ptr ) ) # */

/* sk_KRB5_PRINCNAME_insert ( st , val , i ) SKM_sk_insert ( KRB5_PRINCNAME , ( st ) , ( val ) , ( i ) ) # */

/* sk_KRB5_PRINCNAME_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( KRB5_PRINCNAME , ( st ) , ( cmp ) ) # */

/* sk_KRB5_PRINCNAME_dup ( st ) SKM_sk_dup ( KRB5_PRINCNAME , st ) # */

/* sk_KRB5_PRINCNAME_pop_free ( st , free_func ) SKM_sk_pop_free ( KRB5_PRINCNAME , ( st ) , ( free_func ) ) # */

/* sk_KRB5_PRINCNAME_shift ( st ) SKM_sk_shift ( KRB5_PRINCNAME , ( st ) ) # */

/* sk_KRB5_PRINCNAME_pop ( st ) SKM_sk_pop ( KRB5_PRINCNAME , ( st ) ) # */

/* sk_KRB5_PRINCNAME_sort ( st ) SKM_sk_sort ( KRB5_PRINCNAME , ( st ) ) # */

/* sk_KRB5_PRINCNAME_is_sorted ( st ) SKM_sk_is_sorted ( KRB5_PRINCNAME , ( st ) ) # */

/* sk_KRB5_TKTBODY_new ( cmp ) SKM_sk_new ( KRB5_TKTBODY , ( cmp ) ) # */

/* sk_KRB5_TKTBODY_new_null ( ) SKM_sk_new_null ( KRB5_TKTBODY ) # */

/* sk_KRB5_TKTBODY_free ( st ) SKM_sk_free ( KRB5_TKTBODY , ( st ) ) # */

/* sk_KRB5_TKTBODY_num ( st ) SKM_sk_num ( KRB5_TKTBODY , ( st ) ) # */

/* sk_KRB5_TKTBODY_value ( st , i ) SKM_sk_value ( KRB5_TKTBODY , ( st ) , ( i ) ) # */

/* sk_KRB5_TKTBODY_set ( st , i , val ) SKM_sk_set ( KRB5_TKTBODY , ( st ) , ( i ) , ( val ) ) # */

/* sk_KRB5_TKTBODY_zero ( st ) SKM_sk_zero ( KRB5_TKTBODY , ( st ) ) # */

/* sk_KRB5_TKTBODY_push ( st , val ) SKM_sk_push ( KRB5_TKTBODY , ( st ) , ( val ) ) # */

/* sk_KRB5_TKTBODY_unshift ( st , val ) SKM_sk_unshift ( KRB5_TKTBODY , ( st ) , ( val ) ) # */

/* sk_KRB5_TKTBODY_find ( st , val ) SKM_sk_find ( KRB5_TKTBODY , ( st ) , ( val ) ) # */

/* sk_KRB5_TKTBODY_find_ex ( st , val ) SKM_sk_find_ex ( KRB5_TKTBODY , ( st ) , ( val ) ) # */

/* sk_KRB5_TKTBODY_delete ( st , i ) SKM_sk_delete ( KRB5_TKTBODY , ( st ) , ( i ) ) # */

/* sk_KRB5_TKTBODY_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( KRB5_TKTBODY , ( st ) , ( ptr ) ) # */

/* sk_KRB5_TKTBODY_insert ( st , val , i ) SKM_sk_insert ( KRB5_TKTBODY , ( st ) , ( val ) , ( i ) ) # */

/* sk_KRB5_TKTBODY_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( KRB5_TKTBODY , ( st ) , ( cmp ) ) # */

/* sk_KRB5_TKTBODY_dup ( st ) SKM_sk_dup ( KRB5_TKTBODY , st ) # */

/* sk_KRB5_TKTBODY_pop_free ( st , free_func ) SKM_sk_pop_free ( KRB5_TKTBODY , ( st ) , ( free_func ) ) # */

/* sk_KRB5_TKTBODY_shift ( st ) SKM_sk_shift ( KRB5_TKTBODY , ( st ) ) # */

/* sk_KRB5_TKTBODY_pop ( st ) SKM_sk_pop ( KRB5_TKTBODY , ( st ) ) # */

/* sk_KRB5_TKTBODY_sort ( st ) SKM_sk_sort ( KRB5_TKTBODY , ( st ) ) # */

/* sk_KRB5_TKTBODY_is_sorted ( st ) SKM_sk_is_sorted ( KRB5_TKTBODY , ( st ) ) # */

/* sk_MEM_OBJECT_DATA_new ( cmp ) SKM_sk_new ( MEM_OBJECT_DATA , ( cmp ) ) # */

/* sk_MEM_OBJECT_DATA_new_null ( ) SKM_sk_new_null ( MEM_OBJECT_DATA ) # */

/* sk_MEM_OBJECT_DATA_free ( st ) SKM_sk_free ( MEM_OBJECT_DATA , ( st ) ) # */

/* sk_MEM_OBJECT_DATA_num ( st ) SKM_sk_num ( MEM_OBJECT_DATA , ( st ) ) # */

/* sk_MEM_OBJECT_DATA_value ( st , i ) SKM_sk_value ( MEM_OBJECT_DATA , ( st ) , ( i ) ) # */

/* sk_MEM_OBJECT_DATA_set ( st , i , val ) SKM_sk_set ( MEM_OBJECT_DATA , ( st ) , ( i ) , ( val ) ) # */

/* sk_MEM_OBJECT_DATA_zero ( st ) SKM_sk_zero ( MEM_OBJECT_DATA , ( st ) ) # */

/* sk_MEM_OBJECT_DATA_push ( st , val ) SKM_sk_push ( MEM_OBJECT_DATA , ( st ) , ( val ) ) # */

/* sk_MEM_OBJECT_DATA_unshift ( st , val ) SKM_sk_unshift ( MEM_OBJECT_DATA , ( st ) , ( val ) ) # */

/* sk_MEM_OBJECT_DATA_find ( st , val ) SKM_sk_find ( MEM_OBJECT_DATA , ( st ) , ( val ) ) # */

/* sk_MEM_OBJECT_DATA_find_ex ( st , val ) SKM_sk_find_ex ( MEM_OBJECT_DATA , ( st ) , ( val ) ) # */

/* sk_MEM_OBJECT_DATA_delete ( st , i ) SKM_sk_delete ( MEM_OBJECT_DATA , ( st ) , ( i ) ) # */

/* sk_MEM_OBJECT_DATA_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( MEM_OBJECT_DATA , ( st ) , ( ptr ) ) # */

/* sk_MEM_OBJECT_DATA_insert ( st , val , i ) SKM_sk_insert ( MEM_OBJECT_DATA , ( st ) , ( val ) , ( i ) ) # */

/* sk_MEM_OBJECT_DATA_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( MEM_OBJECT_DATA , ( st ) , ( cmp ) ) # */

/* sk_MEM_OBJECT_DATA_dup ( st ) SKM_sk_dup ( MEM_OBJECT_DATA , st ) # */

/* sk_MEM_OBJECT_DATA_pop_free ( st , free_func ) SKM_sk_pop_free ( MEM_OBJECT_DATA , ( st ) , ( free_func ) ) # */

/* sk_MEM_OBJECT_DATA_shift ( st ) SKM_sk_shift ( MEM_OBJECT_DATA , ( st ) ) # */

/* sk_MEM_OBJECT_DATA_pop ( st ) SKM_sk_pop ( MEM_OBJECT_DATA , ( st ) ) # */

/* sk_MEM_OBJECT_DATA_sort ( st ) SKM_sk_sort ( MEM_OBJECT_DATA , ( st ) ) # */

/* sk_MEM_OBJECT_DATA_is_sorted ( st ) SKM_sk_is_sorted ( MEM_OBJECT_DATA , ( st ) ) # */

/* sk_MIME_HEADER_new ( cmp ) SKM_sk_new ( MIME_HEADER , ( cmp ) ) # */

/* sk_MIME_HEADER_new_null ( ) SKM_sk_new_null ( MIME_HEADER ) # */

/* sk_MIME_HEADER_free ( st ) SKM_sk_free ( MIME_HEADER , ( st ) ) # */

/* sk_MIME_HEADER_num ( st ) SKM_sk_num ( MIME_HEADER , ( st ) ) # */

/* sk_MIME_HEADER_value ( st , i ) SKM_sk_value ( MIME_HEADER , ( st ) , ( i ) ) # */

/* sk_MIME_HEADER_set ( st , i , val ) SKM_sk_set ( MIME_HEADER , ( st ) , ( i ) , ( val ) ) # */

/* sk_MIME_HEADER_zero ( st ) SKM_sk_zero ( MIME_HEADER , ( st ) ) # */

/* sk_MIME_HEADER_push ( st , val ) SKM_sk_push ( MIME_HEADER , ( st ) , ( val ) ) # */

/* sk_MIME_HEADER_unshift ( st , val ) SKM_sk_unshift ( MIME_HEADER , ( st ) , ( val ) ) # */

/* sk_MIME_HEADER_find ( st , val ) SKM_sk_find ( MIME_HEADER , ( st ) , ( val ) ) # */

/* sk_MIME_HEADER_find_ex ( st , val ) SKM_sk_find_ex ( MIME_HEADER , ( st ) , ( val ) ) # */

/* sk_MIME_HEADER_delete ( st , i ) SKM_sk_delete ( MIME_HEADER , ( st ) , ( i ) ) # */

/* sk_MIME_HEADER_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( MIME_HEADER , ( st ) , ( ptr ) ) # */

/* sk_MIME_HEADER_insert ( st , val , i ) SKM_sk_insert ( MIME_HEADER , ( st ) , ( val ) , ( i ) ) # */

/* sk_MIME_HEADER_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( MIME_HEADER , ( st ) , ( cmp ) ) # */

/* sk_MIME_HEADER_dup ( st ) SKM_sk_dup ( MIME_HEADER , st ) # */

/* sk_MIME_HEADER_pop_free ( st , free_func ) SKM_sk_pop_free ( MIME_HEADER , ( st ) , ( free_func ) ) # */

/* sk_MIME_HEADER_shift ( st ) SKM_sk_shift ( MIME_HEADER , ( st ) ) # */

/* sk_MIME_HEADER_pop ( st ) SKM_sk_pop ( MIME_HEADER , ( st ) ) # */

/* sk_MIME_HEADER_sort ( st ) SKM_sk_sort ( MIME_HEADER , ( st ) ) # */

/* sk_MIME_HEADER_is_sorted ( st ) SKM_sk_is_sorted ( MIME_HEADER , ( st ) ) # */

/* sk_MIME_PARAM_new ( cmp ) SKM_sk_new ( MIME_PARAM , ( cmp ) ) # */

/* sk_MIME_PARAM_new_null ( ) SKM_sk_new_null ( MIME_PARAM ) # */

/* sk_MIME_PARAM_free ( st ) SKM_sk_free ( MIME_PARAM , ( st ) ) # */

/* sk_MIME_PARAM_num ( st ) SKM_sk_num ( MIME_PARAM , ( st ) ) # */

/* sk_MIME_PARAM_value ( st , i ) SKM_sk_value ( MIME_PARAM , ( st ) , ( i ) ) # */

/* sk_MIME_PARAM_set ( st , i , val ) SKM_sk_set ( MIME_PARAM , ( st ) , ( i ) , ( val ) ) # */

/* sk_MIME_PARAM_zero ( st ) SKM_sk_zero ( MIME_PARAM , ( st ) ) # */

/* sk_MIME_PARAM_push ( st , val ) SKM_sk_push ( MIME_PARAM , ( st ) , ( val ) ) # */

/* sk_MIME_PARAM_unshift ( st , val ) SKM_sk_unshift ( MIME_PARAM , ( st ) , ( val ) ) # */

/* sk_MIME_PARAM_find ( st , val ) SKM_sk_find ( MIME_PARAM , ( st ) , ( val ) ) # */

/* sk_MIME_PARAM_find_ex ( st , val ) SKM_sk_find_ex ( MIME_PARAM , ( st ) , ( val ) ) # */

/* sk_MIME_PARAM_delete ( st , i ) SKM_sk_delete ( MIME_PARAM , ( st ) , ( i ) ) # */

/* sk_MIME_PARAM_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( MIME_PARAM , ( st ) , ( ptr ) ) # */

/* sk_MIME_PARAM_insert ( st , val , i ) SKM_sk_insert ( MIME_PARAM , ( st ) , ( val ) , ( i ) ) # */

/* sk_MIME_PARAM_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( MIME_PARAM , ( st ) , ( cmp ) ) # */

/* sk_MIME_PARAM_dup ( st ) SKM_sk_dup ( MIME_PARAM , st ) # */

/* sk_MIME_PARAM_pop_free ( st , free_func ) SKM_sk_pop_free ( MIME_PARAM , ( st ) , ( free_func ) ) # */

/* sk_MIME_PARAM_shift ( st ) SKM_sk_shift ( MIME_PARAM , ( st ) ) # */

/* sk_MIME_PARAM_pop ( st ) SKM_sk_pop ( MIME_PARAM , ( st ) ) # */

/* sk_MIME_PARAM_sort ( st ) SKM_sk_sort ( MIME_PARAM , ( st ) ) # */

/* sk_MIME_PARAM_is_sorted ( st ) SKM_sk_is_sorted ( MIME_PARAM , ( st ) ) # */

/* sk_NAME_FUNCS_new ( cmp ) SKM_sk_new ( NAME_FUNCS , ( cmp ) ) # */

/* sk_NAME_FUNCS_new_null ( ) SKM_sk_new_null ( NAME_FUNCS ) # */

/* sk_NAME_FUNCS_free ( st ) SKM_sk_free ( NAME_FUNCS , ( st ) ) # */

/* sk_NAME_FUNCS_num ( st ) SKM_sk_num ( NAME_FUNCS , ( st ) ) # */

/* sk_NAME_FUNCS_value ( st , i ) SKM_sk_value ( NAME_FUNCS , ( st ) , ( i ) ) # */

/* sk_NAME_FUNCS_set ( st , i , val ) SKM_sk_set ( NAME_FUNCS , ( st ) , ( i ) , ( val ) ) # */

/* sk_NAME_FUNCS_zero ( st ) SKM_sk_zero ( NAME_FUNCS , ( st ) ) # */

/* sk_NAME_FUNCS_push ( st , val ) SKM_sk_push ( NAME_FUNCS , ( st ) , ( val ) ) # */

/* sk_NAME_FUNCS_unshift ( st , val ) SKM_sk_unshift ( NAME_FUNCS , ( st ) , ( val ) ) # */

/* sk_NAME_FUNCS_find ( st , val ) SKM_sk_find ( NAME_FUNCS , ( st ) , ( val ) ) # */

/* sk_NAME_FUNCS_find_ex ( st , val ) SKM_sk_find_ex ( NAME_FUNCS , ( st ) , ( val ) ) # */

/* sk_NAME_FUNCS_delete ( st , i ) SKM_sk_delete ( NAME_FUNCS , ( st ) , ( i ) ) # */

/* sk_NAME_FUNCS_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( NAME_FUNCS , ( st ) , ( ptr ) ) # */

/* sk_NAME_FUNCS_insert ( st , val , i ) SKM_sk_insert ( NAME_FUNCS , ( st ) , ( val ) , ( i ) ) # */

/* sk_NAME_FUNCS_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( NAME_FUNCS , ( st ) , ( cmp ) ) # */

/* sk_NAME_FUNCS_dup ( st ) SKM_sk_dup ( NAME_FUNCS , st ) # */

/* sk_NAME_FUNCS_pop_free ( st , free_func ) SKM_sk_pop_free ( NAME_FUNCS , ( st ) , ( free_func ) ) # */

/* sk_NAME_FUNCS_shift ( st ) SKM_sk_shift ( NAME_FUNCS , ( st ) ) # */

/* sk_NAME_FUNCS_pop ( st ) SKM_sk_pop ( NAME_FUNCS , ( st ) ) # */

/* sk_NAME_FUNCS_sort ( st ) SKM_sk_sort ( NAME_FUNCS , ( st ) ) # */

/* sk_NAME_FUNCS_is_sorted ( st ) SKM_sk_is_sorted ( NAME_FUNCS , ( st ) ) # */

/* sk_OCSP_CERTID_new ( cmp ) SKM_sk_new ( OCSP_CERTID , ( cmp ) ) # */

/* sk_OCSP_CERTID_new_null ( ) SKM_sk_new_null ( OCSP_CERTID ) # */

/* sk_OCSP_CERTID_free ( st ) SKM_sk_free ( OCSP_CERTID , ( st ) ) # */

/* sk_OCSP_CERTID_num ( st ) SKM_sk_num ( OCSP_CERTID , ( st ) ) # */

/* sk_OCSP_CERTID_value ( st , i ) SKM_sk_value ( OCSP_CERTID , ( st ) , ( i ) ) # */

/* sk_OCSP_CERTID_set ( st , i , val ) SKM_sk_set ( OCSP_CERTID , ( st ) , ( i ) , ( val ) ) # */

/* sk_OCSP_CERTID_zero ( st ) SKM_sk_zero ( OCSP_CERTID , ( st ) ) # */

/* sk_OCSP_CERTID_push ( st , val ) SKM_sk_push ( OCSP_CERTID , ( st ) , ( val ) ) # */

/* sk_OCSP_CERTID_unshift ( st , val ) SKM_sk_unshift ( OCSP_CERTID , ( st ) , ( val ) ) # */

/* sk_OCSP_CERTID_find ( st , val ) SKM_sk_find ( OCSP_CERTID , ( st ) , ( val ) ) # */

/* sk_OCSP_CERTID_find_ex ( st , val ) SKM_sk_find_ex ( OCSP_CERTID , ( st ) , ( val ) ) # */

/* sk_OCSP_CERTID_delete ( st , i ) SKM_sk_delete ( OCSP_CERTID , ( st ) , ( i ) ) # */

/* sk_OCSP_CERTID_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( OCSP_CERTID , ( st ) , ( ptr ) ) # */

/* sk_OCSP_CERTID_insert ( st , val , i ) SKM_sk_insert ( OCSP_CERTID , ( st ) , ( val ) , ( i ) ) # */

/* sk_OCSP_CERTID_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( OCSP_CERTID , ( st ) , ( cmp ) ) # */

/* sk_OCSP_CERTID_dup ( st ) SKM_sk_dup ( OCSP_CERTID , st ) # */

/* sk_OCSP_CERTID_pop_free ( st , free_func ) SKM_sk_pop_free ( OCSP_CERTID , ( st ) , ( free_func ) ) # */

/* sk_OCSP_CERTID_shift ( st ) SKM_sk_shift ( OCSP_CERTID , ( st ) ) # */

/* sk_OCSP_CERTID_pop ( st ) SKM_sk_pop ( OCSP_CERTID , ( st ) ) # */

/* sk_OCSP_CERTID_sort ( st ) SKM_sk_sort ( OCSP_CERTID , ( st ) ) # */

/* sk_OCSP_CERTID_is_sorted ( st ) SKM_sk_is_sorted ( OCSP_CERTID , ( st ) ) # */

/* sk_OCSP_ONEREQ_new ( cmp ) SKM_sk_new ( OCSP_ONEREQ , ( cmp ) ) # */

/* sk_OCSP_ONEREQ_new_null ( ) SKM_sk_new_null ( OCSP_ONEREQ ) # */

/* sk_OCSP_ONEREQ_free ( st ) SKM_sk_free ( OCSP_ONEREQ , ( st ) ) # */

/* sk_OCSP_ONEREQ_num ( st ) SKM_sk_num ( OCSP_ONEREQ , ( st ) ) # */

/* sk_OCSP_ONEREQ_value ( st , i ) SKM_sk_value ( OCSP_ONEREQ , ( st ) , ( i ) ) # */

/* sk_OCSP_ONEREQ_set ( st , i , val ) SKM_sk_set ( OCSP_ONEREQ , ( st ) , ( i ) , ( val ) ) # */

/* sk_OCSP_ONEREQ_zero ( st ) SKM_sk_zero ( OCSP_ONEREQ , ( st ) ) # */

/* sk_OCSP_ONEREQ_push ( st , val ) SKM_sk_push ( OCSP_ONEREQ , ( st ) , ( val ) ) # */

/* sk_OCSP_ONEREQ_unshift ( st , val ) SKM_sk_unshift ( OCSP_ONEREQ , ( st ) , ( val ) ) # */

/* sk_OCSP_ONEREQ_find ( st , val ) SKM_sk_find ( OCSP_ONEREQ , ( st ) , ( val ) ) # */

/* sk_OCSP_ONEREQ_find_ex ( st , val ) SKM_sk_find_ex ( OCSP_ONEREQ , ( st ) , ( val ) ) # */

/* sk_OCSP_ONEREQ_delete ( st , i ) SKM_sk_delete ( OCSP_ONEREQ , ( st ) , ( i ) ) # */

/* sk_OCSP_ONEREQ_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( OCSP_ONEREQ , ( st ) , ( ptr ) ) # */

/* sk_OCSP_ONEREQ_insert ( st , val , i ) SKM_sk_insert ( OCSP_ONEREQ , ( st ) , ( val ) , ( i ) ) # */

/* sk_OCSP_ONEREQ_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( OCSP_ONEREQ , ( st ) , ( cmp ) ) # */

/* sk_OCSP_ONEREQ_dup ( st ) SKM_sk_dup ( OCSP_ONEREQ , st ) # */

/* sk_OCSP_ONEREQ_pop_free ( st , free_func ) SKM_sk_pop_free ( OCSP_ONEREQ , ( st ) , ( free_func ) ) # */

/* sk_OCSP_ONEREQ_shift ( st ) SKM_sk_shift ( OCSP_ONEREQ , ( st ) ) # */

/* sk_OCSP_ONEREQ_pop ( st ) SKM_sk_pop ( OCSP_ONEREQ , ( st ) ) # */

/* sk_OCSP_ONEREQ_sort ( st ) SKM_sk_sort ( OCSP_ONEREQ , ( st ) ) # */

/* sk_OCSP_ONEREQ_is_sorted ( st ) SKM_sk_is_sorted ( OCSP_ONEREQ , ( st ) ) # */

/* sk_OCSP_RESPID_new ( cmp ) SKM_sk_new ( OCSP_RESPID , ( cmp ) ) # */

/* sk_OCSP_RESPID_new_null ( ) SKM_sk_new_null ( OCSP_RESPID ) # */

/* sk_OCSP_RESPID_free ( st ) SKM_sk_free ( OCSP_RESPID , ( st ) ) # */

/* sk_OCSP_RESPID_num ( st ) SKM_sk_num ( OCSP_RESPID , ( st ) ) # */

/* sk_OCSP_RESPID_value ( st , i ) SKM_sk_value ( OCSP_RESPID , ( st ) , ( i ) ) # */

/* sk_OCSP_RESPID_set ( st , i , val ) SKM_sk_set ( OCSP_RESPID , ( st ) , ( i ) , ( val ) ) # */

/* sk_OCSP_RESPID_zero ( st ) SKM_sk_zero ( OCSP_RESPID , ( st ) ) # */

/* sk_OCSP_RESPID_push ( st , val ) SKM_sk_push ( OCSP_RESPID , ( st ) , ( val ) ) # */

/* sk_OCSP_RESPID_unshift ( st , val ) SKM_sk_unshift ( OCSP_RESPID , ( st ) , ( val ) ) # */

/* sk_OCSP_RESPID_find ( st , val ) SKM_sk_find ( OCSP_RESPID , ( st ) , ( val ) ) # */

/* sk_OCSP_RESPID_find_ex ( st , val ) SKM_sk_find_ex ( OCSP_RESPID , ( st ) , ( val ) ) # */

/* sk_OCSP_RESPID_delete ( st , i ) SKM_sk_delete ( OCSP_RESPID , ( st ) , ( i ) ) # */

/* sk_OCSP_RESPID_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( OCSP_RESPID , ( st ) , ( ptr ) ) # */

/* sk_OCSP_RESPID_insert ( st , val , i ) SKM_sk_insert ( OCSP_RESPID , ( st ) , ( val ) , ( i ) ) # */

/* sk_OCSP_RESPID_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( OCSP_RESPID , ( st ) , ( cmp ) ) # */

/* sk_OCSP_RESPID_dup ( st ) SKM_sk_dup ( OCSP_RESPID , st ) # */

/* sk_OCSP_RESPID_pop_free ( st , free_func ) SKM_sk_pop_free ( OCSP_RESPID , ( st ) , ( free_func ) ) # */

/* sk_OCSP_RESPID_shift ( st ) SKM_sk_shift ( OCSP_RESPID , ( st ) ) # */

/* sk_OCSP_RESPID_pop ( st ) SKM_sk_pop ( OCSP_RESPID , ( st ) ) # */

/* sk_OCSP_RESPID_sort ( st ) SKM_sk_sort ( OCSP_RESPID , ( st ) ) # */

/* sk_OCSP_RESPID_is_sorted ( st ) SKM_sk_is_sorted ( OCSP_RESPID , ( st ) ) # */

/* sk_OCSP_SINGLERESP_new ( cmp ) SKM_sk_new ( OCSP_SINGLERESP , ( cmp ) ) # */

/* sk_OCSP_SINGLERESP_new_null ( ) SKM_sk_new_null ( OCSP_SINGLERESP ) # */

/* sk_OCSP_SINGLERESP_free ( st ) SKM_sk_free ( OCSP_SINGLERESP , ( st ) ) # */

/* sk_OCSP_SINGLERESP_num ( st ) SKM_sk_num ( OCSP_SINGLERESP , ( st ) ) # */

/* sk_OCSP_SINGLERESP_value ( st , i ) SKM_sk_value ( OCSP_SINGLERESP , ( st ) , ( i ) ) # */

/* sk_OCSP_SINGLERESP_set ( st , i , val ) SKM_sk_set ( OCSP_SINGLERESP , ( st ) , ( i ) , ( val ) ) # */

/* sk_OCSP_SINGLERESP_zero ( st ) SKM_sk_zero ( OCSP_SINGLERESP , ( st ) ) # */

/* sk_OCSP_SINGLERESP_push ( st , val ) SKM_sk_push ( OCSP_SINGLERESP , ( st ) , ( val ) ) # */

/* sk_OCSP_SINGLERESP_unshift ( st , val ) SKM_sk_unshift ( OCSP_SINGLERESP , ( st ) , ( val ) ) # */

/* sk_OCSP_SINGLERESP_find ( st , val ) SKM_sk_find ( OCSP_SINGLERESP , ( st ) , ( val ) ) # */

/* sk_OCSP_SINGLERESP_find_ex ( st , val ) SKM_sk_find_ex ( OCSP_SINGLERESP , ( st ) , ( val ) ) # */

/* sk_OCSP_SINGLERESP_delete ( st , i ) SKM_sk_delete ( OCSP_SINGLERESP , ( st ) , ( i ) ) # */

/* sk_OCSP_SINGLERESP_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( OCSP_SINGLERESP , ( st ) , ( ptr ) ) # */

/* sk_OCSP_SINGLERESP_insert ( st , val , i ) SKM_sk_insert ( OCSP_SINGLERESP , ( st ) , ( val ) , ( i ) ) # */

/* sk_OCSP_SINGLERESP_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( OCSP_SINGLERESP , ( st ) , ( cmp ) ) # */

/* sk_OCSP_SINGLERESP_dup ( st ) SKM_sk_dup ( OCSP_SINGLERESP , st ) # */

/* sk_OCSP_SINGLERESP_pop_free ( st , free_func ) SKM_sk_pop_free ( OCSP_SINGLERESP , ( st ) , ( free_func ) ) # */

/* sk_OCSP_SINGLERESP_shift ( st ) SKM_sk_shift ( OCSP_SINGLERESP , ( st ) ) # */

/* sk_OCSP_SINGLERESP_pop ( st ) SKM_sk_pop ( OCSP_SINGLERESP , ( st ) ) # */

/* sk_OCSP_SINGLERESP_sort ( st ) SKM_sk_sort ( OCSP_SINGLERESP , ( st ) ) # */

/* sk_OCSP_SINGLERESP_is_sorted ( st ) SKM_sk_is_sorted ( OCSP_SINGLERESP , ( st ) ) # */

/* sk_PKCS12_SAFEBAG_new ( cmp ) SKM_sk_new ( PKCS12_SAFEBAG , ( cmp ) ) # */

/* sk_PKCS12_SAFEBAG_new_null ( ) SKM_sk_new_null ( PKCS12_SAFEBAG ) # */

/* sk_PKCS12_SAFEBAG_free ( st ) SKM_sk_free ( PKCS12_SAFEBAG , ( st ) ) # */

/* sk_PKCS12_SAFEBAG_num ( st ) SKM_sk_num ( PKCS12_SAFEBAG , ( st ) ) # */

/* sk_PKCS12_SAFEBAG_value ( st , i ) SKM_sk_value ( PKCS12_SAFEBAG , ( st ) , ( i ) ) # */

/* sk_PKCS12_SAFEBAG_set ( st , i , val ) SKM_sk_set ( PKCS12_SAFEBAG , ( st ) , ( i ) , ( val ) ) # */

/* sk_PKCS12_SAFEBAG_zero ( st ) SKM_sk_zero ( PKCS12_SAFEBAG , ( st ) ) # */

/* sk_PKCS12_SAFEBAG_push ( st , val ) SKM_sk_push ( PKCS12_SAFEBAG , ( st ) , ( val ) ) # */

/* sk_PKCS12_SAFEBAG_unshift ( st , val ) SKM_sk_unshift ( PKCS12_SAFEBAG , ( st ) , ( val ) ) # */

/* sk_PKCS12_SAFEBAG_find ( st , val ) SKM_sk_find ( PKCS12_SAFEBAG , ( st ) , ( val ) ) # */

/* sk_PKCS12_SAFEBAG_find_ex ( st , val ) SKM_sk_find_ex ( PKCS12_SAFEBAG , ( st ) , ( val ) ) # */

/* sk_PKCS12_SAFEBAG_delete ( st , i ) SKM_sk_delete ( PKCS12_SAFEBAG , ( st ) , ( i ) ) # */

/* sk_PKCS12_SAFEBAG_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( PKCS12_SAFEBAG , ( st ) , ( ptr ) ) # */

/* sk_PKCS12_SAFEBAG_insert ( st , val , i ) SKM_sk_insert ( PKCS12_SAFEBAG , ( st ) , ( val ) , ( i ) ) # */

/* sk_PKCS12_SAFEBAG_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( PKCS12_SAFEBAG , ( st ) , ( cmp ) ) # */

/* sk_PKCS12_SAFEBAG_dup ( st ) SKM_sk_dup ( PKCS12_SAFEBAG , st ) # */

/* sk_PKCS12_SAFEBAG_pop_free ( st , free_func ) SKM_sk_pop_free ( PKCS12_SAFEBAG , ( st ) , ( free_func ) ) # */

/* sk_PKCS12_SAFEBAG_shift ( st ) SKM_sk_shift ( PKCS12_SAFEBAG , ( st ) ) # */

/* sk_PKCS12_SAFEBAG_pop ( st ) SKM_sk_pop ( PKCS12_SAFEBAG , ( st ) ) # */

/* sk_PKCS12_SAFEBAG_sort ( st ) SKM_sk_sort ( PKCS12_SAFEBAG , ( st ) ) # */

/* sk_PKCS12_SAFEBAG_is_sorted ( st ) SKM_sk_is_sorted ( PKCS12_SAFEBAG , ( st ) ) # */

/* sk_PKCS7_new ( cmp ) SKM_sk_new ( PKCS7 , ( cmp ) ) # */

/* sk_PKCS7_new_null ( ) SKM_sk_new_null ( PKCS7 ) # */

/* sk_PKCS7_free ( st ) SKM_sk_free ( PKCS7 , ( st ) ) # */

/* sk_PKCS7_num ( st ) SKM_sk_num ( PKCS7 , ( st ) ) # */

/* sk_PKCS7_value ( st , i ) SKM_sk_value ( PKCS7 , ( st ) , ( i ) ) # */

/* sk_PKCS7_set ( st , i , val ) SKM_sk_set ( PKCS7 , ( st ) , ( i ) , ( val ) ) # */

/* sk_PKCS7_zero ( st ) SKM_sk_zero ( PKCS7 , ( st ) ) # */

/* sk_PKCS7_push ( st , val ) SKM_sk_push ( PKCS7 , ( st ) , ( val ) ) # */

/* sk_PKCS7_unshift ( st , val ) SKM_sk_unshift ( PKCS7 , ( st ) , ( val ) ) # */

/* sk_PKCS7_find ( st , val ) SKM_sk_find ( PKCS7 , ( st ) , ( val ) ) # */

/* sk_PKCS7_find_ex ( st , val ) SKM_sk_find_ex ( PKCS7 , ( st ) , ( val ) ) # */

/* sk_PKCS7_delete ( st , i ) SKM_sk_delete ( PKCS7 , ( st ) , ( i ) ) # */

/* sk_PKCS7_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( PKCS7 , ( st ) , ( ptr ) ) # */

/* sk_PKCS7_insert ( st , val , i ) SKM_sk_insert ( PKCS7 , ( st ) , ( val ) , ( i ) ) # */

/* sk_PKCS7_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( PKCS7 , ( st ) , ( cmp ) ) # */

/* sk_PKCS7_dup ( st ) SKM_sk_dup ( PKCS7 , st ) # */

/* sk_PKCS7_pop_free ( st , free_func ) SKM_sk_pop_free ( PKCS7 , ( st ) , ( free_func ) ) # */

/* sk_PKCS7_shift ( st ) SKM_sk_shift ( PKCS7 , ( st ) ) # */

/* sk_PKCS7_pop ( st ) SKM_sk_pop ( PKCS7 , ( st ) ) # */

/* sk_PKCS7_sort ( st ) SKM_sk_sort ( PKCS7 , ( st ) ) # */

/* sk_PKCS7_is_sorted ( st ) SKM_sk_is_sorted ( PKCS7 , ( st ) ) # */

/* sk_PKCS7_RECIP_INFO_new ( cmp ) SKM_sk_new ( PKCS7_RECIP_INFO , ( cmp ) ) # */

/* sk_PKCS7_RECIP_INFO_new_null ( ) SKM_sk_new_null ( PKCS7_RECIP_INFO ) # */

/* sk_PKCS7_RECIP_INFO_free ( st ) SKM_sk_free ( PKCS7_RECIP_INFO , ( st ) ) # */

/* sk_PKCS7_RECIP_INFO_num ( st ) SKM_sk_num ( PKCS7_RECIP_INFO , ( st ) ) # */

/* sk_PKCS7_RECIP_INFO_value ( st , i ) SKM_sk_value ( PKCS7_RECIP_INFO , ( st ) , ( i ) ) # */

/* sk_PKCS7_RECIP_INFO_set ( st , i , val ) SKM_sk_set ( PKCS7_RECIP_INFO , ( st ) , ( i ) , ( val ) ) # */

/* sk_PKCS7_RECIP_INFO_zero ( st ) SKM_sk_zero ( PKCS7_RECIP_INFO , ( st ) ) # */

/* sk_PKCS7_RECIP_INFO_push ( st , val ) SKM_sk_push ( PKCS7_RECIP_INFO , ( st ) , ( val ) ) # */

/* sk_PKCS7_RECIP_INFO_unshift ( st , val ) SKM_sk_unshift ( PKCS7_RECIP_INFO , ( st ) , ( val ) ) # */

/* sk_PKCS7_RECIP_INFO_find ( st , val ) SKM_sk_find ( PKCS7_RECIP_INFO , ( st ) , ( val ) ) # */

/* sk_PKCS7_RECIP_INFO_find_ex ( st , val ) SKM_sk_find_ex ( PKCS7_RECIP_INFO , ( st ) , ( val ) ) # */

/* sk_PKCS7_RECIP_INFO_delete ( st , i ) SKM_sk_delete ( PKCS7_RECIP_INFO , ( st ) , ( i ) ) # */

/* sk_PKCS7_RECIP_INFO_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( PKCS7_RECIP_INFO , ( st ) , ( ptr ) ) # */

/* sk_PKCS7_RECIP_INFO_insert ( st , val , i ) SKM_sk_insert ( PKCS7_RECIP_INFO , ( st ) , ( val ) , ( i ) ) # */

/* sk_PKCS7_RECIP_INFO_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( PKCS7_RECIP_INFO , ( st ) , ( cmp ) ) # */

/* sk_PKCS7_RECIP_INFO_dup ( st ) SKM_sk_dup ( PKCS7_RECIP_INFO , st ) # */

/* sk_PKCS7_RECIP_INFO_pop_free ( st , free_func ) SKM_sk_pop_free ( PKCS7_RECIP_INFO , ( st ) , ( free_func ) ) # */

/* sk_PKCS7_RECIP_INFO_shift ( st ) SKM_sk_shift ( PKCS7_RECIP_INFO , ( st ) ) # */

/* sk_PKCS7_RECIP_INFO_pop ( st ) SKM_sk_pop ( PKCS7_RECIP_INFO , ( st ) ) # */

/* sk_PKCS7_RECIP_INFO_sort ( st ) SKM_sk_sort ( PKCS7_RECIP_INFO , ( st ) ) # */

/* sk_PKCS7_RECIP_INFO_is_sorted ( st ) SKM_sk_is_sorted ( PKCS7_RECIP_INFO , ( st ) ) # */

/* sk_PKCS7_SIGNER_INFO_new ( cmp ) SKM_sk_new ( PKCS7_SIGNER_INFO , ( cmp ) ) # */

/* sk_PKCS7_SIGNER_INFO_new_null ( ) SKM_sk_new_null ( PKCS7_SIGNER_INFO ) # */

/* sk_PKCS7_SIGNER_INFO_free ( st ) SKM_sk_free ( PKCS7_SIGNER_INFO , ( st ) ) # */

/* sk_PKCS7_SIGNER_INFO_num ( st ) SKM_sk_num ( PKCS7_SIGNER_INFO , ( st ) ) # */

/* sk_PKCS7_SIGNER_INFO_value ( st , i ) SKM_sk_value ( PKCS7_SIGNER_INFO , ( st ) , ( i ) ) # */

/* sk_PKCS7_SIGNER_INFO_set ( st , i , val ) SKM_sk_set ( PKCS7_SIGNER_INFO , ( st ) , ( i ) , ( val ) ) # */

/* sk_PKCS7_SIGNER_INFO_zero ( st ) SKM_sk_zero ( PKCS7_SIGNER_INFO , ( st ) ) # */

/* sk_PKCS7_SIGNER_INFO_push ( st , val ) SKM_sk_push ( PKCS7_SIGNER_INFO , ( st ) , ( val ) ) # */

/* sk_PKCS7_SIGNER_INFO_unshift ( st , val ) SKM_sk_unshift ( PKCS7_SIGNER_INFO , ( st ) , ( val ) ) # */

/* sk_PKCS7_SIGNER_INFO_find ( st , val ) SKM_sk_find ( PKCS7_SIGNER_INFO , ( st ) , ( val ) ) # */

/* sk_PKCS7_SIGNER_INFO_find_ex ( st , val ) SKM_sk_find_ex ( PKCS7_SIGNER_INFO , ( st ) , ( val ) ) # */

/* sk_PKCS7_SIGNER_INFO_delete ( st , i ) SKM_sk_delete ( PKCS7_SIGNER_INFO , ( st ) , ( i ) ) # */

/* sk_PKCS7_SIGNER_INFO_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( PKCS7_SIGNER_INFO , ( st ) , ( ptr ) ) # */

/* sk_PKCS7_SIGNER_INFO_insert ( st , val , i ) SKM_sk_insert ( PKCS7_SIGNER_INFO , ( st ) , ( val ) , ( i ) ) # */

/* sk_PKCS7_SIGNER_INFO_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( PKCS7_SIGNER_INFO , ( st ) , ( cmp ) ) # */

/* sk_PKCS7_SIGNER_INFO_dup ( st ) SKM_sk_dup ( PKCS7_SIGNER_INFO , st ) # */

/* sk_PKCS7_SIGNER_INFO_pop_free ( st , free_func ) SKM_sk_pop_free ( PKCS7_SIGNER_INFO , ( st ) , ( free_func ) ) # */

/* sk_PKCS7_SIGNER_INFO_shift ( st ) SKM_sk_shift ( PKCS7_SIGNER_INFO , ( st ) ) # */

/* sk_PKCS7_SIGNER_INFO_pop ( st ) SKM_sk_pop ( PKCS7_SIGNER_INFO , ( st ) ) # */

/* sk_PKCS7_SIGNER_INFO_sort ( st ) SKM_sk_sort ( PKCS7_SIGNER_INFO , ( st ) ) # */

/* sk_PKCS7_SIGNER_INFO_is_sorted ( st ) SKM_sk_is_sorted ( PKCS7_SIGNER_INFO , ( st ) ) # */

/* sk_POLICYINFO_new ( cmp ) SKM_sk_new ( POLICYINFO , ( cmp ) ) # */

/* sk_POLICYINFO_new_null ( ) SKM_sk_new_null ( POLICYINFO ) # */

/* sk_POLICYINFO_free ( st ) SKM_sk_free ( POLICYINFO , ( st ) ) # */

/* sk_POLICYINFO_num ( st ) SKM_sk_num ( POLICYINFO , ( st ) ) # */

/* sk_POLICYINFO_value ( st , i ) SKM_sk_value ( POLICYINFO , ( st ) , ( i ) ) # */

/* sk_POLICYINFO_set ( st , i , val ) SKM_sk_set ( POLICYINFO , ( st ) , ( i ) , ( val ) ) # */

/* sk_POLICYINFO_zero ( st ) SKM_sk_zero ( POLICYINFO , ( st ) ) # */

/* sk_POLICYINFO_push ( st , val ) SKM_sk_push ( POLICYINFO , ( st ) , ( val ) ) # */

/* sk_POLICYINFO_unshift ( st , val ) SKM_sk_unshift ( POLICYINFO , ( st ) , ( val ) ) # */

/* sk_POLICYINFO_find ( st , val ) SKM_sk_find ( POLICYINFO , ( st ) , ( val ) ) # */

/* sk_POLICYINFO_find_ex ( st , val ) SKM_sk_find_ex ( POLICYINFO , ( st ) , ( val ) ) # */

/* sk_POLICYINFO_delete ( st , i ) SKM_sk_delete ( POLICYINFO , ( st ) , ( i ) ) # */

/* sk_POLICYINFO_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( POLICYINFO , ( st ) , ( ptr ) ) # */

/* sk_POLICYINFO_insert ( st , val , i ) SKM_sk_insert ( POLICYINFO , ( st ) , ( val ) , ( i ) ) # */

/* sk_POLICYINFO_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( POLICYINFO , ( st ) , ( cmp ) ) # */

/* sk_POLICYINFO_dup ( st ) SKM_sk_dup ( POLICYINFO , st ) # */

/* sk_POLICYINFO_pop_free ( st , free_func ) SKM_sk_pop_free ( POLICYINFO , ( st ) , ( free_func ) ) # */

/* sk_POLICYINFO_shift ( st ) SKM_sk_shift ( POLICYINFO , ( st ) ) # */

/* sk_POLICYINFO_pop ( st ) SKM_sk_pop ( POLICYINFO , ( st ) ) # */

/* sk_POLICYINFO_sort ( st ) SKM_sk_sort ( POLICYINFO , ( st ) ) # */

/* sk_POLICYINFO_is_sorted ( st ) SKM_sk_is_sorted ( POLICYINFO , ( st ) ) # */

/* sk_POLICYQUALINFO_new ( cmp ) SKM_sk_new ( POLICYQUALINFO , ( cmp ) ) # */

/* sk_POLICYQUALINFO_new_null ( ) SKM_sk_new_null ( POLICYQUALINFO ) # */

/* sk_POLICYQUALINFO_free ( st ) SKM_sk_free ( POLICYQUALINFO , ( st ) ) # */

/* sk_POLICYQUALINFO_num ( st ) SKM_sk_num ( POLICYQUALINFO , ( st ) ) # */

/* sk_POLICYQUALINFO_value ( st , i ) SKM_sk_value ( POLICYQUALINFO , ( st ) , ( i ) ) # */

/* sk_POLICYQUALINFO_set ( st , i , val ) SKM_sk_set ( POLICYQUALINFO , ( st ) , ( i ) , ( val ) ) # */

/* sk_POLICYQUALINFO_zero ( st ) SKM_sk_zero ( POLICYQUALINFO , ( st ) ) # */

/* sk_POLICYQUALINFO_push ( st , val ) SKM_sk_push ( POLICYQUALINFO , ( st ) , ( val ) ) # */

/* sk_POLICYQUALINFO_unshift ( st , val ) SKM_sk_unshift ( POLICYQUALINFO , ( st ) , ( val ) ) # */

/* sk_POLICYQUALINFO_find ( st , val ) SKM_sk_find ( POLICYQUALINFO , ( st ) , ( val ) ) # */

/* sk_POLICYQUALINFO_find_ex ( st , val ) SKM_sk_find_ex ( POLICYQUALINFO , ( st ) , ( val ) ) # */

/* sk_POLICYQUALINFO_delete ( st , i ) SKM_sk_delete ( POLICYQUALINFO , ( st ) , ( i ) ) # */

/* sk_POLICYQUALINFO_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( POLICYQUALINFO , ( st ) , ( ptr ) ) # */

/* sk_POLICYQUALINFO_insert ( st , val , i ) SKM_sk_insert ( POLICYQUALINFO , ( st ) , ( val ) , ( i ) ) # */

/* sk_POLICYQUALINFO_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( POLICYQUALINFO , ( st ) , ( cmp ) ) # */

/* sk_POLICYQUALINFO_dup ( st ) SKM_sk_dup ( POLICYQUALINFO , st ) # */

/* sk_POLICYQUALINFO_pop_free ( st , free_func ) SKM_sk_pop_free ( POLICYQUALINFO , ( st ) , ( free_func ) ) # */

/* sk_POLICYQUALINFO_shift ( st ) SKM_sk_shift ( POLICYQUALINFO , ( st ) ) # */

/* sk_POLICYQUALINFO_pop ( st ) SKM_sk_pop ( POLICYQUALINFO , ( st ) ) # */

/* sk_POLICYQUALINFO_sort ( st ) SKM_sk_sort ( POLICYQUALINFO , ( st ) ) # */

/* sk_POLICYQUALINFO_is_sorted ( st ) SKM_sk_is_sorted ( POLICYQUALINFO , ( st ) ) # */

/* sk_POLICY_MAPPING_new ( cmp ) SKM_sk_new ( POLICY_MAPPING , ( cmp ) ) # */

/* sk_POLICY_MAPPING_new_null ( ) SKM_sk_new_null ( POLICY_MAPPING ) # */

/* sk_POLICY_MAPPING_free ( st ) SKM_sk_free ( POLICY_MAPPING , ( st ) ) # */

/* sk_POLICY_MAPPING_num ( st ) SKM_sk_num ( POLICY_MAPPING , ( st ) ) # */

/* sk_POLICY_MAPPING_value ( st , i ) SKM_sk_value ( POLICY_MAPPING , ( st ) , ( i ) ) # */

/* sk_POLICY_MAPPING_set ( st , i , val ) SKM_sk_set ( POLICY_MAPPING , ( st ) , ( i ) , ( val ) ) # */

/* sk_POLICY_MAPPING_zero ( st ) SKM_sk_zero ( POLICY_MAPPING , ( st ) ) # */

/* sk_POLICY_MAPPING_push ( st , val ) SKM_sk_push ( POLICY_MAPPING , ( st ) , ( val ) ) # */

/* sk_POLICY_MAPPING_unshift ( st , val ) SKM_sk_unshift ( POLICY_MAPPING , ( st ) , ( val ) ) # */

/* sk_POLICY_MAPPING_find ( st , val ) SKM_sk_find ( POLICY_MAPPING , ( st ) , ( val ) ) # */

/* sk_POLICY_MAPPING_find_ex ( st , val ) SKM_sk_find_ex ( POLICY_MAPPING , ( st ) , ( val ) ) # */

/* sk_POLICY_MAPPING_delete ( st , i ) SKM_sk_delete ( POLICY_MAPPING , ( st ) , ( i ) ) # */

/* sk_POLICY_MAPPING_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( POLICY_MAPPING , ( st ) , ( ptr ) ) # */

/* sk_POLICY_MAPPING_insert ( st , val , i ) SKM_sk_insert ( POLICY_MAPPING , ( st ) , ( val ) , ( i ) ) # */

/* sk_POLICY_MAPPING_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( POLICY_MAPPING , ( st ) , ( cmp ) ) # */

/* sk_POLICY_MAPPING_dup ( st ) SKM_sk_dup ( POLICY_MAPPING , st ) # */

/* sk_POLICY_MAPPING_pop_free ( st , free_func ) SKM_sk_pop_free ( POLICY_MAPPING , ( st ) , ( free_func ) ) # */

/* sk_POLICY_MAPPING_shift ( st ) SKM_sk_shift ( POLICY_MAPPING , ( st ) ) # */

/* sk_POLICY_MAPPING_pop ( st ) SKM_sk_pop ( POLICY_MAPPING , ( st ) ) # */

/* sk_POLICY_MAPPING_sort ( st ) SKM_sk_sort ( POLICY_MAPPING , ( st ) ) # */

/* sk_POLICY_MAPPING_is_sorted ( st ) SKM_sk_is_sorted ( POLICY_MAPPING , ( st ) ) # */

/* sk_SRP_gN_new ( cmp ) SKM_sk_new ( SRP_gN , ( cmp ) ) # */

/* sk_SRP_gN_new_null ( ) SKM_sk_new_null ( SRP_gN ) # */

/* sk_SRP_gN_free ( st ) SKM_sk_free ( SRP_gN , ( st ) ) # */

/* sk_SRP_gN_num ( st ) SKM_sk_num ( SRP_gN , ( st ) ) # */

/* sk_SRP_gN_value ( st , i ) SKM_sk_value ( SRP_gN , ( st ) , ( i ) ) # */

/* sk_SRP_gN_set ( st , i , val ) SKM_sk_set ( SRP_gN , ( st ) , ( i ) , ( val ) ) # */

/* sk_SRP_gN_zero ( st ) SKM_sk_zero ( SRP_gN , ( st ) ) # */

/* sk_SRP_gN_push ( st , val ) SKM_sk_push ( SRP_gN , ( st ) , ( val ) ) # */

/* sk_SRP_gN_unshift ( st , val ) SKM_sk_unshift ( SRP_gN , ( st ) , ( val ) ) # */

/* sk_SRP_gN_find ( st , val ) SKM_sk_find ( SRP_gN , ( st ) , ( val ) ) # */

/* sk_SRP_gN_find_ex ( st , val ) SKM_sk_find_ex ( SRP_gN , ( st ) , ( val ) ) # */

/* sk_SRP_gN_delete ( st , i ) SKM_sk_delete ( SRP_gN , ( st ) , ( i ) ) # */

/* sk_SRP_gN_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( SRP_gN , ( st ) , ( ptr ) ) # */

/* sk_SRP_gN_insert ( st , val , i ) SKM_sk_insert ( SRP_gN , ( st ) , ( val ) , ( i ) ) # */

/* sk_SRP_gN_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( SRP_gN , ( st ) , ( cmp ) ) # */

/* sk_SRP_gN_dup ( st ) SKM_sk_dup ( SRP_gN , st ) # */

/* sk_SRP_gN_pop_free ( st , free_func ) SKM_sk_pop_free ( SRP_gN , ( st ) , ( free_func ) ) # */

/* sk_SRP_gN_shift ( st ) SKM_sk_shift ( SRP_gN , ( st ) ) # */

/* sk_SRP_gN_pop ( st ) SKM_sk_pop ( SRP_gN , ( st ) ) # */

/* sk_SRP_gN_sort ( st ) SKM_sk_sort ( SRP_gN , ( st ) ) # */

/* sk_SRP_gN_is_sorted ( st ) SKM_sk_is_sorted ( SRP_gN , ( st ) ) # */

/* sk_SRP_gN_cache_new ( cmp ) SKM_sk_new ( SRP_gN_cache , ( cmp ) ) # */

/* sk_SRP_gN_cache_new_null ( ) SKM_sk_new_null ( SRP_gN_cache ) # */

/* sk_SRP_gN_cache_free ( st ) SKM_sk_free ( SRP_gN_cache , ( st ) ) # */

/* sk_SRP_gN_cache_num ( st ) SKM_sk_num ( SRP_gN_cache , ( st ) ) # */

/* sk_SRP_gN_cache_value ( st , i ) SKM_sk_value ( SRP_gN_cache , ( st ) , ( i ) ) # */

/* sk_SRP_gN_cache_set ( st , i , val ) SKM_sk_set ( SRP_gN_cache , ( st ) , ( i ) , ( val ) ) # */

/* sk_SRP_gN_cache_zero ( st ) SKM_sk_zero ( SRP_gN_cache , ( st ) ) # */

/* sk_SRP_gN_cache_push ( st , val ) SKM_sk_push ( SRP_gN_cache , ( st ) , ( val ) ) # */

/* sk_SRP_gN_cache_unshift ( st , val ) SKM_sk_unshift ( SRP_gN_cache , ( st ) , ( val ) ) # */

/* sk_SRP_gN_cache_find ( st , val ) SKM_sk_find ( SRP_gN_cache , ( st ) , ( val ) ) # */

/* sk_SRP_gN_cache_find_ex ( st , val ) SKM_sk_find_ex ( SRP_gN_cache , ( st ) , ( val ) ) # */

/* sk_SRP_gN_cache_delete ( st , i ) SKM_sk_delete ( SRP_gN_cache , ( st ) , ( i ) ) # */

/* sk_SRP_gN_cache_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( SRP_gN_cache , ( st ) , ( ptr ) ) # */

/* sk_SRP_gN_cache_insert ( st , val , i ) SKM_sk_insert ( SRP_gN_cache , ( st ) , ( val ) , ( i ) ) # */

/* sk_SRP_gN_cache_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( SRP_gN_cache , ( st ) , ( cmp ) ) # */

/* sk_SRP_gN_cache_dup ( st ) SKM_sk_dup ( SRP_gN_cache , st ) # */

/* sk_SRP_gN_cache_pop_free ( st , free_func ) SKM_sk_pop_free ( SRP_gN_cache , ( st ) , ( free_func ) ) # */

/* sk_SRP_gN_cache_shift ( st ) SKM_sk_shift ( SRP_gN_cache , ( st ) ) # */

/* sk_SRP_gN_cache_pop ( st ) SKM_sk_pop ( SRP_gN_cache , ( st ) ) # */

/* sk_SRP_gN_cache_sort ( st ) SKM_sk_sort ( SRP_gN_cache , ( st ) ) # */

/* sk_SRP_gN_cache_is_sorted ( st ) SKM_sk_is_sorted ( SRP_gN_cache , ( st ) ) # */

/* sk_SRP_user_pwd_new ( cmp ) SKM_sk_new ( SRP_user_pwd , ( cmp ) ) # */

/* sk_SRP_user_pwd_new_null ( ) SKM_sk_new_null ( SRP_user_pwd ) # */

/* sk_SRP_user_pwd_free ( st ) SKM_sk_free ( SRP_user_pwd , ( st ) ) # */

/* sk_SRP_user_pwd_num ( st ) SKM_sk_num ( SRP_user_pwd , ( st ) ) # */

/* sk_SRP_user_pwd_value ( st , i ) SKM_sk_value ( SRP_user_pwd , ( st ) , ( i ) ) # */

/* sk_SRP_user_pwd_set ( st , i , val ) SKM_sk_set ( SRP_user_pwd , ( st ) , ( i ) , ( val ) ) # */

/* sk_SRP_user_pwd_zero ( st ) SKM_sk_zero ( SRP_user_pwd , ( st ) ) # */

/* sk_SRP_user_pwd_push ( st , val ) SKM_sk_push ( SRP_user_pwd , ( st ) , ( val ) ) # */

/* sk_SRP_user_pwd_unshift ( st , val ) SKM_sk_unshift ( SRP_user_pwd , ( st ) , ( val ) ) # */

/* sk_SRP_user_pwd_find ( st , val ) SKM_sk_find ( SRP_user_pwd , ( st ) , ( val ) ) # */

/* sk_SRP_user_pwd_find_ex ( st , val ) SKM_sk_find_ex ( SRP_user_pwd , ( st ) , ( val ) ) # */

/* sk_SRP_user_pwd_delete ( st , i ) SKM_sk_delete ( SRP_user_pwd , ( st ) , ( i ) ) # */

/* sk_SRP_user_pwd_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( SRP_user_pwd , ( st ) , ( ptr ) ) # */

/* sk_SRP_user_pwd_insert ( st , val , i ) SKM_sk_insert ( SRP_user_pwd , ( st ) , ( val ) , ( i ) ) # */

/* sk_SRP_user_pwd_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( SRP_user_pwd , ( st ) , ( cmp ) ) # */

/* sk_SRP_user_pwd_dup ( st ) SKM_sk_dup ( SRP_user_pwd , st ) # */

/* sk_SRP_user_pwd_pop_free ( st , free_func ) SKM_sk_pop_free ( SRP_user_pwd , ( st ) , ( free_func ) ) # */

/* sk_SRP_user_pwd_shift ( st ) SKM_sk_shift ( SRP_user_pwd , ( st ) ) # */

/* sk_SRP_user_pwd_pop ( st ) SKM_sk_pop ( SRP_user_pwd , ( st ) ) # */

/* sk_SRP_user_pwd_sort ( st ) SKM_sk_sort ( SRP_user_pwd , ( st ) ) # */

/* sk_SRP_user_pwd_is_sorted ( st ) SKM_sk_is_sorted ( SRP_user_pwd , ( st ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_new ( cmp ) SKM_sk_new ( SRTP_PROTECTION_PROFILE , ( cmp ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_new_null ( ) SKM_sk_new_null ( SRTP_PROTECTION_PROFILE ) # */

/* sk_SRTP_PROTECTION_PROFILE_free ( st ) SKM_sk_free ( SRTP_PROTECTION_PROFILE , ( st ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_num ( st ) SKM_sk_num ( SRTP_PROTECTION_PROFILE , ( st ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_value ( st , i ) SKM_sk_value ( SRTP_PROTECTION_PROFILE , ( st ) , ( i ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_set ( st , i , val ) SKM_sk_set ( SRTP_PROTECTION_PROFILE , ( st ) , ( i ) , ( val ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_zero ( st ) SKM_sk_zero ( SRTP_PROTECTION_PROFILE , ( st ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_push ( st , val ) SKM_sk_push ( SRTP_PROTECTION_PROFILE , ( st ) , ( val ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_unshift ( st , val ) SKM_sk_unshift ( SRTP_PROTECTION_PROFILE , ( st ) , ( val ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_find ( st , val ) SKM_sk_find ( SRTP_PROTECTION_PROFILE , ( st ) , ( val ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_find_ex ( st , val ) SKM_sk_find_ex ( SRTP_PROTECTION_PROFILE , ( st ) , ( val ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_delete ( st , i ) SKM_sk_delete ( SRTP_PROTECTION_PROFILE , ( st ) , ( i ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( SRTP_PROTECTION_PROFILE , ( st ) , ( ptr ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_insert ( st , val , i ) SKM_sk_insert ( SRTP_PROTECTION_PROFILE , ( st ) , ( val ) , ( i ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( SRTP_PROTECTION_PROFILE , ( st ) , ( cmp ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_dup ( st ) SKM_sk_dup ( SRTP_PROTECTION_PROFILE , st ) # */

/* sk_SRTP_PROTECTION_PROFILE_pop_free ( st , free_func ) SKM_sk_pop_free ( SRTP_PROTECTION_PROFILE , ( st ) , ( free_func ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_shift ( st ) SKM_sk_shift ( SRTP_PROTECTION_PROFILE , ( st ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_pop ( st ) SKM_sk_pop ( SRTP_PROTECTION_PROFILE , ( st ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_sort ( st ) SKM_sk_sort ( SRTP_PROTECTION_PROFILE , ( st ) ) # */

/* sk_SRTP_PROTECTION_PROFILE_is_sorted ( st ) SKM_sk_is_sorted ( SRTP_PROTECTION_PROFILE , ( st ) ) # */

/* sk_SSL_CIPHER_new ( cmp ) SKM_sk_new ( SSL_CIPHER , ( cmp ) ) # */

/* sk_SSL_CIPHER_new_null ( ) SKM_sk_new_null ( SSL_CIPHER ) # */

/* sk_SSL_CIPHER_free ( st ) SKM_sk_free ( SSL_CIPHER , ( st ) ) # */

/* sk_SSL_CIPHER_num ( st ) SKM_sk_num ( SSL_CIPHER , ( st ) ) # */

/* sk_SSL_CIPHER_value ( st , i ) SKM_sk_value ( SSL_CIPHER , ( st ) , ( i ) ) # */

/* sk_SSL_CIPHER_set ( st , i , val ) SKM_sk_set ( SSL_CIPHER , ( st ) , ( i ) , ( val ) ) # */

/* sk_SSL_CIPHER_zero ( st ) SKM_sk_zero ( SSL_CIPHER , ( st ) ) # */

/* sk_SSL_CIPHER_push ( st , val ) SKM_sk_push ( SSL_CIPHER , ( st ) , ( val ) ) # */

/* sk_SSL_CIPHER_unshift ( st , val ) SKM_sk_unshift ( SSL_CIPHER , ( st ) , ( val ) ) # */

/* sk_SSL_CIPHER_find ( st , val ) SKM_sk_find ( SSL_CIPHER , ( st ) , ( val ) ) # */

/* sk_SSL_CIPHER_find_ex ( st , val ) SKM_sk_find_ex ( SSL_CIPHER , ( st ) , ( val ) ) # */

/* sk_SSL_CIPHER_delete ( st , i ) SKM_sk_delete ( SSL_CIPHER , ( st ) , ( i ) ) # */

/* sk_SSL_CIPHER_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( SSL_CIPHER , ( st ) , ( ptr ) ) # */

/* sk_SSL_CIPHER_insert ( st , val , i ) SKM_sk_insert ( SSL_CIPHER , ( st ) , ( val ) , ( i ) ) # */

/* sk_SSL_CIPHER_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( SSL_CIPHER , ( st ) , ( cmp ) ) # */

/* sk_SSL_CIPHER_dup ( st ) SKM_sk_dup ( SSL_CIPHER , st ) # */

/* sk_SSL_CIPHER_pop_free ( st , free_func ) SKM_sk_pop_free ( SSL_CIPHER , ( st ) , ( free_func ) ) # */

/* sk_SSL_CIPHER_shift ( st ) SKM_sk_shift ( SSL_CIPHER , ( st ) ) # */

/* sk_SSL_CIPHER_pop ( st ) SKM_sk_pop ( SSL_CIPHER , ( st ) ) # */

/* sk_SSL_CIPHER_sort ( st ) SKM_sk_sort ( SSL_CIPHER , ( st ) ) # */

/* sk_SSL_CIPHER_is_sorted ( st ) SKM_sk_is_sorted ( SSL_CIPHER , ( st ) ) # */

/* sk_SSL_COMP_new ( cmp ) SKM_sk_new ( SSL_COMP , ( cmp ) ) # */

/* sk_SSL_COMP_new_null ( ) SKM_sk_new_null ( SSL_COMP ) # */

/* sk_SSL_COMP_free ( st ) SKM_sk_free ( SSL_COMP , ( st ) ) # */

/* sk_SSL_COMP_num ( st ) SKM_sk_num ( SSL_COMP , ( st ) ) # */

/* sk_SSL_COMP_value ( st , i ) SKM_sk_value ( SSL_COMP , ( st ) , ( i ) ) # */

/* sk_SSL_COMP_set ( st , i , val ) SKM_sk_set ( SSL_COMP , ( st ) , ( i ) , ( val ) ) # */

/* sk_SSL_COMP_zero ( st ) SKM_sk_zero ( SSL_COMP , ( st ) ) # */

/* sk_SSL_COMP_push ( st , val ) SKM_sk_push ( SSL_COMP , ( st ) , ( val ) ) # */

/* sk_SSL_COMP_unshift ( st , val ) SKM_sk_unshift ( SSL_COMP , ( st ) , ( val ) ) # */

/* sk_SSL_COMP_find ( st , val ) SKM_sk_find ( SSL_COMP , ( st ) , ( val ) ) # */

/* sk_SSL_COMP_find_ex ( st , val ) SKM_sk_find_ex ( SSL_COMP , ( st ) , ( val ) ) # */

/* sk_SSL_COMP_delete ( st , i ) SKM_sk_delete ( SSL_COMP , ( st ) , ( i ) ) # */

/* sk_SSL_COMP_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( SSL_COMP , ( st ) , ( ptr ) ) # */

/* sk_SSL_COMP_insert ( st , val , i ) SKM_sk_insert ( SSL_COMP , ( st ) , ( val ) , ( i ) ) # */

/* sk_SSL_COMP_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( SSL_COMP , ( st ) , ( cmp ) ) # */

/* sk_SSL_COMP_dup ( st ) SKM_sk_dup ( SSL_COMP , st ) # */

/* sk_SSL_COMP_pop_free ( st , free_func ) SKM_sk_pop_free ( SSL_COMP , ( st ) , ( free_func ) ) # */

/* sk_SSL_COMP_shift ( st ) SKM_sk_shift ( SSL_COMP , ( st ) ) # */

/* sk_SSL_COMP_pop ( st ) SKM_sk_pop ( SSL_COMP , ( st ) ) # */

/* sk_SSL_COMP_sort ( st ) SKM_sk_sort ( SSL_COMP , ( st ) ) # */

/* sk_SSL_COMP_is_sorted ( st ) SKM_sk_is_sorted ( SSL_COMP , ( st ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_new ( cmp ) SKM_sk_new ( STACK_OF_X509_NAME_ENTRY , ( cmp ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_new_null ( ) SKM_sk_new_null ( STACK_OF_X509_NAME_ENTRY ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_free ( st ) SKM_sk_free ( STACK_OF_X509_NAME_ENTRY , ( st ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_num ( st ) SKM_sk_num ( STACK_OF_X509_NAME_ENTRY , ( st ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_value ( st , i ) SKM_sk_value ( STACK_OF_X509_NAME_ENTRY , ( st ) , ( i ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_set ( st , i , val ) SKM_sk_set ( STACK_OF_X509_NAME_ENTRY , ( st ) , ( i ) , ( val ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_zero ( st ) SKM_sk_zero ( STACK_OF_X509_NAME_ENTRY , ( st ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_push ( st , val ) SKM_sk_push ( STACK_OF_X509_NAME_ENTRY , ( st ) , ( val ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_unshift ( st , val ) SKM_sk_unshift ( STACK_OF_X509_NAME_ENTRY , ( st ) , ( val ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_find ( st , val ) SKM_sk_find ( STACK_OF_X509_NAME_ENTRY , ( st ) , ( val ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_find_ex ( st , val ) SKM_sk_find_ex ( STACK_OF_X509_NAME_ENTRY , ( st ) , ( val ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_delete ( st , i ) SKM_sk_delete ( STACK_OF_X509_NAME_ENTRY , ( st ) , ( i ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( STACK_OF_X509_NAME_ENTRY , ( st ) , ( ptr ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_insert ( st , val , i ) SKM_sk_insert ( STACK_OF_X509_NAME_ENTRY , ( st ) , ( val ) , ( i ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( STACK_OF_X509_NAME_ENTRY , ( st ) , ( cmp ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_dup ( st ) SKM_sk_dup ( STACK_OF_X509_NAME_ENTRY , st ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_pop_free ( st , free_func ) SKM_sk_pop_free ( STACK_OF_X509_NAME_ENTRY , ( st ) , ( free_func ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_shift ( st ) SKM_sk_shift ( STACK_OF_X509_NAME_ENTRY , ( st ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_pop ( st ) SKM_sk_pop ( STACK_OF_X509_NAME_ENTRY , ( st ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_sort ( st ) SKM_sk_sort ( STACK_OF_X509_NAME_ENTRY , ( st ) ) # */

/* sk_STACK_OF_X509_NAME_ENTRY_is_sorted ( st ) SKM_sk_is_sorted ( STACK_OF_X509_NAME_ENTRY , ( st ) ) # */

/* sk_STORE_ATTR_INFO_new ( cmp ) SKM_sk_new ( STORE_ATTR_INFO , ( cmp ) ) # */

/* sk_STORE_ATTR_INFO_new_null ( ) SKM_sk_new_null ( STORE_ATTR_INFO ) # */

/* sk_STORE_ATTR_INFO_free ( st ) SKM_sk_free ( STORE_ATTR_INFO , ( st ) ) # */

/* sk_STORE_ATTR_INFO_num ( st ) SKM_sk_num ( STORE_ATTR_INFO , ( st ) ) # */

/* sk_STORE_ATTR_INFO_value ( st , i ) SKM_sk_value ( STORE_ATTR_INFO , ( st ) , ( i ) ) # */

/* sk_STORE_ATTR_INFO_set ( st , i , val ) SKM_sk_set ( STORE_ATTR_INFO , ( st ) , ( i ) , ( val ) ) # */

/* sk_STORE_ATTR_INFO_zero ( st ) SKM_sk_zero ( STORE_ATTR_INFO , ( st ) ) # */

/* sk_STORE_ATTR_INFO_push ( st , val ) SKM_sk_push ( STORE_ATTR_INFO , ( st ) , ( val ) ) # */

/* sk_STORE_ATTR_INFO_unshift ( st , val ) SKM_sk_unshift ( STORE_ATTR_INFO , ( st ) , ( val ) ) # */

/* sk_STORE_ATTR_INFO_find ( st , val ) SKM_sk_find ( STORE_ATTR_INFO , ( st ) , ( val ) ) # */

/* sk_STORE_ATTR_INFO_find_ex ( st , val ) SKM_sk_find_ex ( STORE_ATTR_INFO , ( st ) , ( val ) ) # */

/* sk_STORE_ATTR_INFO_delete ( st , i ) SKM_sk_delete ( STORE_ATTR_INFO , ( st ) , ( i ) ) # */

/* sk_STORE_ATTR_INFO_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( STORE_ATTR_INFO , ( st ) , ( ptr ) ) # */

/* sk_STORE_ATTR_INFO_insert ( st , val , i ) SKM_sk_insert ( STORE_ATTR_INFO , ( st ) , ( val ) , ( i ) ) # */

/* sk_STORE_ATTR_INFO_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( STORE_ATTR_INFO , ( st ) , ( cmp ) ) # */

/* sk_STORE_ATTR_INFO_dup ( st ) SKM_sk_dup ( STORE_ATTR_INFO , st ) # */

/* sk_STORE_ATTR_INFO_pop_free ( st , free_func ) SKM_sk_pop_free ( STORE_ATTR_INFO , ( st ) , ( free_func ) ) # */

/* sk_STORE_ATTR_INFO_shift ( st ) SKM_sk_shift ( STORE_ATTR_INFO , ( st ) ) # */

/* sk_STORE_ATTR_INFO_pop ( st ) SKM_sk_pop ( STORE_ATTR_INFO , ( st ) ) # */

/* sk_STORE_ATTR_INFO_sort ( st ) SKM_sk_sort ( STORE_ATTR_INFO , ( st ) ) # */

/* sk_STORE_ATTR_INFO_is_sorted ( st ) SKM_sk_is_sorted ( STORE_ATTR_INFO , ( st ) ) # */

/* sk_STORE_OBJECT_new ( cmp ) SKM_sk_new ( STORE_OBJECT , ( cmp ) ) # */

/* sk_STORE_OBJECT_new_null ( ) SKM_sk_new_null ( STORE_OBJECT ) # */

/* sk_STORE_OBJECT_free ( st ) SKM_sk_free ( STORE_OBJECT , ( st ) ) # */

/* sk_STORE_OBJECT_num ( st ) SKM_sk_num ( STORE_OBJECT , ( st ) ) # */

/* sk_STORE_OBJECT_value ( st , i ) SKM_sk_value ( STORE_OBJECT , ( st ) , ( i ) ) # */

/* sk_STORE_OBJECT_set ( st , i , val ) SKM_sk_set ( STORE_OBJECT , ( st ) , ( i ) , ( val ) ) # */

/* sk_STORE_OBJECT_zero ( st ) SKM_sk_zero ( STORE_OBJECT , ( st ) ) # */

/* sk_STORE_OBJECT_push ( st , val ) SKM_sk_push ( STORE_OBJECT , ( st ) , ( val ) ) # */

/* sk_STORE_OBJECT_unshift ( st , val ) SKM_sk_unshift ( STORE_OBJECT , ( st ) , ( val ) ) # */

/* sk_STORE_OBJECT_find ( st , val ) SKM_sk_find ( STORE_OBJECT , ( st ) , ( val ) ) # */

/* sk_STORE_OBJECT_find_ex ( st , val ) SKM_sk_find_ex ( STORE_OBJECT , ( st ) , ( val ) ) # */

/* sk_STORE_OBJECT_delete ( st , i ) SKM_sk_delete ( STORE_OBJECT , ( st ) , ( i ) ) # */

/* sk_STORE_OBJECT_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( STORE_OBJECT , ( st ) , ( ptr ) ) # */

/* sk_STORE_OBJECT_insert ( st , val , i ) SKM_sk_insert ( STORE_OBJECT , ( st ) , ( val ) , ( i ) ) # */

/* sk_STORE_OBJECT_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( STORE_OBJECT , ( st ) , ( cmp ) ) # */

/* sk_STORE_OBJECT_dup ( st ) SKM_sk_dup ( STORE_OBJECT , st ) # */

/* sk_STORE_OBJECT_pop_free ( st , free_func ) SKM_sk_pop_free ( STORE_OBJECT , ( st ) , ( free_func ) ) # */

/* sk_STORE_OBJECT_shift ( st ) SKM_sk_shift ( STORE_OBJECT , ( st ) ) # */

/* sk_STORE_OBJECT_pop ( st ) SKM_sk_pop ( STORE_OBJECT , ( st ) ) # */

/* sk_STORE_OBJECT_sort ( st ) SKM_sk_sort ( STORE_OBJECT , ( st ) ) # */

/* sk_STORE_OBJECT_is_sorted ( st ) SKM_sk_is_sorted ( STORE_OBJECT , ( st ) ) # */

/* sk_SXNETID_new ( cmp ) SKM_sk_new ( SXNETID , ( cmp ) ) # */

/* sk_SXNETID_new_null ( ) SKM_sk_new_null ( SXNETID ) # */

/* sk_SXNETID_free ( st ) SKM_sk_free ( SXNETID , ( st ) ) # */

/* sk_SXNETID_num ( st ) SKM_sk_num ( SXNETID , ( st ) ) # */

/* sk_SXNETID_value ( st , i ) SKM_sk_value ( SXNETID , ( st ) , ( i ) ) # */

/* sk_SXNETID_set ( st , i , val ) SKM_sk_set ( SXNETID , ( st ) , ( i ) , ( val ) ) # */

/* sk_SXNETID_zero ( st ) SKM_sk_zero ( SXNETID , ( st ) ) # */

/* sk_SXNETID_push ( st , val ) SKM_sk_push ( SXNETID , ( st ) , ( val ) ) # */

/* sk_SXNETID_unshift ( st , val ) SKM_sk_unshift ( SXNETID , ( st ) , ( val ) ) # */

/* sk_SXNETID_find ( st , val ) SKM_sk_find ( SXNETID , ( st ) , ( val ) ) # */

/* sk_SXNETID_find_ex ( st , val ) SKM_sk_find_ex ( SXNETID , ( st ) , ( val ) ) # */

/* sk_SXNETID_delete ( st , i ) SKM_sk_delete ( SXNETID , ( st ) , ( i ) ) # */

/* sk_SXNETID_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( SXNETID , ( st ) , ( ptr ) ) # */

/* sk_SXNETID_insert ( st , val , i ) SKM_sk_insert ( SXNETID , ( st ) , ( val ) , ( i ) ) # */

/* sk_SXNETID_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( SXNETID , ( st ) , ( cmp ) ) # */

/* sk_SXNETID_dup ( st ) SKM_sk_dup ( SXNETID , st ) # */

/* sk_SXNETID_pop_free ( st , free_func ) SKM_sk_pop_free ( SXNETID , ( st ) , ( free_func ) ) # */

/* sk_SXNETID_shift ( st ) SKM_sk_shift ( SXNETID , ( st ) ) # */

/* sk_SXNETID_pop ( st ) SKM_sk_pop ( SXNETID , ( st ) ) # */

/* sk_SXNETID_sort ( st ) SKM_sk_sort ( SXNETID , ( st ) ) # */

/* sk_SXNETID_is_sorted ( st ) SKM_sk_is_sorted ( SXNETID , ( st ) ) # */

/* sk_UI_STRING_new ( cmp ) SKM_sk_new ( UI_STRING , ( cmp ) ) # */

/* sk_UI_STRING_new_null ( ) SKM_sk_new_null ( UI_STRING ) # */

/* sk_UI_STRING_free ( st ) SKM_sk_free ( UI_STRING , ( st ) ) # */

/* sk_UI_STRING_num ( st ) SKM_sk_num ( UI_STRING , ( st ) ) # */

/* sk_UI_STRING_value ( st , i ) SKM_sk_value ( UI_STRING , ( st ) , ( i ) ) # */

/* sk_UI_STRING_set ( st , i , val ) SKM_sk_set ( UI_STRING , ( st ) , ( i ) , ( val ) ) # */

/* sk_UI_STRING_zero ( st ) SKM_sk_zero ( UI_STRING , ( st ) ) # */

/* sk_UI_STRING_push ( st , val ) SKM_sk_push ( UI_STRING , ( st ) , ( val ) ) # */

/* sk_UI_STRING_unshift ( st , val ) SKM_sk_unshift ( UI_STRING , ( st ) , ( val ) ) # */

/* sk_UI_STRING_find ( st , val ) SKM_sk_find ( UI_STRING , ( st ) , ( val ) ) # */

/* sk_UI_STRING_find_ex ( st , val ) SKM_sk_find_ex ( UI_STRING , ( st ) , ( val ) ) # */

/* sk_UI_STRING_delete ( st , i ) SKM_sk_delete ( UI_STRING , ( st ) , ( i ) ) # */

/* sk_UI_STRING_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( UI_STRING , ( st ) , ( ptr ) ) # */

/* sk_UI_STRING_insert ( st , val , i ) SKM_sk_insert ( UI_STRING , ( st ) , ( val ) , ( i ) ) # */

/* sk_UI_STRING_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( UI_STRING , ( st ) , ( cmp ) ) # */

/* sk_UI_STRING_dup ( st ) SKM_sk_dup ( UI_STRING , st ) # */

/* sk_UI_STRING_pop_free ( st , free_func ) SKM_sk_pop_free ( UI_STRING , ( st ) , ( free_func ) ) # */

/* sk_UI_STRING_shift ( st ) SKM_sk_shift ( UI_STRING , ( st ) ) # */

/* sk_UI_STRING_pop ( st ) SKM_sk_pop ( UI_STRING , ( st ) ) # */

/* sk_UI_STRING_sort ( st ) SKM_sk_sort ( UI_STRING , ( st ) ) # */

/* sk_UI_STRING_is_sorted ( st ) SKM_sk_is_sorted ( UI_STRING , ( st ) ) # */

/* sk_X509_new ( cmp ) SKM_sk_new ( X509 , ( cmp ) ) # */

/* sk_X509_new_null ( ) SKM_sk_new_null ( X509 ) # */

/* sk_X509_free ( st ) SKM_sk_free ( X509 , ( st ) ) # */

/* sk_X509_num ( st ) SKM_sk_num ( X509 , ( st ) ) # */

/* sk_X509_value ( st , i ) SKM_sk_value ( X509 , ( st ) , ( i ) ) # */

/* sk_X509_set ( st , i , val ) SKM_sk_set ( X509 , ( st ) , ( i ) , ( val ) ) # */

/* sk_X509_zero ( st ) SKM_sk_zero ( X509 , ( st ) ) # */

/* sk_X509_push ( st , val ) SKM_sk_push ( X509 , ( st ) , ( val ) ) # */

/* sk_X509_unshift ( st , val ) SKM_sk_unshift ( X509 , ( st ) , ( val ) ) # */

/* sk_X509_find ( st , val ) SKM_sk_find ( X509 , ( st ) , ( val ) ) # */

/* sk_X509_find_ex ( st , val ) SKM_sk_find_ex ( X509 , ( st ) , ( val ) ) # */

/* sk_X509_delete ( st , i ) SKM_sk_delete ( X509 , ( st ) , ( i ) ) # */

/* sk_X509_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( X509 , ( st ) , ( ptr ) ) # */

/* sk_X509_insert ( st , val , i ) SKM_sk_insert ( X509 , ( st ) , ( val ) , ( i ) ) # */

/* sk_X509_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( X509 , ( st ) , ( cmp ) ) # */

/* sk_X509_dup ( st ) SKM_sk_dup ( X509 , st ) # */

/* sk_X509_pop_free ( st , free_func ) SKM_sk_pop_free ( X509 , ( st ) , ( free_func ) ) # */

/* sk_X509_shift ( st ) SKM_sk_shift ( X509 , ( st ) ) # */

/* sk_X509_pop ( st ) SKM_sk_pop ( X509 , ( st ) ) # */

/* sk_X509_sort ( st ) SKM_sk_sort ( X509 , ( st ) ) # */

/* sk_X509_is_sorted ( st ) SKM_sk_is_sorted ( X509 , ( st ) ) # */

/* sk_X509V3_EXT_METHOD_new ( cmp ) SKM_sk_new ( X509V3_EXT_METHOD , ( cmp ) ) # */

/* sk_X509V3_EXT_METHOD_new_null ( ) SKM_sk_new_null ( X509V3_EXT_METHOD ) # */

/* sk_X509V3_EXT_METHOD_free ( st ) SKM_sk_free ( X509V3_EXT_METHOD , ( st ) ) # */

/* sk_X509V3_EXT_METHOD_num ( st ) SKM_sk_num ( X509V3_EXT_METHOD , ( st ) ) # */

/* sk_X509V3_EXT_METHOD_value ( st , i ) SKM_sk_value ( X509V3_EXT_METHOD , ( st ) , ( i ) ) # */

/* sk_X509V3_EXT_METHOD_set ( st , i , val ) SKM_sk_set ( X509V3_EXT_METHOD , ( st ) , ( i ) , ( val ) ) # */

/* sk_X509V3_EXT_METHOD_zero ( st ) SKM_sk_zero ( X509V3_EXT_METHOD , ( st ) ) # */

/* sk_X509V3_EXT_METHOD_push ( st , val ) SKM_sk_push ( X509V3_EXT_METHOD , ( st ) , ( val ) ) # */

/* sk_X509V3_EXT_METHOD_unshift ( st , val ) SKM_sk_unshift ( X509V3_EXT_METHOD , ( st ) , ( val ) ) # */

/* sk_X509V3_EXT_METHOD_find ( st , val ) SKM_sk_find ( X509V3_EXT_METHOD , ( st ) , ( val ) ) # */

/* sk_X509V3_EXT_METHOD_find_ex ( st , val ) SKM_sk_find_ex ( X509V3_EXT_METHOD , ( st ) , ( val ) ) # */

/* sk_X509V3_EXT_METHOD_delete ( st , i ) SKM_sk_delete ( X509V3_EXT_METHOD , ( st ) , ( i ) ) # */

/* sk_X509V3_EXT_METHOD_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( X509V3_EXT_METHOD , ( st ) , ( ptr ) ) # */

/* sk_X509V3_EXT_METHOD_insert ( st , val , i ) SKM_sk_insert ( X509V3_EXT_METHOD , ( st ) , ( val ) , ( i ) ) # */

/* sk_X509V3_EXT_METHOD_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( X509V3_EXT_METHOD , ( st ) , ( cmp ) ) # */

/* sk_X509V3_EXT_METHOD_dup ( st ) SKM_sk_dup ( X509V3_EXT_METHOD , st ) # */

/* sk_X509V3_EXT_METHOD_pop_free ( st , free_func ) SKM_sk_pop_free ( X509V3_EXT_METHOD , ( st ) , ( free_func ) ) # */

/* sk_X509V3_EXT_METHOD_shift ( st ) SKM_sk_shift ( X509V3_EXT_METHOD , ( st ) ) # */

/* sk_X509V3_EXT_METHOD_pop ( st ) SKM_sk_pop ( X509V3_EXT_METHOD , ( st ) ) # */

/* sk_X509V3_EXT_METHOD_sort ( st ) SKM_sk_sort ( X509V3_EXT_METHOD , ( st ) ) # */

/* sk_X509V3_EXT_METHOD_is_sorted ( st ) SKM_sk_is_sorted ( X509V3_EXT_METHOD , ( st ) ) # */

/* sk_X509_ALGOR_new ( cmp ) SKM_sk_new ( X509_ALGOR , ( cmp ) ) # */

/* sk_X509_ALGOR_new_null ( ) SKM_sk_new_null ( X509_ALGOR ) # */

/* sk_X509_ALGOR_free ( st ) SKM_sk_free ( X509_ALGOR , ( st ) ) # */

/* sk_X509_ALGOR_num ( st ) SKM_sk_num ( X509_ALGOR , ( st ) ) # */

/* sk_X509_ALGOR_value ( st , i ) SKM_sk_value ( X509_ALGOR , ( st ) , ( i ) ) # */

/* sk_X509_ALGOR_set ( st , i , val ) SKM_sk_set ( X509_ALGOR , ( st ) , ( i ) , ( val ) ) # */

/* sk_X509_ALGOR_zero ( st ) SKM_sk_zero ( X509_ALGOR , ( st ) ) # */

/* sk_X509_ALGOR_push ( st , val ) SKM_sk_push ( X509_ALGOR , ( st ) , ( val ) ) # */

/* sk_X509_ALGOR_unshift ( st , val ) SKM_sk_unshift ( X509_ALGOR , ( st ) , ( val ) ) # */

/* sk_X509_ALGOR_find ( st , val ) SKM_sk_find ( X509_ALGOR , ( st ) , ( val ) ) # */

/* sk_X509_ALGOR_find_ex ( st , val ) SKM_sk_find_ex ( X509_ALGOR , ( st ) , ( val ) ) # */

/* sk_X509_ALGOR_delete ( st , i ) SKM_sk_delete ( X509_ALGOR , ( st ) , ( i ) ) # */

/* sk_X509_ALGOR_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( X509_ALGOR , ( st ) , ( ptr ) ) # */

/* sk_X509_ALGOR_insert ( st , val , i ) SKM_sk_insert ( X509_ALGOR , ( st ) , ( val ) , ( i ) ) # */

/* sk_X509_ALGOR_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( X509_ALGOR , ( st ) , ( cmp ) ) # */

/* sk_X509_ALGOR_dup ( st ) SKM_sk_dup ( X509_ALGOR , st ) # */

/* sk_X509_ALGOR_pop_free ( st , free_func ) SKM_sk_pop_free ( X509_ALGOR , ( st ) , ( free_func ) ) # */

/* sk_X509_ALGOR_shift ( st ) SKM_sk_shift ( X509_ALGOR , ( st ) ) # */

/* sk_X509_ALGOR_pop ( st ) SKM_sk_pop ( X509_ALGOR , ( st ) ) # */

/* sk_X509_ALGOR_sort ( st ) SKM_sk_sort ( X509_ALGOR , ( st ) ) # */

/* sk_X509_ALGOR_is_sorted ( st ) SKM_sk_is_sorted ( X509_ALGOR , ( st ) ) # */

/* sk_X509_ATTRIBUTE_new ( cmp ) SKM_sk_new ( X509_ATTRIBUTE , ( cmp ) ) # */

/* sk_X509_ATTRIBUTE_new_null ( ) SKM_sk_new_null ( X509_ATTRIBUTE ) # */

/* sk_X509_ATTRIBUTE_free ( st ) SKM_sk_free ( X509_ATTRIBUTE , ( st ) ) # */

/* sk_X509_ATTRIBUTE_num ( st ) SKM_sk_num ( X509_ATTRIBUTE , ( st ) ) # */

/* sk_X509_ATTRIBUTE_value ( st , i ) SKM_sk_value ( X509_ATTRIBUTE , ( st ) , ( i ) ) # */

/* sk_X509_ATTRIBUTE_set ( st , i , val ) SKM_sk_set ( X509_ATTRIBUTE , ( st ) , ( i ) , ( val ) ) # */

/* sk_X509_ATTRIBUTE_zero ( st ) SKM_sk_zero ( X509_ATTRIBUTE , ( st ) ) # */

/* sk_X509_ATTRIBUTE_push ( st , val ) SKM_sk_push ( X509_ATTRIBUTE , ( st ) , ( val ) ) # */

/* sk_X509_ATTRIBUTE_unshift ( st , val ) SKM_sk_unshift ( X509_ATTRIBUTE , ( st ) , ( val ) ) # */

/* sk_X509_ATTRIBUTE_find ( st , val ) SKM_sk_find ( X509_ATTRIBUTE , ( st ) , ( val ) ) # */

/* sk_X509_ATTRIBUTE_find_ex ( st , val ) SKM_sk_find_ex ( X509_ATTRIBUTE , ( st ) , ( val ) ) # */

/* sk_X509_ATTRIBUTE_delete ( st , i ) SKM_sk_delete ( X509_ATTRIBUTE , ( st ) , ( i ) ) # */

/* sk_X509_ATTRIBUTE_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( X509_ATTRIBUTE , ( st ) , ( ptr ) ) # */

/* sk_X509_ATTRIBUTE_insert ( st , val , i ) SKM_sk_insert ( X509_ATTRIBUTE , ( st ) , ( val ) , ( i ) ) # */

/* sk_X509_ATTRIBUTE_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( X509_ATTRIBUTE , ( st ) , ( cmp ) ) # */

/* sk_X509_ATTRIBUTE_dup ( st ) SKM_sk_dup ( X509_ATTRIBUTE , st ) # */

/* sk_X509_ATTRIBUTE_pop_free ( st , free_func ) SKM_sk_pop_free ( X509_ATTRIBUTE , ( st ) , ( free_func ) ) # */

/* sk_X509_ATTRIBUTE_shift ( st ) SKM_sk_shift ( X509_ATTRIBUTE , ( st ) ) # */

/* sk_X509_ATTRIBUTE_pop ( st ) SKM_sk_pop ( X509_ATTRIBUTE , ( st ) ) # */

/* sk_X509_ATTRIBUTE_sort ( st ) SKM_sk_sort ( X509_ATTRIBUTE , ( st ) ) # */

/* sk_X509_ATTRIBUTE_is_sorted ( st ) SKM_sk_is_sorted ( X509_ATTRIBUTE , ( st ) ) # */

/* sk_X509_CRL_new ( cmp ) SKM_sk_new ( X509_CRL , ( cmp ) ) # */

/* sk_X509_CRL_new_null ( ) SKM_sk_new_null ( X509_CRL ) # */

/* sk_X509_CRL_free ( st ) SKM_sk_free ( X509_CRL , ( st ) ) # */

/* sk_X509_CRL_num ( st ) SKM_sk_num ( X509_CRL , ( st ) ) # */

/* sk_X509_CRL_value ( st , i ) SKM_sk_value ( X509_CRL , ( st ) , ( i ) ) # */

/* sk_X509_CRL_set ( st , i , val ) SKM_sk_set ( X509_CRL , ( st ) , ( i ) , ( val ) ) # */

/* sk_X509_CRL_zero ( st ) SKM_sk_zero ( X509_CRL , ( st ) ) # */

/* sk_X509_CRL_push ( st , val ) SKM_sk_push ( X509_CRL , ( st ) , ( val ) ) # */

/* sk_X509_CRL_unshift ( st , val ) SKM_sk_unshift ( X509_CRL , ( st ) , ( val ) ) # */

/* sk_X509_CRL_find ( st , val ) SKM_sk_find ( X509_CRL , ( st ) , ( val ) ) # */

/* sk_X509_CRL_find_ex ( st , val ) SKM_sk_find_ex ( X509_CRL , ( st ) , ( val ) ) # */

/* sk_X509_CRL_delete ( st , i ) SKM_sk_delete ( X509_CRL , ( st ) , ( i ) ) # */

/* sk_X509_CRL_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( X509_CRL , ( st ) , ( ptr ) ) # */

/* sk_X509_CRL_insert ( st , val , i ) SKM_sk_insert ( X509_CRL , ( st ) , ( val ) , ( i ) ) # */

/* sk_X509_CRL_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( X509_CRL , ( st ) , ( cmp ) ) # */

/* sk_X509_CRL_dup ( st ) SKM_sk_dup ( X509_CRL , st ) # */

/* sk_X509_CRL_pop_free ( st , free_func ) SKM_sk_pop_free ( X509_CRL , ( st ) , ( free_func ) ) # */

/* sk_X509_CRL_shift ( st ) SKM_sk_shift ( X509_CRL , ( st ) ) # */

/* sk_X509_CRL_pop ( st ) SKM_sk_pop ( X509_CRL , ( st ) ) # */

/* sk_X509_CRL_sort ( st ) SKM_sk_sort ( X509_CRL , ( st ) ) # */

/* sk_X509_CRL_is_sorted ( st ) SKM_sk_is_sorted ( X509_CRL , ( st ) ) # */

/* sk_X509_EXTENSION_new ( cmp ) SKM_sk_new ( X509_EXTENSION , ( cmp ) ) # */

/* sk_X509_EXTENSION_new_null ( ) SKM_sk_new_null ( X509_EXTENSION ) # */

/* sk_X509_EXTENSION_free ( st ) SKM_sk_free ( X509_EXTENSION , ( st ) ) # */

/* sk_X509_EXTENSION_num ( st ) SKM_sk_num ( X509_EXTENSION , ( st ) ) # */

/* sk_X509_EXTENSION_value ( st , i ) SKM_sk_value ( X509_EXTENSION , ( st ) , ( i ) ) # */

/* sk_X509_EXTENSION_set ( st , i , val ) SKM_sk_set ( X509_EXTENSION , ( st ) , ( i ) , ( val ) ) # */

/* sk_X509_EXTENSION_zero ( st ) SKM_sk_zero ( X509_EXTENSION , ( st ) ) # */

/* sk_X509_EXTENSION_push ( st , val ) SKM_sk_push ( X509_EXTENSION , ( st ) , ( val ) ) # */

/* sk_X509_EXTENSION_unshift ( st , val ) SKM_sk_unshift ( X509_EXTENSION , ( st ) , ( val ) ) # */

/* sk_X509_EXTENSION_find ( st , val ) SKM_sk_find ( X509_EXTENSION , ( st ) , ( val ) ) # */

/* sk_X509_EXTENSION_find_ex ( st , val ) SKM_sk_find_ex ( X509_EXTENSION , ( st ) , ( val ) ) # */

/* sk_X509_EXTENSION_delete ( st , i ) SKM_sk_delete ( X509_EXTENSION , ( st ) , ( i ) ) # */

/* sk_X509_EXTENSION_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( X509_EXTENSION , ( st ) , ( ptr ) ) # */

/* sk_X509_EXTENSION_insert ( st , val , i ) SKM_sk_insert ( X509_EXTENSION , ( st ) , ( val ) , ( i ) ) # */

/* sk_X509_EXTENSION_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( X509_EXTENSION , ( st ) , ( cmp ) ) # */

/* sk_X509_EXTENSION_dup ( st ) SKM_sk_dup ( X509_EXTENSION , st ) # */

/* sk_X509_EXTENSION_pop_free ( st , free_func ) SKM_sk_pop_free ( X509_EXTENSION , ( st ) , ( free_func ) ) # */

/* sk_X509_EXTENSION_shift ( st ) SKM_sk_shift ( X509_EXTENSION , ( st ) ) # */

/* sk_X509_EXTENSION_pop ( st ) SKM_sk_pop ( X509_EXTENSION , ( st ) ) # */

/* sk_X509_EXTENSION_sort ( st ) SKM_sk_sort ( X509_EXTENSION , ( st ) ) # */

/* sk_X509_EXTENSION_is_sorted ( st ) SKM_sk_is_sorted ( X509_EXTENSION , ( st ) ) # */

/* sk_X509_INFO_new ( cmp ) SKM_sk_new ( X509_INFO , ( cmp ) ) # */

/* sk_X509_INFO_new_null ( ) SKM_sk_new_null ( X509_INFO ) # */

/* sk_X509_INFO_free ( st ) SKM_sk_free ( X509_INFO , ( st ) ) # */

/* sk_X509_INFO_num ( st ) SKM_sk_num ( X509_INFO , ( st ) ) # */

/* sk_X509_INFO_value ( st , i ) SKM_sk_value ( X509_INFO , ( st ) , ( i ) ) # */

/* sk_X509_INFO_set ( st , i , val ) SKM_sk_set ( X509_INFO , ( st ) , ( i ) , ( val ) ) # */

/* sk_X509_INFO_zero ( st ) SKM_sk_zero ( X509_INFO , ( st ) ) # */

/* sk_X509_INFO_push ( st , val ) SKM_sk_push ( X509_INFO , ( st ) , ( val ) ) # */

/* sk_X509_INFO_unshift ( st , val ) SKM_sk_unshift ( X509_INFO , ( st ) , ( val ) ) # */

/* sk_X509_INFO_find ( st , val ) SKM_sk_find ( X509_INFO , ( st ) , ( val ) ) # */

/* sk_X509_INFO_find_ex ( st , val ) SKM_sk_find_ex ( X509_INFO , ( st ) , ( val ) ) # */

/* sk_X509_INFO_delete ( st , i ) SKM_sk_delete ( X509_INFO , ( st ) , ( i ) ) # */

/* sk_X509_INFO_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( X509_INFO , ( st ) , ( ptr ) ) # */

/* sk_X509_INFO_insert ( st , val , i ) SKM_sk_insert ( X509_INFO , ( st ) , ( val ) , ( i ) ) # */

/* sk_X509_INFO_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( X509_INFO , ( st ) , ( cmp ) ) # */

/* sk_X509_INFO_dup ( st ) SKM_sk_dup ( X509_INFO , st ) # */

/* sk_X509_INFO_pop_free ( st , free_func ) SKM_sk_pop_free ( X509_INFO , ( st ) , ( free_func ) ) # */

/* sk_X509_INFO_shift ( st ) SKM_sk_shift ( X509_INFO , ( st ) ) # */

/* sk_X509_INFO_pop ( st ) SKM_sk_pop ( X509_INFO , ( st ) ) # */

/* sk_X509_INFO_sort ( st ) SKM_sk_sort ( X509_INFO , ( st ) ) # */

/* sk_X509_INFO_is_sorted ( st ) SKM_sk_is_sorted ( X509_INFO , ( st ) ) # */

/* sk_X509_LOOKUP_new ( cmp ) SKM_sk_new ( X509_LOOKUP , ( cmp ) ) # */

/* sk_X509_LOOKUP_new_null ( ) SKM_sk_new_null ( X509_LOOKUP ) # */

/* sk_X509_LOOKUP_free ( st ) SKM_sk_free ( X509_LOOKUP , ( st ) ) # */

/* sk_X509_LOOKUP_num ( st ) SKM_sk_num ( X509_LOOKUP , ( st ) ) # */

/* sk_X509_LOOKUP_value ( st , i ) SKM_sk_value ( X509_LOOKUP , ( st ) , ( i ) ) # */

/* sk_X509_LOOKUP_set ( st , i , val ) SKM_sk_set ( X509_LOOKUP , ( st ) , ( i ) , ( val ) ) # */

/* sk_X509_LOOKUP_zero ( st ) SKM_sk_zero ( X509_LOOKUP , ( st ) ) # */

/* sk_X509_LOOKUP_push ( st , val ) SKM_sk_push ( X509_LOOKUP , ( st ) , ( val ) ) # */

/* sk_X509_LOOKUP_unshift ( st , val ) SKM_sk_unshift ( X509_LOOKUP , ( st ) , ( val ) ) # */

/* sk_X509_LOOKUP_find ( st , val ) SKM_sk_find ( X509_LOOKUP , ( st ) , ( val ) ) # */

/* sk_X509_LOOKUP_find_ex ( st , val ) SKM_sk_find_ex ( X509_LOOKUP , ( st ) , ( val ) ) # */

/* sk_X509_LOOKUP_delete ( st , i ) SKM_sk_delete ( X509_LOOKUP , ( st ) , ( i ) ) # */

/* sk_X509_LOOKUP_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( X509_LOOKUP , ( st ) , ( ptr ) ) # */

/* sk_X509_LOOKUP_insert ( st , val , i ) SKM_sk_insert ( X509_LOOKUP , ( st ) , ( val ) , ( i ) ) # */

/* sk_X509_LOOKUP_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( X509_LOOKUP , ( st ) , ( cmp ) ) # */

/* sk_X509_LOOKUP_dup ( st ) SKM_sk_dup ( X509_LOOKUP , st ) # */

/* sk_X509_LOOKUP_pop_free ( st , free_func ) SKM_sk_pop_free ( X509_LOOKUP , ( st ) , ( free_func ) ) # */

/* sk_X509_LOOKUP_shift ( st ) SKM_sk_shift ( X509_LOOKUP , ( st ) ) # */

/* sk_X509_LOOKUP_pop ( st ) SKM_sk_pop ( X509_LOOKUP , ( st ) ) # */

/* sk_X509_LOOKUP_sort ( st ) SKM_sk_sort ( X509_LOOKUP , ( st ) ) # */

/* sk_X509_LOOKUP_is_sorted ( st ) SKM_sk_is_sorted ( X509_LOOKUP , ( st ) ) # */

/* sk_X509_NAME_new ( cmp ) SKM_sk_new ( X509_NAME , ( cmp ) ) # */

/* sk_X509_NAME_new_null ( ) SKM_sk_new_null ( X509_NAME ) # */

/* sk_X509_NAME_free ( st ) SKM_sk_free ( X509_NAME , ( st ) ) # */

/* sk_X509_NAME_num ( st ) SKM_sk_num ( X509_NAME , ( st ) ) # */

/* sk_X509_NAME_value ( st , i ) SKM_sk_value ( X509_NAME , ( st ) , ( i ) ) # */

/* sk_X509_NAME_set ( st , i , val ) SKM_sk_set ( X509_NAME , ( st ) , ( i ) , ( val ) ) # */

/* sk_X509_NAME_zero ( st ) SKM_sk_zero ( X509_NAME , ( st ) ) # */

/* sk_X509_NAME_push ( st , val ) SKM_sk_push ( X509_NAME , ( st ) , ( val ) ) # */

/* sk_X509_NAME_unshift ( st , val ) SKM_sk_unshift ( X509_NAME , ( st ) , ( val ) ) # */

/* sk_X509_NAME_find ( st , val ) SKM_sk_find ( X509_NAME , ( st ) , ( val ) ) # */

/* sk_X509_NAME_find_ex ( st , val ) SKM_sk_find_ex ( X509_NAME , ( st ) , ( val ) ) # */

/* sk_X509_NAME_delete ( st , i ) SKM_sk_delete ( X509_NAME , ( st ) , ( i ) ) # */

/* sk_X509_NAME_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( X509_NAME , ( st ) , ( ptr ) ) # */

/* sk_X509_NAME_insert ( st , val , i ) SKM_sk_insert ( X509_NAME , ( st ) , ( val ) , ( i ) ) # */

/* sk_X509_NAME_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( X509_NAME , ( st ) , ( cmp ) ) # */

/* sk_X509_NAME_dup ( st ) SKM_sk_dup ( X509_NAME , st ) # */

/* sk_X509_NAME_pop_free ( st , free_func ) SKM_sk_pop_free ( X509_NAME , ( st ) , ( free_func ) ) # */

/* sk_X509_NAME_shift ( st ) SKM_sk_shift ( X509_NAME , ( st ) ) # */

/* sk_X509_NAME_pop ( st ) SKM_sk_pop ( X509_NAME , ( st ) ) # */

/* sk_X509_NAME_sort ( st ) SKM_sk_sort ( X509_NAME , ( st ) ) # */

/* sk_X509_NAME_is_sorted ( st ) SKM_sk_is_sorted ( X509_NAME , ( st ) ) # */

/* sk_X509_NAME_ENTRY_new ( cmp ) SKM_sk_new ( X509_NAME_ENTRY , ( cmp ) ) # */

/* sk_X509_NAME_ENTRY_new_null ( ) SKM_sk_new_null ( X509_NAME_ENTRY ) # */

/* sk_X509_NAME_ENTRY_free ( st ) SKM_sk_free ( X509_NAME_ENTRY , ( st ) ) # */

/* sk_X509_NAME_ENTRY_num ( st ) SKM_sk_num ( X509_NAME_ENTRY , ( st ) ) # */

/* sk_X509_NAME_ENTRY_value ( st , i ) SKM_sk_value ( X509_NAME_ENTRY , ( st ) , ( i ) ) # */

/* sk_X509_NAME_ENTRY_set ( st , i , val ) SKM_sk_set ( X509_NAME_ENTRY , ( st ) , ( i ) , ( val ) ) # */

/* sk_X509_NAME_ENTRY_zero ( st ) SKM_sk_zero ( X509_NAME_ENTRY , ( st ) ) # */

/* sk_X509_NAME_ENTRY_push ( st , val ) SKM_sk_push ( X509_NAME_ENTRY , ( st ) , ( val ) ) # */

/* sk_X509_NAME_ENTRY_unshift ( st , val ) SKM_sk_unshift ( X509_NAME_ENTRY , ( st ) , ( val ) ) # */

/* sk_X509_NAME_ENTRY_find ( st , val ) SKM_sk_find ( X509_NAME_ENTRY , ( st ) , ( val ) ) # */

/* sk_X509_NAME_ENTRY_find_ex ( st , val ) SKM_sk_find_ex ( X509_NAME_ENTRY , ( st ) , ( val ) ) # */

/* sk_X509_NAME_ENTRY_delete ( st , i ) SKM_sk_delete ( X509_NAME_ENTRY , ( st ) , ( i ) ) # */

/* sk_X509_NAME_ENTRY_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( X509_NAME_ENTRY , ( st ) , ( ptr ) ) # */

/* sk_X509_NAME_ENTRY_insert ( st , val , i ) SKM_sk_insert ( X509_NAME_ENTRY , ( st ) , ( val ) , ( i ) ) # */

/* sk_X509_NAME_ENTRY_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( X509_NAME_ENTRY , ( st ) , ( cmp ) ) # */

/* sk_X509_NAME_ENTRY_dup ( st ) SKM_sk_dup ( X509_NAME_ENTRY , st ) # */

/* sk_X509_NAME_ENTRY_pop_free ( st , free_func ) SKM_sk_pop_free ( X509_NAME_ENTRY , ( st ) , ( free_func ) ) # */

/* sk_X509_NAME_ENTRY_shift ( st ) SKM_sk_shift ( X509_NAME_ENTRY , ( st ) ) # */

/* sk_X509_NAME_ENTRY_pop ( st ) SKM_sk_pop ( X509_NAME_ENTRY , ( st ) ) # */

/* sk_X509_NAME_ENTRY_sort ( st ) SKM_sk_sort ( X509_NAME_ENTRY , ( st ) ) # */

/* sk_X509_NAME_ENTRY_is_sorted ( st ) SKM_sk_is_sorted ( X509_NAME_ENTRY , ( st ) ) # */

/* sk_X509_OBJECT_new ( cmp ) SKM_sk_new ( X509_OBJECT , ( cmp ) ) # */

/* sk_X509_OBJECT_new_null ( ) SKM_sk_new_null ( X509_OBJECT ) # */

/* sk_X509_OBJECT_free ( st ) SKM_sk_free ( X509_OBJECT , ( st ) ) # */

/* sk_X509_OBJECT_num ( st ) SKM_sk_num ( X509_OBJECT , ( st ) ) # */

/* sk_X509_OBJECT_value ( st , i ) SKM_sk_value ( X509_OBJECT , ( st ) , ( i ) ) # */

/* sk_X509_OBJECT_set ( st , i , val ) SKM_sk_set ( X509_OBJECT , ( st ) , ( i ) , ( val ) ) # */

/* sk_X509_OBJECT_zero ( st ) SKM_sk_zero ( X509_OBJECT , ( st ) ) # */

/* sk_X509_OBJECT_push ( st , val ) SKM_sk_push ( X509_OBJECT , ( st ) , ( val ) ) # */

/* sk_X509_OBJECT_unshift ( st , val ) SKM_sk_unshift ( X509_OBJECT , ( st ) , ( val ) ) # */

/* sk_X509_OBJECT_find ( st , val ) SKM_sk_find ( X509_OBJECT , ( st ) , ( val ) ) # */

/* sk_X509_OBJECT_find_ex ( st , val ) SKM_sk_find_ex ( X509_OBJECT , ( st ) , ( val ) ) # */

/* sk_X509_OBJECT_delete ( st , i ) SKM_sk_delete ( X509_OBJECT , ( st ) , ( i ) ) # */

/* sk_X509_OBJECT_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( X509_OBJECT , ( st ) , ( ptr ) ) # */

/* sk_X509_OBJECT_insert ( st , val , i ) SKM_sk_insert ( X509_OBJECT , ( st ) , ( val ) , ( i ) ) # */

/* sk_X509_OBJECT_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( X509_OBJECT , ( st ) , ( cmp ) ) # */

/* sk_X509_OBJECT_dup ( st ) SKM_sk_dup ( X509_OBJECT , st ) # */

/* sk_X509_OBJECT_pop_free ( st , free_func ) SKM_sk_pop_free ( X509_OBJECT , ( st ) , ( free_func ) ) # */

/* sk_X509_OBJECT_shift ( st ) SKM_sk_shift ( X509_OBJECT , ( st ) ) # */

/* sk_X509_OBJECT_pop ( st ) SKM_sk_pop ( X509_OBJECT , ( st ) ) # */

/* sk_X509_OBJECT_sort ( st ) SKM_sk_sort ( X509_OBJECT , ( st ) ) # */

/* sk_X509_OBJECT_is_sorted ( st ) SKM_sk_is_sorted ( X509_OBJECT , ( st ) ) # */

/* sk_X509_POLICY_DATA_new ( cmp ) SKM_sk_new ( X509_POLICY_DATA , ( cmp ) ) # */

/* sk_X509_POLICY_DATA_new_null ( ) SKM_sk_new_null ( X509_POLICY_DATA ) # */

/* sk_X509_POLICY_DATA_free ( st ) SKM_sk_free ( X509_POLICY_DATA , ( st ) ) # */

/* sk_X509_POLICY_DATA_num ( st ) SKM_sk_num ( X509_POLICY_DATA , ( st ) ) # */

/* sk_X509_POLICY_DATA_value ( st , i ) SKM_sk_value ( X509_POLICY_DATA , ( st ) , ( i ) ) # */

/* sk_X509_POLICY_DATA_set ( st , i , val ) SKM_sk_set ( X509_POLICY_DATA , ( st ) , ( i ) , ( val ) ) # */

/* sk_X509_POLICY_DATA_zero ( st ) SKM_sk_zero ( X509_POLICY_DATA , ( st ) ) # */

/* sk_X509_POLICY_DATA_push ( st , val ) SKM_sk_push ( X509_POLICY_DATA , ( st ) , ( val ) ) # */

/* sk_X509_POLICY_DATA_unshift ( st , val ) SKM_sk_unshift ( X509_POLICY_DATA , ( st ) , ( val ) ) # */

/* sk_X509_POLICY_DATA_find ( st , val ) SKM_sk_find ( X509_POLICY_DATA , ( st ) , ( val ) ) # */

/* sk_X509_POLICY_DATA_find_ex ( st , val ) SKM_sk_find_ex ( X509_POLICY_DATA , ( st ) , ( val ) ) # */

/* sk_X509_POLICY_DATA_delete ( st , i ) SKM_sk_delete ( X509_POLICY_DATA , ( st ) , ( i ) ) # */

/* sk_X509_POLICY_DATA_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( X509_POLICY_DATA , ( st ) , ( ptr ) ) # */

/* sk_X509_POLICY_DATA_insert ( st , val , i ) SKM_sk_insert ( X509_POLICY_DATA , ( st ) , ( val ) , ( i ) ) # */

/* sk_X509_POLICY_DATA_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( X509_POLICY_DATA , ( st ) , ( cmp ) ) # */

/* sk_X509_POLICY_DATA_dup ( st ) SKM_sk_dup ( X509_POLICY_DATA , st ) # */

/* sk_X509_POLICY_DATA_pop_free ( st , free_func ) SKM_sk_pop_free ( X509_POLICY_DATA , ( st ) , ( free_func ) ) # */

/* sk_X509_POLICY_DATA_shift ( st ) SKM_sk_shift ( X509_POLICY_DATA , ( st ) ) # */

/* sk_X509_POLICY_DATA_pop ( st ) SKM_sk_pop ( X509_POLICY_DATA , ( st ) ) # */

/* sk_X509_POLICY_DATA_sort ( st ) SKM_sk_sort ( X509_POLICY_DATA , ( st ) ) # */

/* sk_X509_POLICY_DATA_is_sorted ( st ) SKM_sk_is_sorted ( X509_POLICY_DATA , ( st ) ) # */

/* sk_X509_POLICY_NODE_new ( cmp ) SKM_sk_new ( X509_POLICY_NODE , ( cmp ) ) # */

/* sk_X509_POLICY_NODE_new_null ( ) SKM_sk_new_null ( X509_POLICY_NODE ) # */

/* sk_X509_POLICY_NODE_free ( st ) SKM_sk_free ( X509_POLICY_NODE , ( st ) ) # */

/* sk_X509_POLICY_NODE_num ( st ) SKM_sk_num ( X509_POLICY_NODE , ( st ) ) # */

/* sk_X509_POLICY_NODE_value ( st , i ) SKM_sk_value ( X509_POLICY_NODE , ( st ) , ( i ) ) # */

/* sk_X509_POLICY_NODE_set ( st , i , val ) SKM_sk_set ( X509_POLICY_NODE , ( st ) , ( i ) , ( val ) ) # */

/* sk_X509_POLICY_NODE_zero ( st ) SKM_sk_zero ( X509_POLICY_NODE , ( st ) ) # */

/* sk_X509_POLICY_NODE_push ( st , val ) SKM_sk_push ( X509_POLICY_NODE , ( st ) , ( val ) ) # */

/* sk_X509_POLICY_NODE_unshift ( st , val ) SKM_sk_unshift ( X509_POLICY_NODE , ( st ) , ( val ) ) # */

/* sk_X509_POLICY_NODE_find ( st , val ) SKM_sk_find ( X509_POLICY_NODE , ( st ) , ( val ) ) # */

/* sk_X509_POLICY_NODE_find_ex ( st , val ) SKM_sk_find_ex ( X509_POLICY_NODE , ( st ) , ( val ) ) # */

/* sk_X509_POLICY_NODE_delete ( st , i ) SKM_sk_delete ( X509_POLICY_NODE , ( st ) , ( i ) ) # */

/* sk_X509_POLICY_NODE_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( X509_POLICY_NODE , ( st ) , ( ptr ) ) # */

/* sk_X509_POLICY_NODE_insert ( st , val , i ) SKM_sk_insert ( X509_POLICY_NODE , ( st ) , ( val ) , ( i ) ) # */

/* sk_X509_POLICY_NODE_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( X509_POLICY_NODE , ( st ) , ( cmp ) ) # */

/* sk_X509_POLICY_NODE_dup ( st ) SKM_sk_dup ( X509_POLICY_NODE , st ) # */

/* sk_X509_POLICY_NODE_pop_free ( st , free_func ) SKM_sk_pop_free ( X509_POLICY_NODE , ( st ) , ( free_func ) ) # */

/* sk_X509_POLICY_NODE_shift ( st ) SKM_sk_shift ( X509_POLICY_NODE , ( st ) ) # */

/* sk_X509_POLICY_NODE_pop ( st ) SKM_sk_pop ( X509_POLICY_NODE , ( st ) ) # */

/* sk_X509_POLICY_NODE_sort ( st ) SKM_sk_sort ( X509_POLICY_NODE , ( st ) ) # */

/* sk_X509_POLICY_NODE_is_sorted ( st ) SKM_sk_is_sorted ( X509_POLICY_NODE , ( st ) ) # */

/* sk_X509_PURPOSE_new ( cmp ) SKM_sk_new ( X509_PURPOSE , ( cmp ) ) # */

/* sk_X509_PURPOSE_new_null ( ) SKM_sk_new_null ( X509_PURPOSE ) # */

/* sk_X509_PURPOSE_free ( st ) SKM_sk_free ( X509_PURPOSE , ( st ) ) # */

/* sk_X509_PURPOSE_num ( st ) SKM_sk_num ( X509_PURPOSE , ( st ) ) # */

/* sk_X509_PURPOSE_value ( st , i ) SKM_sk_value ( X509_PURPOSE , ( st ) , ( i ) ) # */

/* sk_X509_PURPOSE_set ( st , i , val ) SKM_sk_set ( X509_PURPOSE , ( st ) , ( i ) , ( val ) ) # */

/* sk_X509_PURPOSE_zero ( st ) SKM_sk_zero ( X509_PURPOSE , ( st ) ) # */

/* sk_X509_PURPOSE_push ( st , val ) SKM_sk_push ( X509_PURPOSE , ( st ) , ( val ) ) # */

/* sk_X509_PURPOSE_unshift ( st , val ) SKM_sk_unshift ( X509_PURPOSE , ( st ) , ( val ) ) # */

/* sk_X509_PURPOSE_find ( st , val ) SKM_sk_find ( X509_PURPOSE , ( st ) , ( val ) ) # */

/* sk_X509_PURPOSE_find_ex ( st , val ) SKM_sk_find_ex ( X509_PURPOSE , ( st ) , ( val ) ) # */

/* sk_X509_PURPOSE_delete ( st , i ) SKM_sk_delete ( X509_PURPOSE , ( st ) , ( i ) ) # */

/* sk_X509_PURPOSE_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( X509_PURPOSE , ( st ) , ( ptr ) ) # */

/* sk_X509_PURPOSE_insert ( st , val , i ) SKM_sk_insert ( X509_PURPOSE , ( st ) , ( val ) , ( i ) ) # */

/* sk_X509_PURPOSE_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( X509_PURPOSE , ( st ) , ( cmp ) ) # */

/* sk_X509_PURPOSE_dup ( st ) SKM_sk_dup ( X509_PURPOSE , st ) # */

/* sk_X509_PURPOSE_pop_free ( st , free_func ) SKM_sk_pop_free ( X509_PURPOSE , ( st ) , ( free_func ) ) # */

/* sk_X509_PURPOSE_shift ( st ) SKM_sk_shift ( X509_PURPOSE , ( st ) ) # */

/* sk_X509_PURPOSE_pop ( st ) SKM_sk_pop ( X509_PURPOSE , ( st ) ) # */

/* sk_X509_PURPOSE_sort ( st ) SKM_sk_sort ( X509_PURPOSE , ( st ) ) # */

/* sk_X509_PURPOSE_is_sorted ( st ) SKM_sk_is_sorted ( X509_PURPOSE , ( st ) ) # */

/* sk_X509_REVOKED_new ( cmp ) SKM_sk_new ( X509_REVOKED , ( cmp ) ) # */

/* sk_X509_REVOKED_new_null ( ) SKM_sk_new_null ( X509_REVOKED ) # */

/* sk_X509_REVOKED_free ( st ) SKM_sk_free ( X509_REVOKED , ( st ) ) # */

/* sk_X509_REVOKED_num ( st ) SKM_sk_num ( X509_REVOKED , ( st ) ) # */

/* sk_X509_REVOKED_value ( st , i ) SKM_sk_value ( X509_REVOKED , ( st ) , ( i ) ) # */

/* sk_X509_REVOKED_set ( st , i , val ) SKM_sk_set ( X509_REVOKED , ( st ) , ( i ) , ( val ) ) # */

/* sk_X509_REVOKED_zero ( st ) SKM_sk_zero ( X509_REVOKED , ( st ) ) # */

/* sk_X509_REVOKED_push ( st , val ) SKM_sk_push ( X509_REVOKED , ( st ) , ( val ) ) # */

/* sk_X509_REVOKED_unshift ( st , val ) SKM_sk_unshift ( X509_REVOKED , ( st ) , ( val ) ) # */

/* sk_X509_REVOKED_find ( st , val ) SKM_sk_find ( X509_REVOKED , ( st ) , ( val ) ) # */

/* sk_X509_REVOKED_find_ex ( st , val ) SKM_sk_find_ex ( X509_REVOKED , ( st ) , ( val ) ) # */

/* sk_X509_REVOKED_delete ( st , i ) SKM_sk_delete ( X509_REVOKED , ( st ) , ( i ) ) # */

/* sk_X509_REVOKED_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( X509_REVOKED , ( st ) , ( ptr ) ) # */

/* sk_X509_REVOKED_insert ( st , val , i ) SKM_sk_insert ( X509_REVOKED , ( st ) , ( val ) , ( i ) ) # */

/* sk_X509_REVOKED_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( X509_REVOKED , ( st ) , ( cmp ) ) # */

/* sk_X509_REVOKED_dup ( st ) SKM_sk_dup ( X509_REVOKED , st ) # */

/* sk_X509_REVOKED_pop_free ( st , free_func ) SKM_sk_pop_free ( X509_REVOKED , ( st ) , ( free_func ) ) # */

/* sk_X509_REVOKED_shift ( st ) SKM_sk_shift ( X509_REVOKED , ( st ) ) # */

/* sk_X509_REVOKED_pop ( st ) SKM_sk_pop ( X509_REVOKED , ( st ) ) # */

/* sk_X509_REVOKED_sort ( st ) SKM_sk_sort ( X509_REVOKED , ( st ) ) # */

/* sk_X509_REVOKED_is_sorted ( st ) SKM_sk_is_sorted ( X509_REVOKED , ( st ) ) # */

/* sk_X509_TRUST_new ( cmp ) SKM_sk_new ( X509_TRUST , ( cmp ) ) # */

/* sk_X509_TRUST_new_null ( ) SKM_sk_new_null ( X509_TRUST ) # */

/* sk_X509_TRUST_free ( st ) SKM_sk_free ( X509_TRUST , ( st ) ) # */

/* sk_X509_TRUST_num ( st ) SKM_sk_num ( X509_TRUST , ( st ) ) # */

/* sk_X509_TRUST_value ( st , i ) SKM_sk_value ( X509_TRUST , ( st ) , ( i ) ) # */

/* sk_X509_TRUST_set ( st , i , val ) SKM_sk_set ( X509_TRUST , ( st ) , ( i ) , ( val ) ) # */

/* sk_X509_TRUST_zero ( st ) SKM_sk_zero ( X509_TRUST , ( st ) ) # */

/* sk_X509_TRUST_push ( st , val ) SKM_sk_push ( X509_TRUST , ( st ) , ( val ) ) # */

/* sk_X509_TRUST_unshift ( st , val ) SKM_sk_unshift ( X509_TRUST , ( st ) , ( val ) ) # */

/* sk_X509_TRUST_find ( st , val ) SKM_sk_find ( X509_TRUST , ( st ) , ( val ) ) # */

/* sk_X509_TRUST_find_ex ( st , val ) SKM_sk_find_ex ( X509_TRUST , ( st ) , ( val ) ) # */

/* sk_X509_TRUST_delete ( st , i ) SKM_sk_delete ( X509_TRUST , ( st ) , ( i ) ) # */

/* sk_X509_TRUST_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( X509_TRUST , ( st ) , ( ptr ) ) # */

/* sk_X509_TRUST_insert ( st , val , i ) SKM_sk_insert ( X509_TRUST , ( st ) , ( val ) , ( i ) ) # */

/* sk_X509_TRUST_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( X509_TRUST , ( st ) , ( cmp ) ) # */

/* sk_X509_TRUST_dup ( st ) SKM_sk_dup ( X509_TRUST , st ) # */

/* sk_X509_TRUST_pop_free ( st , free_func ) SKM_sk_pop_free ( X509_TRUST , ( st ) , ( free_func ) ) # */

/* sk_X509_TRUST_shift ( st ) SKM_sk_shift ( X509_TRUST , ( st ) ) # */

/* sk_X509_TRUST_pop ( st ) SKM_sk_pop ( X509_TRUST , ( st ) ) # */

/* sk_X509_TRUST_sort ( st ) SKM_sk_sort ( X509_TRUST , ( st ) ) # */

/* sk_X509_TRUST_is_sorted ( st ) SKM_sk_is_sorted ( X509_TRUST , ( st ) ) # */

/* sk_X509_VERIFY_PARAM_new ( cmp ) SKM_sk_new ( X509_VERIFY_PARAM , ( cmp ) ) # */

/* sk_X509_VERIFY_PARAM_new_null ( ) SKM_sk_new_null ( X509_VERIFY_PARAM ) # */

/* sk_X509_VERIFY_PARAM_free ( st ) SKM_sk_free ( X509_VERIFY_PARAM , ( st ) ) # */

/* sk_X509_VERIFY_PARAM_num ( st ) SKM_sk_num ( X509_VERIFY_PARAM , ( st ) ) # */

/* sk_X509_VERIFY_PARAM_value ( st , i ) SKM_sk_value ( X509_VERIFY_PARAM , ( st ) , ( i ) ) # */

/* sk_X509_VERIFY_PARAM_set ( st , i , val ) SKM_sk_set ( X509_VERIFY_PARAM , ( st ) , ( i ) , ( val ) ) # */

/* sk_X509_VERIFY_PARAM_zero ( st ) SKM_sk_zero ( X509_VERIFY_PARAM , ( st ) ) # */

/* sk_X509_VERIFY_PARAM_push ( st , val ) SKM_sk_push ( X509_VERIFY_PARAM , ( st ) , ( val ) ) # */

/* sk_X509_VERIFY_PARAM_unshift ( st , val ) SKM_sk_unshift ( X509_VERIFY_PARAM , ( st ) , ( val ) ) # */

/* sk_X509_VERIFY_PARAM_find ( st , val ) SKM_sk_find ( X509_VERIFY_PARAM , ( st ) , ( val ) ) # */

/* sk_X509_VERIFY_PARAM_find_ex ( st , val ) SKM_sk_find_ex ( X509_VERIFY_PARAM , ( st ) , ( val ) ) # */

/* sk_X509_VERIFY_PARAM_delete ( st , i ) SKM_sk_delete ( X509_VERIFY_PARAM , ( st ) , ( i ) ) # */

/* sk_X509_VERIFY_PARAM_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( X509_VERIFY_PARAM , ( st ) , ( ptr ) ) # */

/* sk_X509_VERIFY_PARAM_insert ( st , val , i ) SKM_sk_insert ( X509_VERIFY_PARAM , ( st ) , ( val ) , ( i ) ) # */

/* sk_X509_VERIFY_PARAM_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( X509_VERIFY_PARAM , ( st ) , ( cmp ) ) # */

/* sk_X509_VERIFY_PARAM_dup ( st ) SKM_sk_dup ( X509_VERIFY_PARAM , st ) # */

/* sk_X509_VERIFY_PARAM_pop_free ( st , free_func ) SKM_sk_pop_free ( X509_VERIFY_PARAM , ( st ) , ( free_func ) ) # */

/* sk_X509_VERIFY_PARAM_shift ( st ) SKM_sk_shift ( X509_VERIFY_PARAM , ( st ) ) # */

/* sk_X509_VERIFY_PARAM_pop ( st ) SKM_sk_pop ( X509_VERIFY_PARAM , ( st ) ) # */

/* sk_X509_VERIFY_PARAM_sort ( st ) SKM_sk_sort ( X509_VERIFY_PARAM , ( st ) ) # */

/* sk_X509_VERIFY_PARAM_is_sorted ( st ) SKM_sk_is_sorted ( X509_VERIFY_PARAM , ( st ) ) # */

/* sk_nid_triple_new ( cmp ) SKM_sk_new ( nid_triple , ( cmp ) ) # */

/* sk_nid_triple_new_null ( ) SKM_sk_new_null ( nid_triple ) # */

/* sk_nid_triple_free ( st ) SKM_sk_free ( nid_triple , ( st ) ) # */

/* sk_nid_triple_num ( st ) SKM_sk_num ( nid_triple , ( st ) ) # */

/* sk_nid_triple_value ( st , i ) SKM_sk_value ( nid_triple , ( st ) , ( i ) ) # */

/* sk_nid_triple_set ( st , i , val ) SKM_sk_set ( nid_triple , ( st ) , ( i ) , ( val ) ) # */

/* sk_nid_triple_zero ( st ) SKM_sk_zero ( nid_triple , ( st ) ) # */

/* sk_nid_triple_push ( st , val ) SKM_sk_push ( nid_triple , ( st ) , ( val ) ) # */

/* sk_nid_triple_unshift ( st , val ) SKM_sk_unshift ( nid_triple , ( st ) , ( val ) ) # */

/* sk_nid_triple_find ( st , val ) SKM_sk_find ( nid_triple , ( st ) , ( val ) ) # */

/* sk_nid_triple_find_ex ( st , val ) SKM_sk_find_ex ( nid_triple , ( st ) , ( val ) ) # */

/* sk_nid_triple_delete ( st , i ) SKM_sk_delete ( nid_triple , ( st ) , ( i ) ) # */

/* sk_nid_triple_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( nid_triple , ( st ) , ( ptr ) ) # */

/* sk_nid_triple_insert ( st , val , i ) SKM_sk_insert ( nid_triple , ( st ) , ( val ) , ( i ) ) # */

/* sk_nid_triple_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( nid_triple , ( st ) , ( cmp ) ) # */

/* sk_nid_triple_dup ( st ) SKM_sk_dup ( nid_triple , st ) # */

/* sk_nid_triple_pop_free ( st , free_func ) SKM_sk_pop_free ( nid_triple , ( st ) , ( free_func ) ) # */

/* sk_nid_triple_shift ( st ) SKM_sk_shift ( nid_triple , ( st ) ) # */

/* sk_nid_triple_pop ( st ) SKM_sk_pop ( nid_triple , ( st ) ) # */

/* sk_nid_triple_sort ( st ) SKM_sk_sort ( nid_triple , ( st ) ) # */

/* sk_nid_triple_is_sorted ( st ) SKM_sk_is_sorted ( nid_triple , ( st ) ) # */

/* sk_void_new ( cmp ) SKM_sk_new ( void , ( cmp ) ) # */

/* sk_void_new_null ( ) SKM_sk_new_null ( void ) # */

/* sk_void_free ( st ) SKM_sk_free ( void , ( st ) ) # */

/* sk_void_num ( st ) SKM_sk_num ( void , ( st ) ) # */

/* sk_void_value ( st , i ) SKM_sk_value ( void , ( st ) , ( i ) ) # */

/* sk_void_set ( st , i , val ) SKM_sk_set ( void , ( st ) , ( i ) , ( val ) ) # */

/* sk_void_zero ( st ) SKM_sk_zero ( void , ( st ) ) # */

/* sk_void_push ( st , val ) SKM_sk_push ( void , ( st ) , ( val ) ) # */

/* sk_void_unshift ( st , val ) SKM_sk_unshift ( void , ( st ) , ( val ) ) # */

/* sk_void_find ( st , val ) SKM_sk_find ( void , ( st ) , ( val ) ) # */

/* sk_void_find_ex ( st , val ) SKM_sk_find_ex ( void , ( st ) , ( val ) ) # */

/* sk_void_delete ( st , i ) SKM_sk_delete ( void , ( st ) , ( i ) ) # */

/* sk_void_delete_ptr ( st , ptr ) SKM_sk_delete_ptr ( void , ( st ) , ( ptr ) ) # */

/* sk_void_insert ( st , val , i ) SKM_sk_insert ( void , ( st ) , ( val ) , ( i ) ) # */

/* sk_void_set_cmp_func ( st , cmp ) SKM_sk_set_cmp_func ( void , ( st ) , ( cmp ) ) # */

/* sk_void_dup ( st ) SKM_sk_dup ( void , st ) # */

/* sk_void_pop_free ( st , free_func ) SKM_sk_pop_free ( void , ( st ) , ( free_func ) ) # */

/* sk_void_shift ( st ) SKM_sk_shift ( void , ( st ) ) # */

/* sk_void_pop ( st ) SKM_sk_pop ( void , ( st ) ) # */

/* sk_void_sort ( st ) SKM_sk_sort ( void , ( st ) ) # */

/* sk_void_is_sorted ( st ) SKM_sk_is_sorted ( void , ( st ) ) # */

/* sk_OPENSSL_STRING_new ( cmp ) ( ( STACK_OF ( OPENSSL_STRING ) * ) sk_new ( CHECKED_SK_CMP_FUNC ( char , cmp ) ) ) # */

/* sk_OPENSSL_STRING_new_null ( ) ( ( STACK_OF ( OPENSSL_STRING ) * ) sk_new_null ( ) ) # */

/* sk_OPENSSL_STRING_push ( st , val ) sk_push ( CHECKED_STACK_OF ( OPENSSL_STRING , st ) , CHECKED_PTR_OF ( char , val ) ) # */

/* sk_OPENSSL_STRING_find ( st , val ) sk_find ( CHECKED_STACK_OF ( OPENSSL_STRING , st ) , CHECKED_PTR_OF ( char , val ) ) # */

/* sk_OPENSSL_STRING_value ( st , i ) ( ( OPENSSL_STRING ) sk_value ( CHECKED_STACK_OF ( OPENSSL_STRING , st ) , i ) ) # */

/* sk_OPENSSL_STRING_num ( st ) SKM_sk_num ( OPENSSL_STRING , st ) # */

/* sk_OPENSSL_STRING_pop_free ( st , free_func ) sk_pop_free ( CHECKED_STACK_OF ( OPENSSL_STRING , st ) , CHECKED_SK_FREE_FUNC2 ( OPENSSL_STRING , free_func ) ) # */

/* sk_OPENSSL_STRING_insert ( st , val , i ) sk_insert ( CHECKED_STACK_OF ( OPENSSL_STRING , st ) , CHECKED_PTR_OF ( char , val ) , i ) # */

/* sk_OPENSSL_STRING_free ( st ) SKM_sk_free ( OPENSSL_STRING , st ) # */

/* sk_OPENSSL_STRING_set ( st , i , val ) sk_set ( CHECKED_STACK_OF ( OPENSSL_STRING , st ) , i , CHECKED_PTR_OF ( char , val ) ) # */

/* sk_OPENSSL_STRING_zero ( st ) SKM_sk_zero ( OPENSSL_STRING , ( st ) ) # */

/* sk_OPENSSL_STRING_unshift ( st , val ) sk_unshift ( CHECKED_STACK_OF ( OPENSSL_STRING , st ) , CHECKED_PTR_OF ( char , val ) ) # */

/* sk_OPENSSL_STRING_find_ex ( st , val ) sk_find_ex ( ( _STACK * ) CHECKED_CONST_PTR_OF ( STACK_OF ( OPENSSL_STRING ) , st ) , CHECKED_CONST_PTR_OF ( char , val ) ) # */

/* sk_OPENSSL_STRING_delete ( st , i ) SKM_sk_delete ( OPENSSL_STRING , ( st ) , ( i ) ) # */

/* sk_OPENSSL_STRING_delete_ptr ( st , ptr ) ( OPENSSL_STRING * ) sk_delete_ptr ( CHECKED_STACK_OF ( OPENSSL_STRING , st ) , CHECKED_PTR_OF ( char , ptr ) ) # */

/* sk_OPENSSL_STRING_set_cmp_func ( st , cmp ) ( ( int ( * ) ( const char * const * , const char * const * ) ) sk_set_cmp_func ( CHECKED_STACK_OF ( OPENSSL_STRING , st ) , CHECKED_SK_CMP_FUNC ( char , cmp ) ) ) # */

/* sk_OPENSSL_STRING_dup ( st ) SKM_sk_dup ( OPENSSL_STRING , st ) # */

/* sk_OPENSSL_STRING_shift ( st ) SKM_sk_shift ( OPENSSL_STRING , ( st ) ) # */

/* sk_OPENSSL_STRING_pop ( st ) ( char * ) sk_pop ( CHECKED_STACK_OF ( OPENSSL_STRING , st ) ) # */

/* sk_OPENSSL_STRING_sort ( st ) SKM_sk_sort ( OPENSSL_STRING , ( st ) ) # */

/* sk_OPENSSL_STRING_is_sorted ( st ) SKM_sk_is_sorted ( OPENSSL_STRING , ( st ) ) # */

/* sk_OPENSSL_BLOCK_new ( cmp ) ( ( STACK_OF ( OPENSSL_BLOCK ) * ) sk_new ( CHECKED_SK_CMP_FUNC ( void , cmp ) ) ) # */

/* sk_OPENSSL_BLOCK_new_null ( ) ( ( STACK_OF ( OPENSSL_BLOCK ) * ) sk_new_null ( ) ) # */

/* sk_OPENSSL_BLOCK_push ( st , val ) sk_push ( CHECKED_STACK_OF ( OPENSSL_BLOCK , st ) , CHECKED_PTR_OF ( void , val ) ) # */

/* sk_OPENSSL_BLOCK_find ( st , val ) sk_find ( CHECKED_STACK_OF ( OPENSSL_BLOCK , st ) , CHECKED_PTR_OF ( void , val ) ) # */

/* sk_OPENSSL_BLOCK_value ( st , i ) ( ( OPENSSL_BLOCK ) sk_value ( CHECKED_STACK_OF ( OPENSSL_BLOCK , st ) , i ) ) # */

/* sk_OPENSSL_BLOCK_num ( st ) SKM_sk_num ( OPENSSL_BLOCK , st ) # */

/* sk_OPENSSL_BLOCK_pop_free ( st , free_func ) sk_pop_free ( CHECKED_STACK_OF ( OPENSSL_BLOCK , st ) , CHECKED_SK_FREE_FUNC2 ( OPENSSL_BLOCK , free_func ) ) # */

/* sk_OPENSSL_BLOCK_insert ( st , val , i ) sk_insert ( CHECKED_STACK_OF ( OPENSSL_BLOCK , st ) , CHECKED_PTR_OF ( void , val ) , i ) # */

/* sk_OPENSSL_BLOCK_free ( st ) SKM_sk_free ( OPENSSL_BLOCK , st ) # */

/* sk_OPENSSL_BLOCK_set ( st , i , val ) sk_set ( CHECKED_STACK_OF ( OPENSSL_BLOCK , st ) , i , CHECKED_PTR_OF ( void , val ) ) # */

/* sk_OPENSSL_BLOCK_zero ( st ) SKM_sk_zero ( OPENSSL_BLOCK , ( st ) ) # */

/* sk_OPENSSL_BLOCK_unshift ( st , val ) sk_unshift ( CHECKED_STACK_OF ( OPENSSL_BLOCK , st ) , CHECKED_PTR_OF ( void , val ) ) # */

/* sk_OPENSSL_BLOCK_find_ex ( st , val ) sk_find_ex ( ( _STACK * ) CHECKED_CONST_PTR_OF ( STACK_OF ( OPENSSL_BLOCK ) , st ) , CHECKED_CONST_PTR_OF ( void , val ) ) # */

/* sk_OPENSSL_BLOCK_delete ( st , i ) SKM_sk_delete ( OPENSSL_BLOCK , ( st ) , ( i ) ) # */

/* sk_OPENSSL_BLOCK_delete_ptr ( st , ptr ) ( OPENSSL_BLOCK * ) sk_delete_ptr ( CHECKED_STACK_OF ( OPENSSL_BLOCK , st ) , CHECKED_PTR_OF ( void , ptr ) ) # */

/* sk_OPENSSL_BLOCK_set_cmp_func ( st , cmp ) ( ( int ( * ) ( const void * const * , const void * const * ) ) sk_set_cmp_func ( CHECKED_STACK_OF ( OPENSSL_BLOCK , st ) , CHECKED_SK_CMP_FUNC ( void , cmp ) ) ) # */

/* sk_OPENSSL_BLOCK_dup ( st ) SKM_sk_dup ( OPENSSL_BLOCK , st ) # */

/* sk_OPENSSL_BLOCK_shift ( st ) SKM_sk_shift ( OPENSSL_BLOCK , ( st ) ) # */

/* sk_OPENSSL_BLOCK_pop ( st ) ( void * ) sk_pop ( CHECKED_STACK_OF ( OPENSSL_BLOCK , st ) ) # */

/* sk_OPENSSL_BLOCK_sort ( st ) SKM_sk_sort ( OPENSSL_BLOCK , ( st ) ) # */

/* sk_OPENSSL_BLOCK_is_sorted ( st ) SKM_sk_is_sorted ( OPENSSL_BLOCK , ( st ) ) # */

/* sk_OPENSSL_PSTRING_new ( cmp ) ( ( STACK_OF ( OPENSSL_PSTRING ) * ) sk_new ( CHECKED_SK_CMP_FUNC ( OPENSSL_STRING , cmp ) ) ) # */

/* sk_OPENSSL_PSTRING_new_null ( ) ( ( STACK_OF ( OPENSSL_PSTRING ) * ) sk_new_null ( ) ) # */

/* sk_OPENSSL_PSTRING_push ( st , val ) sk_push ( CHECKED_STACK_OF ( OPENSSL_PSTRING , st ) , CHECKED_PTR_OF ( OPENSSL_STRING , val ) ) # */

/* sk_OPENSSL_PSTRING_find ( st , val ) sk_find ( CHECKED_STACK_OF ( OPENSSL_PSTRING , st ) , CHECKED_PTR_OF ( OPENSSL_STRING , val ) ) # */

/* sk_OPENSSL_PSTRING_value ( st , i ) ( ( OPENSSL_PSTRING ) sk_value ( CHECKED_STACK_OF ( OPENSSL_PSTRING , st ) , i ) ) # */

/* sk_OPENSSL_PSTRING_num ( st ) SKM_sk_num ( OPENSSL_PSTRING , st ) # */

/* sk_OPENSSL_PSTRING_pop_free ( st , free_func ) sk_pop_free ( CHECKED_STACK_OF ( OPENSSL_PSTRING , st ) , CHECKED_SK_FREE_FUNC2 ( OPENSSL_PSTRING , free_func ) ) # */

/* sk_OPENSSL_PSTRING_insert ( st , val , i ) sk_insert ( CHECKED_STACK_OF ( OPENSSL_PSTRING , st ) , CHECKED_PTR_OF ( OPENSSL_STRING , val ) , i ) # */

/* sk_OPENSSL_PSTRING_free ( st ) SKM_sk_free ( OPENSSL_PSTRING , st ) # */

/* sk_OPENSSL_PSTRING_set ( st , i , val ) sk_set ( CHECKED_STACK_OF ( OPENSSL_PSTRING , st ) , i , CHECKED_PTR_OF ( OPENSSL_STRING , val ) ) # */

/* sk_OPENSSL_PSTRING_zero ( st ) SKM_sk_zero ( OPENSSL_PSTRING , ( st ) ) # */

/* sk_OPENSSL_PSTRING_unshift ( st , val ) sk_unshift ( CHECKED_STACK_OF ( OPENSSL_PSTRING , st ) , CHECKED_PTR_OF ( OPENSSL_STRING , val ) ) # */

/* sk_OPENSSL_PSTRING_find_ex ( st , val ) sk_find_ex ( ( _STACK * ) CHECKED_CONST_PTR_OF ( STACK_OF ( OPENSSL_PSTRING ) , st ) , CHECKED_CONST_PTR_OF ( OPENSSL_STRING , val ) ) # */

/* sk_OPENSSL_PSTRING_delete ( st , i ) SKM_sk_delete ( OPENSSL_PSTRING , ( st ) , ( i ) ) # */

/* sk_OPENSSL_PSTRING_delete_ptr ( st , ptr ) ( OPENSSL_PSTRING * ) sk_delete_ptr ( CHECKED_STACK_OF ( OPENSSL_PSTRING , st ) , CHECKED_PTR_OF ( OPENSSL_STRING , ptr ) ) # */

/* sk_OPENSSL_PSTRING_set_cmp_func ( st , cmp ) ( ( int ( * ) ( const OPENSSL_STRING * const * , const OPENSSL_STRING * const * ) ) sk_set_cmp_func ( CHECKED_STACK_OF ( OPENSSL_PSTRING , st ) , CHECKED_SK_CMP_FUNC ( OPENSSL_STRING , cmp ) ) ) # */

/* sk_OPENSSL_PSTRING_dup ( st ) SKM_sk_dup ( OPENSSL_PSTRING , st ) # */

/* sk_OPENSSL_PSTRING_shift ( st ) SKM_sk_shift ( OPENSSL_PSTRING , ( st ) ) # */

/* sk_OPENSSL_PSTRING_pop ( st ) ( OPENSSL_STRING * ) sk_pop ( CHECKED_STACK_OF ( OPENSSL_PSTRING , st ) ) # */

/* sk_OPENSSL_PSTRING_sort ( st ) SKM_sk_sort ( OPENSSL_PSTRING , ( st ) ) # */

/* sk_OPENSSL_PSTRING_is_sorted ( st ) SKM_sk_is_sorted ( OPENSSL_PSTRING , ( st ) ) # */

/* d2i_ASN1_SET_OF_ACCESS_DESCRIPTION ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( ACCESS_DESCRIPTION , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_ACCESS_DESCRIPTION ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( ACCESS_DESCRIPTION , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_ACCESS_DESCRIPTION ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( ACCESS_DESCRIPTION , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_ACCESS_DESCRIPTION ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( ACCESS_DESCRIPTION , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_ASN1_INTEGER ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( ASN1_INTEGER , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_ASN1_INTEGER ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( ASN1_INTEGER , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_ASN1_INTEGER ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( ASN1_INTEGER , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_ASN1_INTEGER ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( ASN1_INTEGER , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_ASN1_OBJECT ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( ASN1_OBJECT , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_ASN1_OBJECT ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( ASN1_OBJECT , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_ASN1_OBJECT ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( ASN1_OBJECT , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_ASN1_OBJECT ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( ASN1_OBJECT , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_ASN1_TYPE ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( ASN1_TYPE , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_ASN1_TYPE ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( ASN1_TYPE , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_ASN1_TYPE ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( ASN1_TYPE , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_ASN1_TYPE ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( ASN1_TYPE , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_ASN1_UTF8STRING ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( ASN1_UTF8STRING , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_ASN1_UTF8STRING ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( ASN1_UTF8STRING , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_ASN1_UTF8STRING ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( ASN1_UTF8STRING , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_ASN1_UTF8STRING ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( ASN1_UTF8STRING , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_DIST_POINT ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( DIST_POINT , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_DIST_POINT ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( DIST_POINT , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_DIST_POINT ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( DIST_POINT , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_DIST_POINT ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( DIST_POINT , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_ESS_CERT_ID ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( ESS_CERT_ID , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_ESS_CERT_ID ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( ESS_CERT_ID , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_ESS_CERT_ID ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( ESS_CERT_ID , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_ESS_CERT_ID ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( ESS_CERT_ID , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_EVP_MD ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( EVP_MD , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_EVP_MD ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( EVP_MD , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_EVP_MD ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( EVP_MD , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_EVP_MD ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( EVP_MD , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_GENERAL_NAME ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( GENERAL_NAME , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_GENERAL_NAME ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( GENERAL_NAME , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_GENERAL_NAME ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( GENERAL_NAME , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_GENERAL_NAME ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( GENERAL_NAME , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_OCSP_ONEREQ ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( OCSP_ONEREQ , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_OCSP_ONEREQ ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( OCSP_ONEREQ , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_OCSP_ONEREQ ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( OCSP_ONEREQ , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_OCSP_ONEREQ ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( OCSP_ONEREQ , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_OCSP_SINGLERESP ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( OCSP_SINGLERESP , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_OCSP_SINGLERESP ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( OCSP_SINGLERESP , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_OCSP_SINGLERESP ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( OCSP_SINGLERESP , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_OCSP_SINGLERESP ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( OCSP_SINGLERESP , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_PKCS12_SAFEBAG ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( PKCS12_SAFEBAG , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_PKCS12_SAFEBAG ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( PKCS12_SAFEBAG , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_PKCS12_SAFEBAG ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( PKCS12_SAFEBAG , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_PKCS12_SAFEBAG ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( PKCS12_SAFEBAG , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_PKCS7 ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( PKCS7 , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_PKCS7 ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( PKCS7 , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_PKCS7 ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( PKCS7 , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_PKCS7 ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( PKCS7 , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_PKCS7_RECIP_INFO ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( PKCS7_RECIP_INFO , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_PKCS7_RECIP_INFO ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( PKCS7_RECIP_INFO , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_PKCS7_RECIP_INFO ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( PKCS7_RECIP_INFO , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_PKCS7_RECIP_INFO ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( PKCS7_RECIP_INFO , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_PKCS7_SIGNER_INFO ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( PKCS7_SIGNER_INFO , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_PKCS7_SIGNER_INFO ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( PKCS7_SIGNER_INFO , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_PKCS7_SIGNER_INFO ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( PKCS7_SIGNER_INFO , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_PKCS7_SIGNER_INFO ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( PKCS7_SIGNER_INFO , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_POLICYINFO ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( POLICYINFO , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_POLICYINFO ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( POLICYINFO , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_POLICYINFO ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( POLICYINFO , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_POLICYINFO ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( POLICYINFO , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_POLICYQUALINFO ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( POLICYQUALINFO , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_POLICYQUALINFO ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( POLICYQUALINFO , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_POLICYQUALINFO ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( POLICYQUALINFO , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_POLICYQUALINFO ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( POLICYQUALINFO , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_SXNETID ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( SXNETID , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_SXNETID ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( SXNETID , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_SXNETID ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( SXNETID , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_SXNETID ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( SXNETID , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_X509 ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( X509 , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_X509 ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( X509 , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_X509 ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( X509 , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_X509 ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( X509 , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_X509_ALGOR ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( X509_ALGOR , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_X509_ALGOR ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( X509_ALGOR , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_X509_ALGOR ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( X509_ALGOR , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_X509_ALGOR ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( X509_ALGOR , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_X509_ATTRIBUTE ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( X509_ATTRIBUTE , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_X509_ATTRIBUTE ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( X509_ATTRIBUTE , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_X509_ATTRIBUTE ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( X509_ATTRIBUTE , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_X509_ATTRIBUTE ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( X509_ATTRIBUTE , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_X509_CRL ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( X509_CRL , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_X509_CRL ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( X509_CRL , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_X509_CRL ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( X509_CRL , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_X509_CRL ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( X509_CRL , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_X509_EXTENSION ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( X509_EXTENSION , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_X509_EXTENSION ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( X509_EXTENSION , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_X509_EXTENSION ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( X509_EXTENSION , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_X509_EXTENSION ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( X509_EXTENSION , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_X509_NAME_ENTRY ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( X509_NAME_ENTRY , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_X509_NAME_ENTRY ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( X509_NAME_ENTRY , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_X509_NAME_ENTRY ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( X509_NAME_ENTRY , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_X509_NAME_ENTRY ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( X509_NAME_ENTRY , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* d2i_ASN1_SET_OF_X509_REVOKED ( st , pp , length , d2i_func , free_func , ex_tag , ex_class ) SKM_ASN1_SET_OF_d2i ( X509_REVOKED , ( st ) , ( pp ) , ( length ) , ( d2i_func ) , ( free_func ) , ( ex_tag ) , ( ex_class ) ) # */

/* i2d_ASN1_SET_OF_X509_REVOKED ( st , pp , i2d_func , ex_tag , ex_class , is_set ) SKM_ASN1_SET_OF_i2d ( X509_REVOKED , ( st ) , ( pp ) , ( i2d_func ) , ( ex_tag ) , ( ex_class ) , ( is_set ) ) # */

/* ASN1_seq_pack_X509_REVOKED ( st , i2d_func , buf , len ) SKM_ASN1_seq_pack ( X509_REVOKED , ( st ) , ( i2d_func ) , ( buf ) , ( len ) ) # */

/* ASN1_seq_unpack_X509_REVOKED ( buf , len , d2i_func , free_func ) SKM_ASN1_seq_unpack ( X509_REVOKED , ( buf ) , ( len ) , ( d2i_func ) , ( free_func ) ) # */

/* PKCS12_decrypt_d2i_PKCS12_SAFEBAG ( algor , d2i_func , free_func , pass , passlen , oct , seq ) SKM_PKCS12_decrypt_d2i ( PKCS12_SAFEBAG , ( algor ) , ( d2i_func ) , ( free_func ) , ( pass ) , ( passlen ) , ( oct ) , ( seq ) ) # */

/* PKCS12_decrypt_d2i_PKCS7 ( algor , d2i_func , free_func , pass , passlen , oct , seq ) SKM_PKCS12_decrypt_d2i ( PKCS7 , ( algor ) , ( d2i_func ) , ( free_func ) , ( pass ) , ( passlen ) , ( oct ) , ( seq ) ) # */

/* lh_ADDED_OBJ_new ( ) LHM_lh_new ( ADDED_OBJ , added_obj ) # */

/* lh_ADDED_OBJ_insert ( lh , inst ) LHM_lh_insert ( ADDED_OBJ , lh , inst ) # */

/* lh_ADDED_OBJ_retrieve ( lh , inst ) LHM_lh_retrieve ( ADDED_OBJ , lh , inst ) # */

/* lh_ADDED_OBJ_delete ( lh , inst ) LHM_lh_delete ( ADDED_OBJ , lh , inst ) # */

/* lh_ADDED_OBJ_doall ( lh , fn ) LHM_lh_doall ( ADDED_OBJ , lh , fn ) # */

/* lh_ADDED_OBJ_doall_arg ( lh , fn , arg_type , arg ) LHM_lh_doall_arg ( ADDED_OBJ , lh , fn , arg_type , arg ) # */

/* lh_ADDED_OBJ_error ( lh ) LHM_lh_error ( ADDED_OBJ , lh ) # */

/* lh_ADDED_OBJ_num_items ( lh ) LHM_lh_num_items ( ADDED_OBJ , lh ) # */

/* lh_ADDED_OBJ_down_load ( lh ) LHM_lh_down_load ( ADDED_OBJ , lh ) # */

/* lh_ADDED_OBJ_node_stats_bio ( lh , out ) LHM_lh_node_stats_bio ( ADDED_OBJ , lh , out ) # */

/* lh_ADDED_OBJ_node_usage_stats_bio ( lh , out ) LHM_lh_node_usage_stats_bio ( ADDED_OBJ , lh , out ) # */

/* lh_ADDED_OBJ_stats_bio ( lh , out ) LHM_lh_stats_bio ( ADDED_OBJ , lh , out ) # */

/* lh_ADDED_OBJ_free ( lh ) LHM_lh_free ( ADDED_OBJ , lh ) # */

/* lh_APP_INFO_new ( ) LHM_lh_new ( APP_INFO , app_info ) # */

/* lh_APP_INFO_insert ( lh , inst ) LHM_lh_insert ( APP_INFO , lh , inst ) # */

/* lh_APP_INFO_retrieve ( lh , inst ) LHM_lh_retrieve ( APP_INFO , lh , inst ) # */

/* lh_APP_INFO_delete ( lh , inst ) LHM_lh_delete ( APP_INFO , lh , inst ) # */

/* lh_APP_INFO_doall ( lh , fn ) LHM_lh_doall ( APP_INFO , lh , fn ) # */

/* lh_APP_INFO_doall_arg ( lh , fn , arg_type , arg ) LHM_lh_doall_arg ( APP_INFO , lh , fn , arg_type , arg ) # */

/* lh_APP_INFO_error ( lh ) LHM_lh_error ( APP_INFO , lh ) # */

/* lh_APP_INFO_num_items ( lh ) LHM_lh_num_items ( APP_INFO , lh ) # */

/* lh_APP_INFO_down_load ( lh ) LHM_lh_down_load ( APP_INFO , lh ) # */

/* lh_APP_INFO_node_stats_bio ( lh , out ) LHM_lh_node_stats_bio ( APP_INFO , lh , out ) # */

/* lh_APP_INFO_node_usage_stats_bio ( lh , out ) LHM_lh_node_usage_stats_bio ( APP_INFO , lh , out ) # */

/* lh_APP_INFO_stats_bio ( lh , out ) LHM_lh_stats_bio ( APP_INFO , lh , out ) # */

/* lh_APP_INFO_free ( lh ) LHM_lh_free ( APP_INFO , lh ) # */

/* lh_CONF_VALUE_new ( ) LHM_lh_new ( CONF_VALUE , conf_value ) # */

/* lh_CONF_VALUE_insert ( lh , inst ) LHM_lh_insert ( CONF_VALUE , lh , inst ) # */

/* lh_CONF_VALUE_retrieve ( lh , inst ) LHM_lh_retrieve ( CONF_VALUE , lh , inst ) # */

/* lh_CONF_VALUE_delete ( lh , inst ) LHM_lh_delete ( CONF_VALUE , lh , inst ) # */

/* lh_CONF_VALUE_doall ( lh , fn ) LHM_lh_doall ( CONF_VALUE , lh , fn ) # */

/* lh_CONF_VALUE_doall_arg ( lh , fn , arg_type , arg ) LHM_lh_doall_arg ( CONF_VALUE , lh , fn , arg_type , arg ) # */

/* lh_CONF_VALUE_error ( lh ) LHM_lh_error ( CONF_VALUE , lh ) # */

/* lh_CONF_VALUE_num_items ( lh ) LHM_lh_num_items ( CONF_VALUE , lh ) # */

/* lh_CONF_VALUE_down_load ( lh ) LHM_lh_down_load ( CONF_VALUE , lh ) # */

/* lh_CONF_VALUE_node_stats_bio ( lh , out ) LHM_lh_node_stats_bio ( CONF_VALUE , lh , out ) # */

/* lh_CONF_VALUE_node_usage_stats_bio ( lh , out ) LHM_lh_node_usage_stats_bio ( CONF_VALUE , lh , out ) # */

/* lh_CONF_VALUE_stats_bio ( lh , out ) LHM_lh_stats_bio ( CONF_VALUE , lh , out ) # */

/* lh_CONF_VALUE_free ( lh ) LHM_lh_free ( CONF_VALUE , lh ) # */

/* lh_ENGINE_PILE_new ( ) LHM_lh_new ( ENGINE_PILE , engine_pile ) # */

/* lh_ENGINE_PILE_insert ( lh , inst ) LHM_lh_insert ( ENGINE_PILE , lh , inst ) # */

/* lh_ENGINE_PILE_retrieve ( lh , inst ) LHM_lh_retrieve ( ENGINE_PILE , lh , inst ) # */

/* lh_ENGINE_PILE_delete ( lh , inst ) LHM_lh_delete ( ENGINE_PILE , lh , inst ) # */

/* lh_ENGINE_PILE_doall ( lh , fn ) LHM_lh_doall ( ENGINE_PILE , lh , fn ) # */

/* lh_ENGINE_PILE_doall_arg ( lh , fn , arg_type , arg ) LHM_lh_doall_arg ( ENGINE_PILE , lh , fn , arg_type , arg ) # */

/* lh_ENGINE_PILE_error ( lh ) LHM_lh_error ( ENGINE_PILE , lh ) # */

/* lh_ENGINE_PILE_num_items ( lh ) LHM_lh_num_items ( ENGINE_PILE , lh ) # */

/* lh_ENGINE_PILE_down_load ( lh ) LHM_lh_down_load ( ENGINE_PILE , lh ) # */

/* lh_ENGINE_PILE_node_stats_bio ( lh , out ) LHM_lh_node_stats_bio ( ENGINE_PILE , lh , out ) # */

/* lh_ENGINE_PILE_node_usage_stats_bio ( lh , out ) LHM_lh_node_usage_stats_bio ( ENGINE_PILE , lh , out ) # */

/* lh_ENGINE_PILE_stats_bio ( lh , out ) LHM_lh_stats_bio ( ENGINE_PILE , lh , out ) # */

/* lh_ENGINE_PILE_free ( lh ) LHM_lh_free ( ENGINE_PILE , lh ) # */

/* lh_ERR_STATE_new ( ) LHM_lh_new ( ERR_STATE , err_state ) # */

/* lh_ERR_STATE_insert ( lh , inst ) LHM_lh_insert ( ERR_STATE , lh , inst ) # */

/* lh_ERR_STATE_retrieve ( lh , inst ) LHM_lh_retrieve ( ERR_STATE , lh , inst ) # */

/* lh_ERR_STATE_delete ( lh , inst ) LHM_lh_delete ( ERR_STATE , lh , inst ) # */

/* lh_ERR_STATE_doall ( lh , fn ) LHM_lh_doall ( ERR_STATE , lh , fn ) # */

/* lh_ERR_STATE_doall_arg ( lh , fn , arg_type , arg ) LHM_lh_doall_arg ( ERR_STATE , lh , fn , arg_type , arg ) # */

/* lh_ERR_STATE_error ( lh ) LHM_lh_error ( ERR_STATE , lh ) # */

/* lh_ERR_STATE_num_items ( lh ) LHM_lh_num_items ( ERR_STATE , lh ) # */

/* lh_ERR_STATE_down_load ( lh ) LHM_lh_down_load ( ERR_STATE , lh ) # */

/* lh_ERR_STATE_node_stats_bio ( lh , out ) LHM_lh_node_stats_bio ( ERR_STATE , lh , out ) # */

/* lh_ERR_STATE_node_usage_stats_bio ( lh , out ) LHM_lh_node_usage_stats_bio ( ERR_STATE , lh , out ) # */

/* lh_ERR_STATE_stats_bio ( lh , out ) LHM_lh_stats_bio ( ERR_STATE , lh , out ) # */

/* lh_ERR_STATE_free ( lh ) LHM_lh_free ( ERR_STATE , lh ) # */

/* lh_ERR_STRING_DATA_new ( ) LHM_lh_new ( ERR_STRING_DATA , err_string_data ) # */

/* lh_ERR_STRING_DATA_insert ( lh , inst ) LHM_lh_insert ( ERR_STRING_DATA , lh , inst ) # */

/* lh_ERR_STRING_DATA_retrieve ( lh , inst ) LHM_lh_retrieve ( ERR_STRING_DATA , lh , inst ) # */

/* lh_ERR_STRING_DATA_delete ( lh , inst ) LHM_lh_delete ( ERR_STRING_DATA , lh , inst ) # */

/* lh_ERR_STRING_DATA_doall ( lh , fn ) LHM_lh_doall ( ERR_STRING_DATA , lh , fn ) # */

/* lh_ERR_STRING_DATA_doall_arg ( lh , fn , arg_type , arg ) LHM_lh_doall_arg ( ERR_STRING_DATA , lh , fn , arg_type , arg ) # */

/* lh_ERR_STRING_DATA_error ( lh ) LHM_lh_error ( ERR_STRING_DATA , lh ) # */

/* lh_ERR_STRING_DATA_num_items ( lh ) LHM_lh_num_items ( ERR_STRING_DATA , lh ) # */

/* lh_ERR_STRING_DATA_down_load ( lh ) LHM_lh_down_load ( ERR_STRING_DATA , lh ) # */

/* lh_ERR_STRING_DATA_node_stats_bio ( lh , out ) LHM_lh_node_stats_bio ( ERR_STRING_DATA , lh , out ) # */

/* lh_ERR_STRING_DATA_node_usage_stats_bio ( lh , out ) LHM_lh_node_usage_stats_bio ( ERR_STRING_DATA , lh , out ) # */

/* lh_ERR_STRING_DATA_stats_bio ( lh , out ) LHM_lh_stats_bio ( ERR_STRING_DATA , lh , out ) # */

/* lh_ERR_STRING_DATA_free ( lh ) LHM_lh_free ( ERR_STRING_DATA , lh ) # */

/* lh_EX_CLASS_ITEM_new ( ) LHM_lh_new ( EX_CLASS_ITEM , ex_class_item ) # */

/* lh_EX_CLASS_ITEM_insert ( lh , inst ) LHM_lh_insert ( EX_CLASS_ITEM , lh , inst ) # */

/* lh_EX_CLASS_ITEM_retrieve ( lh , inst ) LHM_lh_retrieve ( EX_CLASS_ITEM , lh , inst ) # */

/* lh_EX_CLASS_ITEM_delete ( lh , inst ) LHM_lh_delete ( EX_CLASS_ITEM , lh , inst ) # */

/* lh_EX_CLASS_ITEM_doall ( lh , fn ) LHM_lh_doall ( EX_CLASS_ITEM , lh , fn ) # */

/* lh_EX_CLASS_ITEM_doall_arg ( lh , fn , arg_type , arg ) LHM_lh_doall_arg ( EX_CLASS_ITEM , lh , fn , arg_type , arg ) # */

/* lh_EX_CLASS_ITEM_error ( lh ) LHM_lh_error ( EX_CLASS_ITEM , lh ) # */

/* lh_EX_CLASS_ITEM_num_items ( lh ) LHM_lh_num_items ( EX_CLASS_ITEM , lh ) # */

/* lh_EX_CLASS_ITEM_down_load ( lh ) LHM_lh_down_load ( EX_CLASS_ITEM , lh ) # */

/* lh_EX_CLASS_ITEM_node_stats_bio ( lh , out ) LHM_lh_node_stats_bio ( EX_CLASS_ITEM , lh , out ) # */

/* lh_EX_CLASS_ITEM_node_usage_stats_bio ( lh , out ) LHM_lh_node_usage_stats_bio ( EX_CLASS_ITEM , lh , out ) # */

/* lh_EX_CLASS_ITEM_stats_bio ( lh , out ) LHM_lh_stats_bio ( EX_CLASS_ITEM , lh , out ) # */

/* lh_EX_CLASS_ITEM_free ( lh ) LHM_lh_free ( EX_CLASS_ITEM , lh ) # */

/* lh_FUNCTION_new ( ) LHM_lh_new ( FUNCTION , function ) # */

/* lh_FUNCTION_insert ( lh , inst ) LHM_lh_insert ( FUNCTION , lh , inst ) # */

/* lh_FUNCTION_retrieve ( lh , inst ) LHM_lh_retrieve ( FUNCTION , lh , inst ) # */

/* lh_FUNCTION_delete ( lh , inst ) LHM_lh_delete ( FUNCTION , lh , inst ) # */

/* lh_FUNCTION_doall ( lh , fn ) LHM_lh_doall ( FUNCTION , lh , fn ) # */

/* lh_FUNCTION_doall_arg ( lh , fn , arg_type , arg ) LHM_lh_doall_arg ( FUNCTION , lh , fn , arg_type , arg ) # */

/* lh_FUNCTION_error ( lh ) LHM_lh_error ( FUNCTION , lh ) # */

/* lh_FUNCTION_num_items ( lh ) LHM_lh_num_items ( FUNCTION , lh ) # */

/* lh_FUNCTION_down_load ( lh ) LHM_lh_down_load ( FUNCTION , lh ) # */

/* lh_FUNCTION_node_stats_bio ( lh , out ) LHM_lh_node_stats_bio ( FUNCTION , lh , out ) # */

/* lh_FUNCTION_node_usage_stats_bio ( lh , out ) LHM_lh_node_usage_stats_bio ( FUNCTION , lh , out ) # */

/* lh_FUNCTION_stats_bio ( lh , out ) LHM_lh_stats_bio ( FUNCTION , lh , out ) # */

/* lh_FUNCTION_free ( lh ) LHM_lh_free ( FUNCTION , lh ) # */

/* lh_MEM_new ( ) LHM_lh_new ( MEM , mem ) # */

/* lh_MEM_insert ( lh , inst ) LHM_lh_insert ( MEM , lh , inst ) # */

/* lh_MEM_retrieve ( lh , inst ) LHM_lh_retrieve ( MEM , lh , inst ) # */

/* lh_MEM_delete ( lh , inst ) LHM_lh_delete ( MEM , lh , inst ) # */

/* lh_MEM_doall ( lh , fn ) LHM_lh_doall ( MEM , lh , fn ) # */

/* lh_MEM_doall_arg ( lh , fn , arg_type , arg ) LHM_lh_doall_arg ( MEM , lh , fn , arg_type , arg ) # */

/* lh_MEM_error ( lh ) LHM_lh_error ( MEM , lh ) # */

/* lh_MEM_num_items ( lh ) LHM_lh_num_items ( MEM , lh ) # */

/* lh_MEM_down_load ( lh ) LHM_lh_down_load ( MEM , lh ) # */

/* lh_MEM_node_stats_bio ( lh , out ) LHM_lh_node_stats_bio ( MEM , lh , out ) # */

/* lh_MEM_node_usage_stats_bio ( lh , out ) LHM_lh_node_usage_stats_bio ( MEM , lh , out ) # */

/* lh_MEM_stats_bio ( lh , out ) LHM_lh_stats_bio ( MEM , lh , out ) # */

/* lh_MEM_free ( lh ) LHM_lh_free ( MEM , lh ) # */

/* lh_OBJ_NAME_new ( ) LHM_lh_new ( OBJ_NAME , obj_name ) # */

/* lh_OBJ_NAME_insert ( lh , inst ) LHM_lh_insert ( OBJ_NAME , lh , inst ) # */

/* lh_OBJ_NAME_retrieve ( lh , inst ) LHM_lh_retrieve ( OBJ_NAME , lh , inst ) # */

/* lh_OBJ_NAME_delete ( lh , inst ) LHM_lh_delete ( OBJ_NAME , lh , inst ) # */

/* lh_OBJ_NAME_doall ( lh , fn ) LHM_lh_doall ( OBJ_NAME , lh , fn ) # */

/* lh_OBJ_NAME_doall_arg ( lh , fn , arg_type , arg ) LHM_lh_doall_arg ( OBJ_NAME , lh , fn , arg_type , arg ) # */

/* lh_OBJ_NAME_error ( lh ) LHM_lh_error ( OBJ_NAME , lh ) # */

/* lh_OBJ_NAME_num_items ( lh ) LHM_lh_num_items ( OBJ_NAME , lh ) # */

/* lh_OBJ_NAME_down_load ( lh ) LHM_lh_down_load ( OBJ_NAME , lh ) # */

/* lh_OBJ_NAME_node_stats_bio ( lh , out ) LHM_lh_node_stats_bio ( OBJ_NAME , lh , out ) # */

/* lh_OBJ_NAME_node_usage_stats_bio ( lh , out ) LHM_lh_node_usage_stats_bio ( OBJ_NAME , lh , out ) # */

/* lh_OBJ_NAME_stats_bio ( lh , out ) LHM_lh_stats_bio ( OBJ_NAME , lh , out ) # */

/* lh_OBJ_NAME_free ( lh ) LHM_lh_free ( OBJ_NAME , lh ) # */

/* lh_OPENSSL_CSTRING_new ( ) LHM_lh_new ( OPENSSL_CSTRING , openssl_cstring ) # */

/* lh_OPENSSL_CSTRING_insert ( lh , inst ) LHM_lh_insert ( OPENSSL_CSTRING , lh , inst ) # */

/* lh_OPENSSL_CSTRING_retrieve ( lh , inst ) LHM_lh_retrieve ( OPENSSL_CSTRING , lh , inst ) # */

/* lh_OPENSSL_CSTRING_delete ( lh , inst ) LHM_lh_delete ( OPENSSL_CSTRING , lh , inst ) # */

/* lh_OPENSSL_CSTRING_doall ( lh , fn ) LHM_lh_doall ( OPENSSL_CSTRING , lh , fn ) # */

/* lh_OPENSSL_CSTRING_doall_arg ( lh , fn , arg_type , arg ) LHM_lh_doall_arg ( OPENSSL_CSTRING , lh , fn , arg_type , arg ) # */

/* lh_OPENSSL_CSTRING_error ( lh ) LHM_lh_error ( OPENSSL_CSTRING , lh ) # */

/* lh_OPENSSL_CSTRING_num_items ( lh ) LHM_lh_num_items ( OPENSSL_CSTRING , lh ) # */

/* lh_OPENSSL_CSTRING_down_load ( lh ) LHM_lh_down_load ( OPENSSL_CSTRING , lh ) # */

/* lh_OPENSSL_CSTRING_node_stats_bio ( lh , out ) LHM_lh_node_stats_bio ( OPENSSL_CSTRING , lh , out ) # */

/* lh_OPENSSL_CSTRING_node_usage_stats_bio ( lh , out ) LHM_lh_node_usage_stats_bio ( OPENSSL_CSTRING , lh , out ) # */

/* lh_OPENSSL_CSTRING_stats_bio ( lh , out ) LHM_lh_stats_bio ( OPENSSL_CSTRING , lh , out ) # */

/* lh_OPENSSL_CSTRING_free ( lh ) LHM_lh_free ( OPENSSL_CSTRING , lh ) # */

/* lh_OPENSSL_STRING_new ( ) LHM_lh_new ( OPENSSL_STRING , openssl_string ) # */

/* lh_OPENSSL_STRING_insert ( lh , inst ) LHM_lh_insert ( OPENSSL_STRING , lh , inst ) # */

/* lh_OPENSSL_STRING_retrieve ( lh , inst ) LHM_lh_retrieve ( OPENSSL_STRING , lh , inst ) # */

/* lh_OPENSSL_STRING_delete ( lh , inst ) LHM_lh_delete ( OPENSSL_STRING , lh , inst ) # */

/* lh_OPENSSL_STRING_doall ( lh , fn ) LHM_lh_doall ( OPENSSL_STRING , lh , fn ) # */

/* lh_OPENSSL_STRING_doall_arg ( lh , fn , arg_type , arg ) LHM_lh_doall_arg ( OPENSSL_STRING , lh , fn , arg_type , arg ) # */

/* lh_OPENSSL_STRING_error ( lh ) LHM_lh_error ( OPENSSL_STRING , lh ) # */

/* lh_OPENSSL_STRING_num_items ( lh ) LHM_lh_num_items ( OPENSSL_STRING , lh ) # */

/* lh_OPENSSL_STRING_down_load ( lh ) LHM_lh_down_load ( OPENSSL_STRING , lh ) # */

/* lh_OPENSSL_STRING_node_stats_bio ( lh , out ) LHM_lh_node_stats_bio ( OPENSSL_STRING , lh , out ) # */

/* lh_OPENSSL_STRING_node_usage_stats_bio ( lh , out ) LHM_lh_node_usage_stats_bio ( OPENSSL_STRING , lh , out ) # */

/* lh_OPENSSL_STRING_stats_bio ( lh , out ) LHM_lh_stats_bio ( OPENSSL_STRING , lh , out ) # */

/* lh_OPENSSL_STRING_free ( lh ) LHM_lh_free ( OPENSSL_STRING , lh ) # */

/* lh_SSL_SESSION_new ( ) LHM_lh_new ( SSL_SESSION , ssl_session ) # */

/* lh_SSL_SESSION_insert ( lh , inst ) LHM_lh_insert ( SSL_SESSION , lh , inst ) # */

/* lh_SSL_SESSION_retrieve ( lh , inst ) LHM_lh_retrieve ( SSL_SESSION , lh , inst ) # */

/* lh_SSL_SESSION_delete ( lh , inst ) LHM_lh_delete ( SSL_SESSION , lh , inst ) # */

/* lh_SSL_SESSION_doall ( lh , fn ) LHM_lh_doall ( SSL_SESSION , lh , fn ) # */

/* lh_SSL_SESSION_doall_arg ( lh , fn , arg_type , arg ) LHM_lh_doall_arg ( SSL_SESSION , lh , fn , arg_type , arg ) # */

/* lh_SSL_SESSION_error ( lh ) LHM_lh_error ( SSL_SESSION , lh ) # */

/* lh_SSL_SESSION_num_items ( lh ) LHM_lh_num_items ( SSL_SESSION , lh ) # */

/* lh_SSL_SESSION_down_load ( lh ) LHM_lh_down_load ( SSL_SESSION , lh ) # */

/* lh_SSL_SESSION_node_stats_bio ( lh , out ) LHM_lh_node_stats_bio ( SSL_SESSION , lh , out ) # */

/* lh_SSL_SESSION_node_usage_stats_bio ( lh , out ) LHM_lh_node_usage_stats_bio ( SSL_SESSION , lh , out ) # */

/* lh_SSL_SESSION_stats_bio ( lh , out ) LHM_lh_stats_bio ( SSL_SESSION , lh , out ) # */

/* lh_SSL_SESSION_free ( lh ) LHM_lh_free ( SSL_SESSION , lh ) /* End of util/mkstack.pl block, you may now edit :-) */ */

/* HEADER_OPENSSLV_H /* Numeric release version identifier:
 * MNNFFPPS: major minor fix patch status
 * The status nibble has one of the values 0 for development, 1 to e for betas
 * 1 to 14, and f for release.  The patch level is exactly that.
 * For example:
 * 0.9.3-dev	  0x00903000
 * 0.9.3-beta1	  0x00903001
 * 0.9.3-beta2-dev 0x00903002
 * 0.9.3-beta2    0x00903002 (same as ...beta2-dev)
 * 0.9.3	  0x0090300f
 * 0.9.3a	  0x0090301f
 * 0.9.4 	  0x0090400f
 * 1.2.3z	  0x102031af
 *
 * For continuity reasons (because 0.9.5 is already out, and is coded
 * 0x00905100), between 0.9.5 and 0.9.6 the coding of the patch level
 * part is slightly different, by setting the highest bit.  This means
 * that 0.9.5a looks like this: 0x0090581f.  At 0.9.6, we can start
 * with 0x0090600S...
 *
 * (Prior to 0.9.3-dev a different scheme was used: 0.9.2b is 0x0922.)
 * (Prior to 0.9.5a beta1, a different scheme was used: MMNNFFRBB for
 *  major minor fix final patch/beta)
 */ */

/* OPENSSL_VERSION_NUMBER 0x1000105fL # */

/* OPENSSL_VERSION_TEXT "OpenSSL 1.0.1e 11 Feb 2013" # */

/* OPENSSL_VERSION_PTEXT " part of " OPENSSL_VERSION_TEXT /* The macros below are to be used for shared library (.so, .dll, ...)
 * versioning.  That kind of versioning works a bit differently between
 * operating systems.  The most usual scheme is to set a major and a minor
 * number, and have the runtime loader check that the major number is equal
 * to what it was at application link time, while the minor number has to
 * be greater or equal to what it was at application link time.  With this
 * scheme, the version number is usually part of the file name, like this:
 *
 *	libcrypto.so.0.9
 *
 * Some unixen also make a softlink with the major verson number only:
 *
 *	libcrypto.so.0
 *
 * On Tru64 and IRIX 6.x it works a little bit differently.  There, the
 * shared library version is stored in the file, and is actually a series
 * of versions, separated by colons.  The rightmost version present in the
 * library when linking an application is stored in the application to be
 * matched at run time.  When the application is run, a check is done to
 * see if the library version stored in the application matches any of the
 * versions in the version string of the library itself.
 * This version string can be constructed in any way, depending on what
 * kind of matching is desired.  However, to implement the same scheme as
 * the one used in the other unixen, all compatible versions, from lowest
 * to highest, should be part of the string.  Consecutive builds would
 * give the following versions strings:
 *
 *	3.0
 *	3.0:3.1
 *	3.0:3.1:3.2
 *	4.0
 *	4.0:4.1
 *
 * Notice how version 4 is completely incompatible with version, and
 * therefore give the breach you can see.
 *
 * There may be other schemes as well that I haven't yet discovered.
 *
 * So, here's the way it works here: first of all, the library version
 * number doesn't need at all to match the overall OpenSSL version.
 * However, it's nice and more understandable if it actually does.
 * The current library version is stored in the macro SHLIB_VERSION_NUMBER,
 * which is just a piece of text in the format "M.m.e" (Major, minor, edit).
 * For the sake of Tru64, IRIX, and any other OS that behaves in similar ways,
 * we need to keep a history of version numbers, which is done in the
 * macro SHLIB_VERSION_HISTORY.  The numbers are separated by colons and
 * should only keep the versions that are binary compatible with the current.
 */ */

/* SHLIB_VERSION_HISTORY "" # */

/* SHLIB_VERSION_NUMBER "1.0.0" # */

/* HEADER_OPENSSL_TYPES_H # */

/* OPENSSL_CPUID_OBJ /* crypto/opensslconf.h.in */ */

/* OPENSSL_UNISTD < unistd . h > # */

/* DECLARE_PKCS12_STACK_OF ( type ) /* Nothing */ */

/* IMPLEMENT_PKCS12_STACK_OF ( type ) /* Nothing */ */

/* HEADER_SYMHACKS_H # */

/* OPENSSL_CPUID_OBJ /* crypto/opensslconf.h.in */ */

/* OPENSSL_UNISTD < unistd . h > # */

/* SSLEAY_VERSION_NUMBER OPENSSL_VERSION_NUMBER # */

/* SSLEAY_VERSION 0 /* #define SSLEAY_OPTIONS	1 no longer supported */ */
pub const SSLEAY_VERSION: i32 = 0;

/* SSLEAY_CFLAGS 2 # */
pub const SSLEAY_CFLAGS: i32 = 2;

/* SSLEAY_BUILT_ON 3 # */
pub const SSLEAY_BUILT_ON: i32 = 3;

/* SSLEAY_PLATFORM 4 # */
pub const SSLEAY_PLATFORM: i32 = 4;

/* SSLEAY_DIR 5 /* Already declared in ossl_typ.h */ */
pub const SSLEAY_DIR: i32 = 5;

/* CRYPTO_LOCK_ERR 1 # */
pub const CRYPTO_LOCK_ERR: i32 = 1;

/* CRYPTO_LOCK_EX_DATA 2 # */
pub const CRYPTO_LOCK_EX_DATA: i32 = 2;

/* CRYPTO_LOCK_X509 3 # */
pub const CRYPTO_LOCK_X509: i32 = 3;

/* CRYPTO_LOCK_X509_INFO 4 # */
pub const CRYPTO_LOCK_X509_INFO: i32 = 4;

/* CRYPTO_LOCK_X509_PKEY 5 # */
pub const CRYPTO_LOCK_X509_PKEY: i32 = 5;

/* CRYPTO_LOCK_X509_CRL 6 # */
pub const CRYPTO_LOCK_X509_CRL: i32 = 6;

/* CRYPTO_LOCK_X509_REQ 7 # */
pub const CRYPTO_LOCK_X509_REQ: i32 = 7;

/* CRYPTO_LOCK_DSA 8 # */
pub const CRYPTO_LOCK_DSA: i32 = 8;

/* CRYPTO_LOCK_RSA 9 # */
pub const CRYPTO_LOCK_RSA: i32 = 9;

/* CRYPTO_LOCK_EVP_PKEY 10 # */
pub const CRYPTO_LOCK_EVP_PKEY: i32 = 10;

/* CRYPTO_LOCK_X509_STORE 11 # */
pub const CRYPTO_LOCK_X509_STORE: i32 = 11;

/* CRYPTO_LOCK_SSL_CTX 12 # */
pub const CRYPTO_LOCK_SSL_CTX: i32 = 12;

/* CRYPTO_LOCK_SSL_CERT 13 # */
pub const CRYPTO_LOCK_SSL_CERT: i32 = 13;

/* CRYPTO_LOCK_SSL_SESSION 14 # */
pub const CRYPTO_LOCK_SSL_SESSION: i32 = 14;

/* CRYPTO_LOCK_SSL_SESS_CERT 15 # */
pub const CRYPTO_LOCK_SSL_SESS_CERT: i32 = 15;

/* CRYPTO_LOCK_SSL 16 # */
pub const CRYPTO_LOCK_SSL: i32 = 16;

/* CRYPTO_LOCK_SSL_METHOD 17 # */
pub const CRYPTO_LOCK_SSL_METHOD: i32 = 17;

/* CRYPTO_LOCK_RAND 18 # */
pub const CRYPTO_LOCK_RAND: i32 = 18;

/* CRYPTO_LOCK_RAND2 19 # */
pub const CRYPTO_LOCK_RAND2: i32 = 19;

/* CRYPTO_LOCK_MALLOC 20 # */
pub const CRYPTO_LOCK_MALLOC: i32 = 20;

/* CRYPTO_LOCK_BIO 21 # */
pub const CRYPTO_LOCK_BIO: i32 = 21;

/* CRYPTO_LOCK_GETHOSTBYNAME 22 # */
pub const CRYPTO_LOCK_GETHOSTBYNAME: i32 = 22;

/* CRYPTO_LOCK_GETSERVBYNAME 23 # */
pub const CRYPTO_LOCK_GETSERVBYNAME: i32 = 23;

/* CRYPTO_LOCK_READDIR 24 # */
pub const CRYPTO_LOCK_READDIR: i32 = 24;

/* CRYPTO_LOCK_RSA_BLINDING 25 # */
pub const CRYPTO_LOCK_RSA_BLINDING: i32 = 25;

/* CRYPTO_LOCK_DH 26 # */
pub const CRYPTO_LOCK_DH: i32 = 26;

/* CRYPTO_LOCK_MALLOC2 27 # */
pub const CRYPTO_LOCK_MALLOC2: i32 = 27;

/* CRYPTO_LOCK_DSO 28 # */
pub const CRYPTO_LOCK_DSO: i32 = 28;

/* CRYPTO_LOCK_DYNLOCK 29 # */
pub const CRYPTO_LOCK_DYNLOCK: i32 = 29;

/* CRYPTO_LOCK_ENGINE 30 # */
pub const CRYPTO_LOCK_ENGINE: i32 = 30;

/* CRYPTO_LOCK_UI 31 # */
pub const CRYPTO_LOCK_UI: i32 = 31;

/* CRYPTO_LOCK_ECDSA 32 # */
pub const CRYPTO_LOCK_ECDSA: i32 = 32;

/* CRYPTO_LOCK_EC 33 # */
pub const CRYPTO_LOCK_EC: i32 = 33;

/* CRYPTO_LOCK_ECDH 34 # */
pub const CRYPTO_LOCK_ECDH: i32 = 34;

/* CRYPTO_LOCK_BN 35 # */
pub const CRYPTO_LOCK_BN: i32 = 35;

/* CRYPTO_LOCK_EC_PRE_COMP 36 # */
pub const CRYPTO_LOCK_EC_PRE_COMP: i32 = 36;

/* CRYPTO_LOCK_STORE 37 # */
pub const CRYPTO_LOCK_STORE: i32 = 37;

/* CRYPTO_LOCK_COMP 38 # */
pub const CRYPTO_LOCK_COMP: i32 = 38;

/* CRYPTO_LOCK_FIPS 39 # */
pub const CRYPTO_LOCK_FIPS: i32 = 39;

/* CRYPTO_LOCK_FIPS2 40 # */
pub const CRYPTO_LOCK_FIPS2: i32 = 40;

/* CRYPTO_NUM_LOCKS 41 # */
pub const CRYPTO_NUM_LOCKS: i32 = 41;

/* CRYPTO_LOCK 1 # */
pub const CRYPTO_LOCK: i32 = 1;

/* CRYPTO_UNLOCK 2 # */
pub const CRYPTO_UNLOCK: i32 = 2;

/* CRYPTO_READ 4 # */
pub const CRYPTO_READ: i32 = 4;

/* CRYPTO_WRITE 8 # */
pub const CRYPTO_WRITE: i32 = 8;

/* CRYPTO_w_lock ( type ) CRYPTO_lock ( CRYPTO_LOCK | CRYPTO_WRITE , type , __FILE__ , __LINE__ ) # */

/* CRYPTO_w_unlock ( type ) CRYPTO_lock ( CRYPTO_UNLOCK | CRYPTO_WRITE , type , __FILE__ , __LINE__ ) # */

/* CRYPTO_r_lock ( type ) CRYPTO_lock ( CRYPTO_LOCK | CRYPTO_READ , type , __FILE__ , __LINE__ ) # */

/* CRYPTO_r_unlock ( type ) CRYPTO_lock ( CRYPTO_UNLOCK | CRYPTO_READ , type , __FILE__ , __LINE__ ) # */

/* CRYPTO_add ( addr , amount , type ) CRYPTO_add_lock ( addr , amount , type , __FILE__ , __LINE__ ) # */

/* CRYPTO_MEM_CHECK_OFF 0x0 /* an enume */ */
pub const CRYPTO_MEM_CHECK_OFF: i32 = 0;

/* CRYPTO_MEM_CHECK_ON 0x1 /* a bit */ */
pub const CRYPTO_MEM_CHECK_ON: i32 = 1;

/* CRYPTO_MEM_CHECK_ENABLE 0x2 /* a bit */ */
pub const CRYPTO_MEM_CHECK_ENABLE: i32 = 2;

/* CRYPTO_MEM_CHECK_DISABLE 0x3 /* an enume */ */
pub const CRYPTO_MEM_CHECK_DISABLE: i32 = 3;

/* V_CRYPTO_MDEBUG_TIME 0x1 /* a bit */ */
pub const V_CRYPTO_MDEBUG_TIME: i32 = 1;

/* V_CRYPTO_MDEBUG_THREAD 0x2 /* a bit */ */
pub const V_CRYPTO_MDEBUG_THREAD: i32 = 2;

/* V_CRYPTO_MDEBUG_ALL ( V_CRYPTO_MDEBUG_TIME | V_CRYPTO_MDEBUG_THREAD ) /* predec of the BIO type */ */

/* CRYPTO_EX_INDEX_BIO 0 # */
pub const CRYPTO_EX_INDEX_BIO: i32 = 0;

/* CRYPTO_EX_INDEX_SSL 1 # */
pub const CRYPTO_EX_INDEX_SSL: i32 = 1;

/* CRYPTO_EX_INDEX_SSL_CTX 2 # */
pub const CRYPTO_EX_INDEX_SSL_CTX: i32 = 2;

/* CRYPTO_EX_INDEX_SSL_SESSION 3 # */
pub const CRYPTO_EX_INDEX_SSL_SESSION: i32 = 3;

/* CRYPTO_EX_INDEX_X509_STORE 4 # */
pub const CRYPTO_EX_INDEX_X509_STORE: i32 = 4;

/* CRYPTO_EX_INDEX_X509_STORE_CTX 5 # */
pub const CRYPTO_EX_INDEX_X509_STORE_CTX: i32 = 5;

/* CRYPTO_EX_INDEX_RSA 6 # */
pub const CRYPTO_EX_INDEX_RSA: i32 = 6;

/* CRYPTO_EX_INDEX_DSA 7 # */
pub const CRYPTO_EX_INDEX_DSA: i32 = 7;

/* CRYPTO_EX_INDEX_DH 8 # */
pub const CRYPTO_EX_INDEX_DH: i32 = 8;

/* CRYPTO_EX_INDEX_ENGINE 9 # */
pub const CRYPTO_EX_INDEX_ENGINE: i32 = 9;

/* CRYPTO_EX_INDEX_X509 10 # */
pub const CRYPTO_EX_INDEX_X509: i32 = 10;

/* CRYPTO_EX_INDEX_UI 11 # */
pub const CRYPTO_EX_INDEX_UI: i32 = 11;

/* CRYPTO_EX_INDEX_ECDSA 12 # */
pub const CRYPTO_EX_INDEX_ECDSA: i32 = 12;

/* CRYPTO_EX_INDEX_ECDH 13 # */
pub const CRYPTO_EX_INDEX_ECDH: i32 = 13;

/* CRYPTO_EX_INDEX_COMP 14 # */
pub const CRYPTO_EX_INDEX_COMP: i32 = 14;

/* CRYPTO_EX_INDEX_STORE 15 /* Dynamically assigned indexes start from this value (don't use directly, use
 * via CRYPTO_ex_data_new_class). */ */
pub const CRYPTO_EX_INDEX_STORE: i32 = 15;

/* CRYPTO_EX_INDEX_USER 100 /* This is the default callbacks, but we can have others as well:
 * this is needed in Win32 where the application malloc and the
 * library malloc may not be the same.
 */ */
pub const CRYPTO_EX_INDEX_USER: i32 = 100;

/* CRYPTO_malloc_init ( ) CRYPTO_set_mem_functions ( malloc , realloc , free ) # */

/* CRYPTO_malloc_debug_init ( ) do { CRYPTO_set_mem_debug_functions ( CRYPTO_dbg_malloc , CRYPTO_dbg_realloc , CRYPTO_dbg_free , CRYPTO_dbg_set_options , CRYPTO_dbg_get_options ) ; } while ( 0 ) int */

/* MemCheck_start ( ) CRYPTO_mem_ctrl ( CRYPTO_MEM_CHECK_ON ) # */

/* MemCheck_stop ( ) CRYPTO_mem_ctrl ( CRYPTO_MEM_CHECK_OFF ) /* for library-internal use */ */

/* MemCheck_on ( ) CRYPTO_mem_ctrl ( CRYPTO_MEM_CHECK_ENABLE ) # */

/* MemCheck_off ( ) CRYPTO_mem_ctrl ( CRYPTO_MEM_CHECK_DISABLE ) # */

/* is_MemCheck_on ( ) CRYPTO_is_mem_check_on ( ) # */

/* OPENSSL_malloc ( num ) CRYPTO_malloc ( ( int ) num , __FILE__ , __LINE__ ) # */

/* OPENSSL_strdup ( str ) CRYPTO_strdup ( ( str ) , __FILE__ , __LINE__ ) # */

/* OPENSSL_realloc ( addr , num ) CRYPTO_realloc ( ( char * ) addr , ( int ) num , __FILE__ , __LINE__ ) # */

/* OPENSSL_realloc_clean ( addr , old_num , num ) CRYPTO_realloc_clean ( addr , old_num , num , __FILE__ , __LINE__ ) # */

/* OPENSSL_remalloc ( addr , num ) CRYPTO_remalloc ( ( char * * ) addr , ( int ) num , __FILE__ , __LINE__ ) # */

/* OPENSSL_freeFunc CRYPTO_free # */

/* OPENSSL_free ( addr ) CRYPTO_free ( addr ) # */

/* OPENSSL_malloc_locked ( num ) CRYPTO_malloc_locked ( ( int ) num , __FILE__ , __LINE__ ) # */

/* OPENSSL_free_locked ( addr ) CRYPTO_free_locked ( addr ) const */

/* CRYPTO_push_info ( info ) CRYPTO_push_info_ ( info , __FILE__ , __LINE__ ) ; int */

/* OPENSSL_assert ( e ) ( void ) ( ( e ) ? 0 : ( OpenSSLDie ( __FILE__ , __LINE__ , # e ) , 1 ) ) unsigned */

/* OPENSSL_ia32cap ( * ( OPENSSL_ia32cap_loc ( ) ) ) int */

/* fips_md_init ( alg ) fips_md_init_ctx ( alg , alg ) # */

/* fips_md_init_ctx ( alg , cx ) int alg ## _Init ( cx ## _CTX * c ) # */

/* fips_cipher_abort ( alg ) while ( 0 ) # */

/* CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX 100 # */
pub const CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX: i32 = 100;

/* CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID 103 # */
pub const CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID: i32 = 103;

/* CRYPTO_F_CRYPTO_GET_NEW_LOCKID 101 # */
pub const CRYPTO_F_CRYPTO_GET_NEW_LOCKID: i32 = 101;

/* CRYPTO_F_CRYPTO_SET_EX_DATA 102 # */
pub const CRYPTO_F_CRYPTO_SET_EX_DATA: i32 = 102;

/* CRYPTO_F_DEF_ADD_INDEX 104 # */
pub const CRYPTO_F_DEF_ADD_INDEX: i32 = 104;

/* CRYPTO_F_DEF_GET_CLASS 105 # */
pub const CRYPTO_F_DEF_GET_CLASS: i32 = 105;

/* CRYPTO_F_FIPS_MODE_SET 109 # */
pub const CRYPTO_F_FIPS_MODE_SET: i32 = 109;

/* CRYPTO_F_INT_DUP_EX_DATA 106 # */
pub const CRYPTO_F_INT_DUP_EX_DATA: i32 = 106;

/* CRYPTO_F_INT_FREE_EX_DATA 107 # */
pub const CRYPTO_F_INT_FREE_EX_DATA: i32 = 107;

/* CRYPTO_F_INT_NEW_EX_DATA 108 /* Reason codes. */ */
pub const CRYPTO_F_INT_NEW_EX_DATA: i32 = 108;

/* CRYPTO_R_FIPS_MODE_NOT_SUPPORTED 101 # */
pub const CRYPTO_R_FIPS_MODE_NOT_SUPPORTED: i32 = 101;

/* CRYPTO_R_NO_DYNLOCK_CREATE_CALLBACK 100 # */
pub const CRYPTO_R_NO_DYNLOCK_CREATE_CALLBACK: i32 = 100;

/* BIO_TYPE_NONE 0 # */
pub const BIO_TYPE_NONE: i32 = 0;

/* BIO_TYPE_MEM ( 1 | 0x0400 ) # */

/* BIO_TYPE_FILE ( 2 | 0x0400 ) # */

/* BIO_TYPE_FD ( 4 | 0x0400 | 0x0100 ) # */

/* BIO_TYPE_SOCKET ( 5 | 0x0400 | 0x0100 ) # */

/* BIO_TYPE_NULL ( 6 | 0x0400 ) # */

/* BIO_TYPE_SSL ( 7 | 0x0200 ) # */

/* BIO_TYPE_MD ( 8 | 0x0200 ) /* passive filter */ */

/* BIO_TYPE_BUFFER ( 9 | 0x0200 ) /* filter */ */

/* BIO_TYPE_CIPHER ( 10 | 0x0200 ) /* filter */ */

/* BIO_TYPE_BASE64 ( 11 | 0x0200 ) /* filter */ */

/* BIO_TYPE_CONNECT ( 12 | 0x0400 | 0x0100 ) /* socket - connect */ */

/* BIO_TYPE_ACCEPT ( 13 | 0x0400 | 0x0100 ) /* socket for accept */ */

/* BIO_TYPE_PROXY_CLIENT ( 14 | 0x0200 ) /* client proxy BIO */ */

/* BIO_TYPE_PROXY_SERVER ( 15 | 0x0200 ) /* server proxy BIO */ */

/* BIO_TYPE_NBIO_TEST ( 16 | 0x0200 ) /* server proxy BIO */ */

/* BIO_TYPE_NULL_FILTER ( 17 | 0x0200 ) # */

/* BIO_TYPE_BER ( 18 | 0x0200 ) /* BER -> bin filter */ */

/* BIO_TYPE_BIO ( 19 | 0x0400 ) /* (half a) BIO pair */ */

/* BIO_TYPE_LINEBUFFER ( 20 | 0x0200 ) /* filter */ */

/* BIO_TYPE_DGRAM ( 21 | 0x0400 | 0x0100 ) # */

/* BIO_TYPE_ASN1 ( 22 | 0x0200 ) /* filter */ */

/* BIO_TYPE_COMP ( 23 | 0x0200 ) /* filter */ */

/* BIO_TYPE_DESCRIPTOR 0x0100 /* socket, fd, connect or accept */ */
pub const BIO_TYPE_DESCRIPTOR: i32 = 256;

/* BIO_TYPE_FILTER 0x0200 # */
pub const BIO_TYPE_FILTER: i32 = 512;

/* BIO_TYPE_SOURCE_SINK 0x0400 /* BIO_FILENAME_READ|BIO_CLOSE to open or close on free.
 * BIO_set_fp(in,stdin,BIO_NOCLOSE); */ */
pub const BIO_TYPE_SOURCE_SINK: i32 = 1024;

/* BIO_NOCLOSE 0x00 # */
pub const BIO_NOCLOSE: i32 = 0;

/* BIO_CLOSE 0x01 /* These are used in the following macros and are passed to
 * BIO_ctrl() */ */
pub const BIO_CLOSE: i32 = 1;

/* BIO_CTRL_RESET 1 /* opt - rewind/zero etc */ */
pub const BIO_CTRL_RESET: i32 = 1;

/* BIO_CTRL_EOF 2 /* opt - are we at the eof */ */
pub const BIO_CTRL_EOF: i32 = 2;

/* BIO_CTRL_INFO 3 /* opt - extra tit-bits */ */
pub const BIO_CTRL_INFO: i32 = 3;

/* BIO_CTRL_SET 4 /* man - set the 'IO' type */ */
pub const BIO_CTRL_SET: i32 = 4;

/* BIO_CTRL_GET 5 /* man - get the 'IO' type */ */
pub const BIO_CTRL_GET: i32 = 5;

/* BIO_CTRL_PUSH 6 /* opt - internal, used to signify change */ */
pub const BIO_CTRL_PUSH: i32 = 6;

/* BIO_CTRL_POP 7 /* opt - internal, used to signify change */ */
pub const BIO_CTRL_POP: i32 = 7;

/* BIO_CTRL_GET_CLOSE 8 /* man - set the 'close' on free */ */
pub const BIO_CTRL_GET_CLOSE: i32 = 8;

/* BIO_CTRL_SET_CLOSE 9 /* man - set the 'close' on free */ */
pub const BIO_CTRL_SET_CLOSE: i32 = 9;

/* BIO_CTRL_PENDING 10 /* opt - is their more data buffered */ */
pub const BIO_CTRL_PENDING: i32 = 10;

/* BIO_CTRL_FLUSH 11 /* opt - 'flush' buffered output */ */
pub const BIO_CTRL_FLUSH: i32 = 11;

/* BIO_CTRL_DUP 12 /* man - extra stuff for 'duped' BIO */ */
pub const BIO_CTRL_DUP: i32 = 12;

/* BIO_CTRL_WPENDING 13 /* opt - number of bytes still to write */ */
pub const BIO_CTRL_WPENDING: i32 = 13;

/* BIO_CTRL_SET_CALLBACK 14 /* opt - set callback function */ */
pub const BIO_CTRL_SET_CALLBACK: i32 = 14;

/* BIO_CTRL_GET_CALLBACK 15 /* opt - set callback function */ */
pub const BIO_CTRL_GET_CALLBACK: i32 = 15;

/* BIO_CTRL_SET_FILENAME 30 /* BIO_s_file special */ */
pub const BIO_CTRL_SET_FILENAME: i32 = 30;

/* BIO_CTRL_DGRAM_CONNECT 31 /* BIO dgram special */ */
pub const BIO_CTRL_DGRAM_CONNECT: i32 = 31;

/* BIO_CTRL_DGRAM_SET_CONNECTED 32 /* allow for an externally
					  * connected socket to be
					  * passed in */ */
pub const BIO_CTRL_DGRAM_SET_CONNECTED: i32 = 32;

/* BIO_CTRL_DGRAM_SET_RECV_TIMEOUT 33 /* setsockopt, essentially */ */
pub const BIO_CTRL_DGRAM_SET_RECV_TIMEOUT: i32 = 33;

/* BIO_CTRL_DGRAM_GET_RECV_TIMEOUT 34 /* getsockopt, essentially */ */
pub const BIO_CTRL_DGRAM_GET_RECV_TIMEOUT: i32 = 34;

/* BIO_CTRL_DGRAM_SET_SEND_TIMEOUT 35 /* setsockopt, essentially */ */
pub const BIO_CTRL_DGRAM_SET_SEND_TIMEOUT: i32 = 35;

/* BIO_CTRL_DGRAM_GET_SEND_TIMEOUT 36 /* getsockopt, essentially */ */
pub const BIO_CTRL_DGRAM_GET_SEND_TIMEOUT: i32 = 36;

/* BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP 37 /* flag whether the last */ */
pub const BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP: i32 = 37;

/* BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP 38 /* I/O operation tiemd out */ */
pub const BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP: i32 = 38;

/* BIO_CTRL_DGRAM_MTU_DISCOVER 39 /* set DF bit on egress packets */ */
pub const BIO_CTRL_DGRAM_MTU_DISCOVER: i32 = 39;

/* BIO_CTRL_DGRAM_QUERY_MTU 40 /* as kernel for current MTU */ */
pub const BIO_CTRL_DGRAM_QUERY_MTU: i32 = 40;

/* BIO_CTRL_DGRAM_GET_FALLBACK_MTU 47 # */
pub const BIO_CTRL_DGRAM_GET_FALLBACK_MTU: i32 = 47;

/* BIO_CTRL_DGRAM_GET_MTU 41 /* get cached value for MTU */ */
pub const BIO_CTRL_DGRAM_GET_MTU: i32 = 41;

/* BIO_CTRL_DGRAM_SET_MTU 42 /* set cached value for
					      * MTU. want to use this
					      * if asking the kernel
					      * fails */ */
pub const BIO_CTRL_DGRAM_SET_MTU: i32 = 42;

/* BIO_CTRL_DGRAM_MTU_EXCEEDED 43 /* check whether the MTU
					      * was exceed in the
					      * previous write
					      * operation */ */
pub const BIO_CTRL_DGRAM_MTU_EXCEEDED: i32 = 43;

/* BIO_CTRL_DGRAM_GET_PEER 46 # */
pub const BIO_CTRL_DGRAM_GET_PEER: i32 = 46;

/* BIO_CTRL_DGRAM_SET_PEER 44 /* Destination for the data */ */
pub const BIO_CTRL_DGRAM_SET_PEER: i32 = 44;

/* BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT 45 /* Next DTLS handshake timeout to
                                              * adjust socket timeouts */ */
pub const BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT: i32 = 45;

/* BIO_FP_READ 0x02 # */
pub const BIO_FP_READ: i32 = 2;

/* BIO_FP_WRITE 0x04 # */
pub const BIO_FP_WRITE: i32 = 4;

/* BIO_FP_APPEND 0x08 # */
pub const BIO_FP_APPEND: i32 = 8;

/* BIO_FP_TEXT 0x10 # */
pub const BIO_FP_TEXT: i32 = 16;

/* BIO_FLAGS_READ 0x01 # */
pub const BIO_FLAGS_READ: i32 = 1;

/* BIO_FLAGS_WRITE 0x02 # */
pub const BIO_FLAGS_WRITE: i32 = 2;

/* BIO_FLAGS_IO_SPECIAL 0x04 # */
pub const BIO_FLAGS_IO_SPECIAL: i32 = 4;

/* BIO_FLAGS_RWS ( BIO_FLAGS_READ | BIO_FLAGS_WRITE | BIO_FLAGS_IO_SPECIAL ) # */

/* BIO_FLAGS_SHOULD_RETRY 0x08 # */
pub const BIO_FLAGS_SHOULD_RETRY: i32 = 8;

/* BIO_FLAGS_UPLINK 0 # */
pub const BIO_FLAGS_UPLINK: i32 = 0;

/* BIO_GHBN_CTRL_HITS 1 # */
pub const BIO_GHBN_CTRL_HITS: i32 = 1;

/* BIO_GHBN_CTRL_MISSES 2 # */
pub const BIO_GHBN_CTRL_MISSES: i32 = 2;

/* BIO_GHBN_CTRL_CACHE_SIZE 3 # */
pub const BIO_GHBN_CTRL_CACHE_SIZE: i32 = 3;

/* BIO_GHBN_CTRL_GET_ENTRY 4 # */
pub const BIO_GHBN_CTRL_GET_ENTRY: i32 = 4;

/* BIO_GHBN_CTRL_FLUSH 5 /* Mostly used in the SSL BIO */ */
pub const BIO_GHBN_CTRL_FLUSH: i32 = 5;

/* BIO_FLAGS_BASE64_NO_NL 0x100 /* This is used with memory BIOs: it means we shouldn't free up or change the
 * data in any way.
 */ */
pub const BIO_FLAGS_BASE64_NO_NL: i32 = 256;

/* BIO_FLAGS_MEM_RDONLY 0x200 typedef */
pub const BIO_FLAGS_MEM_RDONLY: i32 = 512;

/* BIO_get_flags ( b ) BIO_test_flags ( b , ~ ( 0x0 ) ) # */

/* BIO_set_retry_special ( b ) BIO_set_flags ( b , ( BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY ) ) # */

/* BIO_set_retry_read ( b ) BIO_set_flags ( b , ( BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY ) ) # */

/* BIO_set_retry_write ( b ) BIO_set_flags ( b , ( BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY ) ) /* These are normally used internally in BIOs */ */

/* BIO_clear_retry_flags ( b ) BIO_clear_flags ( b , ( BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY ) ) # */

/* BIO_get_retry_flags ( b ) BIO_test_flags ( b , ( BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY ) ) /* These should be used by the application to tell why we should retry */ */

/* BIO_should_read ( a ) BIO_test_flags ( a , BIO_FLAGS_READ ) # */

/* BIO_should_write ( a ) BIO_test_flags ( a , BIO_FLAGS_WRITE ) # */

/* BIO_should_io_special ( a ) BIO_test_flags ( a , BIO_FLAGS_IO_SPECIAL ) # */

/* BIO_retry_type ( a ) BIO_test_flags ( a , BIO_FLAGS_RWS ) # */

/* BIO_should_retry ( a ) BIO_test_flags ( a , BIO_FLAGS_SHOULD_RETRY ) /* The next three are used in conjunction with the
 * BIO_should_io_special() condition.  After this returns true,
 * BIO *BIO_get_retry_BIO(BIO *bio, int *reason); will walk the BIO 
 * stack and return the 'reason' for the special and the offending BIO.
 * Given a BIO, BIO_get_retry_reason(bio) will return the code. */ */

/* BIO_RR_SSL_X509_LOOKUP 0x01 /* Returned from the connect BIO when a connect would have blocked */ */
pub const BIO_RR_SSL_X509_LOOKUP: i32 = 1;

/* BIO_RR_CONNECT 0x02 /* Returned from the accept BIO when an accept would have blocked */ */
pub const BIO_RR_CONNECT: i32 = 2;

/* BIO_RR_ACCEPT 0x03 /* These are passed by the BIO callback */ */
pub const BIO_RR_ACCEPT: i32 = 3;

/* BIO_CB_FREE 0x01 # */
pub const BIO_CB_FREE: i32 = 1;

/* BIO_CB_READ 0x02 # */
pub const BIO_CB_READ: i32 = 2;

/* BIO_CB_WRITE 0x03 # */
pub const BIO_CB_WRITE: i32 = 3;

/* BIO_CB_PUTS 0x04 # */
pub const BIO_CB_PUTS: i32 = 4;

/* BIO_CB_GETS 0x05 # */
pub const BIO_CB_GETS: i32 = 5;

/* BIO_CB_CTRL 0x06 /* The callback is called before and after the underling operation,
 * The BIO_CB_RETURN flag indicates if it is after the call */ */
pub const BIO_CB_CTRL: i32 = 6;

/* BIO_CB_RETURN 0x80 # */
pub const BIO_CB_RETURN: i32 = 128;

/* BIO_CB_return ( a ) ( ( a ) | BIO_CB_RETURN ) ) # */

/* BIO_cb_pre ( a ) ( ! ( ( a ) & BIO_CB_RETURN ) ) # */

/* BIO_cb_post ( a ) ( ( a ) & BIO_CB_RETURN ) long */

/* BIO_CONN_S_BEFORE 1 # */
pub const BIO_CONN_S_BEFORE: i32 = 1;

/* BIO_CONN_S_GET_IP 2 # */
pub const BIO_CONN_S_GET_IP: i32 = 2;

/* BIO_CONN_S_GET_PORT 3 # */
pub const BIO_CONN_S_GET_PORT: i32 = 3;

/* BIO_CONN_S_CREATE_SOCKET 4 # */
pub const BIO_CONN_S_CREATE_SOCKET: i32 = 4;

/* BIO_CONN_S_CONNECT 5 # */
pub const BIO_CONN_S_CONNECT: i32 = 5;

/* BIO_CONN_S_OK 6 # */
pub const BIO_CONN_S_OK: i32 = 6;

/* BIO_CONN_S_BLOCKED_CONNECT 7 # */
pub const BIO_CONN_S_BLOCKED_CONNECT: i32 = 7;

/* BIO_CONN_S_NBIO 8 /*#define BIO_CONN_get_param_hostname	BIO_ctrl */ */
pub const BIO_CONN_S_NBIO: i32 = 8;

/* BIO_C_SET_CONNECT 100 # */
pub const BIO_C_SET_CONNECT: i32 = 100;

/* BIO_C_DO_STATE_MACHINE 101 # */
pub const BIO_C_DO_STATE_MACHINE: i32 = 101;

/* BIO_C_SET_NBIO 102 # */
pub const BIO_C_SET_NBIO: i32 = 102;

/* BIO_C_SET_PROXY_PARAM 103 # */
pub const BIO_C_SET_PROXY_PARAM: i32 = 103;

/* BIO_C_SET_FD 104 # */
pub const BIO_C_SET_FD: i32 = 104;

/* BIO_C_GET_FD 105 # */
pub const BIO_C_GET_FD: i32 = 105;

/* BIO_C_SET_FILE_PTR 106 # */
pub const BIO_C_SET_FILE_PTR: i32 = 106;

/* BIO_C_GET_FILE_PTR 107 # */
pub const BIO_C_GET_FILE_PTR: i32 = 107;

/* BIO_C_SET_FILENAME 108 # */
pub const BIO_C_SET_FILENAME: i32 = 108;

/* BIO_C_SET_SSL 109 # */
pub const BIO_C_SET_SSL: i32 = 109;

/* BIO_C_GET_SSL 110 # */
pub const BIO_C_GET_SSL: i32 = 110;

/* BIO_C_SET_MD 111 # */
pub const BIO_C_SET_MD: i32 = 111;

/* BIO_C_GET_MD 112 # */
pub const BIO_C_GET_MD: i32 = 112;

/* BIO_C_GET_CIPHER_STATUS 113 # */
pub const BIO_C_GET_CIPHER_STATUS: i32 = 113;

/* BIO_C_SET_BUF_MEM 114 # */
pub const BIO_C_SET_BUF_MEM: i32 = 114;

/* BIO_C_GET_BUF_MEM_PTR 115 # */
pub const BIO_C_GET_BUF_MEM_PTR: i32 = 115;

/* BIO_C_GET_BUFF_NUM_LINES 116 # */
pub const BIO_C_GET_BUFF_NUM_LINES: i32 = 116;

/* BIO_C_SET_BUFF_SIZE 117 # */
pub const BIO_C_SET_BUFF_SIZE: i32 = 117;

/* BIO_C_SET_ACCEPT 118 # */
pub const BIO_C_SET_ACCEPT: i32 = 118;

/* BIO_C_SSL_MODE 119 # */
pub const BIO_C_SSL_MODE: i32 = 119;

/* BIO_C_GET_MD_CTX 120 # */
pub const BIO_C_GET_MD_CTX: i32 = 120;

/* BIO_C_GET_PROXY_PARAM 121 # */
pub const BIO_C_GET_PROXY_PARAM: i32 = 121;

/* BIO_C_SET_BUFF_READ_DATA 122 /* data to read first */ */
pub const BIO_C_SET_BUFF_READ_DATA: i32 = 122;

/* BIO_C_GET_CONNECT 123 # */
pub const BIO_C_GET_CONNECT: i32 = 123;

/* BIO_C_GET_ACCEPT 124 # */
pub const BIO_C_GET_ACCEPT: i32 = 124;

/* BIO_C_SET_SSL_RENEGOTIATE_BYTES 125 # */
pub const BIO_C_SET_SSL_RENEGOTIATE_BYTES: i32 = 125;

/* BIO_C_GET_SSL_NUM_RENEGOTIATES 126 # */
pub const BIO_C_GET_SSL_NUM_RENEGOTIATES: i32 = 126;

/* BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT 127 # */
pub const BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT: i32 = 127;

/* BIO_C_FILE_SEEK 128 # */
pub const BIO_C_FILE_SEEK: i32 = 128;

/* BIO_C_GET_CIPHER_CTX 129 # */
pub const BIO_C_GET_CIPHER_CTX: i32 = 129;

/* BIO_C_SET_BUF_MEM_EOF_RETURN 130 /*return end of input value*/ */
pub const BIO_C_SET_BUF_MEM_EOF_RETURN: i32 = 130;

/* BIO_C_SET_BIND_MODE 131 # */
pub const BIO_C_SET_BIND_MODE: i32 = 131;

/* BIO_C_GET_BIND_MODE 132 # */
pub const BIO_C_GET_BIND_MODE: i32 = 132;

/* BIO_C_FILE_TELL 133 # */
pub const BIO_C_FILE_TELL: i32 = 133;

/* BIO_C_GET_SOCKS 134 # */
pub const BIO_C_GET_SOCKS: i32 = 134;

/* BIO_C_SET_SOCKS 135 # */
pub const BIO_C_SET_SOCKS: i32 = 135;

/* BIO_C_SET_WRITE_BUF_SIZE 136 /* for BIO_s_bio */ */
pub const BIO_C_SET_WRITE_BUF_SIZE: i32 = 136;

/* BIO_C_GET_WRITE_BUF_SIZE 137 # */
pub const BIO_C_GET_WRITE_BUF_SIZE: i32 = 137;

/* BIO_C_MAKE_BIO_PAIR 138 # */
pub const BIO_C_MAKE_BIO_PAIR: i32 = 138;

/* BIO_C_DESTROY_BIO_PAIR 139 # */
pub const BIO_C_DESTROY_BIO_PAIR: i32 = 139;

/* BIO_C_GET_WRITE_GUARANTEE 140 # */
pub const BIO_C_GET_WRITE_GUARANTEE: i32 = 140;

/* BIO_C_GET_READ_REQUEST 141 # */
pub const BIO_C_GET_READ_REQUEST: i32 = 141;

/* BIO_C_SHUTDOWN_WR 142 # */
pub const BIO_C_SHUTDOWN_WR: i32 = 142;

/* BIO_C_NREAD0 143 # */
pub const BIO_C_NREAD0: i32 = 143;

/* BIO_C_NREAD 144 # */
pub const BIO_C_NREAD: i32 = 144;

/* BIO_C_NWRITE0 145 # */
pub const BIO_C_NWRITE0: i32 = 145;

/* BIO_C_NWRITE 146 # */
pub const BIO_C_NWRITE: i32 = 146;

/* BIO_C_RESET_READ_REQUEST 147 # */
pub const BIO_C_RESET_READ_REQUEST: i32 = 147;

/* BIO_C_SET_MD_CTX 148 # */
pub const BIO_C_SET_MD_CTX: i32 = 148;

/* BIO_C_SET_PREFIX 149 # */
pub const BIO_C_SET_PREFIX: i32 = 149;

/* BIO_C_GET_PREFIX 150 # */
pub const BIO_C_GET_PREFIX: i32 = 150;

/* BIO_C_SET_SUFFIX 151 # */
pub const BIO_C_SET_SUFFIX: i32 = 151;

/* BIO_C_GET_SUFFIX 152 # */
pub const BIO_C_GET_SUFFIX: i32 = 152;

/* BIO_C_SET_EX_ARG 153 # */
pub const BIO_C_SET_EX_ARG: i32 = 153;

/* BIO_C_GET_EX_ARG 154 # */
pub const BIO_C_GET_EX_ARG: i32 = 154;

/* BIO_set_app_data ( s , arg ) BIO_set_ex_data ( s , 0 , arg ) # */

/* BIO_get_app_data ( s ) BIO_get_ex_data ( s , 0 ) /* BIO_s_connect() and BIO_s_socks4a_connect() */ */

/* BIO_set_conn_hostname ( b , name ) BIO_ctrl ( b , BIO_C_SET_CONNECT , 0 , ( char * ) name ) # */

/* BIO_set_conn_port ( b , port ) BIO_ctrl ( b , BIO_C_SET_CONNECT , 1 , ( char * ) port ) # */

/* BIO_set_conn_ip ( b , ip ) BIO_ctrl ( b , BIO_C_SET_CONNECT , 2 , ( char * ) ip ) # */

/* BIO_set_conn_int_port ( b , port ) BIO_ctrl ( b , BIO_C_SET_CONNECT , 3 , ( char * ) port ) # */

/* BIO_get_conn_hostname ( b ) BIO_ptr_ctrl ( b , BIO_C_GET_CONNECT , 0 ) # */

/* BIO_get_conn_port ( b ) BIO_ptr_ctrl ( b , BIO_C_GET_CONNECT , 1 ) # */

/* BIO_get_conn_ip ( b ) BIO_ptr_ctrl ( b , BIO_C_GET_CONNECT , 2 ) # */

/* BIO_get_conn_int_port ( b ) BIO_int_ctrl ( b , BIO_C_GET_CONNECT , 3 , 0 ) # */

/* BIO_set_nbio ( b , n ) BIO_ctrl ( b , BIO_C_SET_NBIO , ( n ) , NULL ) /* BIO_s_accept_socket() */ */

/* BIO_set_accept_port ( b , name ) BIO_ctrl ( b , BIO_C_SET_ACCEPT , 0 , ( char * ) name ) # */

/* BIO_get_accept_port ( b ) BIO_ptr_ctrl ( b , BIO_C_GET_ACCEPT , 0 ) /* #define BIO_set_nbio(b,n)	BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL) */ */

/* BIO_set_nbio_accept ( b , n ) BIO_ctrl ( b , BIO_C_SET_ACCEPT , 1 , ( n ) ? ( void * ) "a" : NULL ) # */

/* BIO_set_accept_bios ( b , bio ) BIO_ctrl ( b , BIO_C_SET_ACCEPT , 2 , ( char * ) bio ) # */

/* BIO_BIND_NORMAL 0 # */
pub const BIO_BIND_NORMAL: i32 = 0;

/* BIO_BIND_REUSEADDR_IF_UNUSED 1 # */
pub const BIO_BIND_REUSEADDR_IF_UNUSED: i32 = 1;

/* BIO_BIND_REUSEADDR 2 # */
pub const BIO_BIND_REUSEADDR: i32 = 2;

/* BIO_set_bind_mode ( b , mode ) BIO_ctrl ( b , BIO_C_SET_BIND_MODE , mode , NULL ) # */

/* BIO_get_bind_mode ( b , mode ) BIO_ctrl ( b , BIO_C_GET_BIND_MODE , 0 , NULL ) # */

/* BIO_do_connect ( b ) BIO_do_handshake ( b ) # */

/* BIO_do_accept ( b ) BIO_do_handshake ( b ) # */

/* BIO_do_handshake ( b ) BIO_ctrl ( b , BIO_C_DO_STATE_MACHINE , 0 , NULL ) /* BIO_s_proxy_client() */ */

/* BIO_set_url ( b , url ) BIO_ctrl ( b , BIO_C_SET_PROXY_PARAM , 0 , ( char * ) ( url ) ) # */

/* BIO_set_proxies ( b , p ) BIO_ctrl ( b , BIO_C_SET_PROXY_PARAM , 1 , ( char * ) ( p ) ) /* BIO_set_nbio(b,n) */ */

/* BIO_set_filter_bio ( b , s ) BIO_ctrl ( b , BIO_C_SET_PROXY_PARAM , 2 , ( char * ) ( s ) ) /* BIO *BIO_get_filter_bio(BIO *bio); */ */

/* BIO_set_proxy_cb ( b , cb ) BIO_callback_ctrl ( b , BIO_C_SET_PROXY_PARAM , 3 , ( void * ( * cb ) ( ) ) ) # */

/* BIO_set_proxy_header ( b , sk ) BIO_ctrl ( b , BIO_C_SET_PROXY_PARAM , 4 , ( char * ) sk ) # */

/* BIO_set_no_connect_return ( b , bool ) BIO_int_ctrl ( b , BIO_C_SET_PROXY_PARAM , 5 , bool ) # */

/* BIO_get_proxy_header ( b , skp ) BIO_ctrl ( b , BIO_C_GET_PROXY_PARAM , 0 , ( char * ) skp ) # */

/* BIO_get_proxies ( b , pxy_p ) BIO_ctrl ( b , BIO_C_GET_PROXY_PARAM , 1 , ( char * ) ( pxy_p ) ) # */

/* BIO_get_url ( b , url ) BIO_ctrl ( b , BIO_C_GET_PROXY_PARAM , 2 , ( char * ) ( url ) ) # */

/* BIO_get_no_connect_return ( b ) BIO_ctrl ( b , BIO_C_GET_PROXY_PARAM , 5 , NULL ) # */

/* BIO_set_fd ( b , fd , c ) BIO_int_ctrl ( b , BIO_C_SET_FD , c , fd ) # */

/* BIO_get_fd ( b , c ) BIO_ctrl ( b , BIO_C_GET_FD , 0 , ( char * ) c ) # */

/* BIO_set_fp ( b , fp , c ) BIO_ctrl ( b , BIO_C_SET_FILE_PTR , c , ( char * ) fp ) # */

/* BIO_get_fp ( b , fpp ) BIO_ctrl ( b , BIO_C_GET_FILE_PTR , 0 , ( char * ) fpp ) # */

/* BIO_seek ( b , ofs ) ( int ) BIO_ctrl ( b , BIO_C_FILE_SEEK , ofs , NULL ) # */

/* BIO_tell ( b ) ( int ) BIO_ctrl ( b , BIO_C_FILE_TELL , 0 , NULL ) /* name is cast to lose const, but might be better to route through a function
   so we can do it safely */ */

/* BIO_read_filename ( b , name ) BIO_ctrl ( b , BIO_C_SET_FILENAME , BIO_CLOSE | BIO_FP_READ , ( char * ) name ) # */

/* BIO_write_filename ( b , name ) BIO_ctrl ( b , BIO_C_SET_FILENAME , BIO_CLOSE | BIO_FP_WRITE , name ) # */

/* BIO_append_filename ( b , name ) BIO_ctrl ( b , BIO_C_SET_FILENAME , BIO_CLOSE | BIO_FP_APPEND , name ) # */

/* BIO_rw_filename ( b , name ) BIO_ctrl ( b , BIO_C_SET_FILENAME , BIO_CLOSE | BIO_FP_READ | BIO_FP_WRITE , name ) /* WARNING WARNING, this ups the reference count on the read bio of the
 * SSL structure.  This is because the ssl read BIO is now pointed to by
 * the next_bio field in the bio.  So when you free the BIO, make sure
 * you are doing a BIO_free_all() to catch the underlying BIO. */ */

/* BIO_set_ssl ( b , ssl , c ) BIO_ctrl ( b , BIO_C_SET_SSL , c , ( char * ) ssl ) # */

/* BIO_get_ssl ( b , sslp ) BIO_ctrl ( b , BIO_C_GET_SSL , 0 , ( char * ) sslp ) # */

/* BIO_set_ssl_mode ( b , client ) BIO_ctrl ( b , BIO_C_SSL_MODE , client , NULL ) # */

/* BIO_set_ssl_renegotiate_bytes ( b , num ) BIO_ctrl ( b , BIO_C_SET_SSL_RENEGOTIATE_BYTES , num , NULL ) ; # */

/* BIO_get_num_renegotiates ( b ) BIO_ctrl ( b , BIO_C_GET_SSL_NUM_RENEGOTIATES , 0 , NULL ) ; # */

/* BIO_set_ssl_renegotiate_timeout ( b , seconds ) BIO_ctrl ( b , BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT , seconds , NULL ) ; /* defined in evp.h */ */

/* BIO_get_mem_data ( b , pp ) BIO_ctrl ( b , BIO_CTRL_INFO , 0 , ( char * ) pp ) # */

/* BIO_set_mem_buf ( b , bm , c ) BIO_ctrl ( b , BIO_C_SET_BUF_MEM , c , ( char * ) bm ) # */

/* BIO_get_mem_ptr ( b , pp ) BIO_ctrl ( b , BIO_C_GET_BUF_MEM_PTR , 0 , ( char * ) pp ) # */

/* BIO_set_mem_eof_return ( b , v ) BIO_ctrl ( b , BIO_C_SET_BUF_MEM_EOF_RETURN , v , NULL ) /* For the BIO_f_buffer() type */ */

/* BIO_get_buffer_num_lines ( b ) BIO_ctrl ( b , BIO_C_GET_BUFF_NUM_LINES , 0 , NULL ) # */

/* BIO_set_buffer_size ( b , size ) BIO_ctrl ( b , BIO_C_SET_BUFF_SIZE , size , NULL ) # */

/* BIO_set_read_buffer_size ( b , size ) BIO_int_ctrl ( b , BIO_C_SET_BUFF_SIZE , size , 0 ) # */

/* BIO_set_write_buffer_size ( b , size ) BIO_int_ctrl ( b , BIO_C_SET_BUFF_SIZE , size , 1 ) # */

/* BIO_set_buffer_read_data ( b , buf , num ) BIO_ctrl ( b , BIO_C_SET_BUFF_READ_DATA , num , buf ) /* Don't use the next one unless you know what you are doing :-) */ */

/* BIO_dup_state ( b , ret ) BIO_ctrl ( b , BIO_CTRL_DUP , 0 , ( char * ) ( ret ) ) # */

/* BIO_reset ( b ) ( int ) BIO_ctrl ( b , BIO_CTRL_RESET , 0 , NULL ) # */

/* BIO_eof ( b ) ( int ) BIO_ctrl ( b , BIO_CTRL_EOF , 0 , NULL ) # */

/* BIO_set_close ( b , c ) ( int ) BIO_ctrl ( b , BIO_CTRL_SET_CLOSE , ( c ) , NULL ) # */

/* BIO_get_close ( b ) ( int ) BIO_ctrl ( b , BIO_CTRL_GET_CLOSE , 0 , NULL ) # */

/* BIO_pending ( b ) ( int ) BIO_ctrl ( b , BIO_CTRL_PENDING , 0 , NULL ) # */

/* BIO_wpending ( b ) ( int ) BIO_ctrl ( b , BIO_CTRL_WPENDING , 0 , NULL ) /* ...pending macros have inappropriate return type */ */

/* BIO_flush ( b ) ( int ) BIO_ctrl ( b , BIO_CTRL_FLUSH , 0 , NULL ) # */

/* BIO_get_info_callback ( b , cbp ) ( int ) BIO_ctrl ( b , BIO_CTRL_GET_CALLBACK , 0 , cbp ) # */

/* BIO_set_info_callback ( b , cb ) ( int ) BIO_callback_ctrl ( b , BIO_CTRL_SET_CALLBACK , cb ) /* For the BIO_f_buffer() type */ */

/* BIO_buffer_get_num_lines ( b ) BIO_ctrl ( b , BIO_CTRL_GET , 0 , NULL ) /* For BIO_s_bio() */ */

/* BIO_set_write_buf_size ( b , size ) ( int ) BIO_ctrl ( b , BIO_C_SET_WRITE_BUF_SIZE , size , NULL ) # */

/* BIO_get_write_buf_size ( b , size ) ( size_t ) BIO_ctrl ( b , BIO_C_GET_WRITE_BUF_SIZE , size , NULL ) # */

/* BIO_make_bio_pair ( b1 , b2 ) ( int ) BIO_ctrl ( b1 , BIO_C_MAKE_BIO_PAIR , 0 , b2 ) # */

/* BIO_destroy_bio_pair ( b ) ( int ) BIO_ctrl ( b , BIO_C_DESTROY_BIO_PAIR , 0 , NULL ) # */

/* BIO_shutdown_wr ( b ) ( int ) BIO_ctrl ( b , BIO_C_SHUTDOWN_WR , 0 , NULL ) /* macros with inappropriate type -- but ...pending macros use int too: */ */

/* BIO_get_write_guarantee ( b ) ( int ) BIO_ctrl ( b , BIO_C_GET_WRITE_GUARANTEE , 0 , NULL ) # */

/* BIO_get_read_request ( b ) ( int ) BIO_ctrl ( b , BIO_C_GET_READ_REQUEST , 0 , NULL ) size_t */

/* BIO_ctrl_dgram_connect ( b , peer ) ( int ) BIO_ctrl ( b , BIO_CTRL_DGRAM_CONNECT , 0 , ( char * ) peer ) # */

/* BIO_ctrl_set_connected ( b , state , peer ) ( int ) BIO_ctrl ( b , BIO_CTRL_DGRAM_SET_CONNECTED , state , ( char * ) peer ) # */

/* BIO_dgram_recv_timedout ( b ) ( int ) BIO_ctrl ( b , BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP , 0 , NULL ) # */

/* BIO_dgram_send_timedout ( b ) ( int ) BIO_ctrl ( b , BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP , 0 , NULL ) # */

/* BIO_dgram_get_peer ( b , peer ) ( int ) BIO_ctrl ( b , BIO_CTRL_DGRAM_GET_PEER , 0 , ( char * ) peer ) # */

/* BIO_dgram_set_peer ( b , peer ) ( int ) BIO_ctrl ( b , BIO_CTRL_DGRAM_SET_PEER , 0 , ( char * ) peer ) /* These two aren't currently implemented */ */

/* BIO_s_file_internal BIO_s_file # */

/* __bio_h__attr__ __attribute__ # */

/* BIO_F_ACPT_STATE 100 # */
pub const BIO_F_ACPT_STATE: i32 = 100;

/* BIO_F_BIO_ACCEPT 101 # */
pub const BIO_F_BIO_ACCEPT: i32 = 101;

/* BIO_F_BIO_BER_GET_HEADER 102 # */
pub const BIO_F_BIO_BER_GET_HEADER: i32 = 102;

/* BIO_F_BIO_CALLBACK_CTRL 131 # */
pub const BIO_F_BIO_CALLBACK_CTRL: i32 = 131;

/* BIO_F_BIO_CTRL 103 # */
pub const BIO_F_BIO_CTRL: i32 = 103;

/* BIO_F_BIO_GETHOSTBYNAME 120 # */
pub const BIO_F_BIO_GETHOSTBYNAME: i32 = 120;

/* BIO_F_BIO_GETS 104 # */
pub const BIO_F_BIO_GETS: i32 = 104;

/* BIO_F_BIO_GET_ACCEPT_SOCKET 105 # */
pub const BIO_F_BIO_GET_ACCEPT_SOCKET: i32 = 105;

/* BIO_F_BIO_GET_HOST_IP 106 # */
pub const BIO_F_BIO_GET_HOST_IP: i32 = 106;

/* BIO_F_BIO_GET_PORT 107 # */
pub const BIO_F_BIO_GET_PORT: i32 = 107;

/* BIO_F_BIO_MAKE_PAIR 121 # */
pub const BIO_F_BIO_MAKE_PAIR: i32 = 121;

/* BIO_F_BIO_NEW 108 # */
pub const BIO_F_BIO_NEW: i32 = 108;

/* BIO_F_BIO_NEW_FILE 109 # */
pub const BIO_F_BIO_NEW_FILE: i32 = 109;

/* BIO_F_BIO_NEW_MEM_BUF 126 # */
pub const BIO_F_BIO_NEW_MEM_BUF: i32 = 126;

/* BIO_F_BIO_NREAD 123 # */
pub const BIO_F_BIO_NREAD: i32 = 123;

/* BIO_F_BIO_NREAD0 124 # */
pub const BIO_F_BIO_NREAD0: i32 = 124;

/* BIO_F_BIO_NWRITE 125 # */
pub const BIO_F_BIO_NWRITE: i32 = 125;

/* BIO_F_BIO_NWRITE0 122 # */
pub const BIO_F_BIO_NWRITE0: i32 = 122;

/* BIO_F_BIO_PUTS 110 # */
pub const BIO_F_BIO_PUTS: i32 = 110;

/* BIO_F_BIO_READ 111 # */
pub const BIO_F_BIO_READ: i32 = 111;

/* BIO_F_BIO_SOCK_INIT 112 # */
pub const BIO_F_BIO_SOCK_INIT: i32 = 112;

/* BIO_F_BIO_WRITE 113 # */
pub const BIO_F_BIO_WRITE: i32 = 113;

/* BIO_F_BUFFER_CTRL 114 # */
pub const BIO_F_BUFFER_CTRL: i32 = 114;

/* BIO_F_CONN_CTRL 127 # */
pub const BIO_F_CONN_CTRL: i32 = 127;

/* BIO_F_CONN_STATE 115 # */
pub const BIO_F_CONN_STATE: i32 = 115;

/* BIO_F_DGRAM_SCTP_READ 132 # */
pub const BIO_F_DGRAM_SCTP_READ: i32 = 132;

/* BIO_F_FILE_CTRL 116 # */
pub const BIO_F_FILE_CTRL: i32 = 116;

/* BIO_F_FILE_READ 130 # */
pub const BIO_F_FILE_READ: i32 = 130;

/* BIO_F_LINEBUFFER_CTRL 129 # */
pub const BIO_F_LINEBUFFER_CTRL: i32 = 129;

/* BIO_F_MEM_READ 128 # */
pub const BIO_F_MEM_READ: i32 = 128;

/* BIO_F_MEM_WRITE 117 # */
pub const BIO_F_MEM_WRITE: i32 = 117;

/* BIO_F_SSL_NEW 118 # */
pub const BIO_F_SSL_NEW: i32 = 118;

/* BIO_F_WSASTARTUP 119 /* Reason codes. */ */
pub const BIO_F_WSASTARTUP: i32 = 119;

/* BIO_R_ACCEPT_ERROR 100 # */
pub const BIO_R_ACCEPT_ERROR: i32 = 100;

/* BIO_R_BAD_FOPEN_MODE 101 # */
pub const BIO_R_BAD_FOPEN_MODE: i32 = 101;

/* BIO_R_BAD_HOSTNAME_LOOKUP 102 # */
pub const BIO_R_BAD_HOSTNAME_LOOKUP: i32 = 102;

/* BIO_R_BROKEN_PIPE 124 # */
pub const BIO_R_BROKEN_PIPE: i32 = 124;

/* BIO_R_CONNECT_ERROR 103 # */
pub const BIO_R_CONNECT_ERROR: i32 = 103;

/* BIO_R_EOF_ON_MEMORY_BIO 127 # */
pub const BIO_R_EOF_ON_MEMORY_BIO: i32 = 127;

/* BIO_R_ERROR_SETTING_NBIO 104 # */
pub const BIO_R_ERROR_SETTING_NBIO: i32 = 104;

/* BIO_R_ERROR_SETTING_NBIO_ON_ACCEPTED_SOCKET 105 # */
pub const BIO_R_ERROR_SETTING_NBIO_ON_ACCEPTED_SOCKET: i32 = 105;

/* BIO_R_ERROR_SETTING_NBIO_ON_ACCEPT_SOCKET 106 # */
pub const BIO_R_ERROR_SETTING_NBIO_ON_ACCEPT_SOCKET: i32 = 106;

/* BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET 107 # */
pub const BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET: i32 = 107;

/* BIO_R_INVALID_ARGUMENT 125 # */
pub const BIO_R_INVALID_ARGUMENT: i32 = 125;

/* BIO_R_INVALID_IP_ADDRESS 108 # */
pub const BIO_R_INVALID_IP_ADDRESS: i32 = 108;

/* BIO_R_IN_USE 123 # */
pub const BIO_R_IN_USE: i32 = 123;

/* BIO_R_KEEPALIVE 109 # */
pub const BIO_R_KEEPALIVE: i32 = 109;

/* BIO_R_NBIO_CONNECT_ERROR 110 # */
pub const BIO_R_NBIO_CONNECT_ERROR: i32 = 110;

/* BIO_R_NO_ACCEPT_PORT_SPECIFIED 111 # */
pub const BIO_R_NO_ACCEPT_PORT_SPECIFIED: i32 = 111;

/* BIO_R_NO_HOSTNAME_SPECIFIED 112 # */
pub const BIO_R_NO_HOSTNAME_SPECIFIED: i32 = 112;

/* BIO_R_NO_PORT_DEFINED 113 # */
pub const BIO_R_NO_PORT_DEFINED: i32 = 113;

/* BIO_R_NO_PORT_SPECIFIED 114 # */
pub const BIO_R_NO_PORT_SPECIFIED: i32 = 114;

/* BIO_R_NO_SUCH_FILE 128 # */
pub const BIO_R_NO_SUCH_FILE: i32 = 128;

/* BIO_R_NULL_PARAMETER 115 # */
pub const BIO_R_NULL_PARAMETER: i32 = 115;

/* BIO_R_TAG_MISMATCH 116 # */
pub const BIO_R_TAG_MISMATCH: i32 = 116;

/* BIO_R_UNABLE_TO_BIND_SOCKET 117 # */
pub const BIO_R_UNABLE_TO_BIND_SOCKET: i32 = 117;

/* BIO_R_UNABLE_TO_CREATE_SOCKET 118 # */
pub const BIO_R_UNABLE_TO_CREATE_SOCKET: i32 = 118;

/* BIO_R_UNABLE_TO_LISTEN_SOCKET 119 # */
pub const BIO_R_UNABLE_TO_LISTEN_SOCKET: i32 = 119;

/* BIO_R_UNINITIALIZED 120 # */
pub const BIO_R_UNINITIALIZED: i32 = 120;

/* BIO_R_UNSUPPORTED_METHOD 121 # */
pub const BIO_R_UNSUPPORTED_METHOD: i32 = 121;

/* BIO_R_WRITE_TO_READ_ONLY_BIO 126 # */
pub const BIO_R_WRITE_TO_READ_ONLY_BIO: i32 = 126;

/* BIO_R_WSASTARTUP 122 # */
pub const BIO_R_WSASTARTUP: i32 = 122;

/* HEADER_BN_H # */

/* OPENSSL_CPUID_OBJ /* crypto/opensslconf.h.in */ */

/* OPENSSL_UNISTD < unistd . h > # */

/* CONFIG_HEADER_BN_H # */

/* SIXTY_FOUR_BIT_LONG # */

/* BN_MUL_COMBA # */

/* BN_SQR_COMBA # */

/* BN_RECURSION # */

/* BN_DIV2W # */

/* BN_ULLONG unsigned long long # */

/* BN_ULONG unsigned long # */

/* BN_LONG long # */

/* BN_BITS 128 # */
pub const BN_BITS: i32 = 128;

/* BN_BYTES 8 # */
pub const BN_BYTES: i32 = 8;

/* BN_BITS2 64 # */
pub const BN_BITS2: i32 = 64;

/* BN_BITS4 32 # */
pub const BN_BITS4: i32 = 32;

/* BN_MASK ( 0xffffffffffffffffffffffffffffffffLL ) # */

/* BN_MASK2 ( 0xffffffffffffffffL ) # */

/* BN_MASK2l ( 0xffffffffL ) # */

/* BN_MASK2h ( 0xffffffff00000000L ) # */

/* BN_MASK2h1 ( 0xffffffff80000000L ) # */

/* BN_TBIT ( 0x8000000000000000L ) # */

/* BN_DEC_CONV ( 10000000000000000000UL ) # */

/* BN_DEC_FMT1 "%lu" # */

/* BN_DEC_FMT2 "%019lu" # */

/* BN_DEC_NUM 19 # */
pub const BN_DEC_NUM: i32 = 19;

/* BN_HEX_FMT1 "%lX" # */

/* BN_HEX_FMT2 "%016lX" # */

/* PTR_SIZE_INT size_t # */

/* BN_DEFAULT_BITS 1280 # */
pub const BN_DEFAULT_BITS: i32 = 1280;

/* BN_FLG_MALLOCED 0x01 # */
pub const BN_FLG_MALLOCED: i32 = 1;

/* BN_FLG_STATIC_DATA 0x02 # */
pub const BN_FLG_STATIC_DATA: i32 = 2;

/* BN_FLG_CONSTTIME 0x04 /* avoid leaking exponent information through timing,
                                      * BN_mod_exp_mont() will call BN_mod_exp_mont_consttime,
                                      * BN_div() will call BN_div_no_branch,
                                      * BN_mod_inverse() will call BN_mod_inverse_no_branch.
                                      */ */
pub const BN_FLG_CONSTTIME: i32 = 4;

/* BN_FLG_EXP_CONSTTIME BN_FLG_CONSTTIME /* deprecated name for the flag */ */

/* BN_FLG_FREE 0x8000 /* used for debuging */ */
pub const BN_FLG_FREE: i32 = 32768;

/* BN_set_flags ( b , n ) ( ( b ) -> flags |= ( n ) ) # */

/* BN_get_flags ( b , n ) ( ( b ) -> flags & ( n ) ) /* get a clone of a BIGNUM with changed flags, for *temporary* use only
 * (the two BIGNUMs cannot not be used in parallel!) */ */

/* BN_with_flags ( dest , b , n ) ( ( dest ) -> d = ( b ) -> d , ( dest ) -> top = ( b ) -> top , ( dest ) -> dmax = ( b ) -> dmax , ( dest ) -> neg = ( b ) -> neg , ( dest ) -> flags = ( ( ( dest ) -> flags & BN_FLG_MALLOCED ) | ( ( b ) -> flags & ~ BN_FLG_MALLOCED ) | BN_FLG_STATIC_DATA | ( n ) ) ) /* Already declared in ossl_typ.h */ */

/* BN_GENCB_set_old ( gencb , callback , cb_arg ) { BN_GENCB * tmp_gencb = ( gencb ) ; tmp_gencb -> ver = 1 ; tmp_gencb -> arg = ( cb_arg ) ; tmp_gencb -> cb . cb_1 = ( callback ) ; } /* Macro to populate a BN_GENCB structure with a "new"-style callback */ */

/* BN_GENCB_set ( gencb , callback , cb_arg ) { BN_GENCB * tmp_gencb = ( gencb ) ; tmp_gencb -> ver = 2 ; tmp_gencb -> arg = ( cb_arg ) ; tmp_gencb -> cb . cb_2 = ( callback ) ; } # */

/* BN_prime_checks 0 /* default: select number of iterations
			     based on the size of the number */ */
pub const BN_prime_checks: i32 = 0;

/* BN_prime_checks_for_size ( b ) ( ( b ) >= 1300 ? 2 : ( b ) >= 850 ? 3 : ( b ) >= 650 ? 4 : ( b ) >= 550 ? 5 : ( b ) >= 450 ? 6 : ( b ) >= 400 ? 7 : ( b ) >= 350 ? 8 : ( b ) >= 300 ? 9 : ( b ) >= 250 ? 12 : ( b ) >= 200 ? 15 : ( b ) >= 150 ? 18 : /* b >= 100 */ 27 ) # */

/* BN_num_bytes ( a ) ( ( BN_num_bits ( a ) + 7 ) / 8 ) /* Note that BN_abs_is_word didn't work reliably for w == 0 until 0.9.8 */ */

/* BN_abs_is_word ( a , w ) ( ( ( ( a ) -> top == 1 ) && ( ( a ) -> d [ 0 ] == ( BN_ULONG ) ( w ) ) ) || ( ( ( w ) == 0 ) && ( ( a ) -> top == 0 ) ) ) # */

/* BN_is_zero ( a ) ( ( a ) -> top == 0 ) # */

/* BN_is_one ( a ) ( BN_abs_is_word ( ( a ) , 1 ) && ! ( a ) -> neg ) # */

/* BN_is_word ( a , w ) ( BN_abs_is_word ( ( a ) , ( w ) ) && ( ! ( w ) || ! ( a ) -> neg ) ) # */

/* BN_is_odd ( a ) ( ( ( a ) -> top > 0 ) && ( ( a ) -> d [ 0 ] & 1 ) ) # */

/* BN_one ( a ) ( BN_set_word ( ( a ) , 1 ) ) # */

/* BN_zero_ex ( a ) do { BIGNUM * _tmp_bn = ( a ) ; _tmp_bn -> top = 0 ; _tmp_bn -> neg = 0 ; } while ( 0 ) # */

/* BN_zero ( a ) ( BN_set_word ( ( a ) , 0 ) ) # */

/* BN_is_negative ( a ) ( ( a ) -> neg != 0 ) int */

/* BN_mod ( rem , m , d , ctx ) BN_div ( NULL , ( rem ) , ( m ) , ( d ) , ( ctx ) ) int */

/* BN_to_montgomery ( r , a , mont , ctx ) BN_mod_mul_montgomery ( ( r ) , ( a ) , & ( ( mont ) -> RR ) , ( mont ) , ( ctx ) ) int */

/* BN_BLINDING_NO_UPDATE 0x00000001 # */
pub const BN_BLINDING_NO_UPDATE: i32 = 1;

/* BN_BLINDING_NO_RECREATE 0x00000002 BN_BLINDING */
pub const BN_BLINDING_NO_RECREATE: i32 = 2;

/* BN_GF2m_sub ( r , a , b ) BN_GF2m_add ( r , a , b ) int */

/* BN_GF2m_cmp ( a , b ) BN_ucmp ( ( a ) , ( b ) ) /* Some functions allow for representation of the irreducible polynomials
 * as an unsigned int[], say p.  The irreducible f(t) is then of the form:
 *     t^p[0] + t^p[1] + ... + t^p[k]
 * where m = p[0] > p[1] > ... > p[k] = 0.
 */ */

/* bn_expand ( a , bits ) ( ( ( ( ( ( bits + BN_BITS2 - 1 ) ) / BN_BITS2 ) ) <= ( a ) -> dmax ) ? ( a ) : bn_expand2 ( ( a ) , ( bits + BN_BITS2 - 1 ) / BN_BITS2 ) ) # */

/* bn_wexpand ( a , words ) ( ( ( words ) <= ( a ) -> dmax ) ? ( a ) : bn_expand2 ( ( a ) , ( words ) ) ) BIGNUM */

/* bn_pollute ( a ) # */

/* bn_check_top ( a ) # */

/* bn_fix_top ( a ) bn_correct_top ( a ) # */

/* bn_check_size ( bn , bits ) # */

/* bn_wcheck_size ( bn , words ) # */

/* bn_correct_top ( a ) { BN_ULONG * ftl ; int tmp_top = ( a ) -> top ; if ( tmp_top > 0 ) { for ( ftl = & ( ( a ) -> d [ tmp_top - 1 ] ) ; tmp_top > 0 ; tmp_top -- ) if ( * ( ftl -- ) ) break ; ( a ) -> top = tmp_top ; } bn_pollute ( a ) ; } BN_ULONG */

/* BN_F_BNRAND 127 # */
pub const BN_F_BNRAND: i32 = 127;

/* BN_F_BN_BLINDING_CONVERT_EX 100 # */
pub const BN_F_BN_BLINDING_CONVERT_EX: i32 = 100;

/* BN_F_BN_BLINDING_CREATE_PARAM 128 # */
pub const BN_F_BN_BLINDING_CREATE_PARAM: i32 = 128;

/* BN_F_BN_BLINDING_INVERT_EX 101 # */
pub const BN_F_BN_BLINDING_INVERT_EX: i32 = 101;

/* BN_F_BN_BLINDING_NEW 102 # */
pub const BN_F_BN_BLINDING_NEW: i32 = 102;

/* BN_F_BN_BLINDING_UPDATE 103 # */
pub const BN_F_BN_BLINDING_UPDATE: i32 = 103;

/* BN_F_BN_BN2DEC 104 # */
pub const BN_F_BN_BN2DEC: i32 = 104;

/* BN_F_BN_BN2HEX 105 # */
pub const BN_F_BN_BN2HEX: i32 = 105;

/* BN_F_BN_CTX_GET 116 # */
pub const BN_F_BN_CTX_GET: i32 = 116;

/* BN_F_BN_CTX_NEW 106 # */
pub const BN_F_BN_CTX_NEW: i32 = 106;

/* BN_F_BN_CTX_START 129 # */
pub const BN_F_BN_CTX_START: i32 = 129;

/* BN_F_BN_DIV 107 # */
pub const BN_F_BN_DIV: i32 = 107;

/* BN_F_BN_DIV_NO_BRANCH 138 # */
pub const BN_F_BN_DIV_NO_BRANCH: i32 = 138;

/* BN_F_BN_DIV_RECP 130 # */
pub const BN_F_BN_DIV_RECP: i32 = 130;

/* BN_F_BN_EXP 123 # */
pub const BN_F_BN_EXP: i32 = 123;

/* BN_F_BN_EXPAND2 108 # */
pub const BN_F_BN_EXPAND2: i32 = 108;

/* BN_F_BN_EXPAND_INTERNAL 120 # */
pub const BN_F_BN_EXPAND_INTERNAL: i32 = 120;

/* BN_F_BN_GF2M_MOD 131 # */
pub const BN_F_BN_GF2M_MOD: i32 = 131;

/* BN_F_BN_GF2M_MOD_EXP 132 # */
pub const BN_F_BN_GF2M_MOD_EXP: i32 = 132;

/* BN_F_BN_GF2M_MOD_MUL 133 # */
pub const BN_F_BN_GF2M_MOD_MUL: i32 = 133;

/* BN_F_BN_GF2M_MOD_SOLVE_QUAD 134 # */
pub const BN_F_BN_GF2M_MOD_SOLVE_QUAD: i32 = 134;

/* BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR 135 # */
pub const BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR: i32 = 135;

/* BN_F_BN_GF2M_MOD_SQR 136 # */
pub const BN_F_BN_GF2M_MOD_SQR: i32 = 136;

/* BN_F_BN_GF2M_MOD_SQRT 137 # */
pub const BN_F_BN_GF2M_MOD_SQRT: i32 = 137;

/* BN_F_BN_MOD_EXP2_MONT 118 # */
pub const BN_F_BN_MOD_EXP2_MONT: i32 = 118;

/* BN_F_BN_MOD_EXP_MONT 109 # */
pub const BN_F_BN_MOD_EXP_MONT: i32 = 109;

/* BN_F_BN_MOD_EXP_MONT_CONSTTIME 124 # */
pub const BN_F_BN_MOD_EXP_MONT_CONSTTIME: i32 = 124;

/* BN_F_BN_MOD_EXP_MONT_WORD 117 # */
pub const BN_F_BN_MOD_EXP_MONT_WORD: i32 = 117;

/* BN_F_BN_MOD_EXP_RECP 125 # */
pub const BN_F_BN_MOD_EXP_RECP: i32 = 125;

/* BN_F_BN_MOD_EXP_SIMPLE 126 # */
pub const BN_F_BN_MOD_EXP_SIMPLE: i32 = 126;

/* BN_F_BN_MOD_INVERSE 110 # */
pub const BN_F_BN_MOD_INVERSE: i32 = 110;

/* BN_F_BN_MOD_INVERSE_NO_BRANCH 139 # */
pub const BN_F_BN_MOD_INVERSE_NO_BRANCH: i32 = 139;

/* BN_F_BN_MOD_LSHIFT_QUICK 119 # */
pub const BN_F_BN_MOD_LSHIFT_QUICK: i32 = 119;

/* BN_F_BN_MOD_MUL_RECIPROCAL 111 # */
pub const BN_F_BN_MOD_MUL_RECIPROCAL: i32 = 111;

/* BN_F_BN_MOD_SQRT 121 # */
pub const BN_F_BN_MOD_SQRT: i32 = 121;

/* BN_F_BN_MPI2BN 112 # */
pub const BN_F_BN_MPI2BN: i32 = 112;

/* BN_F_BN_NEW 113 # */
pub const BN_F_BN_NEW: i32 = 113;

/* BN_F_BN_RAND 114 # */
pub const BN_F_BN_RAND: i32 = 114;

/* BN_F_BN_RAND_RANGE 122 # */
pub const BN_F_BN_RAND_RANGE: i32 = 122;

/* BN_F_BN_USUB 115 /* Reason codes. */ */
pub const BN_F_BN_USUB: i32 = 115;

/* BN_R_ARG2_LT_ARG3 100 # */
pub const BN_R_ARG2_LT_ARG3: i32 = 100;

/* BN_R_BAD_RECIPROCAL 101 # */
pub const BN_R_BAD_RECIPROCAL: i32 = 101;

/* BN_R_BIGNUM_TOO_LONG 114 # */
pub const BN_R_BIGNUM_TOO_LONG: i32 = 114;

/* BN_R_CALLED_WITH_EVEN_MODULUS 102 # */
pub const BN_R_CALLED_WITH_EVEN_MODULUS: i32 = 102;

/* BN_R_DIV_BY_ZERO 103 # */
pub const BN_R_DIV_BY_ZERO: i32 = 103;

/* BN_R_ENCODING_ERROR 104 # */
pub const BN_R_ENCODING_ERROR: i32 = 104;

/* BN_R_EXPAND_ON_STATIC_BIGNUM_DATA 105 # */
pub const BN_R_EXPAND_ON_STATIC_BIGNUM_DATA: i32 = 105;

/* BN_R_INPUT_NOT_REDUCED 110 # */
pub const BN_R_INPUT_NOT_REDUCED: i32 = 110;

/* BN_R_INVALID_LENGTH 106 # */
pub const BN_R_INVALID_LENGTH: i32 = 106;

/* BN_R_INVALID_RANGE 115 # */
pub const BN_R_INVALID_RANGE: i32 = 115;

/* BN_R_NOT_A_SQUARE 111 # */
pub const BN_R_NOT_A_SQUARE: i32 = 111;

/* BN_R_NOT_INITIALIZED 107 # */
pub const BN_R_NOT_INITIALIZED: i32 = 107;

/* BN_R_NO_INVERSE 108 # */
pub const BN_R_NO_INVERSE: i32 = 108;

/* BN_R_NO_SOLUTION 116 # */
pub const BN_R_NO_SOLUTION: i32 = 116;

/* BN_R_P_IS_NOT_PRIME 112 # */
pub const BN_R_P_IS_NOT_PRIME: i32 = 112;

/* BN_R_TOO_MANY_ITERATIONS 113 # */
pub const BN_R_TOO_MANY_ITERATIONS: i32 = 113;

/* BN_R_TOO_MANY_TEMPORARY_VARIABLES 109 # */
pub const BN_R_TOO_MANY_TEMPORARY_VARIABLES: i32 = 109;

/* V_ASN1_UNIVERSAL 0x00 # */
pub const V_ASN1_UNIVERSAL: i32 = 0;

/* V_ASN1_APPLICATION 0x40 # */
pub const V_ASN1_APPLICATION: i32 = 64;

/* V_ASN1_CONTEXT_SPECIFIC 0x80 # */
pub const V_ASN1_CONTEXT_SPECIFIC: i32 = 128;

/* V_ASN1_PRIVATE 0xc0 # */
pub const V_ASN1_PRIVATE: i32 = 192;

/* V_ASN1_CONSTRUCTED 0x20 # */
pub const V_ASN1_CONSTRUCTED: i32 = 32;

/* V_ASN1_PRIMITIVE_TAG 0x1f # */
pub const V_ASN1_PRIMITIVE_TAG: i32 = 31;

/* V_ASN1_PRIMATIVE_TAG 0x1f # */
pub const V_ASN1_PRIMATIVE_TAG: i32 = 31;

/* V_ASN1_APP_CHOOSE - 2 /* let the recipient choose */ */
pub const V_ASN1_APP_CHOOSE: i32 = -2;

/* V_ASN1_OTHER - 3 /* used in ASN1_TYPE */ */
pub const V_ASN1_OTHER: i32 = -3;

/* V_ASN1_ANY - 4 /* used in ASN1 template code */ */
pub const V_ASN1_ANY: i32 = -4;

/* V_ASN1_NEG 0x100 /* negative flag */ */
pub const V_ASN1_NEG: i32 = 256;

/* V_ASN1_UNDEF - 1 # */
pub const V_ASN1_UNDEF: i32 = -1;

/* V_ASN1_EOC 0 # */
pub const V_ASN1_EOC: i32 = 0;

/* V_ASN1_BOOLEAN 1 /**/ */
pub const V_ASN1_BOOLEAN: i32 = 1;

/* V_ASN1_INTEGER 2 # */
pub const V_ASN1_INTEGER: i32 = 2;

/* V_ASN1_NEG_INTEGER ( 2 | V_ASN1_NEG ) # */

/* V_ASN1_BIT_STRING 3 # */
pub const V_ASN1_BIT_STRING: i32 = 3;

/* V_ASN1_OCTET_STRING 4 # */
pub const V_ASN1_OCTET_STRING: i32 = 4;

/* V_ASN1_NULL 5 # */
pub const V_ASN1_NULL: i32 = 5;

/* V_ASN1_OBJECT 6 # */
pub const V_ASN1_OBJECT: i32 = 6;

/* V_ASN1_OBJECT_DESCRIPTOR 7 # */
pub const V_ASN1_OBJECT_DESCRIPTOR: i32 = 7;

/* V_ASN1_EXTERNAL 8 # */
pub const V_ASN1_EXTERNAL: i32 = 8;

/* V_ASN1_REAL 9 # */
pub const V_ASN1_REAL: i32 = 9;

/* V_ASN1_ENUMERATED 10 # */
pub const V_ASN1_ENUMERATED: i32 = 10;

/* V_ASN1_NEG_ENUMERATED ( 10 | V_ASN1_NEG ) # */

/* V_ASN1_UTF8STRING 12 # */
pub const V_ASN1_UTF8STRING: i32 = 12;

/* V_ASN1_SEQUENCE 16 # */
pub const V_ASN1_SEQUENCE: i32 = 16;

/* V_ASN1_SET 17 # */
pub const V_ASN1_SET: i32 = 17;

/* V_ASN1_NUMERICSTRING 18 /**/ */
pub const V_ASN1_NUMERICSTRING: i32 = 18;

/* V_ASN1_PRINTABLESTRING 19 # */
pub const V_ASN1_PRINTABLESTRING: i32 = 19;

/* V_ASN1_T61STRING 20 # */
pub const V_ASN1_T61STRING: i32 = 20;

/* V_ASN1_TELETEXSTRING 20 /* alias */ */
pub const V_ASN1_TELETEXSTRING: i32 = 20;

/* V_ASN1_VIDEOTEXSTRING 21 /**/ */
pub const V_ASN1_VIDEOTEXSTRING: i32 = 21;

/* V_ASN1_IA5STRING 22 # */
pub const V_ASN1_IA5STRING: i32 = 22;

/* V_ASN1_UTCTIME 23 # */
pub const V_ASN1_UTCTIME: i32 = 23;

/* V_ASN1_GENERALIZEDTIME 24 /**/ */
pub const V_ASN1_GENERALIZEDTIME: i32 = 24;

/* V_ASN1_GRAPHICSTRING 25 /**/ */
pub const V_ASN1_GRAPHICSTRING: i32 = 25;

/* V_ASN1_ISO64STRING 26 /**/ */
pub const V_ASN1_ISO64STRING: i32 = 26;

/* V_ASN1_VISIBLESTRING 26 /* alias */ */
pub const V_ASN1_VISIBLESTRING: i32 = 26;

/* V_ASN1_GENERALSTRING 27 /**/ */
pub const V_ASN1_GENERALSTRING: i32 = 27;

/* V_ASN1_UNIVERSALSTRING 28 /**/ */
pub const V_ASN1_UNIVERSALSTRING: i32 = 28;

/* V_ASN1_BMPSTRING 30 /* For use with d2i_ASN1_type_bytes() */ */
pub const V_ASN1_BMPSTRING: i32 = 30;

/* B_ASN1_NUMERICSTRING 0x0001 # */
pub const B_ASN1_NUMERICSTRING: i32 = 1;

/* B_ASN1_PRINTABLESTRING 0x0002 # */
pub const B_ASN1_PRINTABLESTRING: i32 = 2;

/* B_ASN1_T61STRING 0x0004 # */
pub const B_ASN1_T61STRING: i32 = 4;

/* B_ASN1_TELETEXSTRING 0x0004 # */
pub const B_ASN1_TELETEXSTRING: i32 = 4;

/* B_ASN1_VIDEOTEXSTRING 0x0008 # */
pub const B_ASN1_VIDEOTEXSTRING: i32 = 8;

/* B_ASN1_IA5STRING 0x0010 # */
pub const B_ASN1_IA5STRING: i32 = 16;

/* B_ASN1_GRAPHICSTRING 0x0020 # */
pub const B_ASN1_GRAPHICSTRING: i32 = 32;

/* B_ASN1_ISO64STRING 0x0040 # */
pub const B_ASN1_ISO64STRING: i32 = 64;

/* B_ASN1_VISIBLESTRING 0x0040 # */
pub const B_ASN1_VISIBLESTRING: i32 = 64;

/* B_ASN1_GENERALSTRING 0x0080 # */
pub const B_ASN1_GENERALSTRING: i32 = 128;

/* B_ASN1_UNIVERSALSTRING 0x0100 # */
pub const B_ASN1_UNIVERSALSTRING: i32 = 256;

/* B_ASN1_OCTET_STRING 0x0200 # */
pub const B_ASN1_OCTET_STRING: i32 = 512;

/* B_ASN1_BIT_STRING 0x0400 # */
pub const B_ASN1_BIT_STRING: i32 = 1024;

/* B_ASN1_BMPSTRING 0x0800 # */
pub const B_ASN1_BMPSTRING: i32 = 2048;

/* B_ASN1_UNKNOWN 0x1000 # */
pub const B_ASN1_UNKNOWN: i32 = 4096;

/* B_ASN1_UTF8STRING 0x2000 # */
pub const B_ASN1_UTF8STRING: i32 = 8192;

/* B_ASN1_UTCTIME 0x4000 # */
pub const B_ASN1_UTCTIME: i32 = 16384;

/* B_ASN1_GENERALIZEDTIME 0x8000 # */
pub const B_ASN1_GENERALIZEDTIME: i32 = 32768;

/* B_ASN1_SEQUENCE 0x10000 /* For use with ASN1_mbstring_copy() */ */
pub const B_ASN1_SEQUENCE: i32 = 65536;

/* MBSTRING_FLAG 0x1000 # */
pub const MBSTRING_FLAG: i32 = 4096;

/* MBSTRING_UTF8 ( MBSTRING_FLAG ) # */

/* MBSTRING_ASC ( MBSTRING_FLAG | 1 ) # */

/* MBSTRING_BMP ( MBSTRING_FLAG | 2 ) # */

/* MBSTRING_UNIV ( MBSTRING_FLAG | 4 ) # */

/* SMIME_OLDMIME 0x400 # */
pub const SMIME_OLDMIME: i32 = 1024;

/* SMIME_CRLFEOL 0x800 # */
pub const SMIME_CRLFEOL: i32 = 2048;

/* SMIME_STREAM 0x1000 struct */
pub const SMIME_STREAM: i32 = 4096;

/* DECLARE_ASN1_SET_OF ( type ) /* filled in by mkstack.pl */ */

/* IMPLEMENT_ASN1_SET_OF ( type ) /* nothing, no longer needed */ */

/* ASN1_OBJECT_FLAG_DYNAMIC 0x01 /* internal use */ */
pub const ASN1_OBJECT_FLAG_DYNAMIC: i32 = 1;

/* ASN1_OBJECT_FLAG_CRITICAL 0x02 /* critical x509v3 object id */ */
pub const ASN1_OBJECT_FLAG_CRITICAL: i32 = 2;

/* ASN1_OBJECT_FLAG_DYNAMIC_STRINGS 0x04 /* internal use */ */
pub const ASN1_OBJECT_FLAG_DYNAMIC_STRINGS: i32 = 4;

/* ASN1_OBJECT_FLAG_DYNAMIC_DATA 0x08 /* internal use */ */
pub const ASN1_OBJECT_FLAG_DYNAMIC_DATA: i32 = 8;

/* ASN1_STRING_FLAG_BITS_LEFT 0x08 /* Set if 0x07 has bits left value */ */
pub const ASN1_STRING_FLAG_BITS_LEFT: i32 = 8;

/* ASN1_STRING_FLAG_NDEF 0x010 /* This flag is used by the CMS code to indicate that a string is not
 * complete and is a place holder for content when it had all been 
 * accessed. The flag will be reset when content has been written to it.
 */ */
pub const ASN1_STRING_FLAG_NDEF: i32 = 16;

/* ASN1_STRING_FLAG_CONT 0x020 /* This flag is used by ASN1 code to indicate an ASN1_STRING is an MSTRING
 * type.
 */ */
pub const ASN1_STRING_FLAG_CONT: i32 = 32;

/* ASN1_STRING_FLAG_MSTRING 0x040 /* This is the base type that holds just about everything :-) */ */
pub const ASN1_STRING_FLAG_MSTRING: i32 = 64;

/* ASN1_LONG_UNDEF 0x7fffffffL # */

/* STABLE_FLAGS_MALLOC 0x01 # */
pub const STABLE_FLAGS_MALLOC: i32 = 1;

/* STABLE_NO_MASK 0x02 # */
pub const STABLE_NO_MASK: i32 = 2;

/* DIRSTRING_TYPE ( B_ASN1_PRINTABLESTRING | B_ASN1_T61STRING | B_ASN1_BMPSTRING | B_ASN1_UTF8STRING ) # */

/* PKCS9STRING_TYPE ( DIRSTRING_TYPE | B_ASN1_IA5STRING ) typedef */

/* ub_name 32768 # */
pub const ub_name: i32 = 32768;

/* ub_common_name 64 # */
pub const ub_common_name: i32 = 64;

/* ub_locality_name 128 # */
pub const ub_locality_name: i32 = 128;

/* ub_state_name 128 # */
pub const ub_state_name: i32 = 128;

/* ub_organization_name 64 # */
pub const ub_organization_name: i32 = 64;

/* ub_organization_unit_name 64 # */
pub const ub_organization_unit_name: i32 = 64;

/* ub_title 64 # */
pub const ub_title: i32 = 64;

/* ub_email_address 128 /* Declarations for template structures: for full definitions
 * see asn1t.h
 */ */
pub const ub_email_address: i32 = 128;

/* DECLARE_ASN1_FUNCTIONS ( type ) DECLARE_ASN1_FUNCTIONS_name ( type , type ) # */

/* DECLARE_ASN1_ALLOC_FUNCTIONS ( type ) DECLARE_ASN1_ALLOC_FUNCTIONS_name ( type , type ) # */

/* DECLARE_ASN1_FUNCTIONS_name ( type , name ) DECLARE_ASN1_ALLOC_FUNCTIONS_name ( type , name ) DECLARE_ASN1_ENCODE_FUNCTIONS ( type , name , name ) # */

/* DECLARE_ASN1_FUNCTIONS_fname ( type , itname , name ) DECLARE_ASN1_ALLOC_FUNCTIONS_name ( type , name ) DECLARE_ASN1_ENCODE_FUNCTIONS ( type , itname , name ) # */

/* DECLARE_ASN1_ENCODE_FUNCTIONS ( type , itname , name ) type * d2i_ ## name ( type * * a , const unsigned char * * in , long len ) ; int i2d_ ## name ( type * a , unsigned char * * out ) ; DECLARE_ASN1_ITEM ( itname ) # */

/* DECLARE_ASN1_ENCODE_FUNCTIONS_const ( type , name ) type * d2i_ ## name ( type * * a , const unsigned char * * in , long len ) ; int i2d_ ## name ( const type * a , unsigned char * * out ) ; DECLARE_ASN1_ITEM ( name ) # */

/* DECLARE_ASN1_NDEF_FUNCTION ( name ) int i2d_ ## name ## _NDEF ( name * a , unsigned char * * out ) ; # */

/* DECLARE_ASN1_FUNCTIONS_const ( name ) DECLARE_ASN1_ALLOC_FUNCTIONS ( name ) DECLARE_ASN1_ENCODE_FUNCTIONS_const ( name , name ) # */

/* DECLARE_ASN1_ALLOC_FUNCTIONS_name ( type , name ) type * name ## _new ( void ) ; void name ## _free ( type * a ) ; # */

/* DECLARE_ASN1_PRINT_FUNCTION ( stname ) DECLARE_ASN1_PRINT_FUNCTION_fname ( stname , stname ) # */

/* DECLARE_ASN1_PRINT_FUNCTION_fname ( stname , fname ) int fname ## _print_ctx ( BIO * out , stname * x , int indent , const ASN1_PCTX * pctx ) ; # */

/* D2I_OF ( type ) type * ( * ) ( type * * , const unsigned char * * , long ) # */

/* I2D_OF ( type ) int ( * ) ( type * , unsigned char * * ) # */

/* I2D_OF_const ( type ) int ( * ) ( const type * , unsigned char * * ) # */

/* CHECKED_D2I_OF ( type , d2i ) ( ( d2i_of_void * ) ( 1 ? d2i : ( ( D2I_OF ( type ) ) 0 ) ) ) # */

/* CHECKED_I2D_OF ( type , i2d ) ( ( i2d_of_void * ) ( 1 ? i2d : ( ( I2D_OF ( type ) ) 0 ) ) ) # */

/* CHECKED_NEW_OF ( type , xnew ) ( ( void * ( * ) ( void ) ) ( 1 ? xnew : ( ( type * ( * ) ( void ) ) 0 ) ) ) # */

/* CHECKED_PTR_OF ( type , p ) ( ( void * ) ( 1 ? p : ( type * ) 0 ) ) # */

/* CHECKED_PPTR_OF ( type , p ) ( ( void * * ) ( 1 ? p : ( type * * ) 0 ) ) # */

/* TYPEDEF_D2I_OF ( type ) typedef type * d2i_of_ ## type ( type * * , const unsigned char * * , long ) # */

/* TYPEDEF_I2D_OF ( type ) typedef int i2d_of_ ## type ( type * , unsigned char * * ) # */

/* TYPEDEF_D2I2D_OF ( type ) TYPEDEF_D2I_OF ( type ) ; TYPEDEF_I2D_OF ( type ) TYPEDEF_D2I2D_OF */

/* ASN1_ITEM_ptr ( iptr ) ( iptr ) /* Macro to include ASN1_ITEM pointer from base type */ */

/* ASN1_ITEM_ref ( iptr ) ( & ( iptr ## _it ) ) # */

/* ASN1_ITEM_rptr ( ref ) ( & ( ref ## _it ) ) # */

/* DECLARE_ASN1_ITEM ( name ) OPENSSL_EXTERN const ASN1_ITEM name ## _it ; # */

/* ASN1_STRFLGS_ESC_2253 1 # */
pub const ASN1_STRFLGS_ESC_2253: i32 = 1;

/* ASN1_STRFLGS_ESC_CTRL 2 # */
pub const ASN1_STRFLGS_ESC_CTRL: i32 = 2;

/* ASN1_STRFLGS_ESC_MSB 4 /* This flag determines how we do escaping: normally
 * RC2253 backslash only, set this to use backslash and
 * quote.
 */ */
pub const ASN1_STRFLGS_ESC_MSB: i32 = 4;

/* ASN1_STRFLGS_ESC_QUOTE 8 /* These three flags are internal use only. */ */
pub const ASN1_STRFLGS_ESC_QUOTE: i32 = 8;

/* CHARTYPE_PRINTABLESTRING 0x10 /* Character needs escaping if it is the first character */ */
pub const CHARTYPE_PRINTABLESTRING: i32 = 16;

/* CHARTYPE_FIRST_ESC_2253 0x20 /* Character needs escaping if it is the last character */ */
pub const CHARTYPE_FIRST_ESC_2253: i32 = 32;

/* CHARTYPE_LAST_ESC_2253 0x40 /* NB the internal flags are safely reused below by flags
 * handled at the top level.
 */ */
pub const CHARTYPE_LAST_ESC_2253: i32 = 64;

/* ASN1_STRFLGS_UTF8_CONVERT 0x10 /* If this is set we don't attempt to interpret content:
 * just assume all strings are 1 byte per character. This
 * will produce some pretty odd looking output!
 */ */
pub const ASN1_STRFLGS_UTF8_CONVERT: i32 = 16;

/* ASN1_STRFLGS_IGNORE_TYPE 0x20 /* If this is set we include the string type in the output */ */
pub const ASN1_STRFLGS_IGNORE_TYPE: i32 = 32;

/* ASN1_STRFLGS_SHOW_TYPE 0x40 /* This determines which strings to display and which to
 * 'dump' (hex dump of content octets or DER encoding). We can
 * only dump non character strings or everything. If we
 * don't dump 'unknown' they are interpreted as character
 * strings with 1 octet per character and are subject to
 * the usual escaping options.
 */ */
pub const ASN1_STRFLGS_SHOW_TYPE: i32 = 64;

/* ASN1_STRFLGS_DUMP_ALL 0x80 # */
pub const ASN1_STRFLGS_DUMP_ALL: i32 = 128;

/* ASN1_STRFLGS_DUMP_UNKNOWN 0x100 /* These determine what 'dumping' does, we can dump the
 * content octets or the DER encoding: both use the
 * RFC2253 #XXXXX notation.
 */ */
pub const ASN1_STRFLGS_DUMP_UNKNOWN: i32 = 256;

/* ASN1_STRFLGS_DUMP_DER 0x200 /* All the string flags consistent with RFC2253,
 * escaping control characters isn't essential in
 * RFC2253 but it is advisable anyway.
 */ */
pub const ASN1_STRFLGS_DUMP_DER: i32 = 512;

/* ASN1_STRFLGS_RFC2253 ( ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_ESC_CTRL | ASN1_STRFLGS_ESC_MSB | ASN1_STRFLGS_UTF8_CONVERT | ASN1_STRFLGS_DUMP_UNKNOWN | ASN1_STRFLGS_DUMP_DER ) DECLARE_STACK_OF */

/* M_ASN1_STRING_length ( x ) ( ( x ) -> length ) # */

/* M_ASN1_STRING_length_set ( x , n ) ( ( x ) -> length = ( n ) ) # */

/* M_ASN1_STRING_type ( x ) ( ( x ) -> type ) # */

/* M_ASN1_STRING_data ( x ) ( ( x ) -> data ) /* Macros for string operations */ */

/* M_ASN1_BIT_STRING_new ( ) ( ASN1_BIT_STRING * ) ASN1_STRING_type_new ( V_ASN1_BIT_STRING ) # */

/* M_ASN1_BIT_STRING_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_ASN1_BIT_STRING_dup ( a ) ( ASN1_BIT_STRING * ) ASN1_STRING_dup ( ( const ASN1_STRING * ) a ) # */

/* M_ASN1_BIT_STRING_cmp ( a , b ) ASN1_STRING_cmp ( ( const ASN1_STRING * ) a , ( const ASN1_STRING * ) b ) # */

/* M_ASN1_BIT_STRING_set ( a , b , c ) ASN1_STRING_set ( ( ASN1_STRING * ) a , b , c ) # */

/* M_ASN1_INTEGER_new ( ) ( ASN1_INTEGER * ) ASN1_STRING_type_new ( V_ASN1_INTEGER ) # */

/* M_ASN1_INTEGER_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_ASN1_INTEGER_dup ( a ) ( ASN1_INTEGER * ) ASN1_STRING_dup ( ( const ASN1_STRING * ) a ) # */

/* M_ASN1_INTEGER_cmp ( a , b ) ASN1_STRING_cmp ( ( const ASN1_STRING * ) a , ( const ASN1_STRING * ) b ) # */

/* M_ASN1_ENUMERATED_new ( ) ( ASN1_ENUMERATED * ) ASN1_STRING_type_new ( V_ASN1_ENUMERATED ) # */

/* M_ASN1_ENUMERATED_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_ASN1_ENUMERATED_dup ( a ) ( ASN1_ENUMERATED * ) ASN1_STRING_dup ( ( const ASN1_STRING * ) a ) # */

/* M_ASN1_ENUMERATED_cmp ( a , b ) ASN1_STRING_cmp ( ( const ASN1_STRING * ) a , ( const ASN1_STRING * ) b ) # */

/* M_ASN1_OCTET_STRING_new ( ) ( ASN1_OCTET_STRING * ) ASN1_STRING_type_new ( V_ASN1_OCTET_STRING ) # */

/* M_ASN1_OCTET_STRING_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_ASN1_OCTET_STRING_dup ( a ) ( ASN1_OCTET_STRING * ) ASN1_STRING_dup ( ( const ASN1_STRING * ) a ) # */

/* M_ASN1_OCTET_STRING_cmp ( a , b ) ASN1_STRING_cmp ( ( const ASN1_STRING * ) a , ( const ASN1_STRING * ) b ) # */

/* M_ASN1_OCTET_STRING_set ( a , b , c ) ASN1_STRING_set ( ( ASN1_STRING * ) a , b , c ) # */

/* M_ASN1_OCTET_STRING_print ( a , b ) ASN1_STRING_print ( a , ( ASN1_STRING * ) b ) # */

/* M_i2d_ASN1_OCTET_STRING ( a , pp ) i2d_ASN1_bytes ( ( ASN1_STRING * ) a , pp , V_ASN1_OCTET_STRING , V_ASN1_UNIVERSAL ) # */

/* B_ASN1_TIME B_ASN1_UTCTIME | B_ASN1_GENERALIZEDTIME # */

/* B_ASN1_PRINTABLE B_ASN1_NUMERICSTRING | B_ASN1_PRINTABLESTRING | B_ASN1_T61STRING | B_ASN1_IA5STRING | B_ASN1_BIT_STRING | B_ASN1_UNIVERSALSTRING | B_ASN1_BMPSTRING | B_ASN1_UTF8STRING | B_ASN1_SEQUENCE | B_ASN1_UNKNOWN # */

/* B_ASN1_DIRECTORYSTRING B_ASN1_PRINTABLESTRING | B_ASN1_TELETEXSTRING | B_ASN1_BMPSTRING | B_ASN1_UNIVERSALSTRING | B_ASN1_UTF8STRING # */

/* B_ASN1_DISPLAYTEXT B_ASN1_IA5STRING | B_ASN1_VISIBLESTRING | B_ASN1_BMPSTRING | B_ASN1_UTF8STRING # */

/* M_ASN1_PRINTABLE_new ( ) ASN1_STRING_type_new ( V_ASN1_T61STRING ) # */

/* M_ASN1_PRINTABLE_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_i2d_ASN1_PRINTABLE ( a , pp ) i2d_ASN1_bytes ( ( ASN1_STRING * ) a , pp , a -> type , V_ASN1_UNIVERSAL ) # */

/* M_d2i_ASN1_PRINTABLE ( a , pp , l ) d2i_ASN1_type_bytes ( ( ASN1_STRING * * ) a , pp , l , B_ASN1_PRINTABLE ) # */

/* M_DIRECTORYSTRING_new ( ) ASN1_STRING_type_new ( V_ASN1_PRINTABLESTRING ) # */

/* M_DIRECTORYSTRING_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_i2d_DIRECTORYSTRING ( a , pp ) i2d_ASN1_bytes ( ( ASN1_STRING * ) a , pp , a -> type , V_ASN1_UNIVERSAL ) # */

/* M_d2i_DIRECTORYSTRING ( a , pp , l ) d2i_ASN1_type_bytes ( ( ASN1_STRING * * ) a , pp , l , B_ASN1_DIRECTORYSTRING ) # */

/* M_DISPLAYTEXT_new ( ) ASN1_STRING_type_new ( V_ASN1_VISIBLESTRING ) # */

/* M_DISPLAYTEXT_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_i2d_DISPLAYTEXT ( a , pp ) i2d_ASN1_bytes ( ( ASN1_STRING * ) a , pp , a -> type , V_ASN1_UNIVERSAL ) # */

/* M_d2i_DISPLAYTEXT ( a , pp , l ) d2i_ASN1_type_bytes ( ( ASN1_STRING * * ) a , pp , l , B_ASN1_DISPLAYTEXT ) # */

/* M_ASN1_PRINTABLESTRING_new ( ) ( ASN1_PRINTABLESTRING * ) ASN1_STRING_type_new ( V_ASN1_PRINTABLESTRING ) # */

/* M_ASN1_PRINTABLESTRING_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_i2d_ASN1_PRINTABLESTRING ( a , pp ) i2d_ASN1_bytes ( ( ASN1_STRING * ) a , pp , V_ASN1_PRINTABLESTRING , V_ASN1_UNIVERSAL ) # */

/* M_d2i_ASN1_PRINTABLESTRING ( a , pp , l ) ( ASN1_PRINTABLESTRING * ) d2i_ASN1_type_bytes ( ( ASN1_STRING * * ) a , pp , l , B_ASN1_PRINTABLESTRING ) # */

/* M_ASN1_T61STRING_new ( ) ( ASN1_T61STRING * ) ASN1_STRING_type_new ( V_ASN1_T61STRING ) # */

/* M_ASN1_T61STRING_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_i2d_ASN1_T61STRING ( a , pp ) i2d_ASN1_bytes ( ( ASN1_STRING * ) a , pp , V_ASN1_T61STRING , V_ASN1_UNIVERSAL ) # */

/* M_d2i_ASN1_T61STRING ( a , pp , l ) ( ASN1_T61STRING * ) d2i_ASN1_type_bytes ( ( ASN1_STRING * * ) a , pp , l , B_ASN1_T61STRING ) # */

/* M_ASN1_IA5STRING_new ( ) ( ASN1_IA5STRING * ) ASN1_STRING_type_new ( V_ASN1_IA5STRING ) # */

/* M_ASN1_IA5STRING_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_ASN1_IA5STRING_dup ( a ) ( ASN1_IA5STRING * ) ASN1_STRING_dup ( ( const ASN1_STRING * ) a ) # */

/* M_i2d_ASN1_IA5STRING ( a , pp ) i2d_ASN1_bytes ( ( ASN1_STRING * ) a , pp , V_ASN1_IA5STRING , V_ASN1_UNIVERSAL ) # */

/* M_d2i_ASN1_IA5STRING ( a , pp , l ) ( ASN1_IA5STRING * ) d2i_ASN1_type_bytes ( ( ASN1_STRING * * ) a , pp , l , B_ASN1_IA5STRING ) # */

/* M_ASN1_UTCTIME_new ( ) ( ASN1_UTCTIME * ) ASN1_STRING_type_new ( V_ASN1_UTCTIME ) # */

/* M_ASN1_UTCTIME_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_ASN1_UTCTIME_dup ( a ) ( ASN1_UTCTIME * ) ASN1_STRING_dup ( ( const ASN1_STRING * ) a ) # */

/* M_ASN1_GENERALIZEDTIME_new ( ) ( ASN1_GENERALIZEDTIME * ) ASN1_STRING_type_new ( V_ASN1_GENERALIZEDTIME ) # */

/* M_ASN1_GENERALIZEDTIME_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_ASN1_GENERALIZEDTIME_dup ( a ) ( ASN1_GENERALIZEDTIME * ) ASN1_STRING_dup ( ( const ASN1_STRING * ) a ) # */

/* M_ASN1_TIME_new ( ) ( ASN1_TIME * ) ASN1_STRING_type_new ( V_ASN1_UTCTIME ) # */

/* M_ASN1_TIME_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_ASN1_TIME_dup ( a ) ( ASN1_TIME * ) ASN1_STRING_dup ( ( const ASN1_STRING * ) a ) # */

/* M_ASN1_GENERALSTRING_new ( ) ( ASN1_GENERALSTRING * ) ASN1_STRING_type_new ( V_ASN1_GENERALSTRING ) # */

/* M_ASN1_GENERALSTRING_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_i2d_ASN1_GENERALSTRING ( a , pp ) i2d_ASN1_bytes ( ( ASN1_STRING * ) a , pp , V_ASN1_GENERALSTRING , V_ASN1_UNIVERSAL ) # */

/* M_d2i_ASN1_GENERALSTRING ( a , pp , l ) ( ASN1_GENERALSTRING * ) d2i_ASN1_type_bytes ( ( ASN1_STRING * * ) a , pp , l , B_ASN1_GENERALSTRING ) # */

/* M_ASN1_UNIVERSALSTRING_new ( ) ( ASN1_UNIVERSALSTRING * ) ASN1_STRING_type_new ( V_ASN1_UNIVERSALSTRING ) # */

/* M_ASN1_UNIVERSALSTRING_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_i2d_ASN1_UNIVERSALSTRING ( a , pp ) i2d_ASN1_bytes ( ( ASN1_STRING * ) a , pp , V_ASN1_UNIVERSALSTRING , V_ASN1_UNIVERSAL ) # */

/* M_d2i_ASN1_UNIVERSALSTRING ( a , pp , l ) ( ASN1_UNIVERSALSTRING * ) d2i_ASN1_type_bytes ( ( ASN1_STRING * * ) a , pp , l , B_ASN1_UNIVERSALSTRING ) # */

/* M_ASN1_BMPSTRING_new ( ) ( ASN1_BMPSTRING * ) ASN1_STRING_type_new ( V_ASN1_BMPSTRING ) # */

/* M_ASN1_BMPSTRING_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_i2d_ASN1_BMPSTRING ( a , pp ) i2d_ASN1_bytes ( ( ASN1_STRING * ) a , pp , V_ASN1_BMPSTRING , V_ASN1_UNIVERSAL ) # */

/* M_d2i_ASN1_BMPSTRING ( a , pp , l ) ( ASN1_BMPSTRING * ) d2i_ASN1_type_bytes ( ( ASN1_STRING * * ) a , pp , l , B_ASN1_BMPSTRING ) # */

/* M_ASN1_VISIBLESTRING_new ( ) ( ASN1_VISIBLESTRING * ) ASN1_STRING_type_new ( V_ASN1_VISIBLESTRING ) # */

/* M_ASN1_VISIBLESTRING_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_i2d_ASN1_VISIBLESTRING ( a , pp ) i2d_ASN1_bytes ( ( ASN1_STRING * ) a , pp , V_ASN1_VISIBLESTRING , V_ASN1_UNIVERSAL ) # */

/* M_d2i_ASN1_VISIBLESTRING ( a , pp , l ) ( ASN1_VISIBLESTRING * ) d2i_ASN1_type_bytes ( ( ASN1_STRING * * ) a , pp , l , B_ASN1_VISIBLESTRING ) # */

/* M_ASN1_UTF8STRING_new ( ) ( ASN1_UTF8STRING * ) ASN1_STRING_type_new ( V_ASN1_UTF8STRING ) # */

/* M_ASN1_UTF8STRING_free ( a ) ASN1_STRING_free ( ( ASN1_STRING * ) a ) # */

/* M_i2d_ASN1_UTF8STRING ( a , pp ) i2d_ASN1_bytes ( ( ASN1_STRING * ) a , pp , V_ASN1_UTF8STRING , V_ASN1_UNIVERSAL ) # */

/* M_d2i_ASN1_UTF8STRING ( a , pp , l ) ( ASN1_UTF8STRING * ) d2i_ASN1_type_bytes ( ( ASN1_STRING * * ) a , pp , l , B_ASN1_UTF8STRING ) /* for the is_set parameter to i2d_ASN1_SET */ */

/* IS_SEQUENCE 0 # */
pub const IS_SEQUENCE: i32 = 0;

/* IS_SET 1 DECLARE_ASN1_FUNCTIONS_fname */
pub const IS_SET: i32 = 1;

/* ASN1_dup_of ( type , i2d , d2i , x ) ( ( type * ) ASN1_dup ( CHECKED_I2D_OF ( type , i2d ) , CHECKED_D2I_OF ( type , d2i ) , CHECKED_PTR_OF ( type , x ) ) ) # */

/* ASN1_dup_of_const ( type , i2d , d2i , x ) ( ( type * ) ASN1_dup ( CHECKED_I2D_OF ( const type , i2d ) , CHECKED_D2I_OF ( type , d2i ) , CHECKED_PTR_OF ( const type , x ) ) ) void */

/* M_ASN1_new_of ( type ) ( type * ) ASN1_item_new ( ASN1_ITEM_rptr ( type ) ) # */

/* M_ASN1_free_of ( x , type ) ASN1_item_free ( CHECKED_PTR_OF ( type , x ) , ASN1_ITEM_rptr ( type ) ) # */

/* ASN1_d2i_fp_of ( type , xnew , d2i , in , x ) ( ( type * ) ASN1_d2i_fp ( CHECKED_NEW_OF ( type , xnew ) , CHECKED_D2I_OF ( type , d2i ) , in , CHECKED_PPTR_OF ( type , x ) ) ) void */

/* ASN1_i2d_fp_of ( type , i2d , out , x ) ( ASN1_i2d_fp ( CHECKED_I2D_OF ( type , i2d ) , out , CHECKED_PTR_OF ( type , x ) ) ) # */

/* ASN1_i2d_fp_of_const ( type , i2d , out , x ) ( ASN1_i2d_fp ( CHECKED_I2D_OF ( const type , i2d ) , out , CHECKED_PTR_OF ( const type , x ) ) ) int */

/* ASN1_d2i_bio_of ( type , xnew , d2i , in , x ) ( ( type * ) ASN1_d2i_bio ( CHECKED_NEW_OF ( type , xnew ) , CHECKED_D2I_OF ( type , d2i ) , in , CHECKED_PPTR_OF ( type , x ) ) ) void */

/* ASN1_i2d_bio_of ( type , i2d , out , x ) ( ASN1_i2d_bio ( CHECKED_I2D_OF ( type , i2d ) , out , CHECKED_PTR_OF ( type , x ) ) ) # */

/* ASN1_i2d_bio_of_const ( type , i2d , out , x ) ( ASN1_i2d_bio ( CHECKED_I2D_OF ( const type , i2d ) , out , CHECKED_PTR_OF ( const type , x ) ) ) int */

/* ASN1_pack_string_of ( type , obj , i2d , oct ) ( ASN1_pack_string ( CHECKED_PTR_OF ( type , obj ) , CHECKED_I2D_OF ( type , i2d ) , oct ) ) ASN1_STRING */

/* ASN1_PCTX_FLAGS_SHOW_ABSENT 0x001 /* Mark start and end of SEQUENCE */ */
pub const ASN1_PCTX_FLAGS_SHOW_ABSENT: i32 = 1;

/* ASN1_PCTX_FLAGS_SHOW_SEQUENCE 0x002 /* Mark start and end of SEQUENCE/SET OF */ */
pub const ASN1_PCTX_FLAGS_SHOW_SEQUENCE: i32 = 2;

/* ASN1_PCTX_FLAGS_SHOW_SSOF 0x004 /* Show the ASN1 type of primitives */ */
pub const ASN1_PCTX_FLAGS_SHOW_SSOF: i32 = 4;

/* ASN1_PCTX_FLAGS_SHOW_TYPE 0x008 /* Don't show ASN1 type of ANY */ */
pub const ASN1_PCTX_FLAGS_SHOW_TYPE: i32 = 8;

/* ASN1_PCTX_FLAGS_NO_ANY_TYPE 0x010 /* Don't show ASN1 type of MSTRINGs */ */
pub const ASN1_PCTX_FLAGS_NO_ANY_TYPE: i32 = 16;

/* ASN1_PCTX_FLAGS_NO_MSTRING_TYPE 0x020 /* Don't show field names in SEQUENCE */ */
pub const ASN1_PCTX_FLAGS_NO_MSTRING_TYPE: i32 = 32;

/* ASN1_PCTX_FLAGS_NO_FIELD_NAME 0x040 /* Show structure names of each SEQUENCE field */ */
pub const ASN1_PCTX_FLAGS_NO_FIELD_NAME: i32 = 64;

/* ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME 0x080 /* Don't show structure name even at top level */ */
pub const ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME: i32 = 128;

/* ASN1_PCTX_FLAGS_NO_STRUCT_NAME 0x100 int */
pub const ASN1_PCTX_FLAGS_NO_STRUCT_NAME: i32 = 256;

/* ASN1_F_A2D_ASN1_OBJECT 100 # */
pub const ASN1_F_A2D_ASN1_OBJECT: i32 = 100;

/* ASN1_F_A2I_ASN1_ENUMERATED 101 # */
pub const ASN1_F_A2I_ASN1_ENUMERATED: i32 = 101;

/* ASN1_F_A2I_ASN1_INTEGER 102 # */
pub const ASN1_F_A2I_ASN1_INTEGER: i32 = 102;

/* ASN1_F_A2I_ASN1_STRING 103 # */
pub const ASN1_F_A2I_ASN1_STRING: i32 = 103;

/* ASN1_F_APPEND_EXP 176 # */
pub const ASN1_F_APPEND_EXP: i32 = 176;

/* ASN1_F_ASN1_BIT_STRING_SET_BIT 183 # */
pub const ASN1_F_ASN1_BIT_STRING_SET_BIT: i32 = 183;

/* ASN1_F_ASN1_CB 177 # */
pub const ASN1_F_ASN1_CB: i32 = 177;

/* ASN1_F_ASN1_CHECK_TLEN 104 # */
pub const ASN1_F_ASN1_CHECK_TLEN: i32 = 104;

/* ASN1_F_ASN1_COLLATE_PRIMITIVE 105 # */
pub const ASN1_F_ASN1_COLLATE_PRIMITIVE: i32 = 105;

/* ASN1_F_ASN1_COLLECT 106 # */
pub const ASN1_F_ASN1_COLLECT: i32 = 106;

/* ASN1_F_ASN1_D2I_EX_PRIMITIVE 108 # */
pub const ASN1_F_ASN1_D2I_EX_PRIMITIVE: i32 = 108;

/* ASN1_F_ASN1_D2I_FP 109 # */
pub const ASN1_F_ASN1_D2I_FP: i32 = 109;

/* ASN1_F_ASN1_D2I_READ_BIO 107 # */
pub const ASN1_F_ASN1_D2I_READ_BIO: i32 = 107;

/* ASN1_F_ASN1_DIGEST 184 # */
pub const ASN1_F_ASN1_DIGEST: i32 = 184;

/* ASN1_F_ASN1_DO_ADB 110 # */
pub const ASN1_F_ASN1_DO_ADB: i32 = 110;

/* ASN1_F_ASN1_DUP 111 # */
pub const ASN1_F_ASN1_DUP: i32 = 111;

/* ASN1_F_ASN1_ENUMERATED_SET 112 # */
pub const ASN1_F_ASN1_ENUMERATED_SET: i32 = 112;

/* ASN1_F_ASN1_ENUMERATED_TO_BN 113 # */
pub const ASN1_F_ASN1_ENUMERATED_TO_BN: i32 = 113;

/* ASN1_F_ASN1_EX_C2I 204 # */
pub const ASN1_F_ASN1_EX_C2I: i32 = 204;

/* ASN1_F_ASN1_FIND_END 190 # */
pub const ASN1_F_ASN1_FIND_END: i32 = 190;

/* ASN1_F_ASN1_GENERALIZEDTIME_ADJ 216 # */
pub const ASN1_F_ASN1_GENERALIZEDTIME_ADJ: i32 = 216;

/* ASN1_F_ASN1_GENERALIZEDTIME_SET 185 # */
pub const ASN1_F_ASN1_GENERALIZEDTIME_SET: i32 = 185;

/* ASN1_F_ASN1_GENERATE_V3 178 # */
pub const ASN1_F_ASN1_GENERATE_V3: i32 = 178;

/* ASN1_F_ASN1_GET_OBJECT 114 # */
pub const ASN1_F_ASN1_GET_OBJECT: i32 = 114;

/* ASN1_F_ASN1_HEADER_NEW 115 # */
pub const ASN1_F_ASN1_HEADER_NEW: i32 = 115;

/* ASN1_F_ASN1_I2D_BIO 116 # */
pub const ASN1_F_ASN1_I2D_BIO: i32 = 116;

/* ASN1_F_ASN1_I2D_FP 117 # */
pub const ASN1_F_ASN1_I2D_FP: i32 = 117;

/* ASN1_F_ASN1_INTEGER_SET 118 # */
pub const ASN1_F_ASN1_INTEGER_SET: i32 = 118;

/* ASN1_F_ASN1_INTEGER_TO_BN 119 # */
pub const ASN1_F_ASN1_INTEGER_TO_BN: i32 = 119;

/* ASN1_F_ASN1_ITEM_D2I_FP 206 # */
pub const ASN1_F_ASN1_ITEM_D2I_FP: i32 = 206;

/* ASN1_F_ASN1_ITEM_DUP 191 # */
pub const ASN1_F_ASN1_ITEM_DUP: i32 = 191;

/* ASN1_F_ASN1_ITEM_EX_COMBINE_NEW 121 # */
pub const ASN1_F_ASN1_ITEM_EX_COMBINE_NEW: i32 = 121;

/* ASN1_F_ASN1_ITEM_EX_D2I 120 # */
pub const ASN1_F_ASN1_ITEM_EX_D2I: i32 = 120;

/* ASN1_F_ASN1_ITEM_I2D_BIO 192 # */
pub const ASN1_F_ASN1_ITEM_I2D_BIO: i32 = 192;

/* ASN1_F_ASN1_ITEM_I2D_FP 193 # */
pub const ASN1_F_ASN1_ITEM_I2D_FP: i32 = 193;

/* ASN1_F_ASN1_ITEM_PACK 198 # */
pub const ASN1_F_ASN1_ITEM_PACK: i32 = 198;

/* ASN1_F_ASN1_ITEM_SIGN 195 # */
pub const ASN1_F_ASN1_ITEM_SIGN: i32 = 195;

/* ASN1_F_ASN1_ITEM_SIGN_CTX 220 # */
pub const ASN1_F_ASN1_ITEM_SIGN_CTX: i32 = 220;

/* ASN1_F_ASN1_ITEM_UNPACK 199 # */
pub const ASN1_F_ASN1_ITEM_UNPACK: i32 = 199;

/* ASN1_F_ASN1_ITEM_VERIFY 197 # */
pub const ASN1_F_ASN1_ITEM_VERIFY: i32 = 197;

/* ASN1_F_ASN1_MBSTRING_NCOPY 122 # */
pub const ASN1_F_ASN1_MBSTRING_NCOPY: i32 = 122;

/* ASN1_F_ASN1_OBJECT_NEW 123 # */
pub const ASN1_F_ASN1_OBJECT_NEW: i32 = 123;

/* ASN1_F_ASN1_OUTPUT_DATA 214 # */
pub const ASN1_F_ASN1_OUTPUT_DATA: i32 = 214;

/* ASN1_F_ASN1_PACK_STRING 124 # */
pub const ASN1_F_ASN1_PACK_STRING: i32 = 124;

/* ASN1_F_ASN1_PCTX_NEW 205 # */
pub const ASN1_F_ASN1_PCTX_NEW: i32 = 205;

/* ASN1_F_ASN1_PKCS5_PBE_SET 125 # */
pub const ASN1_F_ASN1_PKCS5_PBE_SET: i32 = 125;

/* ASN1_F_ASN1_SEQ_PACK 126 # */
pub const ASN1_F_ASN1_SEQ_PACK: i32 = 126;

/* ASN1_F_ASN1_SEQ_UNPACK 127 # */
pub const ASN1_F_ASN1_SEQ_UNPACK: i32 = 127;

/* ASN1_F_ASN1_SIGN 128 # */
pub const ASN1_F_ASN1_SIGN: i32 = 128;

/* ASN1_F_ASN1_STR2TYPE 179 # */
pub const ASN1_F_ASN1_STR2TYPE: i32 = 179;

/* ASN1_F_ASN1_STRING_SET 186 # */
pub const ASN1_F_ASN1_STRING_SET: i32 = 186;

/* ASN1_F_ASN1_STRING_TABLE_ADD 129 # */
pub const ASN1_F_ASN1_STRING_TABLE_ADD: i32 = 129;

/* ASN1_F_ASN1_STRING_TYPE_NEW 130 # */
pub const ASN1_F_ASN1_STRING_TYPE_NEW: i32 = 130;

/* ASN1_F_ASN1_TEMPLATE_EX_D2I 132 # */
pub const ASN1_F_ASN1_TEMPLATE_EX_D2I: i32 = 132;

/* ASN1_F_ASN1_TEMPLATE_NEW 133 # */
pub const ASN1_F_ASN1_TEMPLATE_NEW: i32 = 133;

/* ASN1_F_ASN1_TEMPLATE_NOEXP_D2I 131 # */
pub const ASN1_F_ASN1_TEMPLATE_NOEXP_D2I: i32 = 131;

/* ASN1_F_ASN1_TIME_ADJ 217 # */
pub const ASN1_F_ASN1_TIME_ADJ: i32 = 217;

/* ASN1_F_ASN1_TIME_SET 175 # */
pub const ASN1_F_ASN1_TIME_SET: i32 = 175;

/* ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING 134 # */
pub const ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING: i32 = 134;

/* ASN1_F_ASN1_TYPE_GET_OCTETSTRING 135 # */
pub const ASN1_F_ASN1_TYPE_GET_OCTETSTRING: i32 = 135;

/* ASN1_F_ASN1_UNPACK_STRING 136 # */
pub const ASN1_F_ASN1_UNPACK_STRING: i32 = 136;

/* ASN1_F_ASN1_UTCTIME_ADJ 218 # */
pub const ASN1_F_ASN1_UTCTIME_ADJ: i32 = 218;

/* ASN1_F_ASN1_UTCTIME_SET 187 # */
pub const ASN1_F_ASN1_UTCTIME_SET: i32 = 187;

/* ASN1_F_ASN1_VERIFY 137 # */
pub const ASN1_F_ASN1_VERIFY: i32 = 137;

/* ASN1_F_B64_READ_ASN1 209 # */
pub const ASN1_F_B64_READ_ASN1: i32 = 209;

/* ASN1_F_B64_WRITE_ASN1 210 # */
pub const ASN1_F_B64_WRITE_ASN1: i32 = 210;

/* ASN1_F_BIO_NEW_NDEF 208 # */
pub const ASN1_F_BIO_NEW_NDEF: i32 = 208;

/* ASN1_F_BITSTR_CB 180 # */
pub const ASN1_F_BITSTR_CB: i32 = 180;

/* ASN1_F_BN_TO_ASN1_ENUMERATED 138 # */
pub const ASN1_F_BN_TO_ASN1_ENUMERATED: i32 = 138;

/* ASN1_F_BN_TO_ASN1_INTEGER 139 # */
pub const ASN1_F_BN_TO_ASN1_INTEGER: i32 = 139;

/* ASN1_F_C2I_ASN1_BIT_STRING 189 # */
pub const ASN1_F_C2I_ASN1_BIT_STRING: i32 = 189;

/* ASN1_F_C2I_ASN1_INTEGER 194 # */
pub const ASN1_F_C2I_ASN1_INTEGER: i32 = 194;

/* ASN1_F_C2I_ASN1_OBJECT 196 # */
pub const ASN1_F_C2I_ASN1_OBJECT: i32 = 196;

/* ASN1_F_COLLECT_DATA 140 # */
pub const ASN1_F_COLLECT_DATA: i32 = 140;

/* ASN1_F_D2I_ASN1_BIT_STRING 141 # */
pub const ASN1_F_D2I_ASN1_BIT_STRING: i32 = 141;

/* ASN1_F_D2I_ASN1_BOOLEAN 142 # */
pub const ASN1_F_D2I_ASN1_BOOLEAN: i32 = 142;

/* ASN1_F_D2I_ASN1_BYTES 143 # */
pub const ASN1_F_D2I_ASN1_BYTES: i32 = 143;

/* ASN1_F_D2I_ASN1_GENERALIZEDTIME 144 # */
pub const ASN1_F_D2I_ASN1_GENERALIZEDTIME: i32 = 144;

/* ASN1_F_D2I_ASN1_HEADER 145 # */
pub const ASN1_F_D2I_ASN1_HEADER: i32 = 145;

/* ASN1_F_D2I_ASN1_INTEGER 146 # */
pub const ASN1_F_D2I_ASN1_INTEGER: i32 = 146;

/* ASN1_F_D2I_ASN1_OBJECT 147 # */
pub const ASN1_F_D2I_ASN1_OBJECT: i32 = 147;

/* ASN1_F_D2I_ASN1_SET 148 # */
pub const ASN1_F_D2I_ASN1_SET: i32 = 148;

/* ASN1_F_D2I_ASN1_TYPE_BYTES 149 # */
pub const ASN1_F_D2I_ASN1_TYPE_BYTES: i32 = 149;

/* ASN1_F_D2I_ASN1_UINTEGER 150 # */
pub const ASN1_F_D2I_ASN1_UINTEGER: i32 = 150;

/* ASN1_F_D2I_ASN1_UTCTIME 151 # */
pub const ASN1_F_D2I_ASN1_UTCTIME: i32 = 151;

/* ASN1_F_D2I_AUTOPRIVATEKEY 207 # */
pub const ASN1_F_D2I_AUTOPRIVATEKEY: i32 = 207;

/* ASN1_F_D2I_NETSCAPE_RSA 152 # */
pub const ASN1_F_D2I_NETSCAPE_RSA: i32 = 152;

/* ASN1_F_D2I_NETSCAPE_RSA_2 153 # */
pub const ASN1_F_D2I_NETSCAPE_RSA_2: i32 = 153;

/* ASN1_F_D2I_PRIVATEKEY 154 # */
pub const ASN1_F_D2I_PRIVATEKEY: i32 = 154;

/* ASN1_F_D2I_PUBLICKEY 155 # */
pub const ASN1_F_D2I_PUBLICKEY: i32 = 155;

/* ASN1_F_D2I_RSA_NET 200 # */
pub const ASN1_F_D2I_RSA_NET: i32 = 200;

/* ASN1_F_D2I_RSA_NET_2 201 # */
pub const ASN1_F_D2I_RSA_NET_2: i32 = 201;

/* ASN1_F_D2I_X509 156 # */
pub const ASN1_F_D2I_X509: i32 = 156;

/* ASN1_F_D2I_X509_CINF 157 # */
pub const ASN1_F_D2I_X509_CINF: i32 = 157;

/* ASN1_F_D2I_X509_PKEY 159 # */
pub const ASN1_F_D2I_X509_PKEY: i32 = 159;

/* ASN1_F_I2D_ASN1_BIO_STREAM 211 # */
pub const ASN1_F_I2D_ASN1_BIO_STREAM: i32 = 211;

/* ASN1_F_I2D_ASN1_SET 188 # */
pub const ASN1_F_I2D_ASN1_SET: i32 = 188;

/* ASN1_F_I2D_ASN1_TIME 160 # */
pub const ASN1_F_I2D_ASN1_TIME: i32 = 160;

/* ASN1_F_I2D_DSA_PUBKEY 161 # */
pub const ASN1_F_I2D_DSA_PUBKEY: i32 = 161;

/* ASN1_F_I2D_EC_PUBKEY 181 # */
pub const ASN1_F_I2D_EC_PUBKEY: i32 = 181;

/* ASN1_F_I2D_PRIVATEKEY 163 # */
pub const ASN1_F_I2D_PRIVATEKEY: i32 = 163;

/* ASN1_F_I2D_PUBLICKEY 164 # */
pub const ASN1_F_I2D_PUBLICKEY: i32 = 164;

/* ASN1_F_I2D_RSA_NET 162 # */
pub const ASN1_F_I2D_RSA_NET: i32 = 162;

/* ASN1_F_I2D_RSA_PUBKEY 165 # */
pub const ASN1_F_I2D_RSA_PUBKEY: i32 = 165;

/* ASN1_F_LONG_C2I 166 # */
pub const ASN1_F_LONG_C2I: i32 = 166;

/* ASN1_F_OID_MODULE_INIT 174 # */
pub const ASN1_F_OID_MODULE_INIT: i32 = 174;

/* ASN1_F_PARSE_TAGGING 182 # */
pub const ASN1_F_PARSE_TAGGING: i32 = 182;

/* ASN1_F_PKCS5_PBE2_SET_IV 167 # */
pub const ASN1_F_PKCS5_PBE2_SET_IV: i32 = 167;

/* ASN1_F_PKCS5_PBE_SET 202 # */
pub const ASN1_F_PKCS5_PBE_SET: i32 = 202;

/* ASN1_F_PKCS5_PBE_SET0_ALGOR 215 # */
pub const ASN1_F_PKCS5_PBE_SET0_ALGOR: i32 = 215;

/* ASN1_F_PKCS5_PBKDF2_SET 219 # */
pub const ASN1_F_PKCS5_PBKDF2_SET: i32 = 219;

/* ASN1_F_SMIME_READ_ASN1 212 # */
pub const ASN1_F_SMIME_READ_ASN1: i32 = 212;

/* ASN1_F_SMIME_TEXT 213 # */
pub const ASN1_F_SMIME_TEXT: i32 = 213;

/* ASN1_F_X509_CINF_NEW 168 # */
pub const ASN1_F_X509_CINF_NEW: i32 = 168;

/* ASN1_F_X509_CRL_ADD0_REVOKED 169 # */
pub const ASN1_F_X509_CRL_ADD0_REVOKED: i32 = 169;

/* ASN1_F_X509_INFO_NEW 170 # */
pub const ASN1_F_X509_INFO_NEW: i32 = 170;

/* ASN1_F_X509_NAME_ENCODE 203 # */
pub const ASN1_F_X509_NAME_ENCODE: i32 = 203;

/* ASN1_F_X509_NAME_EX_D2I 158 # */
pub const ASN1_F_X509_NAME_EX_D2I: i32 = 158;

/* ASN1_F_X509_NAME_EX_NEW 171 # */
pub const ASN1_F_X509_NAME_EX_NEW: i32 = 171;

/* ASN1_F_X509_NEW 172 # */
pub const ASN1_F_X509_NEW: i32 = 172;

/* ASN1_F_X509_PKEY_NEW 173 /* Reason codes. */ */
pub const ASN1_F_X509_PKEY_NEW: i32 = 173;

/* ASN1_R_ADDING_OBJECT 171 # */
pub const ASN1_R_ADDING_OBJECT: i32 = 171;

/* ASN1_R_ASN1_PARSE_ERROR 203 # */
pub const ASN1_R_ASN1_PARSE_ERROR: i32 = 203;

/* ASN1_R_ASN1_SIG_PARSE_ERROR 204 # */
pub const ASN1_R_ASN1_SIG_PARSE_ERROR: i32 = 204;

/* ASN1_R_AUX_ERROR 100 # */
pub const ASN1_R_AUX_ERROR: i32 = 100;

/* ASN1_R_BAD_CLASS 101 # */
pub const ASN1_R_BAD_CLASS: i32 = 101;

/* ASN1_R_BAD_OBJECT_HEADER 102 # */
pub const ASN1_R_BAD_OBJECT_HEADER: i32 = 102;

/* ASN1_R_BAD_PASSWORD_READ 103 # */
pub const ASN1_R_BAD_PASSWORD_READ: i32 = 103;

/* ASN1_R_BAD_TAG 104 # */
pub const ASN1_R_BAD_TAG: i32 = 104;

/* ASN1_R_BMPSTRING_IS_WRONG_LENGTH 214 # */
pub const ASN1_R_BMPSTRING_IS_WRONG_LENGTH: i32 = 214;

/* ASN1_R_BN_LIB 105 # */
pub const ASN1_R_BN_LIB: i32 = 105;

/* ASN1_R_BOOLEAN_IS_WRONG_LENGTH 106 # */
pub const ASN1_R_BOOLEAN_IS_WRONG_LENGTH: i32 = 106;

/* ASN1_R_BUFFER_TOO_SMALL 107 # */
pub const ASN1_R_BUFFER_TOO_SMALL: i32 = 107;

/* ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER 108 # */
pub const ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER: i32 = 108;

/* ASN1_R_CONTEXT_NOT_INITIALISED 217 # */
pub const ASN1_R_CONTEXT_NOT_INITIALISED: i32 = 217;

/* ASN1_R_DATA_IS_WRONG 109 # */
pub const ASN1_R_DATA_IS_WRONG: i32 = 109;

/* ASN1_R_DECODE_ERROR 110 # */
pub const ASN1_R_DECODE_ERROR: i32 = 110;

/* ASN1_R_DECODING_ERROR 111 # */
pub const ASN1_R_DECODING_ERROR: i32 = 111;

/* ASN1_R_DEPTH_EXCEEDED 174 # */
pub const ASN1_R_DEPTH_EXCEEDED: i32 = 174;

/* ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED 198 # */
pub const ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED: i32 = 198;

/* ASN1_R_ENCODE_ERROR 112 # */
pub const ASN1_R_ENCODE_ERROR: i32 = 112;

/* ASN1_R_ERROR_GETTING_TIME 173 # */
pub const ASN1_R_ERROR_GETTING_TIME: i32 = 173;

/* ASN1_R_ERROR_LOADING_SECTION 172 # */
pub const ASN1_R_ERROR_LOADING_SECTION: i32 = 172;

/* ASN1_R_ERROR_PARSING_SET_ELEMENT 113 # */
pub const ASN1_R_ERROR_PARSING_SET_ELEMENT: i32 = 113;

/* ASN1_R_ERROR_SETTING_CIPHER_PARAMS 114 # */
pub const ASN1_R_ERROR_SETTING_CIPHER_PARAMS: i32 = 114;

/* ASN1_R_EXPECTING_AN_INTEGER 115 # */
pub const ASN1_R_EXPECTING_AN_INTEGER: i32 = 115;

/* ASN1_R_EXPECTING_AN_OBJECT 116 # */
pub const ASN1_R_EXPECTING_AN_OBJECT: i32 = 116;

/* ASN1_R_EXPECTING_A_BOOLEAN 117 # */
pub const ASN1_R_EXPECTING_A_BOOLEAN: i32 = 117;

/* ASN1_R_EXPECTING_A_TIME 118 # */
pub const ASN1_R_EXPECTING_A_TIME: i32 = 118;

/* ASN1_R_EXPLICIT_LENGTH_MISMATCH 119 # */
pub const ASN1_R_EXPLICIT_LENGTH_MISMATCH: i32 = 119;

/* ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED 120 # */
pub const ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED: i32 = 120;

/* ASN1_R_FIELD_MISSING 121 # */
pub const ASN1_R_FIELD_MISSING: i32 = 121;

/* ASN1_R_FIRST_NUM_TOO_LARGE 122 # */
pub const ASN1_R_FIRST_NUM_TOO_LARGE: i32 = 122;

/* ASN1_R_HEADER_TOO_LONG 123 # */
pub const ASN1_R_HEADER_TOO_LONG: i32 = 123;

/* ASN1_R_ILLEGAL_BITSTRING_FORMAT 175 # */
pub const ASN1_R_ILLEGAL_BITSTRING_FORMAT: i32 = 175;

/* ASN1_R_ILLEGAL_BOOLEAN 176 # */
pub const ASN1_R_ILLEGAL_BOOLEAN: i32 = 176;

/* ASN1_R_ILLEGAL_CHARACTERS 124 # */
pub const ASN1_R_ILLEGAL_CHARACTERS: i32 = 124;

/* ASN1_R_ILLEGAL_FORMAT 177 # */
pub const ASN1_R_ILLEGAL_FORMAT: i32 = 177;

/* ASN1_R_ILLEGAL_HEX 178 # */
pub const ASN1_R_ILLEGAL_HEX: i32 = 178;

/* ASN1_R_ILLEGAL_IMPLICIT_TAG 179 # */
pub const ASN1_R_ILLEGAL_IMPLICIT_TAG: i32 = 179;

/* ASN1_R_ILLEGAL_INTEGER 180 # */
pub const ASN1_R_ILLEGAL_INTEGER: i32 = 180;

/* ASN1_R_ILLEGAL_NESTED_TAGGING 181 # */
pub const ASN1_R_ILLEGAL_NESTED_TAGGING: i32 = 181;

/* ASN1_R_ILLEGAL_NULL 125 # */
pub const ASN1_R_ILLEGAL_NULL: i32 = 125;

/* ASN1_R_ILLEGAL_NULL_VALUE 182 # */
pub const ASN1_R_ILLEGAL_NULL_VALUE: i32 = 182;

/* ASN1_R_ILLEGAL_OBJECT 183 # */
pub const ASN1_R_ILLEGAL_OBJECT: i32 = 183;

/* ASN1_R_ILLEGAL_OPTIONAL_ANY 126 # */
pub const ASN1_R_ILLEGAL_OPTIONAL_ANY: i32 = 126;

/* ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE 170 # */
pub const ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE: i32 = 170;

/* ASN1_R_ILLEGAL_TAGGED_ANY 127 # */
pub const ASN1_R_ILLEGAL_TAGGED_ANY: i32 = 127;

/* ASN1_R_ILLEGAL_TIME_VALUE 184 # */
pub const ASN1_R_ILLEGAL_TIME_VALUE: i32 = 184;

/* ASN1_R_INTEGER_NOT_ASCII_FORMAT 185 # */
pub const ASN1_R_INTEGER_NOT_ASCII_FORMAT: i32 = 185;

/* ASN1_R_INTEGER_TOO_LARGE_FOR_LONG 128 # */
pub const ASN1_R_INTEGER_TOO_LARGE_FOR_LONG: i32 = 128;

/* ASN1_R_INVALID_BIT_STRING_BITS_LEFT 220 # */
pub const ASN1_R_INVALID_BIT_STRING_BITS_LEFT: i32 = 220;

/* ASN1_R_INVALID_BMPSTRING_LENGTH 129 # */
pub const ASN1_R_INVALID_BMPSTRING_LENGTH: i32 = 129;

/* ASN1_R_INVALID_DIGIT 130 # */
pub const ASN1_R_INVALID_DIGIT: i32 = 130;

/* ASN1_R_INVALID_MIME_TYPE 205 # */
pub const ASN1_R_INVALID_MIME_TYPE: i32 = 205;

/* ASN1_R_INVALID_MODIFIER 186 # */
pub const ASN1_R_INVALID_MODIFIER: i32 = 186;

/* ASN1_R_INVALID_NUMBER 187 # */
pub const ASN1_R_INVALID_NUMBER: i32 = 187;

/* ASN1_R_INVALID_OBJECT_ENCODING 216 # */
pub const ASN1_R_INVALID_OBJECT_ENCODING: i32 = 216;

/* ASN1_R_INVALID_SEPARATOR 131 # */
pub const ASN1_R_INVALID_SEPARATOR: i32 = 131;

/* ASN1_R_INVALID_TIME_FORMAT 132 # */
pub const ASN1_R_INVALID_TIME_FORMAT: i32 = 132;

/* ASN1_R_INVALID_UNIVERSALSTRING_LENGTH 133 # */
pub const ASN1_R_INVALID_UNIVERSALSTRING_LENGTH: i32 = 133;

/* ASN1_R_INVALID_UTF8STRING 134 # */
pub const ASN1_R_INVALID_UTF8STRING: i32 = 134;

/* ASN1_R_IV_TOO_LARGE 135 # */
pub const ASN1_R_IV_TOO_LARGE: i32 = 135;

/* ASN1_R_LENGTH_ERROR 136 # */
pub const ASN1_R_LENGTH_ERROR: i32 = 136;

/* ASN1_R_LIST_ERROR 188 # */
pub const ASN1_R_LIST_ERROR: i32 = 188;

/* ASN1_R_MIME_NO_CONTENT_TYPE 206 # */
pub const ASN1_R_MIME_NO_CONTENT_TYPE: i32 = 206;

/* ASN1_R_MIME_PARSE_ERROR 207 # */
pub const ASN1_R_MIME_PARSE_ERROR: i32 = 207;

/* ASN1_R_MIME_SIG_PARSE_ERROR 208 # */
pub const ASN1_R_MIME_SIG_PARSE_ERROR: i32 = 208;

/* ASN1_R_MISSING_EOC 137 # */
pub const ASN1_R_MISSING_EOC: i32 = 137;

/* ASN1_R_MISSING_SECOND_NUMBER 138 # */
pub const ASN1_R_MISSING_SECOND_NUMBER: i32 = 138;

/* ASN1_R_MISSING_VALUE 189 # */
pub const ASN1_R_MISSING_VALUE: i32 = 189;

/* ASN1_R_MSTRING_NOT_UNIVERSAL 139 # */
pub const ASN1_R_MSTRING_NOT_UNIVERSAL: i32 = 139;

/* ASN1_R_MSTRING_WRONG_TAG 140 # */
pub const ASN1_R_MSTRING_WRONG_TAG: i32 = 140;

/* ASN1_R_NESTED_ASN1_STRING 197 # */
pub const ASN1_R_NESTED_ASN1_STRING: i32 = 197;

/* ASN1_R_NON_HEX_CHARACTERS 141 # */
pub const ASN1_R_NON_HEX_CHARACTERS: i32 = 141;

/* ASN1_R_NOT_ASCII_FORMAT 190 # */
pub const ASN1_R_NOT_ASCII_FORMAT: i32 = 190;

/* ASN1_R_NOT_ENOUGH_DATA 142 # */
pub const ASN1_R_NOT_ENOUGH_DATA: i32 = 142;

/* ASN1_R_NO_CONTENT_TYPE 209 # */
pub const ASN1_R_NO_CONTENT_TYPE: i32 = 209;

/* ASN1_R_NO_DEFAULT_DIGEST 201 # */
pub const ASN1_R_NO_DEFAULT_DIGEST: i32 = 201;

/* ASN1_R_NO_MATCHING_CHOICE_TYPE 143 # */
pub const ASN1_R_NO_MATCHING_CHOICE_TYPE: i32 = 143;

/* ASN1_R_NO_MULTIPART_BODY_FAILURE 210 # */
pub const ASN1_R_NO_MULTIPART_BODY_FAILURE: i32 = 210;

/* ASN1_R_NO_MULTIPART_BOUNDARY 211 # */
pub const ASN1_R_NO_MULTIPART_BOUNDARY: i32 = 211;

/* ASN1_R_NO_SIG_CONTENT_TYPE 212 # */
pub const ASN1_R_NO_SIG_CONTENT_TYPE: i32 = 212;

/* ASN1_R_NULL_IS_WRONG_LENGTH 144 # */
pub const ASN1_R_NULL_IS_WRONG_LENGTH: i32 = 144;

/* ASN1_R_OBJECT_NOT_ASCII_FORMAT 191 # */
pub const ASN1_R_OBJECT_NOT_ASCII_FORMAT: i32 = 191;

/* ASN1_R_ODD_NUMBER_OF_CHARS 145 # */
pub const ASN1_R_ODD_NUMBER_OF_CHARS: i32 = 145;

/* ASN1_R_PRIVATE_KEY_HEADER_MISSING 146 # */
pub const ASN1_R_PRIVATE_KEY_HEADER_MISSING: i32 = 146;

/* ASN1_R_SECOND_NUMBER_TOO_LARGE 147 # */
pub const ASN1_R_SECOND_NUMBER_TOO_LARGE: i32 = 147;

/* ASN1_R_SEQUENCE_LENGTH_MISMATCH 148 # */
pub const ASN1_R_SEQUENCE_LENGTH_MISMATCH: i32 = 148;

/* ASN1_R_SEQUENCE_NOT_CONSTRUCTED 149 # */
pub const ASN1_R_SEQUENCE_NOT_CONSTRUCTED: i32 = 149;

/* ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG 192 # */
pub const ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG: i32 = 192;

/* ASN1_R_SHORT_LINE 150 # */
pub const ASN1_R_SHORT_LINE: i32 = 150;

/* ASN1_R_SIG_INVALID_MIME_TYPE 213 # */
pub const ASN1_R_SIG_INVALID_MIME_TYPE: i32 = 213;

/* ASN1_R_STREAMING_NOT_SUPPORTED 202 # */
pub const ASN1_R_STREAMING_NOT_SUPPORTED: i32 = 202;

/* ASN1_R_STRING_TOO_LONG 151 # */
pub const ASN1_R_STRING_TOO_LONG: i32 = 151;

/* ASN1_R_STRING_TOO_SHORT 152 # */
pub const ASN1_R_STRING_TOO_SHORT: i32 = 152;

/* ASN1_R_TAG_VALUE_TOO_HIGH 153 # */
pub const ASN1_R_TAG_VALUE_TOO_HIGH: i32 = 153;

/* ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD 154 # */
pub const ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD: i32 = 154;

/* ASN1_R_TIME_NOT_ASCII_FORMAT 193 # */
pub const ASN1_R_TIME_NOT_ASCII_FORMAT: i32 = 193;

/* ASN1_R_TOO_LONG 155 # */
pub const ASN1_R_TOO_LONG: i32 = 155;

/* ASN1_R_TYPE_NOT_CONSTRUCTED 156 # */
pub const ASN1_R_TYPE_NOT_CONSTRUCTED: i32 = 156;

/* ASN1_R_UNABLE_TO_DECODE_RSA_KEY 157 # */
pub const ASN1_R_UNABLE_TO_DECODE_RSA_KEY: i32 = 157;

/* ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY 158 # */
pub const ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY: i32 = 158;

/* ASN1_R_UNEXPECTED_EOC 159 # */
pub const ASN1_R_UNEXPECTED_EOC: i32 = 159;

/* ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH 215 # */
pub const ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH: i32 = 215;

/* ASN1_R_UNKNOWN_FORMAT 160 # */
pub const ASN1_R_UNKNOWN_FORMAT: i32 = 160;

/* ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM 161 # */
pub const ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM: i32 = 161;

/* ASN1_R_UNKNOWN_OBJECT_TYPE 162 # */
pub const ASN1_R_UNKNOWN_OBJECT_TYPE: i32 = 162;

/* ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE 163 # */
pub const ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE: i32 = 163;

/* ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM 199 # */
pub const ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM: i32 = 199;

/* ASN1_R_UNKNOWN_TAG 194 # */
pub const ASN1_R_UNKNOWN_TAG: i32 = 194;

/* ASN1_R_UNKOWN_FORMAT 195 # */
pub const ASN1_R_UNKOWN_FORMAT: i32 = 195;

/* ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE 164 # */
pub const ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE: i32 = 164;

/* ASN1_R_UNSUPPORTED_CIPHER 165 # */
pub const ASN1_R_UNSUPPORTED_CIPHER: i32 = 165;

/* ASN1_R_UNSUPPORTED_ENCRYPTION_ALGORITHM 166 # */
pub const ASN1_R_UNSUPPORTED_ENCRYPTION_ALGORITHM: i32 = 166;

/* ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE 167 # */
pub const ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE: i32 = 167;

/* ASN1_R_UNSUPPORTED_TYPE 196 # */
pub const ASN1_R_UNSUPPORTED_TYPE: i32 = 196;

/* ASN1_R_WRONG_PUBLIC_KEY_TYPE 200 # */
pub const ASN1_R_WRONG_PUBLIC_KEY_TYPE: i32 = 200;

/* ASN1_R_WRONG_TAG 168 # */
pub const ASN1_R_WRONG_TAG: i32 = 168;

/* ASN1_R_WRONG_TYPE 169 # */
pub const ASN1_R_WRONG_TYPE: i32 = 169;

/* OPENSSL_ECC_MAX_FIELD_BITS 661 # */
pub const OPENSSL_ECC_MAX_FIELD_BITS: i32 = 661;

/* OPENSSL_EC_NAMED_CURVE 0x001 typedef */
pub const OPENSSL_EC_NAMED_CURVE: i32 = 1;

/* d2i_ECPKParameters_bio ( bp , x ) ASN1_d2i_bio_of ( EC_GROUP , NULL , d2i_ECPKParameters , bp , x ) # */

/* i2d_ECPKParameters_bio ( bp , x ) ASN1_i2d_bio_of_const ( EC_GROUP , i2d_ECPKParameters , bp , x ) # */

/* d2i_ECPKParameters_fp ( fp , x ) ( EC_GROUP * ) ASN1_d2i_fp ( NULL , ( char * ( * ) ( ) ) d2i_ECPKParameters , ( fp ) , ( unsigned char * * ) ( x ) ) # */

/* i2d_ECPKParameters_fp ( fp , x ) ASN1_i2d_fp ( i2d_ECPKParameters , ( fp ) , ( unsigned char * ) ( x ) ) # */

/* EC_PKEY_NO_PARAMETERS 0x001 # */
pub const EC_PKEY_NO_PARAMETERS: i32 = 1;

/* EC_PKEY_NO_PUBKEY 0x002 /* some values for the flags field */ */
pub const EC_PKEY_NO_PUBKEY: i32 = 2;

/* EC_FLAG_NON_FIPS_ALLOW 0x1 # */
pub const EC_FLAG_NON_FIPS_ALLOW: i32 = 1;

/* EC_FLAG_FIPS_CHECKED 0x2 /** Creates a new EC_KEY object.
 *  \return EC_KEY object or NULL if an error occurred.
 */ */
pub const EC_FLAG_FIPS_CHECKED: i32 = 2;

/* ECParameters_dup ( x ) ASN1_dup_of ( EC_KEY , i2d_ECParameters , d2i_ECParameters , x ) # */

/* EVP_PKEY_CTX_set_ec_paramgen_curve_nid ( ctx , nid ) EVP_PKEY_CTX_ctrl ( ctx , EVP_PKEY_EC , EVP_PKEY_OP_PARAMGEN , EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID , nid , NULL ) # */

/* EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID ( EVP_PKEY_ALG_CTRL + 1 ) /* BEGIN ERROR CODES */ */

/* EC_F_BN_TO_FELEM 224 # */
pub const EC_F_BN_TO_FELEM: i32 = 224;

/* EC_F_COMPUTE_WNAF 143 # */
pub const EC_F_COMPUTE_WNAF: i32 = 143;

/* EC_F_D2I_ECPARAMETERS 144 # */
pub const EC_F_D2I_ECPARAMETERS: i32 = 144;

/* EC_F_D2I_ECPKPARAMETERS 145 # */
pub const EC_F_D2I_ECPKPARAMETERS: i32 = 145;

/* EC_F_D2I_ECPRIVATEKEY 146 # */
pub const EC_F_D2I_ECPRIVATEKEY: i32 = 146;

/* EC_F_DO_EC_KEY_PRINT 221 # */
pub const EC_F_DO_EC_KEY_PRINT: i32 = 221;

/* EC_F_ECKEY_PARAM2TYPE 223 # */
pub const EC_F_ECKEY_PARAM2TYPE: i32 = 223;

/* EC_F_ECKEY_PARAM_DECODE 212 # */
pub const EC_F_ECKEY_PARAM_DECODE: i32 = 212;

/* EC_F_ECKEY_PRIV_DECODE 213 # */
pub const EC_F_ECKEY_PRIV_DECODE: i32 = 213;

/* EC_F_ECKEY_PRIV_ENCODE 214 # */
pub const EC_F_ECKEY_PRIV_ENCODE: i32 = 214;

/* EC_F_ECKEY_PUB_DECODE 215 # */
pub const EC_F_ECKEY_PUB_DECODE: i32 = 215;

/* EC_F_ECKEY_PUB_ENCODE 216 # */
pub const EC_F_ECKEY_PUB_ENCODE: i32 = 216;

/* EC_F_ECKEY_TYPE2PARAM 220 # */
pub const EC_F_ECKEY_TYPE2PARAM: i32 = 220;

/* EC_F_ECPARAMETERS_PRINT 147 # */
pub const EC_F_ECPARAMETERS_PRINT: i32 = 147;

/* EC_F_ECPARAMETERS_PRINT_FP 148 # */
pub const EC_F_ECPARAMETERS_PRINT_FP: i32 = 148;

/* EC_F_ECPKPARAMETERS_PRINT 149 # */
pub const EC_F_ECPKPARAMETERS_PRINT: i32 = 149;

/* EC_F_ECPKPARAMETERS_PRINT_FP 150 # */
pub const EC_F_ECPKPARAMETERS_PRINT_FP: i32 = 150;

/* EC_F_ECP_NIST_MOD_192 203 # */
pub const EC_F_ECP_NIST_MOD_192: i32 = 203;

/* EC_F_ECP_NIST_MOD_224 204 # */
pub const EC_F_ECP_NIST_MOD_224: i32 = 204;

/* EC_F_ECP_NIST_MOD_256 205 # */
pub const EC_F_ECP_NIST_MOD_256: i32 = 205;

/* EC_F_ECP_NIST_MOD_521 206 # */
pub const EC_F_ECP_NIST_MOD_521: i32 = 206;

/* EC_F_EC_ASN1_GROUP2CURVE 153 # */
pub const EC_F_EC_ASN1_GROUP2CURVE: i32 = 153;

/* EC_F_EC_ASN1_GROUP2FIELDID 154 # */
pub const EC_F_EC_ASN1_GROUP2FIELDID: i32 = 154;

/* EC_F_EC_ASN1_GROUP2PARAMETERS 155 # */
pub const EC_F_EC_ASN1_GROUP2PARAMETERS: i32 = 155;

/* EC_F_EC_ASN1_GROUP2PKPARAMETERS 156 # */
pub const EC_F_EC_ASN1_GROUP2PKPARAMETERS: i32 = 156;

/* EC_F_EC_ASN1_PARAMETERS2GROUP 157 # */
pub const EC_F_EC_ASN1_PARAMETERS2GROUP: i32 = 157;

/* EC_F_EC_ASN1_PKPARAMETERS2GROUP 158 # */
pub const EC_F_EC_ASN1_PKPARAMETERS2GROUP: i32 = 158;

/* EC_F_EC_EX_DATA_SET_DATA 211 # */
pub const EC_F_EC_EX_DATA_SET_DATA: i32 = 211;

/* EC_F_EC_GF2M_MONTGOMERY_POINT_MULTIPLY 208 # */
pub const EC_F_EC_GF2M_MONTGOMERY_POINT_MULTIPLY: i32 = 208;

/* EC_F_EC_GF2M_SIMPLE_GROUP_CHECK_DISCRIMINANT 159 # */
pub const EC_F_EC_GF2M_SIMPLE_GROUP_CHECK_DISCRIMINANT: i32 = 159;

/* EC_F_EC_GF2M_SIMPLE_GROUP_SET_CURVE 195 # */
pub const EC_F_EC_GF2M_SIMPLE_GROUP_SET_CURVE: i32 = 195;

/* EC_F_EC_GF2M_SIMPLE_OCT2POINT 160 # */
pub const EC_F_EC_GF2M_SIMPLE_OCT2POINT: i32 = 160;

/* EC_F_EC_GF2M_SIMPLE_POINT2OCT 161 # */
pub const EC_F_EC_GF2M_SIMPLE_POINT2OCT: i32 = 161;

/* EC_F_EC_GF2M_SIMPLE_POINT_GET_AFFINE_COORDINATES 162 # */
pub const EC_F_EC_GF2M_SIMPLE_POINT_GET_AFFINE_COORDINATES: i32 = 162;

/* EC_F_EC_GF2M_SIMPLE_POINT_SET_AFFINE_COORDINATES 163 # */
pub const EC_F_EC_GF2M_SIMPLE_POINT_SET_AFFINE_COORDINATES: i32 = 163;

/* EC_F_EC_GF2M_SIMPLE_SET_COMPRESSED_COORDINATES 164 # */
pub const EC_F_EC_GF2M_SIMPLE_SET_COMPRESSED_COORDINATES: i32 = 164;

/* EC_F_EC_GFP_MONT_FIELD_DECODE 133 # */
pub const EC_F_EC_GFP_MONT_FIELD_DECODE: i32 = 133;

/* EC_F_EC_GFP_MONT_FIELD_ENCODE 134 # */
pub const EC_F_EC_GFP_MONT_FIELD_ENCODE: i32 = 134;

/* EC_F_EC_GFP_MONT_FIELD_MUL 131 # */
pub const EC_F_EC_GFP_MONT_FIELD_MUL: i32 = 131;

/* EC_F_EC_GFP_MONT_FIELD_SET_TO_ONE 209 # */
pub const EC_F_EC_GFP_MONT_FIELD_SET_TO_ONE: i32 = 209;

/* EC_F_EC_GFP_MONT_FIELD_SQR 132 # */
pub const EC_F_EC_GFP_MONT_FIELD_SQR: i32 = 132;

/* EC_F_EC_GFP_MONT_GROUP_SET_CURVE 189 # */
pub const EC_F_EC_GFP_MONT_GROUP_SET_CURVE: i32 = 189;

/* EC_F_EC_GFP_MONT_GROUP_SET_CURVE_GFP 135 # */
pub const EC_F_EC_GFP_MONT_GROUP_SET_CURVE_GFP: i32 = 135;

/* EC_F_EC_GFP_NISTP224_GROUP_SET_CURVE 225 # */
pub const EC_F_EC_GFP_NISTP224_GROUP_SET_CURVE: i32 = 225;

/* EC_F_EC_GFP_NISTP224_POINTS_MUL 228 # */
pub const EC_F_EC_GFP_NISTP224_POINTS_MUL: i32 = 228;

/* EC_F_EC_GFP_NISTP224_POINT_GET_AFFINE_COORDINATES 226 # */
pub const EC_F_EC_GFP_NISTP224_POINT_GET_AFFINE_COORDINATES: i32 = 226;

/* EC_F_EC_GFP_NISTP256_GROUP_SET_CURVE 230 # */
pub const EC_F_EC_GFP_NISTP256_GROUP_SET_CURVE: i32 = 230;

/* EC_F_EC_GFP_NISTP256_POINTS_MUL 231 # */
pub const EC_F_EC_GFP_NISTP256_POINTS_MUL: i32 = 231;

/* EC_F_EC_GFP_NISTP256_POINT_GET_AFFINE_COORDINATES 232 # */
pub const EC_F_EC_GFP_NISTP256_POINT_GET_AFFINE_COORDINATES: i32 = 232;

/* EC_F_EC_GFP_NISTP521_GROUP_SET_CURVE 233 # */
pub const EC_F_EC_GFP_NISTP521_GROUP_SET_CURVE: i32 = 233;

/* EC_F_EC_GFP_NISTP521_POINTS_MUL 234 # */
pub const EC_F_EC_GFP_NISTP521_POINTS_MUL: i32 = 234;

/* EC_F_EC_GFP_NISTP521_POINT_GET_AFFINE_COORDINATES 235 # */
pub const EC_F_EC_GFP_NISTP521_POINT_GET_AFFINE_COORDINATES: i32 = 235;

/* EC_F_EC_GFP_NIST_FIELD_MUL 200 # */
pub const EC_F_EC_GFP_NIST_FIELD_MUL: i32 = 200;

/* EC_F_EC_GFP_NIST_FIELD_SQR 201 # */
pub const EC_F_EC_GFP_NIST_FIELD_SQR: i32 = 201;

/* EC_F_EC_GFP_NIST_GROUP_SET_CURVE 202 # */
pub const EC_F_EC_GFP_NIST_GROUP_SET_CURVE: i32 = 202;

/* EC_F_EC_GFP_SIMPLE_GROUP_CHECK_DISCRIMINANT 165 # */
pub const EC_F_EC_GFP_SIMPLE_GROUP_CHECK_DISCRIMINANT: i32 = 165;

/* EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE 166 # */
pub const EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE: i32 = 166;

/* EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE_GFP 100 # */
pub const EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE_GFP: i32 = 100;

/* EC_F_EC_GFP_SIMPLE_GROUP_SET_GENERATOR 101 # */
pub const EC_F_EC_GFP_SIMPLE_GROUP_SET_GENERATOR: i32 = 101;

/* EC_F_EC_GFP_SIMPLE_MAKE_AFFINE 102 # */
pub const EC_F_EC_GFP_SIMPLE_MAKE_AFFINE: i32 = 102;

/* EC_F_EC_GFP_SIMPLE_OCT2POINT 103 # */
pub const EC_F_EC_GFP_SIMPLE_OCT2POINT: i32 = 103;

/* EC_F_EC_GFP_SIMPLE_POINT2OCT 104 # */
pub const EC_F_EC_GFP_SIMPLE_POINT2OCT: i32 = 104;

/* EC_F_EC_GFP_SIMPLE_POINTS_MAKE_AFFINE 137 # */
pub const EC_F_EC_GFP_SIMPLE_POINTS_MAKE_AFFINE: i32 = 137;

/* EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES 167 # */
pub const EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES: i32 = 167;

/* EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES_GFP 105 # */
pub const EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES_GFP: i32 = 105;

/* EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES 168 # */
pub const EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES: i32 = 168;

/* EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES_GFP 128 # */
pub const EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES_GFP: i32 = 128;

/* EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES 169 # */
pub const EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES: i32 = 169;

/* EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES_GFP 129 # */
pub const EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES_GFP: i32 = 129;

/* EC_F_EC_GROUP_CHECK 170 # */
pub const EC_F_EC_GROUP_CHECK: i32 = 170;

/* EC_F_EC_GROUP_CHECK_DISCRIMINANT 171 # */
pub const EC_F_EC_GROUP_CHECK_DISCRIMINANT: i32 = 171;

/* EC_F_EC_GROUP_COPY 106 # */
pub const EC_F_EC_GROUP_COPY: i32 = 106;

/* EC_F_EC_GROUP_GET0_GENERATOR 139 # */
pub const EC_F_EC_GROUP_GET0_GENERATOR: i32 = 139;

/* EC_F_EC_GROUP_GET_COFACTOR 140 # */
pub const EC_F_EC_GROUP_GET_COFACTOR: i32 = 140;

/* EC_F_EC_GROUP_GET_CURVE_GF2M 172 # */
pub const EC_F_EC_GROUP_GET_CURVE_GF2M: i32 = 172;

/* EC_F_EC_GROUP_GET_CURVE_GFP 130 # */
pub const EC_F_EC_GROUP_GET_CURVE_GFP: i32 = 130;

/* EC_F_EC_GROUP_GET_DEGREE 173 # */
pub const EC_F_EC_GROUP_GET_DEGREE: i32 = 173;

/* EC_F_EC_GROUP_GET_ORDER 141 # */
pub const EC_F_EC_GROUP_GET_ORDER: i32 = 141;

/* EC_F_EC_GROUP_GET_PENTANOMIAL_BASIS 193 # */
pub const EC_F_EC_GROUP_GET_PENTANOMIAL_BASIS: i32 = 193;

/* EC_F_EC_GROUP_GET_TRINOMIAL_BASIS 194 # */
pub const EC_F_EC_GROUP_GET_TRINOMIAL_BASIS: i32 = 194;

/* EC_F_EC_GROUP_NEW 108 # */
pub const EC_F_EC_GROUP_NEW: i32 = 108;

/* EC_F_EC_GROUP_NEW_BY_CURVE_NAME 174 # */
pub const EC_F_EC_GROUP_NEW_BY_CURVE_NAME: i32 = 174;

/* EC_F_EC_GROUP_NEW_FROM_DATA 175 # */
pub const EC_F_EC_GROUP_NEW_FROM_DATA: i32 = 175;

/* EC_F_EC_GROUP_PRECOMPUTE_MULT 142 # */
pub const EC_F_EC_GROUP_PRECOMPUTE_MULT: i32 = 142;

/* EC_F_EC_GROUP_SET_CURVE_GF2M 176 # */
pub const EC_F_EC_GROUP_SET_CURVE_GF2M: i32 = 176;

/* EC_F_EC_GROUP_SET_CURVE_GFP 109 # */
pub const EC_F_EC_GROUP_SET_CURVE_GFP: i32 = 109;

/* EC_F_EC_GROUP_SET_EXTRA_DATA 110 # */
pub const EC_F_EC_GROUP_SET_EXTRA_DATA: i32 = 110;

/* EC_F_EC_GROUP_SET_GENERATOR 111 # */
pub const EC_F_EC_GROUP_SET_GENERATOR: i32 = 111;

/* EC_F_EC_KEY_CHECK_KEY 177 # */
pub const EC_F_EC_KEY_CHECK_KEY: i32 = 177;

/* EC_F_EC_KEY_COPY 178 # */
pub const EC_F_EC_KEY_COPY: i32 = 178;

/* EC_F_EC_KEY_GENERATE_KEY 179 # */
pub const EC_F_EC_KEY_GENERATE_KEY: i32 = 179;

/* EC_F_EC_KEY_NEW 182 # */
pub const EC_F_EC_KEY_NEW: i32 = 182;

/* EC_F_EC_KEY_PRINT 180 # */
pub const EC_F_EC_KEY_PRINT: i32 = 180;

/* EC_F_EC_KEY_PRINT_FP 181 # */
pub const EC_F_EC_KEY_PRINT_FP: i32 = 181;

/* EC_F_EC_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES 229 # */
pub const EC_F_EC_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES: i32 = 229;

/* EC_F_EC_POINTS_MAKE_AFFINE 136 # */
pub const EC_F_EC_POINTS_MAKE_AFFINE: i32 = 136;

/* EC_F_EC_POINT_ADD 112 # */
pub const EC_F_EC_POINT_ADD: i32 = 112;

/* EC_F_EC_POINT_CMP 113 # */
pub const EC_F_EC_POINT_CMP: i32 = 113;

/* EC_F_EC_POINT_COPY 114 # */
pub const EC_F_EC_POINT_COPY: i32 = 114;

/* EC_F_EC_POINT_DBL 115 # */
pub const EC_F_EC_POINT_DBL: i32 = 115;

/* EC_F_EC_POINT_GET_AFFINE_COORDINATES_GF2M 183 # */
pub const EC_F_EC_POINT_GET_AFFINE_COORDINATES_GF2M: i32 = 183;

/* EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP 116 # */
pub const EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP: i32 = 116;

/* EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP 117 # */
pub const EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP: i32 = 117;

/* EC_F_EC_POINT_INVERT 210 # */
pub const EC_F_EC_POINT_INVERT: i32 = 210;

/* EC_F_EC_POINT_IS_AT_INFINITY 118 # */
pub const EC_F_EC_POINT_IS_AT_INFINITY: i32 = 118;

/* EC_F_EC_POINT_IS_ON_CURVE 119 # */
pub const EC_F_EC_POINT_IS_ON_CURVE: i32 = 119;

/* EC_F_EC_POINT_MAKE_AFFINE 120 # */
pub const EC_F_EC_POINT_MAKE_AFFINE: i32 = 120;

/* EC_F_EC_POINT_MUL 184 # */
pub const EC_F_EC_POINT_MUL: i32 = 184;

/* EC_F_EC_POINT_NEW 121 # */
pub const EC_F_EC_POINT_NEW: i32 = 121;

/* EC_F_EC_POINT_OCT2POINT 122 # */
pub const EC_F_EC_POINT_OCT2POINT: i32 = 122;

/* EC_F_EC_POINT_POINT2OCT 123 # */
pub const EC_F_EC_POINT_POINT2OCT: i32 = 123;

/* EC_F_EC_POINT_SET_AFFINE_COORDINATES_GF2M 185 # */
pub const EC_F_EC_POINT_SET_AFFINE_COORDINATES_GF2M: i32 = 185;

/* EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP 124 # */
pub const EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP: i32 = 124;

/* EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GF2M 186 # */
pub const EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GF2M: i32 = 186;

/* EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP 125 # */
pub const EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP: i32 = 125;

/* EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP 126 # */
pub const EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP: i32 = 126;

/* EC_F_EC_POINT_SET_TO_INFINITY 127 # */
pub const EC_F_EC_POINT_SET_TO_INFINITY: i32 = 127;

/* EC_F_EC_PRE_COMP_DUP 207 # */
pub const EC_F_EC_PRE_COMP_DUP: i32 = 207;

/* EC_F_EC_PRE_COMP_NEW 196 # */
pub const EC_F_EC_PRE_COMP_NEW: i32 = 196;

/* EC_F_EC_WNAF_MUL 187 # */
pub const EC_F_EC_WNAF_MUL: i32 = 187;

/* EC_F_EC_WNAF_PRECOMPUTE_MULT 188 # */
pub const EC_F_EC_WNAF_PRECOMPUTE_MULT: i32 = 188;

/* EC_F_I2D_ECPARAMETERS 190 # */
pub const EC_F_I2D_ECPARAMETERS: i32 = 190;

/* EC_F_I2D_ECPKPARAMETERS 191 # */
pub const EC_F_I2D_ECPKPARAMETERS: i32 = 191;

/* EC_F_I2D_ECPRIVATEKEY 192 # */
pub const EC_F_I2D_ECPRIVATEKEY: i32 = 192;

/* EC_F_I2O_ECPUBLICKEY 151 # */
pub const EC_F_I2O_ECPUBLICKEY: i32 = 151;

/* EC_F_NISTP224_PRE_COMP_NEW 227 # */
pub const EC_F_NISTP224_PRE_COMP_NEW: i32 = 227;

/* EC_F_NISTP256_PRE_COMP_NEW 236 # */
pub const EC_F_NISTP256_PRE_COMP_NEW: i32 = 236;

/* EC_F_NISTP521_PRE_COMP_NEW 237 # */
pub const EC_F_NISTP521_PRE_COMP_NEW: i32 = 237;

/* EC_F_O2I_ECPUBLICKEY 152 # */
pub const EC_F_O2I_ECPUBLICKEY: i32 = 152;

/* EC_F_OLD_EC_PRIV_DECODE 222 # */
pub const EC_F_OLD_EC_PRIV_DECODE: i32 = 222;

/* EC_F_PKEY_EC_CTRL 197 # */
pub const EC_F_PKEY_EC_CTRL: i32 = 197;

/* EC_F_PKEY_EC_CTRL_STR 198 # */
pub const EC_F_PKEY_EC_CTRL_STR: i32 = 198;

/* EC_F_PKEY_EC_DERIVE 217 # */
pub const EC_F_PKEY_EC_DERIVE: i32 = 217;

/* EC_F_PKEY_EC_KEYGEN 199 # */
pub const EC_F_PKEY_EC_KEYGEN: i32 = 199;

/* EC_F_PKEY_EC_PARAMGEN 219 # */
pub const EC_F_PKEY_EC_PARAMGEN: i32 = 219;

/* EC_F_PKEY_EC_SIGN 218 /* Reason codes. */ */
pub const EC_F_PKEY_EC_SIGN: i32 = 218;

/* EC_R_ASN1_ERROR 115 # */
pub const EC_R_ASN1_ERROR: i32 = 115;

/* EC_R_ASN1_UNKNOWN_FIELD 116 # */
pub const EC_R_ASN1_UNKNOWN_FIELD: i32 = 116;

/* EC_R_BIGNUM_OUT_OF_RANGE 144 # */
pub const EC_R_BIGNUM_OUT_OF_RANGE: i32 = 144;

/* EC_R_BUFFER_TOO_SMALL 100 # */
pub const EC_R_BUFFER_TOO_SMALL: i32 = 100;

/* EC_R_COORDINATES_OUT_OF_RANGE 146 # */
pub const EC_R_COORDINATES_OUT_OF_RANGE: i32 = 146;

/* EC_R_D2I_ECPKPARAMETERS_FAILURE 117 # */
pub const EC_R_D2I_ECPKPARAMETERS_FAILURE: i32 = 117;

/* EC_R_DECODE_ERROR 142 # */
pub const EC_R_DECODE_ERROR: i32 = 142;

/* EC_R_DISCRIMINANT_IS_ZERO 118 # */
pub const EC_R_DISCRIMINANT_IS_ZERO: i32 = 118;

/* EC_R_EC_GROUP_NEW_BY_NAME_FAILURE 119 # */
pub const EC_R_EC_GROUP_NEW_BY_NAME_FAILURE: i32 = 119;

/* EC_R_FIELD_TOO_LARGE 143 # */
pub const EC_R_FIELD_TOO_LARGE: i32 = 143;

/* EC_R_GF2M_NOT_SUPPORTED 147 # */
pub const EC_R_GF2M_NOT_SUPPORTED: i32 = 147;

/* EC_R_GROUP2PKPARAMETERS_FAILURE 120 # */
pub const EC_R_GROUP2PKPARAMETERS_FAILURE: i32 = 120;

/* EC_R_I2D_ECPKPARAMETERS_FAILURE 121 # */
pub const EC_R_I2D_ECPKPARAMETERS_FAILURE: i32 = 121;

/* EC_R_INCOMPATIBLE_OBJECTS 101 # */
pub const EC_R_INCOMPATIBLE_OBJECTS: i32 = 101;

/* EC_R_INVALID_ARGUMENT 112 # */
pub const EC_R_INVALID_ARGUMENT: i32 = 112;

/* EC_R_INVALID_COMPRESSED_POINT 110 # */
pub const EC_R_INVALID_COMPRESSED_POINT: i32 = 110;

/* EC_R_INVALID_COMPRESSION_BIT 109 # */
pub const EC_R_INVALID_COMPRESSION_BIT: i32 = 109;

/* EC_R_INVALID_CURVE 141 # */
pub const EC_R_INVALID_CURVE: i32 = 141;

/* EC_R_INVALID_DIGEST_TYPE 138 # */
pub const EC_R_INVALID_DIGEST_TYPE: i32 = 138;

/* EC_R_INVALID_ENCODING 102 # */
pub const EC_R_INVALID_ENCODING: i32 = 102;

/* EC_R_INVALID_FIELD 103 # */
pub const EC_R_INVALID_FIELD: i32 = 103;

/* EC_R_INVALID_FORM 104 # */
pub const EC_R_INVALID_FORM: i32 = 104;

/* EC_R_INVALID_GROUP_ORDER 122 # */
pub const EC_R_INVALID_GROUP_ORDER: i32 = 122;

/* EC_R_INVALID_PENTANOMIAL_BASIS 132 # */
pub const EC_R_INVALID_PENTANOMIAL_BASIS: i32 = 132;

/* EC_R_INVALID_PRIVATE_KEY 123 # */
pub const EC_R_INVALID_PRIVATE_KEY: i32 = 123;

/* EC_R_INVALID_TRINOMIAL_BASIS 137 # */
pub const EC_R_INVALID_TRINOMIAL_BASIS: i32 = 137;

/* EC_R_KEYS_NOT_SET 140 # */
pub const EC_R_KEYS_NOT_SET: i32 = 140;

/* EC_R_MISSING_PARAMETERS 124 # */
pub const EC_R_MISSING_PARAMETERS: i32 = 124;

/* EC_R_MISSING_PRIVATE_KEY 125 # */
pub const EC_R_MISSING_PRIVATE_KEY: i32 = 125;

/* EC_R_NOT_A_NIST_PRIME 135 # */
pub const EC_R_NOT_A_NIST_PRIME: i32 = 135;

/* EC_R_NOT_A_SUPPORTED_NIST_PRIME 136 # */
pub const EC_R_NOT_A_SUPPORTED_NIST_PRIME: i32 = 136;

/* EC_R_NOT_IMPLEMENTED 126 # */
pub const EC_R_NOT_IMPLEMENTED: i32 = 126;

/* EC_R_NOT_INITIALIZED 111 # */
pub const EC_R_NOT_INITIALIZED: i32 = 111;

/* EC_R_NO_FIELD_MOD 133 # */
pub const EC_R_NO_FIELD_MOD: i32 = 133;

/* EC_R_NO_PARAMETERS_SET 139 # */
pub const EC_R_NO_PARAMETERS_SET: i32 = 139;

/* EC_R_PASSED_NULL_PARAMETER 134 # */
pub const EC_R_PASSED_NULL_PARAMETER: i32 = 134;

/* EC_R_PKPARAMETERS2GROUP_FAILURE 127 # */
pub const EC_R_PKPARAMETERS2GROUP_FAILURE: i32 = 127;

/* EC_R_POINT_AT_INFINITY 106 # */
pub const EC_R_POINT_AT_INFINITY: i32 = 106;

/* EC_R_POINT_IS_NOT_ON_CURVE 107 # */
pub const EC_R_POINT_IS_NOT_ON_CURVE: i32 = 107;

/* EC_R_SLOT_FULL 108 # */
pub const EC_R_SLOT_FULL: i32 = 108;

/* EC_R_UNDEFINED_GENERATOR 113 # */
pub const EC_R_UNDEFINED_GENERATOR: i32 = 113;

/* EC_R_UNDEFINED_ORDER 128 # */
pub const EC_R_UNDEFINED_ORDER: i32 = 128;

/* EC_R_UNKNOWN_GROUP 129 # */
pub const EC_R_UNKNOWN_GROUP: i32 = 129;

/* EC_R_UNKNOWN_ORDER 114 # */
pub const EC_R_UNKNOWN_ORDER: i32 = 114;

/* EC_R_UNSUPPORTED_FIELD 131 # */
pub const EC_R_UNSUPPORTED_FIELD: i32 = 131;

/* EC_R_WRONG_CURVE_PARAMETERS 145 # */
pub const EC_R_WRONG_CURVE_PARAMETERS: i32 = 145;

/* EC_R_WRONG_ORDER 130 # */
pub const EC_R_WRONG_ORDER: i32 = 130;

/* ECDH_F_ECDH_CHECK 102 # */
pub const ECDH_F_ECDH_CHECK: i32 = 102;

/* ECDH_F_ECDH_COMPUTE_KEY 100 # */
pub const ECDH_F_ECDH_COMPUTE_KEY: i32 = 100;

/* ECDH_F_ECDH_DATA_NEW_METHOD 101 /* Reason codes. */ */
pub const ECDH_F_ECDH_DATA_NEW_METHOD: i32 = 101;

/* ECDH_R_KDF_FAILED 102 # */
pub const ECDH_R_KDF_FAILED: i32 = 102;

/* ECDH_R_NON_FIPS_METHOD 103 # */
pub const ECDH_R_NON_FIPS_METHOD: i32 = 103;

/* ECDH_R_NO_PRIVATE_VALUE 100 # */
pub const ECDH_R_NO_PRIVATE_VALUE: i32 = 100;

/* ECDH_R_POINT_ARITHMETIC_FAILURE 101 # */
pub const ECDH_R_POINT_ARITHMETIC_FAILURE: i32 = 101;

