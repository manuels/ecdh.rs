
extern crate libc;
use std::mem;


/*
struct SHAstate_st
		(unsigned int) h0
		(unsigned int) h1
		(unsigned int) h2
		(unsigned int) h3
		(unsigned int) h4
		(unsigned int) Nl
		(unsigned int) Nh
		(unsigned int [16]) data
		(unsigned int) num
*/
#[repr(C)]
pub struct SHAstate_st {
	h0: libc::c_uint,
	h1: libc::c_uint,
	h2: libc::c_uint,
	h3: libc::c_uint,
	h4: libc::c_uint,
	Nl: libc::c_uint,
	Nh: libc::c_uint,
	data: [libc::c_uint; 16],
	num: libc::c_uint,
}

/*
struct SHA256state_st
		(unsigned int [8]) h
		(unsigned int) Nl
		(unsigned int) Nh
		(unsigned int [16]) data
		(unsigned int) num
		(unsigned int) md_len
*/
#[repr(C)]
pub struct SHA256state_st {
	h: [libc::c_uint; 8],
	Nl: libc::c_uint,
	Nh: libc::c_uint,
	data: [libc::c_uint; 16],
	num: libc::c_uint,
	md_len: libc::c_uint,
}

/*
struct SHA512state_st
		(unsigned long long [8]) h
		(unsigned long long) Nl
		(unsigned long long) Nh
		(union SHA512state_st::(anonymous at /usr/include/openssl/sha.h:187:2)) 
		(union (anonymous union at /usr/include/openssl/sha.h:187:2)) u [union SHA512state_st::(anonymous at /usr/include/openssl/sha.h:187:2)]
		(unsigned int) num
		(unsigned int) md_len
*/
#[repr(C)]
pub struct SHA512state_st;

/*
struct SHA_CTX
		(unsigned int) h0
		(unsigned int) h1
		(unsigned int) h2
		(unsigned int) h3
		(unsigned int) h4
		(unsigned int) Nl
		(unsigned int) Nh
		(unsigned int [16]) data
		(unsigned int) num
*/
#[repr(C)]
pub struct SHA_CTX {
	h0: libc::c_uint,
	h1: libc::c_uint,
	h2: libc::c_uint,
	h3: libc::c_uint,
	h4: libc::c_uint,
	Nl: libc::c_uint,
	Nh: libc::c_uint,
	data: [libc::c_uint; 16],
	num: libc::c_uint,
}

/*
struct SHA256_CTX
		(unsigned int [8]) h
		(unsigned int) Nl
		(unsigned int) Nh
		(unsigned int [16]) data
		(unsigned int) num
		(unsigned int) md_len
*/
#[repr(C)]
pub struct SHA256_CTX {
	h: [libc::c_uint; 8],
	Nl: libc::c_uint,
	Nh: libc::c_uint,
	data: [libc::c_uint; 16],
	num: libc::c_uint,
	md_len: libc::c_uint,
}

/*
struct SHA512_CTX
		(unsigned long long [8]) h
		(unsigned long long) Nl
		(unsigned long long) Nh
		(union SHA512state_st::(anonymous at /usr/include/openssl/sha.h:187:2)) 
		(union (anonymous union at /usr/include/openssl/sha.h:187:2)) u [union SHA512state_st::(anonymous at /usr/include/openssl/sha.h:187:2)]
		(unsigned int) num
		(unsigned int) md_len
*/
#[repr(C)]
pub struct SHA512_CTX;

/*
int SHA_Init()
	(SHA_CTX *) c [struct SHAstate_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA_Init(c: *mut SHAstate_st) -> libc::c_int;
}


/*
int SHA_Update()
	(SHA_CTX *) c [struct SHAstate_st *]
	(const void *) data
	(size_t) len [unsigned long]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA_Update(c: *mut SHAstate_st, data: *const libc::c_void, len: libc::c_ulong) -> libc::c_int;
}


/*
int SHA_Final()
	(unsigned char *) md
	(SHA_CTX *) c [struct SHAstate_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA_Final(md: *mut libc::c_uchar, c: *mut SHAstate_st) -> libc::c_int;
}


/*
unsigned char * SHA()
	(const unsigned char *) d
	(size_t) n [unsigned long]
	(unsigned char *) md
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA(d: *const libc::c_uchar, n: libc::c_ulong, md: *mut libc::c_uchar) -> *mut libc::c_uchar;
}


/*
void SHA_Transform()
	(SHA_CTX *) c [struct SHAstate_st *]
	(const unsigned char *) data
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA_Transform(c: *mut SHAstate_st, data: *const libc::c_uchar);
}


/*
int SHA1_Init()
	(SHA_CTX *) c [struct SHAstate_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA1_Init(c: *mut SHAstate_st) -> libc::c_int;
}


/*
int SHA1_Update()
	(SHA_CTX *) c [struct SHAstate_st *]
	(const void *) data
	(size_t) len [unsigned long]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA1_Update(c: *mut SHAstate_st, data: *const libc::c_void, len: libc::c_ulong) -> libc::c_int;
}


/*
int SHA1_Final()
	(unsigned char *) md
	(SHA_CTX *) c [struct SHAstate_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA1_Final(md: *mut libc::c_uchar, c: *mut SHAstate_st) -> libc::c_int;
}


/*
unsigned char * SHA1()
	(const unsigned char *) d
	(size_t) n [unsigned long]
	(unsigned char *) md
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA1(d: *const libc::c_uchar, n: libc::c_ulong, md: *mut libc::c_uchar) -> *mut libc::c_uchar;
}


/*
void SHA1_Transform()
	(SHA_CTX *) c [struct SHAstate_st *]
	(const unsigned char *) data
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA1_Transform(c: *mut SHAstate_st, data: *const libc::c_uchar);
}


/*
int SHA224_Init()
	(SHA256_CTX *) c [struct SHA256state_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA224_Init(c: *mut SHA256state_st) -> libc::c_int;
}


/*
int SHA224_Update()
	(SHA256_CTX *) c [struct SHA256state_st *]
	(const void *) data
	(size_t) len [unsigned long]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA224_Update(c: *mut SHA256state_st, data: *const libc::c_void, len: libc::c_ulong) -> libc::c_int;
}


/*
int SHA224_Final()
	(unsigned char *) md
	(SHA256_CTX *) c [struct SHA256state_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA224_Final(md: *mut libc::c_uchar, c: *mut SHA256state_st) -> libc::c_int;
}


/*
unsigned char * SHA224()
	(const unsigned char *) d
	(size_t) n [unsigned long]
	(unsigned char *) md
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA224(d: *const libc::c_uchar, n: libc::c_ulong, md: *mut libc::c_uchar) -> *mut libc::c_uchar;
}


/*
int SHA256_Init()
	(SHA256_CTX *) c [struct SHA256state_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA256_Init(c: *mut SHA256state_st) -> libc::c_int;
}


/*
int SHA256_Update()
	(SHA256_CTX *) c [struct SHA256state_st *]
	(const void *) data
	(size_t) len [unsigned long]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA256_Update(c: *mut SHA256state_st, data: *const libc::c_void, len: libc::c_ulong) -> libc::c_int;
}


/*
int SHA256_Final()
	(unsigned char *) md
	(SHA256_CTX *) c [struct SHA256state_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA256_Final(md: *mut libc::c_uchar, c: *mut SHA256state_st) -> libc::c_int;
}


/*
unsigned char * SHA256()
	(const unsigned char *) d
	(size_t) n [unsigned long]
	(unsigned char *) md
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA256(d: *const libc::c_uchar, n: libc::c_ulong, md: *mut libc::c_uchar) -> *mut libc::c_uchar;
}


/*
void SHA256_Transform()
	(SHA256_CTX *) c [struct SHA256state_st *]
	(const unsigned char *) data
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA256_Transform(c: *mut SHA256state_st, data: *const libc::c_uchar);
}


/*
int SHA384_Init()
	(SHA512_CTX *) c [struct SHA512state_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA384_Init(c: *mut SHA512state_st) -> libc::c_int;
}


/*
int SHA384_Update()
	(SHA512_CTX *) c [struct SHA512state_st *]
	(const void *) data
	(size_t) len [unsigned long]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA384_Update(c: *mut SHA512state_st, data: *const libc::c_void, len: libc::c_ulong) -> libc::c_int;
}


/*
int SHA384_Final()
	(unsigned char *) md
	(SHA512_CTX *) c [struct SHA512state_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA384_Final(md: *mut libc::c_uchar, c: *mut SHA512state_st) -> libc::c_int;
}


/*
unsigned char * SHA384()
	(const unsigned char *) d
	(size_t) n [unsigned long]
	(unsigned char *) md
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA384(d: *const libc::c_uchar, n: libc::c_ulong, md: *mut libc::c_uchar) -> *mut libc::c_uchar;
}


/*
int SHA512_Init()
	(SHA512_CTX *) c [struct SHA512state_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA512_Init(c: *mut SHA512state_st) -> libc::c_int;
}


/*
int SHA512_Update()
	(SHA512_CTX *) c [struct SHA512state_st *]
	(const void *) data
	(size_t) len [unsigned long]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA512_Update(c: *mut SHA512state_st, data: *const libc::c_void, len: libc::c_ulong) -> libc::c_int;
}


/*
int SHA512_Final()
	(unsigned char *) md
	(SHA512_CTX *) c [struct SHA512state_st *]
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA512_Final(md: *mut libc::c_uchar, c: *mut SHA512state_st) -> libc::c_int;
}


/*
unsigned char * SHA512()
	(const unsigned char *) d
	(size_t) n [unsigned long]
	(unsigned char *) md
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA512(d: *const libc::c_uchar, n: libc::c_ulong, md: *mut libc::c_uchar) -> *mut libc::c_uchar;
}


/*
void SHA512_Transform()
	(SHA512_CTX *) c [struct SHA512state_st *]
	(const unsigned char *) data
*/
#[link(name="crypto")]
extern "C" {
	pub fn SHA512_Transform(c: *mut SHA512state_st, data: *const libc::c_uchar);
}


/* HEADER_SHA_H # */

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

/* SHA_LONG unsigned int # */

/* SHA_LBLOCK 16 # */
pub const SHA_LBLOCK: i32 = 16;

/* SHA_CBLOCK ( SHA_LBLOCK * 4 ) /* SHA treats input data as a
					 * contiguous array of 32 bit
					 * wide big-endian values. */ */

/* SHA_LAST_BLOCK ( SHA_CBLOCK - 8 ) # */

/* SHA_DIGEST_LENGTH 20 typedef */
pub const SHA_DIGEST_LENGTH: i32 = 20;

/* SHA256_CBLOCK ( SHA_LBLOCK * 4 ) /* SHA-256 treats input data as a
					 * contiguous array of 32 bit
					 * wide big-endian values. */ */

/* SHA224_DIGEST_LENGTH 28 # */
pub const SHA224_DIGEST_LENGTH: i32 = 28;

/* SHA256_DIGEST_LENGTH 32 typedef */
pub const SHA256_DIGEST_LENGTH: i32 = 32;

/* SHA384_DIGEST_LENGTH 48 # */
pub const SHA384_DIGEST_LENGTH: i32 = 48;

/* SHA512_DIGEST_LENGTH 64 # */
pub const SHA512_DIGEST_LENGTH: i32 = 64;

/* SHA512_CBLOCK ( SHA_LBLOCK * 8 ) /* SHA-512 treats input data as a
					 * contiguous array of 64 bit
					 * wide big-endian values. */ */

/* SHA_LONG64 unsigned long long # */

/* U64 ( C ) C ## ULL # */

