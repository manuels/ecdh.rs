#![allow(dead_code, unused_imports, non_upper_case_globals, non_snake_case,
	non_camel_case_types)]
#![feature(libc, io, core, collections)]

#[macro_use]
extern crate log;
extern crate libc;

mod bindings_ecdh;
mod bindings_sha;

mod key;

pub mod group;
pub mod private_key;
pub mod public_key;
pub mod ecdh;
mod tests;
