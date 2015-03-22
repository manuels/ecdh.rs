use ecdh;
use key::Key;
use private_key::PrivateKey;
use public_key::PublicKey;

use std::fs::File;

#[test]
fn key_generation_works() {
	let alice = PrivateKey::generate().unwrap();
	assert!(!alice.get_public_key().as_point_ptr().is_null());
}
#[test]
fn key_io_works() {
	let public_key  = vec![48i8, 51, 48, 49, 48, 66, 67, 54, 53, 56, 51, 52, 65, 56, 54, 50, 65, 65, 57, 65, 51, 51, 69, 51, 65, 51, 48, 69, 52, 70, 57, 50, 49, 51, 57, 67, 50, 56, 49, 70, 68, 49, 48, 52, 54, 49, 54, 50, 51, 56, 66, 70, 67, 48, 49, 54, 68, 65, 66, 53, 69, 49, 48, 57, 68, 54, 69, 70, 48, 55, 55, 50, 55, 70, 69, 69, 51, 50, 48, 70, 69, 67, 54, 65, 53, 52, 69, 57, 49, 66, 53, 67, 49, 52, 54, 52, 49, 53, 54, 51, 48, 50, 50, 65, 57, 69, 50, 51, 53, 53, 66, 48, 65, 70, 65, 49, 54, 50, 54, 52, 66, 51, 68, 70, 65, 69, 50, 49, 55, 55, 66, 55, 70, 53];
	let private_key = vec![54i8, 69, 51, 50, 69, 54, 48, 50, 54, 69, 56, 66, 54, 69, 52, 48, 54, 53, 51, 57, 57, 54, 65, 69, 70, 70, 57, 65, 69, 49, 68, 55, 53, 49, 51, 66, 69, 52, 55, 55, 56, 56, 65, 68, 53, 67, 49, 51, 51, 51, 53, 65, 48, 52, 67, 54, 54, 65, 51, 57, 57, 68, 53, 51, 65, 53, 70, 65, 50, 55, 50, 66, 54, 55, 55, 68, 66, 54, 55, 48, 69, 66, 65, 50, 66, 66, 52, 70, 49, 67, 56, 49, 57, 52, 49, 57, 68, 50, 55, 67, 55, 66, 67, 53, 68, 51, 52, 56, 51, 56, 49, 49, 54, 56, 55, 49, 68, 56, 49, 48, 55, 50, 56, 66, 50, 49, 65, 55, 67, 66];

	assert!(PublicKey::from_vec(&public_key).unwrap().to_vec() == public_key);

	let key = PrivateKey::from_vec(&private_key).unwrap();
	assert!(key.to_vec() == private_key);

	let mut file = File::create("/tmp/foo.txt").unwrap();
	key.to_pem(&mut file).unwrap();
}

#[test]
fn ecdh_works() {
	let alice = PrivateKey::generate().unwrap();
	let bob   = PrivateKey::generate().unwrap();
	let eve   = PrivateKey::generate().unwrap();
	
	let alice_symm_key = ecdh::ECDH::compute_key(&alice, &bob.get_public_key());
	let bob_symm_key   = ecdh::ECDH::compute_key(&bob, &alice.get_public_key());
	let eve_symm_key   = ecdh::ECDH::compute_key(&eve, &alice.get_public_key());

	debug!("alice priv: {:?}", alice.to_vec());
	debug!("alice pub: {:?}", alice.get_public_key().to_vec());
	debug!("bob priv: {:?}", bob.to_vec());
	debug!("bob pub: {:?}", bob.get_public_key().to_vec());

	debug!("alice_symm_key: {:?}", alice_symm_key.unwrap().to_vec());
	debug!("bob_symm_key: {:?}", bob_symm_key.unwrap().to_vec());
	debug!("eve_symm_key: {:?}", eve_symm_key.unwrap().to_vec());

	assert!(alice_symm_key.unwrap().to_vec() == bob_symm_key.unwrap().to_vec());
	assert!(alice_symm_key.unwrap().to_vec() != eve_symm_key.unwrap().to_vec());
	assert!(bob_symm_key.unwrap().to_vec()   != eve_symm_key.unwrap().to_vec());
}
