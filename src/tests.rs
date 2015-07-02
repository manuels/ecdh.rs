use ecdh;
use key::Key;
use private_key::PrivateKey;
use public_key::PublicKey;

use std::fs::File;
use std::io::Write;

#[test]
fn key_generation_works() {
	let alice = PrivateKey::generate().unwrap();
	assert!(!alice.get_public_key().as_point_ptr().is_null());
}
#[test]
fn key_io_works() {
	let public_key  = vec![2, 1, 0, 163, 215, 7, 212, 111, 65, 12, 71, 241, 53, 52, 251, 41, 237, 3, 29, 101, 63, 116, 130, 150, 64, 159, 132, 150, 85, 202, 191, 31, 227, 17, 30, 34, 46, 102, 166, 187, 133, 4, 84, 239, 190, 162, 174, 161, 40, 3, 203, 213, 79, 238, 16, 123, 90, 254, 108, 134, 181, 104, 112, 100, 116, 20, 238];
	let private_key = vec![1, 220, 254, 121, 176, 90, 169, 167, 226, 22, 16, 143, 36, 56, 183, 61, 167, 195, 174, 191, 140, 134, 86, 16, 123, 213, 40, 103, 174, 46, 250, 54, 119, 172, 247, 135, 144, 60, 99, 14, 242, 129, 212, 64, 121, 172, 200, 4, 121, 60, 129, 126, 58, 16, 23, 225, 56, 245, 56, 32, 109, 226, 94, 27, 162, 83];

	assert_eq!(PublicKey::from_vec(&public_key).unwrap().to_vec(), public_key);

	let key = PrivateKey::from_vec(&private_key).unwrap();
	assert_eq!(key.to_vec(), private_key);

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
