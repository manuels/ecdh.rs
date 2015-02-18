use ecdh;
use key;

#[test]
fn key_generation_works() {
	let alice = key::Key::generate().unwrap();
	assert!(!alice.public_key().is_null());
}

#[test]
fn ecdh_works() {
	let alice = key::Key::generate().unwrap();
	let bob = key::Key::generate().unwrap();
	let eve = key::Key::generate().unwrap();
	
	let alice_symm_key = ecdh::ECDH::compute_key(&alice, bob.public_key());
	let bob_symm_key   = ecdh::ECDH::compute_key(&bob, alice.public_key());
	let eve_symm_key   = ecdh::ECDH::compute_key(&eve, alice.public_key());

	debug!("alice_symm_key: {:?}", alice_symm_key.unwrap().to_vec());
	debug!("bob_symm_key: {:?}", bob_symm_key.unwrap().to_vec());
	debug!("eve_symm_key: {:?}", eve_symm_key.unwrap().to_vec());

	assert_eq!(alice_symm_key.unwrap().to_vec(), bob_symm_key.unwrap().to_vec());
	assert!(alice_symm_key.unwrap().to_vec() != eve_symm_key.unwrap().to_vec());
	assert!(bob_symm_key.unwrap().to_vec() != eve_symm_key.unwrap().to_vec());
}
