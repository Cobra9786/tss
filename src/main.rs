use rand::rngs::OsRng;
use threshold_crypto::{SecretKeySet, SecretKeyShare, SignatureShare};

fn main() {
    // Step 1: Generate a shared private key
    let threshold = 2; // Minimum shares required to sign
    let total_participants = 3;

    // Create a secret key set for distributed key sharing
    let mut rng = OsRng;
    let sk_set = SecretKeySet::random(threshold, &mut rng);

    // Distribute secret key shares to participants
    let pk_set = sk_set.public_keys();
    let shares: Vec<SecretKeyShare> = (0..total_participants)
        .map(|i| sk_set.secret_key_share(i))
        .collect();

    println!("Distributed Public Key: {:?}", pk_set);

    // Step 2: Simulate a message to sign
    let message = b"Threshold Signature Scheme";

    // Step 3: Each participant signs the message with their share
    // First, collect the signatures into a Vec
    let signature_shares: Vec<SignatureShare> = shares
        .iter()
        .map(|sk_share| sk_share.sign(message))
        .collect();

    // Then, create a Vec of references to the SignatureShare
    let partial_signatures: Vec<(usize, &SignatureShare)> = signature_shares
        .iter()
        .enumerate()
        .collect();

    // Step 4: Combine partial signatures into a final signature
    let signature = pk_set
        .combine_signatures(partial_signatures.iter().map(|(i, s)| (*i, *s)))
        .expect("Failed to combine signatures");

    // Verify the final signature
    let is_valid = pk_set.public_key().verify(&signature,message);
    if is_valid {
        println!("Threshold signature is valid!");
    } else {
        println!("Threshold signature verification failed!");
    }
}
