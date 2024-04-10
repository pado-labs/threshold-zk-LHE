# zkLHE for data sharing

> This is a library that implements a linearly homomorphic encryption for data sharing. The library will provide a zero-knowledge capability to prove each procedure of the underlying linearly homomorphic encryption scheme.

We focus on the following scenario. A seller who has some valuable data, and wants to monetize it for the buyer who will pay for it. A particular requirement is that the seller only wants to publish the data once, and hopefully, all the following procedures should be automatically executed by the system.

To do that, we introduce a role called computation node. They will help to convert the ciphertext (re-encrypt the ciphertexts) from the seller to a new ciphertext that the buyer can decrypt. This is done by using a threshold encryption based on the linearly homomorphic encryption. 

In a nutshell, the seller first splits the message using Shamir Secret Sharing, then encrypts the shares using the public keys belonging to the computation nodes. When a buyer pays to smart contract with his public key. Each node first decrypts the share and re-encrypts with the buyer's public key and publishes the ciphertexts. Then an Aggregator can homomorphically compute the ciphertext that encrypts the message under the buyer's public key.

As long as there are sufficient honest computation nodes, the buyer can always decrypt the ciphertext and get the message. Note that the seller can set the policy with a `threshold`, which means as long as the number of honest nodes is at least `threshold`, then the system is safe.



Let's show how it works on the code side.

```rust
        /// Set the total number of the computation nodes.
        /// Note that the current system only supports up to 20 nodes.
        let total_number = 3;
        /// Set the threshold of the system.
        let threshold_number = 2;
        
        /// Set the index of each node to be 1,2,3. 
        /// Note that you can not set it to 0.
        let indices = [F::new(1), F::new(2), F::new(3)];
        
        let msg_bytes = b"this is the message";

        /// Setup the system.
        let ctx = ThresholdPKE::gen_context(total_number, threshold_number, indices.to_vec());
				
        /// Node 1 generates the keypair, and uses the public to register.
        let (sk1, pk1) = ThresholdPKE::gen_keypair(&ctx);
        
        /// Node 2 generates the keypair, and uses the public to register.
        let (sk2, pk2) = ThresholdPKE::gen_keypair(&ctx);
        
        /// Node 3 generates the keypair, and uses the public to register.
        let (sk3, pk3) = ThresholdPKE::gen_keypair(&ctx);

        /// The buyer generates the keypair
        let (sk, pk) = ThresholdPKE::gen_keypair(&ctx);

        let pks = [pk1, pk2, pk3].to_vec();

        /// The seller encrypts the message in a hybrid model.
        /// In this encryption, the seller chooses a symmetric key and splits it into 3 shares, and then encrypts the shares using each public key of the nodes. The seller encryts the message with the symmetric key under ChaCha20Poly1305, which is an AEAD encryption.
        let (vec_c, nonce, c_bytes) = ThresholdPKE::encrypt_bytes(&ctx, &pks, msg_bytes);

        /// Node 1 re-encrypts the ciphertext.
        let c1 = ThresholdPKE::re_encrypt(&ctx, &vec_c[0], &sk1, &pk);
        
        /// Node 2 re-encrypts the ciphertext.
        let c2 = ThresholdPKE::re_encrypt(&ctx, &vec_c[1], &sk2, &pk);
        
        /// Node 3 re-encrypts the ciphertext.
        let c3 = ThresholdPKE::re_encrypt(&ctx, &vec_c[2], &sk3, &pk);

        let ctxts = [c1, c2, c3].to_vec();
        let chosen_indices = [F::new(1), F::new(2), F::new(3)].to_vec();

        /// An aggregator combine all the ciphertext into one ciphertext under the buyer's public key.
        let c = ThresholdPKE::combine(&ctx, &ctxts, &chosen_indices);

        /// The buyer can then decrypt the ciphertext.
        let m_res = ThresholdPKE::decrypt_bytes(&ctx, &sk, &c, &nonce, &c_bytes);
```




