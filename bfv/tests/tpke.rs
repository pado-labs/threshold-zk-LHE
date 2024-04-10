mod tests {
    use algebra::Field;
    use bfv::{PlainField, ThresholdPKE};

    type F = PlainField;

    #[test]
    fn tpke_test() {
        let total_number = 3;
        let threshold_number = 2;
        let indices = [F::new(1), F::new(2), F::new(3)];
        let msg_bytes = b"this is the message";

        let ctx = ThresholdPKE::gen_context(total_number, threshold_number, indices.to_vec());

        let (sk0, pk0) = ThresholdPKE::gen_keypair(&ctx);
        let (sk1, pk1) = ThresholdPKE::gen_keypair(&ctx);
        let (_, pk2) = ThresholdPKE::gen_keypair(&ctx);

        let (sk, pk) = ThresholdPKE::gen_keypair(&ctx);

        let pks = [pk0, pk1, pk2].to_vec();

        let (vec_c, nonce, c_bytes) = ThresholdPKE::encrypt_bytes(&ctx, &pks, msg_bytes);

        let c0 = ThresholdPKE::re_encrypt(&ctx, &vec_c[0], &sk0, &pk);
        let c1 = ThresholdPKE::re_encrypt(&ctx, &vec_c[1], &sk1, &pk);

        let ctxts = [c0, c1].to_vec();
        let chosen_indices = [F::new(1), F::new(2)].to_vec();

        let c = ThresholdPKE::combine(&ctx, &ctxts, &chosen_indices);

        let m_res = ThresholdPKE::decrypt_bytes(&ctx, &sk, &c, &nonce, &c_bytes);

        assert_eq!(msg_bytes, m_res.as_slice());
    }
}
