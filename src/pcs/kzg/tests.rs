//! Correctness tests for the KZG opening modules.

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::pcs::ArcPcs;
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_poly::{DenseUVPolynomial, Polynomial};
    use ark_std::test_rng;

    #[test]
    fn scalar_batch_verification_rejects_each_corrupted_claim() {
        let pcs = KzgArcPcs::setup_fk20(7, 32, &mut test_rng()).unwrap();
        let polys: Vec<_> = (0..3)
            .map(|i| {
                UniPoly::from_coefficients_vec(
                    (0..8)
                        .map(|j| Fr::from((i * 19 + j * j + 1) as u64))
                        .collect(),
                )
            })
            .collect();
        let committed: Vec<_> = polys.iter().map(|p| pcs.inner.commit(p)).collect();
        // Repeated commitments, distinct points, and a shared point across
        // different commitments all occur in a single client batch.
        let owners = [0, 0, 1, 2];
        let points = [
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(2u64),
            Fr::from(5u64),
        ];
        let proofs: Vec<_> = owners
            .iter()
            .zip(points)
            .map(|(&i, z)| pcs.inner.open(&polys[i], z, &committed[i].1))
            .collect();
        let entries: Vec<_> = owners
            .iter()
            .enumerate()
            .map(|(j, &i)| {
                (
                    &committed[i].0,
                    points[j],
                    polys[i].evaluate(&points[j]),
                    &proofs[j],
                )
            })
            .collect();
        assert!(pcs.verify_batch(&entries).is_ok());
        assert!(pcs.verify_batch(&[]).is_ok());
        for j in 0..entries.len() {
            assert!(pcs.verify_batch(&entries[j..j + 1]).is_ok());
            let mut bad = entries.clone();
            bad[j].2 += Fr::from(1u64);
            assert!(pcs.verify_batch(&bad).is_err(), "value {j}");
            let mut bad = entries.clone();
            bad[j].1 += Fr::from(1u64);
            assert!(pcs.verify_batch(&bad).is_err(), "point {j}");
            let mut bad = entries.clone();
            bad[j].0 = &committed[(owners[j] + 1) % 3].0;
            assert!(pcs.verify_batch(&bad).is_err(), "commitment {j}");
            let mut bad = entries.clone();
            bad[j].3 = &proofs[(j + 1) % proofs.len()];
            assert!(pcs.verify_batch(&bad).is_err(), "proof {j}");
        }
        let zero = Fr::zero();
        let proof = pcs.inner.open(&polys[0], zero, &committed[0].1);
        let value = polys[0].evaluate(&zero);
        assert!(
            pcs.verify_batch(&[(&committed[0].0, zero, value, &proof)])
                .is_ok()
        );
        assert!(
            pcs.verify_batch(&[(&committed[0].0, zero, value + Fr::from(1u64), &proof)])
                .is_err()
        );
    }

    #[test]
    fn all_opening_paths_verify_shared_data() {
        let rng = &mut test_rng();
        let scheme = KzgLocalCodeScheme::setup(63, 8, rng).unwrap();
        let poly = UniPoly::from_coefficients_vec((0..64).map(|_| Fr::rand(rng)).collect());
        let (commitment, randomness) = scheme.commit(&poly);

        let point = Fr::rand(rng);
        let proof = scheme.open(&poly, point, &randomness);
        assert!(scheme.verify(&commitment, point, poly.evaluate(&point), &proof));

        let coset = ark_poly::Radix2EvaluationDomain::<Fr>::new(64).unwrap();
        let representative = coset.element(3);
        let points: Vec<_> = (0..8)
            .map(|i| representative * coset.element(i * 8))
            .collect();
        let values: Vec<_> = points.iter().map(|z| poly.evaluate(z)).collect();
        let coset_proof = scheme.open_coset(&poly, representative);
        assert!(scheme.verify_coset(&commitment, representative, &values, &coset_proof));

        let multipoint_proof = scheme.open_multipoint(&poly, &commitment, &points);
        assert!(scheme.verify_multipoint(&commitment, &points, &values, &multipoint_proof));
    }
}
