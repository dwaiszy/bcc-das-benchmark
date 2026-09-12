//! Ignored release-mode benchmarks for all KZG opening paths.

#[cfg(test)]
mod benchmarks {
    use super::super::*;
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_poly::{DenseUVPolynomial, EvaluationDomain, Polynomial, Radix2EvaluationDomain};
    use ark_std::test_rng;
    use std::time::Instant;

    fn ms(start: Instant) -> f64 {
        start.elapsed().as_secs_f64() * 1_000.0
    }

    #[test]
    #[ignore = "prints n=4096 timings across all schemes"]
    fn benchmark_all_schemes_n4096() {
        let rng = &mut test_rng();
        let scheme = KzgLocalCodeScheme::setup_peerdas(4095, 64, 64, rng).unwrap();
        let poly = UniPoly::from_coefficients_vec((0..4096).map(|_| Fr::rand(rng)).collect());
        let points_domain = Radix2EvaluationDomain::<Fr>::new(4096).unwrap();
        let cosets: Vec<Vec<Fr>> = (0..64)
            .map(|cell| {
                let representative = points_domain.element(cell);
                (0..64)
                    .map(|i| representative * points_domain.element(i * 64))
                    .collect()
            })
            .collect();
        let values: Vec<Vec<Fr>> = cosets
            .iter()
            .map(|points| points.iter().map(|z| poly.evaluate(z)).collect())
            .collect();
        let all_points: Vec<Fr> = cosets.iter().flatten().copied().collect();

        let start = Instant::now();
        let (commitment, randomness) = scheme.commit(&poly);
        let commit_ms = ms(start);

        let start = Instant::now();
        let plain: Vec<_> = all_points
            .iter()
            .map(|&z| scheme.open(&poly, z, &randomness))
            .collect();
        let plain_open_ms = ms(start);
        let start = Instant::now();
        for (z, proof) in all_points.iter().zip(&plain) {
            assert!(scheme.verify(&commitment, *z, poly.evaluate(z), proof));
        }
        let plain_verify_ms = ms(start);

        let start = Instant::now();
        let coset = scheme.open_coset_all_naive(&poly);
        let coset_open_ms = ms(start);
        let start = Instant::now();
        for ((cell, proof), vals) in coset.iter().enumerate().zip(&values) {
            assert!(scheme.verify_coset(&commitment, points_domain.element(cell), vals, proof));
        }
        let coset_verify_ms = ms(start);

        let start = Instant::now();
        let fk20 = scheme.open_coset_all(&poly);
        let fk20_open_ms = ms(start);
        let start = Instant::now();
        for ((cell, proof), vals) in fk20.iter().enumerate().zip(&values) {
            assert!(scheme.verify_coset(&commitment, points_domain.element(cell), vals, proof));
        }
        let fk20_verify_ms = ms(start);

        let start = Instant::now();
        let shplonk: Vec<_> = cosets
            .iter()
            .map(|points| scheme.open_multipoint(&poly, &commitment, points))
            .collect();
        let shplonk_open_ms = ms(start);
        let start = Instant::now();
        for ((points, vals), proof) in cosets.iter().zip(&values).zip(&shplonk) {
            assert!(scheme.verify_multipoint(&commitment, points, vals, proof));
        }
        let shplonk_verify_ms = ms(start);

        println!("| Scheme | Opened workload | Commit ms | Open ms | Verify ms |");
        println!("|---|---:|---:|---:|---:|");
        println!(
            "| Plain KZG10 | 4096 single-point proofs | {commit_ms:.3} | {plain_open_ms:.3} | {plain_verify_ms:.3} |"
        );
        println!(
            "| Coset multiproof | 64 cosets x 64 points | {commit_ms:.3} | {coset_open_ms:.3} | {coset_verify_ms:.3} |"
        );
        println!(
            "| FK20 coset multiproof | 64 cosets x 64 points | {commit_ms:.3} | {fk20_open_ms:.3} | {fk20_verify_ms:.3} |"
        );
        println!(
            "| SHPLONK | 64 multipoint proofs x 64 points | {commit_ms:.3} | {shplonk_open_ms:.3} | {shplonk_verify_ms:.3} |"
        );
    }
}
