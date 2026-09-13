//! FFT-based BCC erasure decoder.
//! The comments below map implementation blocks to Algorithm 1 in the BCC paper.

use crate::error::BcError;
use crate::fft::bcc::encode::FftBlockCirculantCode;
use crate::fft::rs::{fft_erasure_decode, fft_erasure_decode_coeffs};
use ark_ff::FftField;
use ark_poly::EvaluationDomain;
use std::collections::{BTreeSet, HashMap};

pub fn decode<F: FftField>(
    code: &FftBlockCirculantCode<F>,
    received: &[Option<F>],
) -> Result<Vec<F>, BcError> {
    let params = *code.params();
    if received.len() != params.n() {
        return Err(BcError::BadCodewordLength {
            got: received.len(),
            expected: params.n(),
        });
    }

    // Algorithm 1, Lines 1-3: initialize and index the received word.
    let mut recovered = received.to_vec();

    // Algorithm 1, Lines 4-12: local-code decoding.
    phase1_local_recovery(code, &mut recovered);

    // Algorithm 1, Lines 13-40: adjacent-pair decoding.
    phase2_adjacent_pair_recovery(code, &mut recovered);

    // Return the complete codeword or report a stopping pattern.
    if recovered.iter().any(Option::is_none) {
        return Err(BcError::Uncorrectable);
    }
    Ok(recovered.into_iter().map(Option::unwrap).collect())
}

/// Algorithm 1, Lines 4-12: repeatedly repair local codes with at most
/// `rho` erasures.
fn phase1_local_recovery<F: FftField>(code: &FftBlockCirculantCode<F>, received: &mut [Option<F>]) {
    let params = *code.params();
    let points = code.points();
    let mut auxiliary = vec![None; points.domain_n.size()];

    loop {
        let mut progressed = false;
        // Lines 4 and 10: compute the current locally decodable set J1.
        for local_index in 0..params.mu {
            let support = params.local_support(local_index);
            let erasures = count_erasures(&support, received);
            if !(1..=params.rho).contains(&erasures) {
                continue;
            }

            // Lines 6-7: invoke the local RS decoder. The auxiliary FFT
            // domain represents the D^(1) or D^(2) local code variant.
            auxiliary.fill(None);
            copy_support_to_auxiliary(code, &support, received, &mut auxiliary);
            if let Some(coefficients) =
                fft_erasure_decode_coeffs(&points.domain_n, params.k0(), points.offset, &auxiliary)
            {
                // Lines 8-9: merge recovered local symbols.
                code.fill_local_support_from_coeffs(local_index, &coefficients, received);
                progressed = true;
            }
        }
        if !progressed {
            return;
        }
    }
}

/// Algorithm 1, Lines 13-40: adjacent-pair Phase 2.
fn phase2_adjacent_pair_recovery<F: FftField>(
    code: &FftBlockCirculantCode<F>,
    received: &mut [Option<F>],
) {
    let params = *code.params();
    if received.iter().all(Option::is_some) {
        return;
    }

    // Lines 14-21: construct J2 for mu=2 or cyclic adjacent pairs.
    let pairs: Vec<usize> = if params.mu == 2 {
        (count_erasures_all(received) <= 2 * params.rho)
            .then_some(0)
            .into_iter()
            .collect()
    } else {
        (0..params.mu)
            .filter(|&left| adjacent_pair_is_eligible(code, left, received))
            .collect()
    };

    // Lines 22-25: reject erasures outside the selected pairs.
    let mut covered = vec![false; params.mu];
    for &left in &pairs {
        covered[left] = true;
        covered[(left + 1) % params.mu] = true;
    }
    if (0..params.mu).any(|i| !covered[i] && count_erasures(&params.local_support(i), received) > 0)
    {
        return;
    }

    // Line 26: decode each pair in J2.
    for left in pairs {
        recover_adjacent_pair(code, left, received);
    }
}

/// Line 21: select a pair with at most `2*rho` erasures and clean outer blocks.
fn adjacent_pair_is_eligible<F: FftField>(
    code: &FftBlockCirculantCode<F>,
    left: usize,
    received: &[Option<F>],
) -> bool {
    let params = *code.params();
    let right = (left + 1) % params.mu;
    let erasures = count_erasures(&params.local_support(left), received)
        + count_erasures(&params.parity_block(right), received)
        + count_erasures(&params.info_block((right + 1) % params.mu), received);

    erasures > 0
        && erasures <= 2 * params.rho
        && count_erasures(&params.info_block(left), received) == 0
        && count_erasures(&params.info_block((right + 1) % params.mu), received) == 0
}

/// Recover one adjacent pair using a difference polynomial and two auxiliary RS words.
fn recover_adjacent_pair<F: FftField>(
    code: &FftBlockCirculantCode<F>,
    left: usize,
    received: &mut [Option<F>],
) {
    let params = *code.params();
    let points = code.points();
    let right = (left + 1) % params.mu;
    let left_support = params.local_support(left);
    let right_support = params.local_support(right);

    // Lines 27-30: build the difference word from the outer blocks;
    // the shared block contributes zeros because the local polynomials agree.
    let difference_coefficients = if params.mu == 2 {
        vec![F::zero(); params.k0()]
    } else {
        let left_outer = params.info_block(left);
        let right_outer = params.info_block((right + 1) % params.mu);
        let overlap = params.info_block(right);
        let mut difference_word = vec![None; points.domain_n.size()];

        for offset in 0..params.omega {
            let left_value = received[left_outer[offset]].unwrap();
            let right_value = received[right_outer[offset]].unwrap();
            difference_word[points.domain_index(left_outer[offset])] =
                Some(left_value - right_value);
            difference_word[points.domain_index(overlap[offset])] = Some(F::zero());
        }

        match fft_erasure_decode_coeffs(
            &points.domain_n,
            params.k0(),
            points.offset,
            &difference_word,
        ) {
            Some(coefficients) => coefficients,
            None => return,
        }
    };
    // Lines 31-33: decode/interpolate s and evaluate it on the auxiliary domain.
    let difference_evaluations = points.domain_n.fft(&difference_coefficients);

    // Lines 34-36: form the two auxiliary words using m_left=m_right+s
    // and m_right=m_left-s.
    let mut left_auxiliary = vec![None; points.domain_n.size()];
    let mut right_auxiliary = vec![None; points.domain_n.size()];
    copy_support_to_auxiliary(code, &left_support, received, &mut left_auxiliary);
    copy_support_to_auxiliary(code, &right_support, received, &mut right_auxiliary);

    for position in params.parity_block(right) {
        if let Some(value) = received[position] {
            let index = points.domain_index(position);
            left_auxiliary[index] = Some(value + difference_evaluations[index]);
        }
    }
    for position in params.parity_block(left) {
        if let Some(value) = received[position] {
            let index = points.domain_index(position);
            right_auxiliary[index] = Some(value - difference_evaluations[index]);
        }
    }

    // Lines 37-38: decode both auxiliary RS words.
    let Some(left_full) = fft_erasure_decode(
        &points.domain_n,
        params.k0(),
        points.offset,
        &left_auxiliary,
    ) else {
        return;
    };
    let Some(right_full) = fft_erasure_decode(
        &points.domain_n,
        params.k0(),
        points.offset,
        &right_auxiliary,
    ) else {
        return;
    };

    // Line 39: merge the recovered pair symbols into the received word.
    for position in left_support {
        if received[position].is_none() {
            received[position] = Some(left_full[points.domain_index(position)]);
        }
    }
    for position in right_support {
        if received[position].is_none() {
            received[position] = Some(right_full[points.domain_index(position)]);
        }
    }
}

fn copy_support_to_auxiliary<F: FftField>(
    code: &FftBlockCirculantCode<F>,
    support: &[usize],
    received: &[Option<F>],
    auxiliary: &mut [Option<F>],
) {
    for &position in support {
        auxiliary[code.points().domain_index(position)] = received[position];
    }
}

fn count_erasures<F>(support: &[usize], received: &[Option<F>]) -> usize {
    support
        .iter()
        .filter(|&&position| received[position].is_none())
        .count()
}

fn count_erasures_all<F>(received: &[Option<F>]) -> usize {
    received.iter().filter(|value| value.is_none()).count()
}

/// Legacy FFT BCC Phase 2 retained for benchmarks and regression comparison.
///
/// Unlike the paper algorithm, this directly solves the two local codes'
/// combined parity-check equations. It is deliberately not called by
/// [`decode`].
#[allow(dead_code)]
fn legacy_linear_phase2<F: FftField>(
    code: &FftBlockCirculantCode<F>,
    left_support: &[usize],
    right_support: &[usize],
    union: &BTreeSet<usize>,
    received: &[Option<F>],
) -> Option<Vec<F>> {
    let rho = code.params().rho;
    let union: Vec<usize> = union.iter().copied().collect();
    let column_of: HashMap<usize, usize> = union
        .iter()
        .enumerate()
        .map(|(column, &j)| (j, column))
        .collect();

    let mut parity_check = vec![vec![F::zero(); union.len()]; 2 * rho];
    for (block, support) in [left_support, right_support].iter().enumerate() {
        let locators: Vec<F> = support.iter().map(|&j| code.eval_point(j)).collect();
        let interpolator = crate::archive::legacy_bcc::poly::Interpolator::new(&locators);
        for (index, &position) in support.iter().enumerate() {
            let weight = interpolator.weights()[index];
            for row in 0..rho {
                parity_check[block * rho + row][column_of[&position]] +=
                    weight * locators[index].pow([row as u64]);
            }
        }
    }

    let erased_columns: Vec<usize> = union
        .iter()
        .enumerate()
        .filter_map(|(column, &position)| received[position].is_none().then_some(column))
        .collect();
    let known_columns: Vec<usize> = union
        .iter()
        .enumerate()
        .filter_map(|(column, &position)| received[position].is_some().then_some(column))
        .collect();
    let mut matrix = vec![vec![F::zero(); erased_columns.len()]; 2 * rho];
    let mut rhs = vec![F::zero(); 2 * rho];

    for row in 0..2 * rho {
        for &column in &known_columns {
            rhs[row] -= parity_check[row][column] * received[union[column]].unwrap();
        }
        for (target, &column) in erased_columns.iter().enumerate() {
            matrix[row][target] = parity_check[row][column];
        }
    }
    crate::archive::legacy_bcc::linalg::solve(matrix, rhs, erased_columns.len())
}
