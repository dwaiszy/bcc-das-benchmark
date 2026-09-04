//! Finite-field linear algebra used by the legacy BCC pair decoder.

/// Solves `A * x = b` with Gauss-Jordan elimination.
pub fn solve<F>(mut a: Vec<Vec<F>>, mut b: Vec<F>, vars: usize) -> Option<Vec<F>>
where
    F: ark_ff::Field,
{
    let rows = a.len();
    let cols = vars;
    let mut r = 0usize;
    for c in 0..cols {
        let pivot = (r..rows).find(|&i| !a[i][c].is_zero())?;
        a.swap(r, pivot);
        b.swap(r, pivot);
        let inv = a[r][c].inverse()?;
        for j in c..cols {
            a[r][j] *= inv;
        }
        b[r] *= inv;
        let pivot_row = a[r].clone();
        let pivot_b = b[r];
        for i in 0..rows {
            if i == r || a[i][c].is_zero() {
                continue;
            }
            let factor = a[i][c];
            for j in c..cols {
                a[i][j] -= factor * pivot_row[j];
            }
            b[i] -= factor * pivot_b;
        }
        r += 1;
        if r == rows {
            break;
        }
    }
    let mut x = vec![F::zero(); cols];
    for i in 0..cols.min(rows) {
        x[i] = b[i];
    }
    Some(x)
}
