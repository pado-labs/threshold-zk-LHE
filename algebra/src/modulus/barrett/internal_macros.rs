macro_rules! impl_barrett_modulus {
    (impl BarrettModulus<$SelfT:ty>; WideType: $WideT:ty) => {
        impl BarrettModulus<$SelfT> {
            /// Creates a [`BarrettModulus<T>`] instance.
            ///
            /// - `value`: The value of the modulus.
            ///
            /// # Panics
            ///
            #[doc = concat!("The `value`'s `bit_count` should be at most ", stringify!($SelfT::BITS - 1), ", others will panic.")]
            pub const fn new(value: $SelfT) -> Self {
                const HALF_BITS: u32 = <$SelfT>::BITS >> 1;
                const HALF: $SelfT = <$SelfT>::MAX >> HALF_BITS;

                #[inline]
                const fn div_rem(numerator: $SelfT, divisor: $SelfT) -> ($SelfT, $SelfT) {
                    (numerator / divisor, numerator % divisor)
                }

                #[inline]
                const fn div_wide(hi: $SelfT, divisor: $SelfT) -> ($SelfT, $SelfT) {
                    let lhs = (hi as $WideT) << <$SelfT>::BITS;
                    let rhs = divisor as $WideT;
                    ((lhs / rhs) as $SelfT, (lhs % rhs) as $SelfT)
                }

                #[inline]
                const fn div_half(rem: $SelfT, divisor: $SelfT) -> ($SelfT, $SelfT) {
                    let (hi, rem) = div_rem(rem << HALF_BITS, divisor);
                    let (lo, rem) = div_rem(rem << HALF_BITS, divisor);
                    ((hi << HALF_BITS) | lo, rem)
                }

                const fn div_inplace(value: $SelfT) -> ([$SelfT; 2], $SelfT) {
                    let mut numerator = [0, 0];
                    let rem;

                    if value <= HALF {
                        let (q, r) = div_half(1, value);
                        numerator[1] = q;

                        let (q, r) = div_half(r, value);
                        numerator[0] = q;
                        rem = r;
                    } else {
                        let (q, r) = div_wide(1, value);
                        numerator[1] = q;

                        let (q, r) = div_wide(r, value);
                        numerator[0] = q;
                        rem = r;
                    }
                    (numerator, rem)
                }

                match value {
                    0 | 1 => panic!("modulus can't be 0 or 1."),
                    _ => {
                        let bit_count = <$SelfT>::BITS - value.leading_zeros();
                        assert!(bit_count < <$SelfT>::BITS - 1);

                        let (numerator, _) = div_inplace(value);

                        Self {
                            value,
                            ratio: numerator,
                        }
                    }
                }
            }

            /// Returns the bit count of this [`BarrettModulus<T>`].
            #[inline]
            pub const fn bit_count(&self) -> u32 {
                <$SelfT>::BITS - self.value.leading_zeros()
            }
        }

        impl $crate::reduce::LazyReduce<BarrettModulus<Self>> for $SelfT {
            type Output = Self;

            /// Caculates `self (mod 2*modulus)`.
            ///
            /// ## Procedure
            ///
            /// We denote `x` = `self`  and `m` = `modulus` here.
            ///
            /// The algorithm will output `r` = `x` mod `m` with the below procedures:
            ///
            /// 1. `q1` ← `x`, `q2` ← `q1` * `ratio`, `q3` ← ⌊`q2`/b^2⌋.
            /// 2. `r1` ← `x` mod b^2, `r2` ← `q3` * `m` mod b^2, `r` ← `r1` - `r2`.
            /// 3. If `r` ≥ `m` do: `r` ← `r` - `m`.
            /// 4. Return(`r`).
            ///
            /// ## Proof:
            ///
            /// ∵ `q1` = `x` , ⌊b^2 / m⌋ - 1 < `ratio` ≤ ⌊b^2 / m⌋
            ///
            /// ∴ ⌊x * b^2 / m⌋ - x < `q2` = `q1` * `ratio` ≤ ⌊x * b^2 / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 2 < `q3` = ⌊`q2` / b^2⌋ ≤ ⌊x / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 1 ≤ `q3` ≤ ⌊x / m⌋
            ///
            /// ∴ `x` - `q3` * `m` mod b^2 < 2 * m
            #[inline]
            fn lazy_reduce(self, modulus: BarrettModulus<Self>) -> Self::Output {
                let ratio = modulus.ratio();

                // Step 1.
                //              ratio[1]  ratio[0]
                //         *                self
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //            +-------------------+
                //            |  tmp1   |         |    <-- self * ratio[0]
                //            +-------------------+
                //   +------------------+
                //   |      tmp2        |              <-- self * ratio[1]
                //   +------------------+
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //   +--------+
                //   |   q3   |
                //   +--------+
                let tmp = (self as $WideT * ratio[0] as $WideT) >> Self::BITS; // tmp1
                let tmp = ((self as $WideT * ratio[1] as $WideT + tmp) >> Self::BITS) as $SelfT; // q3

                // Step 2.
                self.wrapping_sub(tmp.wrapping_mul(modulus.value())) // r = r1 -r2
            }
        }


        impl $crate::reduce::Reduce<BarrettModulus<Self>> for $SelfT {
            type Output = Self;

            /// Caculates `self (mod 2*modulus)`.
            ///
            /// ## Procedure
            ///
            /// We denote `x` = `self`  and `m` = `modulus` here.
            ///
            /// The algorithm will output `r` = `x` mod `m` with the below procedures:
            ///
            /// 1. `q1` ← `x`, `q2` ← `q1` * `ratio`, `q3` ← ⌊`q2`/b^2⌋.
            /// 2. `r1` ← `x` mod b^2, `r2` ← `q3` * `m` mod b^2, `r` ← `r1` - `r2`.
            /// 3. If `r` ≥ `m` do: `r` ← `r` - `m`.
            /// 4. Return(`r`).
            ///
            /// ## Proof:
            ///
            /// ∵ `q1` = `x` , ⌊b^2 / m⌋ - 1 < `ratio` ≤ ⌊b^2 / m⌋
            ///
            /// ∴ ⌊x * b^2 / m⌋ - x < `q2` = `q1` * `ratio` ≤ ⌊x * b^2 / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 2 < `q3` = ⌊`q2` / b^2⌋ ≤ ⌊x / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 1 ≤ `q3` ≤ ⌊x / m⌋
            ///
            /// ∴ `x` - `q3` * `m` mod b^2 < 2 * m
            #[inline]
            fn reduce(self, modulus: BarrettModulus<Self>) -> Self::Output {
                use $crate::reduce::LazyReduce;
                let tmp = self.lazy_reduce(modulus);

                if tmp >= modulus.value() {
                    tmp - modulus.value()
                } else {
                    tmp
                }
            }
        }

        impl $crate::reduce::LazyReduce<BarrettModulus<$SelfT>> for [$SelfT; 2] {
            type Output = $SelfT;

            /// Caculates `self (mod 2*modulus)`.
            ///
            /// ## Procedure
            ///
            /// We denote `x` = `self`  and `m` = `modulus` here.
            ///
            /// The algorithm will output `r` = `x` mod `m` with the below procedures:
            ///
            /// 1. `q1` ← `x`, `q2` ← `q1` * `ratio`, `q3` ← ⌊`q2`/b^2⌋.
            /// 2. `r1` ← `x` mod b^2, `r2` ← `q3` * `m` mod b^2, `r` ← `r1` - `r2`.
            /// 3. If `r` ≥ `m` do: `r` ← `r` - `m`.
            /// 4. Return(`r`).
            ///
            /// ## Proof:
            ///
            /// ∵ `q1` = `x` , ⌊b^2 / m⌋ - 1 < `ratio` ≤ ⌊b^2 / m⌋
            ///
            /// ∴ ⌊x * b^2 / m⌋ - x < `q2` = `q1` * `ratio` ≤ ⌊x * b^2 / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 2 < `q3` = ⌊`q2` / b^2⌋ ≤ ⌊x / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 1 ≤ `q3` ≤ ⌊x / m⌋
            ///
            /// ∴ `x` - `q3` * `m` mod b^2 < 2 * m
            #[inline]
            fn lazy_reduce(self, modulus: BarrettModulus<$SelfT>) -> Self::Output {
                let ratio = modulus.ratio();

                // Step 1.
                //                        ratio[1]  ratio[0]
                //                   *    value[1]  value[0]
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //                      +-------------------+
                //                      |         a         |    <-- value[0] * ratio[0]
                //                      +-------------------+
                //             +------------------+
                //             |        b         |              <-- value[0] * ratio[1]
                //             +------------------+
                //             +------------------+
                //             |        c         |              <-- value[1] * ratio[0]
                //             +------------------+
                //   +------------------+
                //   |        d         |                        <-- value[1] * ratio[1]
                //   +------------------+
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //   +------------------+
                //   |        q3        |
                //   +------------------+
                let a = ratio[0] as $WideT * self[0] as $WideT;
                let b_plus_a_left = ratio[1] as $WideT * self[0] as $WideT + (a >> <$SelfT>::BITS);

                let c = ratio[0] as $WideT * self[1] as $WideT;
                let d = ratio[1] as $WideT * self[1] as $WideT;

                let tmp = d.wrapping_add((b_plus_a_left + c) >> <$SelfT>::BITS) as $SelfT;

                // Step 2.
                self[0].wrapping_sub(tmp.wrapping_mul(modulus.value()))
            }
        }

        impl $crate::reduce::Reduce<BarrettModulus<$SelfT>> for [$SelfT; 2] {
            type Output = $SelfT;

            /// Caculates `self (mod modulus)`.
            ///
            /// ## Procedure
            ///
            /// We denote `x` = `self`  and `m` = `modulus` here.
            ///
            /// The algorithm will output `r` = `x` mod `m` with the below procedures:
            ///
            /// 1. `q1` ← `x`, `q2` ← `q1` * `ratio`, `q3` ← ⌊`q2`/b^2⌋.
            /// 2. `r1` ← `x` mod b^2, `r2` ← `q3` * `m` mod b^2, `r` ← `r1` - `r2`.
            /// 3. If `r` ≥ `m` do: `r` ← `r` - `m`.
            /// 4. Return(`r`).
            ///
            /// ## Proof:
            ///
            /// ∵ `q1` = `x` , ⌊b^2 / m⌋ - 1 < `ratio` ≤ ⌊b^2 / m⌋
            ///
            /// ∴ ⌊x * b^2 / m⌋ - x < `q2` = `q1` * `ratio` ≤ ⌊x * b^2 / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 2 < `q3` = ⌊`q2` / b^2⌋ ≤ ⌊x / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 1 ≤ `q3` ≤ ⌊x / m⌋
            ///
            /// ∴ `x` - `q3` * `m` mod b^2 < 2 * m
            #[inline]
            fn reduce(self, modulus: BarrettModulus<$SelfT>) -> Self::Output {
                use $crate::reduce::LazyReduce;
                let r = self.lazy_reduce(modulus);

                if r >= modulus.value() {
                    r - modulus.value()
                } else {
                    r
                }
            }
        }

        impl $crate::reduce::LazyReduce<BarrettModulus<$SelfT>> for ($SelfT, $SelfT) {
            type Output = $SelfT;

            /// Caculates `self (mod 2*modulus)`.
            ///
            /// ## Procedure
            ///
            /// We denote `x` = `self`  and `m` = `modulus` here.
            ///
            /// The algorithm will output `r` = `x` mod `m` with the below procedures:
            ///
            /// 1. `q1` ← `x`, `q2` ← `q1` * `ratio`, `q3` ← ⌊`q2`/b^2⌋.
            /// 2. `r1` ← `x` mod b^2, `r2` ← `q3` * `m` mod b^2, `r` ← `r1` - `r2`.
            /// 3. If `r` ≥ `m` do: `r` ← `r` - `m`.
            /// 4. Return(`r`).
            ///
            /// ## Proof:
            ///
            /// ∵ `q1` = `x` , ⌊b^2 / m⌋ - 1 < `ratio` ≤ ⌊b^2 / m⌋
            ///
            /// ∴ ⌊x * b^2 / m⌋ - x < `q2` = `q1` * `ratio` ≤ ⌊x * b^2 / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 2 < `q3` = ⌊`q2` / b^2⌋ ≤ ⌊x / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 1 ≤ `q3` ≤ ⌊x / m⌋
            ///
            /// ∴ `x` - `q3` * `m` mod b^2 < 2 * m
            #[inline]
            fn lazy_reduce(self, modulus: BarrettModulus<$SelfT>) -> Self::Output {
                let ratio = modulus.ratio();

                // Step 1.
                //                        ratio[1]  ratio[0]
                //                   *    value.1   value.0
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //                      +-------------------+
                //                      |         a         |    <-- value.0 * ratio[0]
                //                      +-------------------+
                //             +------------------+
                //             |        b         |              <-- value.0 * ratio[1]
                //             +------------------+
                //             +------------------+
                //             |        c         |              <-- value.1 * ratio[0]
                //             +------------------+
                //   +------------------+
                //   |        d         |                        <-- value.1 * ratio[1]
                //   +------------------+
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //   +------------------+
                //   |        q3        |
                //   +------------------+
                let a = ratio[0] as $WideT * self.0 as $WideT;
                let b_plus_a_left = ratio[1] as $WideT * self.0 as $WideT + (a >> <$SelfT>::BITS);

                let c = ratio[0] as $WideT * self.1 as $WideT;
                let d = ratio[1] as $WideT * self.1 as $WideT;

                let tmp = d.wrapping_add((b_plus_a_left + c) >> <$SelfT>::BITS) as $SelfT;

                // Step 2.
                self.0.wrapping_sub(tmp.wrapping_mul(modulus.value()))
            }
        }

        impl $crate::reduce::Reduce<BarrettModulus<$SelfT>> for ($SelfT, $SelfT) {
            type Output = $SelfT;

            /// Caculates `self (mod modulus)`.
            ///
            /// ## Procedure
            ///
            /// We denote `x` = `self`  and `m` = `modulus` here.
            ///
            /// The algorithm will output `r` = `x` mod `m` with the below procedures:
            ///
            /// 1. `q1` ← `x`, `q2` ← `q1` * `ratio`, `q3` ← ⌊`q2`/b^2⌋.
            /// 2. `r1` ← `x` mod b^2, `r2` ← `q3` * `m` mod b^2, `r` ← `r1` - `r2`.
            /// 3. If `r` ≥ `m` do: `r` ← `r` - `m`.
            /// 4. Return(`r`).
            ///
            /// ## Proof:
            ///
            /// ∵ `q1` = `x` , ⌊b^2 / m⌋ - 1 < `ratio` ≤ ⌊b^2 / m⌋
            ///
            /// ∴ ⌊x * b^2 / m⌋ - x < `q2` = `q1` * `ratio` ≤ ⌊x * b^2 / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 2 < `q3` = ⌊`q2` / b^2⌋ ≤ ⌊x / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 1 ≤ `q3` ≤ ⌊x / m⌋
            ///
            /// ∴ `x` - `q3` * `m` mod b^2 < 2 * m
            #[inline]
            fn reduce(self, modulus: BarrettModulus<$SelfT>) -> Self::Output {
                use $crate::reduce::LazyReduce;
                let r = self.lazy_reduce(modulus);

                if r >= modulus.value() {
                    r - modulus.value()
                } else {
                    r
                }
            }
        }

        impl $crate::reduce::LazyReduce<BarrettModulus<$SelfT>> for &[$SelfT] {
            type Output = $SelfT;

            /// Caculates `self (mod 2*modulus)` when value's length > 0.
            fn lazy_reduce(self, modulus: BarrettModulus<$SelfT>) -> Self::Output {
                match self {
                    &[] => unreachable!(),
                    &[v] => {
                        if v < modulus.value() {
                            v
                        } else {
                            v.lazy_reduce(modulus)
                        }
                    }
                    [other @ .., last] => other
                        .iter()
                        .rfold(*last, |acc, &x| [x, acc].lazy_reduce(modulus)),
                }
            }
        }

        impl $crate::reduce::Reduce<BarrettModulus<$SelfT>> for &[$SelfT] {
            type Output = $SelfT;

            /// Caculates `self (mod modulus)` when value's length > 0.
            fn reduce(self, modulus: BarrettModulus<$SelfT>) -> Self::Output {
                match self {
                    &[] => unreachable!(),
                    &[v] => {
                        if v < modulus.value() {
                            v
                        } else {
                            v.reduce(modulus)
                        }
                    }
                    [other @ .., last] => other
                        .iter()
                        .rfold(*last, |acc, &x| [x, acc].reduce(modulus)),
                }
            }
        }

        impl $crate::reduce::LazyReduceAssign<BarrettModulus<Self>> for $SelfT {
            /// Caculates `self (mod 2*modulus)`.
            ///
            /// ## Procedure
            ///
            /// We denote `x` = `self`  and `m` = `modulus` here.
            ///
            /// The algorithm will output `r` = `x` mod `m` with the below procedures:
            ///
            /// 1. `q1` ← `x`, `q2` ← `q1` * `ratio`, `q3` ← ⌊`q2`/b^2⌋.
            /// 2. `r1` ← `x` mod b^2, `r2` ← `q3` * `m` mod b^2, `r` ← `r1` - `r2`.
            /// 3. If `r` ≥ `m` do: `r` ← `r` - `m`.
            /// 4. Return(`r`).
            ///
            /// ## Proof:
            ///
            /// ∵ `q1` = `x` , ⌊b^2 / m⌋ - 1 < `ratio` ≤ ⌊b^2 / m⌋
            ///
            /// ∴ ⌊x * b^2 / m⌋ - x < `q2` = `q1` * `ratio` ≤ ⌊x * b^2 / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 2 < `q3` = ⌊`q2` / b^2⌋ ≤ ⌊x / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 1 ≤ `q3` ≤ ⌊x / m⌋
            ///
            /// ∴ `x` - `q3` * `m` mod b^2 < 2 * m
            #[inline]
            fn lazy_reduce_assign(&mut self, modulus: BarrettModulus<Self>) {
                use $crate::reduce::LazyReduce;
                *self = (*self).lazy_reduce(modulus);
            }
        }

        impl $crate::reduce::ReduceAssign<BarrettModulus<Self>> for $SelfT {
            /// Caculates `self (mod modulus)`.
            ///
            /// ## Procedure
            ///
            /// We denote `x` = `self`  and `m` = `modulus` here.
            ///
            /// The algorithm will output `r` = `x` mod `m` with the below procedures:
            ///
            /// 1. `q1` ← `x`, `q2` ← `q1` * `ratio`, `q3` ← ⌊`q2`/b^2⌋.
            /// 2. `r1` ← `x` mod b^2, `r2` ← `q3` * `m` mod b^2, `r` ← `r1` - `r2`.
            /// 3. If `r` ≥ `m` do: `r` ← `r` - `m`.
            /// 4. Return(`r`).
            ///
            /// ## Proof:
            ///
            /// ∵ `q1` = `x` , ⌊b^2 / m⌋ - 1 < `ratio` ≤ ⌊b^2 / m⌋
            ///
            /// ∴ ⌊x * b^2 / m⌋ - x < `q2` = `q1` * `ratio` ≤ ⌊x * b^2 / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 2 < `q3` = ⌊`q2` / b^2⌋ ≤ ⌊x / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 1 ≤ `q3` ≤ ⌊x / m⌋
            ///
            /// ∴ `x` - `q3` * `m` mod b^2 < 2 * m
            #[inline]
            fn reduce_assign(&mut self, modulus: BarrettModulus<Self>) {
                use $crate::reduce::Reduce;
                *self = (*self).reduce(modulus);
            }
        }
    };
}
