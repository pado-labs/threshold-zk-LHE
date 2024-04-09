use crate::AlgebraError;

/// The modulo operation.
pub trait Reduce<Modulus>: Sized {
    /// Output type.
    type Output;

    /// Caculates `self (mod modulus)`.
    fn reduce(self, modulus: Modulus) -> Self::Output;
}

/// The modulo assignment operation.
pub trait ReduceAssign<Modulus>: Sized {
    /// Caculates `self (mod modulus)`.
    fn reduce_assign(&mut self, modulus: Modulus);
}

/// The modular addition.
pub trait AddReduce<Modulus, Rhs = Self> {
    /// Output type.
    type Output;

    /// Calculates `self + rhs (mod modulus)`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `rhs < modulus`
    fn add_reduce(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The modular addition assignment.
pub trait AddReduceAssign<Modulus, Rhs = Self> {
    /// Calculates `self += rhs (mod modulus)`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `rhs < modulus`
    fn add_reduce_assign(&mut self, rhs: Rhs, modulus: Modulus);
}

/// The modular subtraction.
pub trait SubReduce<Modulus, Rhs = Self> {
    /// Output type.
    type Output;

    /// Calculates `self - rhs (mod modulus)`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `rhs < modulus`
    fn sub_reduce(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The modular subtraction assignment.
pub trait SubReduceAssign<Modulus, Rhs = Self> {
    /// Calculates `self -= rhs (mod modulus)`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `rhs < modulus`
    fn sub_reduce_assign(&mut self, rhs: Rhs, modulus: Modulus);
}

/// The modular negation.
pub trait NegReduce<Modulus> {
    /// Output type.
    type Output;

    /// Calculates `-self (mod modulus)`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn neg_reduce(self, modulus: Modulus) -> Self::Output;
}

/// The modular negation assignment.
pub trait NegReduceAssign<Modulus> {
    /// Calculates `-self (mod modulus)`
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn neg_reduce_assign(&mut self, modulus: Modulus);
}

/// The modular multiplication.
pub trait MulReduce<Modulus, Rhs = Self> {
    /// Output type.
    type Output;

    /// Calculates `self * rhs (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self*rhs < modulus^2`
    fn mul_reduce(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The modular multiplication assignment.
pub trait MulReduceAssign<Modulus, Rhs = Self> {
    /// Calculates `self *= rhs (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self*rhs < modulus^2`
    fn mul_reduce_assign(&mut self, rhs: Rhs, modulus: Modulus);
}

/// The modular exponentiation.
pub trait PowReduce<Modulus, Exponent> {
    /// Calcualtes `self^exp (mod modulus)`.
    fn pow_reduce(self, exp: Exponent, modulus: Modulus) -> Self;
}

/// Calculate the inverse element for a field.
pub trait InvReduce<Modulus = Self>: Sized {
    /// Calculate the multiplicative inverse of `self (mod modulus)`.
    fn inv_reduce(self, modulus: Modulus) -> Self;
}

/// The modular inversion assignment for a field.
pub trait InvReduceAssign<Modulus = Self> {
    /// Calculates `self^(-1) (mod modulus)`
    fn inv_reduce_assign(&mut self, modulus: Modulus);
}

/// Try to calculate the inverse element when there is not a field.
pub trait TryInvReduce<Modulus = Self>: Sized {
    /// Try to calculate the multiplicative inverse of `self modulo modulus`.
    ///
    /// # Errors
    ///
    /// If there dose not exist the such inverse, a [`AlgebraError`] will be returned.
    fn try_inv_reduce(self, modulus: Modulus) -> Result<Self, AlgebraError>;
}

/// The modular division.
pub trait DivReduce<Modulus, Rhs = Self> {
    /// Output type.
    type Output;

    /// Calculates `self / rhs (mod modulus)`.
    fn div_reduce(self, rhs: Rhs, modulus: Modulus) -> Self::Output;
}

/// The modular division assignment.
pub trait DivReduceAssign<Modulus, Rhs = Self> {
    /// Calculates `self /= rhs (mod modulus)`.
    fn div_reduce_assign(&mut self, rhs: Rhs, modulus: Modulus);
}
