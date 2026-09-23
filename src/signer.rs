//! Composable signing.
//!
//! `inner_sign_v2`, `inner_sign_v2_spending` and `inner_sign_v2_with_context`
//! are the same computation with one concern each, and there is no function
//! for two at once. So: one [`Signer`], and [`Layer`]s that wrap it.
//!
//! ```ignore
//! let mut signer = Stack::new(Holder::new(&share, &verifying_key))
//!     .layer(Bind::new(&ctx))       // epoch and manifest into the message
//!     .layer(Spend::new(&mut log))  // durable, before anything else runs
//!     .into_inner();
//!
//! let z = signer.sign(SignRequest { nonces, approved_message: &msg, nested: &req })?;
//! ```
//!
//! Outermost runs first, as in `tower`: `Spend` above wraps `Bind` wraps
//! `Holder`, so the session is recorded before any signing work begins.
//!
//! Ciphersuite semantics are not layers. BIP340's parity normalisation is
//! part of what signing means under Taproot, not a policy a caller chooses —
//! and a layer can be left off, where leaving that one off gives silently
//! invalid signatures.

use alloc::vec::Vec;

use frost_core::{Ciphersuite, Scalar};

use crate::error::Error;
use crate::nested::{
    inner_sign_v2, InnerNonces, InnerSignatureShare, NestedSigningRequest, SpentSessions,
};
use crate::SecretShare;

/// One signing request: everything that varies per round.
///
/// The long-lived material — the share and the group key — belongs to the
/// [`Signer`], not here.
pub struct SignRequest<'a, C: Ciphersuite>
where
    frost_core::Element<C>: crate::curve::CurvePoint,
    Scalar<C>: crate::curve::CurveScalar,
{
    /// This holder's nonces for the round. Consumed: a nonce pair answers once.
    pub nonces: InnerNonces<Scalar<C>>,
    /// The message the holder approved, which must be the one the package carries.
    pub approved_message: &'a [u8],
    /// The outer round, as the coordinator published it.
    pub nested: &'a NestedSigningRequest<'a, C>,
}

/// A stage that turns a [`SignRequest`] into a signature share.
pub trait Signer<C: Ciphersuite>
where
    frost_core::Element<C>: crate::curve::CurvePoint,
    Scalar<C>: crate::curve::CurveScalar,
{
    /// Produce this holder's share, or refuse.
    fn sign(
        &mut self,
        req: SignRequest<'_, C>,
    ) -> Result<InnerSignatureShare<Scalar<C>>, Error>;
}

/// Wraps a [`Signer`] in one more concern.
pub trait Layer<S> {
    /// The wrapped signer.
    type Signer;
    /// Wrap `inner`.
    fn layer(self, inner: S) -> Self::Signer;
}

/// Builder for a stack of layers, outermost applied last.
pub struct Stack<S>(S);

impl<S> Stack<S> {
    /// Start from a base signer.
    pub fn new(inner: S) -> Self {
        Self(inner)
    }

    /// Wrap what is built so far. The layer added last runs first.
    pub fn layer<L: Layer<S>>(self, layer: L) -> Stack<L::Signer> {
        Stack(layer.layer(self.0))
    }

    /// The assembled signer.
    pub fn into_inner(self) -> S {
        self.0
    }
}

// ============================================================================
// base
// ============================================================================

/// The base signer: one inner holder's share and the group key it anchors to.
///
/// `verifying_key` is the holder's *own* key material, never a coordinator's
/// assertion — that is the whole reason this type holds it rather than taking
/// it per request.
pub struct Holder<'k, C: Ciphersuite>
where
    Scalar<C>: crate::curve::CurveScalar,
{
    share: &'k SecretShare<Scalar<C>>,
    verifying_key: &'k frost_core::VerifyingKey<C>,
}

impl<'k, C: Ciphersuite> Holder<'k, C>
where
    Scalar<C>: crate::curve::CurveScalar,
{
    /// A signer for `share`, anchored to `verifying_key`.
    pub fn new(
        share: &'k SecretShare<Scalar<C>>,
        verifying_key: &'k frost_core::VerifyingKey<C>,
    ) -> Self {
        Self {
            share,
            verifying_key,
        }
    }
}

impl<C> Signer<C> for Holder<'_, C>
where
    C: Ciphersuite,
    frost_core::Element<C>: crate::curve::CurvePoint<Scalar = Scalar<C>>,
    Scalar<C>: crate::curve::CurveScalar,
{
    fn sign(
        &mut self,
        req: SignRequest<'_, C>,
    ) -> Result<InnerSignatureShare<Scalar<C>>, Error> {
        inner_sign_v2::<C>(
            req.nonces,
            self.share,
            self.verifying_key,
            req.approved_message,
            req.nested,
        )
    }
}

// ============================================================================
// layers
// ============================================================================

/// Records the session as spent before the inner signer runs.
///
/// The recording is durable and happens first: if it fails, nothing signs. A
/// holder that signs and then fails to record has already given up the share.
pub struct Spend<'s, T: ?Sized> {
    store: &'s mut T,
}

impl<'s, T: SpentSessions + ?Sized> Spend<'s, T> {
    /// Spend into `store`.
    pub fn new(store: &'s mut T) -> Self {
        Self { store }
    }
}

/// [`Spend`] wrapped around a signer.
pub struct Spending<'s, T: ?Sized, S> {
    store: &'s mut T,
    inner: S,
}

impl<'s, T: SpentSessions + ?Sized, S> Layer<S> for Spend<'s, T> {
    type Signer = Spending<'s, T, S>;

    fn layer(self, inner: S) -> Self::Signer {
        Spending {
            store: self.store,
            inner,
        }
    }
}

impl<C, T, S> Signer<C> for Spending<'_, T, S>
where
    C: Ciphersuite,
    frost_core::Element<C>: crate::curve::CurvePoint,
    Scalar<C>: crate::curve::CurveScalar,
    T: SpentSessions + ?Sized,
    S: Signer<C>,
{
    fn sign(
        &mut self,
        req: SignRequest<'_, C>,
    ) -> Result<InnerSignatureShare<Scalar<C>>, Error> {
        self.store
            .spend(&req.nonces.session_id, req.nonces.holder_index)?;
        self.inner.sign(req)
    }
}

/// Binds an epoch and manifest into the message before signing.
///
/// The holder then signs `ctx.encode()` rather than a bare payload, so a
/// signature valid for one epoch is not a valid authorisation in another.
pub struct Bind<'c> {
    ctx: &'c crate::SigningContext<'c>,
}

impl<'c> Bind<'c> {
    /// Bind `ctx`.
    pub fn new(ctx: &'c crate::SigningContext<'c>) -> Self {
        Self { ctx }
    }
}

/// [`Bind`] wrapped around a signer.
pub struct Bound<'c, S> {
    ctx: &'c crate::SigningContext<'c>,
    inner: S,
}

impl<'c, S> Layer<S> for Bind<'c> {
    type Signer = Bound<'c, S>;

    fn layer(self, inner: S) -> Self::Signer {
        Bound {
            ctx: self.ctx,
            inner,
        }
    }
}

impl<C, S> Signer<C> for Bound<'_, S>
where
    C: Ciphersuite,
    frost_core::Element<C>: crate::curve::CurvePoint,
    Scalar<C>: crate::curve::CurveScalar,
    S: Signer<C>,
{
    fn sign(
        &mut self,
        req: SignRequest<'_, C>,
    ) -> Result<InnerSignatureShare<Scalar<C>>, Error> {
        let encoded: Vec<u8> = self.ctx.encode();
        self.inner.sign(SignRequest {
            nonces: req.nonces,
            approved_message: &encoded,
            nested: req.nested,
        })
    }
}
