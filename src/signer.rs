//! Composable signing.
//!
//! Epoch binding and spent-nonce durability are separate concerns from
//! producing a share, and there was no function that did two at once. So:
//! one [`Signer`], and [`Layer`]s that wrap it.
//!
//! ```ignore
//! let mut signer = Stack::new(Holder::new(&share, &verifying_key))
//!     .layer(Spend::new(log))   // durable, before anything else runs
//!     .into_inner();
//!
//! let z = signer.sign(SignRequest::bound(nonces, &ctx, &req))?;
//! ```
//!
//! Outermost runs first, as in `tower`: `Spend` above wraps `Holder`, so the
//! session is recorded before any signing work begins.
//!
//! # what is a layer and what is not
//!
//! A layer holds material that outlives the round. What varies per round goes
//! in the [`SignRequest`] — including the message, which is why it is fixed at
//! construction by [`raw`](SignRequest::raw) or [`bound`](SignRequest::bound)
//! and has no public field for anything downstream to substitute.
//!
//! Ciphersuite semantics are not layers either. BIP340's parity normalisation
//! is part of what signing means under Taproot, not a policy a caller
//! chooses, and a layer can be left off.

use alloc::borrow::Cow;

use frost_core::Scalar;

use crate::curve::NestedSuite;
use crate::error::Error;
use crate::nested::{
    inner_sign, InnerNonces, InnerSignatureShare, NestedSigningRequest, SpentSessions,
};
use crate::SecretShare;

/// One signing request: everything that varies per round.
///
/// The long-lived material — the share, the group key, the spent-session
/// store — belongs to the [`Signer`], not here.
///
/// The message is not a public field. It is fixed at construction by
/// [`raw`](Self::raw) or [`bound`](Self::bound), so there is exactly one
/// place it can come from and nothing downstream can substitute another.
pub struct SignRequest<'a, C: NestedSuite> {
    /// This holder's nonces for the round. Consumed: a nonce pair answers once.
    pub nonces: InnerNonces<Scalar<C>>,
    /// The outer round, as the coordinator published it.
    pub nested: &'a NestedSigningRequest<'a, C>,
    message: Cow<'a, [u8]>,
}

impl<'a, C: NestedSuite> SignRequest<'a, C> {
    /// Sign `approved_message` as given.
    ///
    /// Use this only where the bytes are fixed by somebody else — a Bitcoin
    /// sighash, an Orchard `SpendAuthSig`. Where this protocol chooses what
    /// gets signed, prefer [`bound`](Self::bound).
    pub fn raw(
        nonces: InnerNonces<Scalar<C>>,
        approved_message: &'a [u8],
        nested: &'a NestedSigningRequest<'a, C>,
    ) -> Self {
        Self {
            nonces,
            nested,
            message: Cow::Borrowed(approved_message),
        }
    }

    /// Sign `ctx.encode()`: the message with its epoch and manifest bound in.
    ///
    /// The coordinator's package must have been built over the same encoding,
    /// or signing fails with [`Error::MessageMismatch`].
    pub fn bound(
        nonces: InnerNonces<Scalar<C>>,
        ctx: &crate::SigningContext<'_>,
        nested: &'a NestedSigningRequest<'a, C>,
    ) -> Self {
        Self {
            nonces,
            nested,
            message: Cow::Owned(ctx.encode()),
        }
    }

    /// The bytes this holder approved.
    pub fn approved_message(&self) -> &[u8] {
        &self.message
    }
}

/// A stage that turns a [`SignRequest`] into a signature share.
pub trait Signer<C: NestedSuite> {
    /// Produce this holder's share, or refuse.
    fn sign(&mut self, req: SignRequest<'_, C>) -> Result<InnerSignatureShare<Scalar<C>>, Error>;
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
pub struct Holder<'k, C: NestedSuite> {
    share: &'k SecretShare<Scalar<C>>,
    verifying_key: &'k frost_core::VerifyingKey<C>,
}

impl<'k, C: NestedSuite> Holder<'k, C> {
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

impl<C: NestedSuite> Signer<C> for Holder<'_, C> {
    fn sign(&mut self, req: SignRequest<'_, C>) -> Result<InnerSignatureShare<Scalar<C>>, Error> {
        inner_sign::<C>(
            req.nonces,
            self.share,
            self.verifying_key,
            &req.message,
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
///
/// The store is owned, so the stack can be built once and held for the life of
/// the holder; [`Spending::into_store`] gives it back.
pub struct Spend<T> {
    store: T,
}

impl<T: SpentSessions> Spend<T> {
    /// Spend into `store`.
    pub fn new(store: T) -> Self {
        Self { store }
    }
}

/// [`Spend`] wrapped around a signer.
pub struct Spending<T, S> {
    store: T,
    inner: S,
}

impl<T: SpentSessions, S> Spending<T, S> {
    /// The spent-session store, back out.
    pub fn into_store(self) -> T {
        self.store
    }

    /// The store, borrowed — to query [`SpentSessions::is_spent`].
    pub fn store(&self) -> &T {
        &self.store
    }
}

impl<T: SpentSessions, S> Layer<S> for Spend<T> {
    type Signer = Spending<T, S>;

    fn layer(self, inner: S) -> Self::Signer {
        Spending {
            store: self.store,
            inner,
        }
    }
}

impl<C, T, S> Signer<C> for Spending<T, S>
where
    C: NestedSuite,
    T: SpentSessions,
    S: Signer<C>,
{
    fn sign(&mut self, req: SignRequest<'_, C>) -> Result<InnerSignatureShare<Scalar<C>>, Error> {
        self.store
            .spend(&req.nonces.session_id, req.nonces.holder_index)?;
        self.inner.sign(req)
    }
}
