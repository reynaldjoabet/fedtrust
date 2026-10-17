package fedtrust.resolver

import cats.MonadThrow
import cats.syntax.all.*
import fedtrust.entity.EntityStatement
import fedtrust.error.FederationError
import fedtrust.jwt.SignedJwt
import fedtrust.types.{*, given}

/** Validates a Trust Chain someone handed over, without fetching anything
  * (spec section 10.2).
  *
  * Chains travel with the things they vouch for: in the `trust_chain` JWS
  * header of a signed request (section 4.3), as the `trust_chain` parameter
  * of an OAuth request, or as an `application/trust-chain+json` explicit
  * registration (section 12.2). In each case the presenter chose the chain, so
  * none of it is trusted until every link verifies and the top verifies under
  * a key the caller pinned.
  *
  * Verification runs from the anchor down. Section 10.2 states the rules
  * bottom up, but every rule says "under a key in ES[j+1]", so a statement can
  * only be checked once the one above it has been — the anchor's
  * configuration first, against the pinned keys, then each statement under
  * the keys of the one already verified.
  */
trait TrustChainVerifier[F[_]] {

  /** `presented` is `ES[0]` through `ES[i]`: the subject's Entity
    * Configuration first, the Trust Anchor's last.
    *
    * Section 4 lets a presenter omit the anchor's Entity Configuration. This
    * verifier requires it, and rejects a chain without it: the result is a
    * [[TrustChain]], whose anchor configuration carries the
    * `trust_mark_issuers` and `trust_mark_owners` that later checks depend on,
    * and inventing one would mean fetching after all.
    */
  def verify(presented: List[SignedJwt], trustAnchors: List[TrustAnchor]): F[TrustChain]
}

object TrustChainVerifier {

  def apply[F[_]: MonadThrow](statements: StatementVerifier[F]): TrustChainVerifier[F] =
    new DefaultTrustChainVerifier[F](statements)
}

private final class DefaultTrustChainVerifier[F[_]](statements: StatementVerifier[F])(using
    F: MonadThrow[F]
) extends TrustChainVerifier[F] {

  def verify(presented: List[SignedJwt], trustAnchors: List[TrustAnchor]): F[TrustChain] =
    presented match {
      case Nil => F.raiseError(invalid("the presented trust chain is empty"))

      case _ =>
        for {
          // The top of the chain names the anchor, but only an unverified read
          // is possible until the anchor is known — which is the point of
          // pinning: the claim picks the candidate keys, the keys decide.
          top <- presented.last.claimsAs[EntityStatement].liftTo[F]
          _   <- F.raiseUnless(top.isEntityConfiguration)(
            invalid(
              "the chain must end with the trust anchor's own entity configuration; " +
                s"it ends with a statement issued by ${top.iss.value} about ${top.sub.value}"
            )
          )
          anchor <- trustAnchors
            .find(_.id == top.iss)
            .liftTo[F](
              FederationError.InvalidTrustAnchor(
                s"${top.iss.value} is not one of the configured trust anchors"
              )
            )

          anchorEc <- statements.verify(presented.last, anchor.jwks, Some(anchor.id))

          // Everything below the anchor, verified downwards: each statement
          // under the jwks of the one above it, which has already passed.
          below <- presented.init.reverse
            .foldLeftM((anchorEc, List.empty[EntityStatement])) {
              case ((above, verified), signed) =>
                statements
                  .verify(signed, above.jwks, expectedSubject = None)
                  .map(statement => (statement, statement :: verified))
            }
            .map(_._2)

          chain <- assemble(presented, below, anchorEc)
        } yield chain
    }

  /** `below` is `ES[0]` through `ES[i-1]`, already signature-checked. What
    * remains is the shape of the chain, the subject's self-signature, and the
    * constraints.
    */
  private def assemble(
      presented: List[SignedJwt],
      below: List[EntityStatement],
      anchorEc: EntityStatement
  ): F[TrustChain] =
    below match {
      // A one-statement chain is the anchor presenting itself.
      case Nil =>
        TrustChain.validated(anchorEc, Nil, anchorEc, presented).liftTo[F]

      case subjectEc :: subordinates =>
        for {
          // Section 10.2 checks ES[0] twice: under ES[1]["jwks"], done above,
          // and under its own jwks. The second is what makes it an Entity
          // Configuration rather than a statement someone else wrote about it.
          _     <- statements.verifySelfIssued(presented.head, subjectEc.sub)
          chain <- TrustChain.validated(subjectEc, subordinates, anchorEc, presented).liftTo[F]
          _     <- ConstraintChecker.check(chain).liftTo[F]
        } yield chain
    }

  private def invalid(detail: String): FederationError =
    FederationError.InvalidTrustChain(detail)
}
