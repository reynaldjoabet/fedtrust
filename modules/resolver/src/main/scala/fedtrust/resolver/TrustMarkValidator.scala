package fedtrust.resolver

import java.time.{Duration, Instant}

import cats.MonadThrow
import cats.syntax.all.*
import fedtrust.entity.{
  EntityStatement,
  TrustMarkClaims,
  TrustMarkDelegationClaims,
  TrustMarkEntry,
  TrustMarkOwner
}
import fedtrust.error.FederationError
import fedtrust.jose.JwsVerifier
import fedtrust.jwk.JwkSet
import fedtrust.jwt.{JwtTyp, SignedJwt}
import fedtrust.types.{*, given}

/** Trust Mark validation (spec section 7.3), including delegation (7.2.2).
  *
  * The ordering the specification insists on is that trust in the issuer comes
  * first: "If the Trust Mark Issuer is not trusted then the trust mark cannot
  * be trusted." So this resolves a Trust Chain from the issuer up to the same
  * Trust Anchor before it will look at a signature — a mark signed by a key
  * belonging to an entity the federation does not vouch for proves nothing, no
  * matter how well formed it is.
  */
final class TrustMarkValidator[F[_]](
    chains: TrustChainResolver[F],
    verifier: JwsVerifier[F],
    clock: F[Instant],
    leeway: Duration
)(using F: MonadThrow[F]) {

  /** Validate every mark carried by a statement, keeping only those that pass.
    *
    * Section 8.3 requires a resolver to verify the marks it returns and says
    * "The response set MUST include only verified Trust Marks." A mark that
    * fails is therefore dropped rather than fatal: an entity does not stop
    * belonging to its federation because one accreditation lapsed, and failing
    * the whole resolution would make an expired mark indistinguishable from a
    * broken chain.
    */
  def validateAll(
      statement: EntityStatement,
      trustAnchorConfiguration: EntityStatement
  ): F[List[TrustMarkEntry]] =
    statement.trustMarkEntries
      .traverse { entry =>
        validate(entry, statement.sub, trustAnchorConfiguration).attempt
          .map(_.toOption.map(_ => entry))
      }
      .map(_.flatten)

  def validate(
      entry: TrustMarkEntry,
      subject: EntityId,
      trustAnchorConfiguration: EntityStatement
  ): F[TrustMarkClaims] =
    for {
      _      <- requireTyp(entry.trustMark, JwtTyp.TrustMark)
      claims <- entry.trustMark.claimsAs[TrustMarkClaims].liftTo[F]

      // Section 3.1.2: the type advertised beside the mark must be the type
      // inside it, or an index built from the outer value would be a lie.
      _ <- F.raiseUnless(claims.trustMarkType == entry.trustMarkType)(
        invalid(
          s"entry advertises ${entry.trustMarkType} but the mark carries ${claims.trustMarkType}"
        )
      )

      _ <- F.raiseUnless(claims.sub == subject)(
        invalid(
          s"mark is about ${claims.sub.value} but appears in the configuration of ${subject.value}"
        )
      )

      now <- clock
      _   <- checkValidity(claims, now)
      _   <- checkIssuerAccepted(claims, trustAnchorConfiguration)

      keys <- issuerKeys(claims.iss, trustAnchorConfiguration)
      _    <- verifier.verify(entry.trustMark, keys)

      _ <- checkDelegation(claims, trustAnchorConfiguration, now)
    } yield claims

  /** Establish trust in the Trust Mark Issuer, as section 7.3 requires before
    * any signature is examined.
    *
    * The keys used are the ones the issuer's Immediate Superior attests, not
    * the ones the issuer publishes about itself — the same rule section 4
    * applies to statements, and for the same reason.
    */
  private def issuerKeys(issuer: EntityId, anchor: EntityStatement): F[JwkSet] =
    if (issuer == anchor.sub) anchor.jwks.pure[F]
    else
      chains
        .resolve(issuer, anchor.sub)
        .adaptErr { case error =>
          invalid(s"no trust chain from the trust mark issuer ${issuer.value}: ${error.getMessage}")
        }
        .map(_.attestedSubjectKeys)

  /** Section 3.1.2: an empty issuer list against a type means anyone may issue
    * it, and a type the Trust Anchor does not mention is not constrained here
    * at all.
    */
  private def checkIssuerAccepted(
      claims: TrustMarkClaims,
      anchor: EntityStatement
  ): F[Unit] =
    F.raiseUnless(anchor.trustMarkIssuersAsAnchor.accepts(claims.trustMarkType, claims.iss))(
      invalid(
        s"${anchor.sub.value} does not accept ${claims.iss.value} as an issuer of ${claims.trustMarkType}"
      )
    )

  private def checkValidity(claims: TrustMarkClaims, now: Instant): F[Unit] =
    for {
      _ <- F.raiseUnless(now.plus(leeway).isAfter(claims.iat))(
        invalid(s"trust mark ${claims.trustMarkType} is not yet valid (iat ${claims.iat})")
      )
      // exp is OPTIONAL on a trust mark: absent means it does not expire, and
      // section 7.3 points at the Trust Mark Status endpoint for checking that
      // such a mark is still active.
      _ <- F.raiseUnless(!claims.isExpiredAt(now.minus(leeway)))(
        invalid(s"trust mark ${claims.trustMarkType} expired at ${claims.exp.orNull}")
      )
    } yield ()

  /** Section 7.3: a type listed in the Trust Anchor's `trust_mark_owners` MUST
    * carry a delegation, and any delegation that is present MUST be validated.
    *
    * A delegation with no registered owner is rejected rather than ignored.
    * Section 7.2.2 verifies it against the owner's keys, which only the Trust
    * Anchor can supply — so with no owner entry there is no way to validate it,
    * and accepting an unvalidatable delegation would defeat the point of
    * requiring one.
    */
  private def checkDelegation(
      claims: TrustMarkClaims,
      anchor: EntityStatement,
      now: Instant
  ): F[Unit] =
    (anchor.trustMarkOwnersAsAnchor.get(claims.trustMarkType), claims.delegation) match {
      case (None, None) => F.unit

      case (Some(owner), Some(delegation)) => validateDelegation(delegation, claims, owner, now)

      case (Some(_), None) =>
        F.raiseError(
          invalid(
            s"${claims.trustMarkType} is owned by a delegating authority, so the mark must carry a delegation"
          )
        )

      case (None, Some(_)) =>
        F.raiseError(
          invalid(
            s"the mark carries a delegation but ${anchor.sub.value} registers no owner for ${claims.trustMarkType}, so it cannot be validated"
          )
        )
    }

  /** Section 7.2.2. */
  private def validateDelegation(
      delegation: SignedJwt,
      mark: TrustMarkClaims,
      owner: TrustMarkOwner,
      now: Instant
  ): F[Unit] =
    for {
      _      <- requireTyp(delegation, JwtTyp.TrustMarkDelegation)
      claims <- delegation.claimsAs[TrustMarkDelegationClaims].liftTo[F]

      _ <- F.raiseUnless(claims.iss == owner.sub)(
        invalid(
          s"delegation is issued by ${claims.iss.value} but the owner of ${mark.trustMarkType} is ${owner.sub.value}"
        )
      )

      _ <- F.raiseUnless(claims.sub == mark.iss)(
        invalid(
          s"delegation is for ${claims.sub.value} but the mark was issued by ${mark.iss.value}"
        )
      )

      _ <- F.raiseUnless(claims.trustMarkType == mark.trustMarkType)(
        invalid(
          s"delegation covers ${claims.trustMarkType} but the mark is ${mark.trustMarkType}"
        )
      )

      _ <- F.raiseUnless(now.plus(leeway).isAfter(claims.iat))(
        invalid(s"delegation for ${mark.trustMarkType} is not yet valid")
      )

      _ <- F.raiseUnless(!claims.isExpiredAt(now.minus(leeway)))(
        invalid(s"delegation for ${mark.trustMarkType} has expired")
      )

      // The owner's keys come from the Trust Anchor's trust_mark_owners claim,
      // which is why this cannot be checked without one.
      _ <- verifier.verify(delegation, owner.jwks)
    } yield ()

  private def requireTyp(signed: SignedJwt, expected: JwtTyp): F[Unit] =
    signed.headerTyp.liftTo[F].flatMap { typ =>
      F.raiseUnless(typ.contains(expected.value))(
        invalid(s"expected typ ${expected.value}, got ${typ.getOrElse("none")}")
      )
    }

  private def invalid(detail: String): FederationError =
    FederationError.InvalidTrustMark(detail)
}

object TrustMarkValidator {

  def apply[F[_]: MonadThrow](
      chains: TrustChainResolver[F],
      verifier: JwsVerifier[F],
      clock: F[Instant],
      leeway: Duration = StatementVerifier.defaultLeeway
  ): TrustMarkValidator[F] =
    new TrustMarkValidator[F](chains, verifier, clock, leeway)
}
