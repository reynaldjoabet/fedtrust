package fedtrust.resolver

import java.time.{Duration, Instant}

import cats.MonadThrow
import cats.syntax.all.*
import fedtrust.entity.EntityStatement
import fedtrust.error.FederationError
import fedtrust.jose.JwsVerifier
import fedtrust.jwk.JwkSet
import fedtrust.jwt.{JwtTyp, SignedJwt}
import fedtrust.types.EntityId

/** Entity Statement validation (spec section 3.2).
  *
  * The steps the spec lists that can be checked on a single statement are done
  * here; the ones that are relations between statements — `iss` matching the
  * next statement's `sub`, and the signature chaining upwards — belong to
  * [[TrustChain]] and [[TrustChainResolver]], which have more than one
  * statement in hand.
  */
final class StatementVerifier[F[_]](
    verifier: JwsVerifier[F],
    clock: F[Instant],
    leeway: Duration
)(using F: MonadThrow[F]) {

  /** Verify a statement's signature against `keys` and validate its claims.
    *
    * `expectedSubject` is checked when the caller knows which entity the
    * statement is supposed to be about, which is every case except the initial
    * fetch of a configuration the caller asked for by identifier.
    */
  def verify(
      signed: SignedJwt,
      keys: JwkSet,
      expectedSubject: Option[EntityId]
  ): F[EntityStatement] =
    for {
      _         <- checkTyp(signed)
      claims    <- verifier.verify(signed, keys)
      statement <- decode(claims)
      _         <- checkSubject(statement, expectedSubject)
      _         <- checkCrit(statement)
      now       <- clock
      _         <- checkValidity(statement, now)
    } yield statement

  /** An Entity Configuration is signed by a key in its own `jwks`, so it is
    * parsed before it can be verified. The claims are read twice on purpose:
    * the unverified read only supplies candidate keys, and nothing from it
    * survives into the result.
    */
  def verifySelfIssued(signed: SignedJwt, expected: EntityId): F[EntityStatement] =
    for {
      unverified <- signed.claimsAs[EntityStatement].liftTo[F]
      _          <- F.raiseUnless(unverified.sub == expected)(
        FederationError.InvalidTrustChain(
          s"asked ${expected.value} for its entity configuration but got one for ${unverified.sub.value}"
        )
      )
      _ <- F.raiseUnless(unverified.isEntityConfiguration)(
        FederationError.InvalidTrustChain(
          s"${expected.value} served a statement issued by ${unverified.iss.value} as its own configuration"
        )
      )
      statement <- verify(signed, unverified.jwks, Some(expected))
    } yield statement

  private def checkTyp(signed: SignedJwt): F[Unit] =
    signed.headerTyp.liftTo[F].flatMap { typ =>
      F.raiseUnless(typ.contains(JwtTyp.EntityStatement))(
        FederationError.MalformedJwt(
          s"expected typ ${JwtTyp.EntityStatement}, got ${typ.getOrElse("none")}"
        )
      )
    }

  private def decode(claims: io.circe.JsonObject): F[EntityStatement] =
    io.circe
      .Decoder[EntityStatement]
      .decodeJson(io.circe.Json.fromJsonObject(claims))
      .leftMap(e => FederationError.MalformedJwt(s"unreadable entity statement: ${e.getMessage}"))
      .liftTo[F]

  private def checkSubject(statement: EntityStatement, expected: Option[EntityId]): F[Unit] =
    expected.fold(F.unit) { subject =>
      F.raiseUnless(statement.sub == subject)(
        FederationError.InvalidTrustChain(
          s"expected a statement about ${subject.value}, got one about ${statement.sub.value}"
        )
      )
    }

  /** Section 3.2: every name in `crit` is a claim not defined by the
    * specification that the implementation MUST understand. This build defines
    * no extension claims, so any `crit` entry is one it cannot honour, and
    * accepting the statement anyway is exactly the failure `crit` exists to
    * prevent.
    */
  private def checkCrit(statement: EntityStatement): F[Unit] =
    statement.crit.getOrElse(Nil) match {
      case Nil   => F.unit
      case names =>
        F.raiseError(
          FederationError.UnsupportedParameter(
            s"unsupported critical claims: ${names.mkString(", ")}"
          )
        )
    }

  private def checkValidity(statement: EntityStatement, now: Instant): F[Unit] =
    for {
      _ <- F.raiseUnless(now.plus(leeway).isAfter(statement.iat))(
        FederationError.Expired(
          s"statement from ${statement.iss.value} is not yet valid (iat ${statement.iat})"
        )
      )
      _ <- F.raiseUnless(now.minus(leeway).isBefore(statement.exp))(
        FederationError.Expired(
          s"statement from ${statement.iss.value} expired at ${statement.exp}"
        )
      )
    } yield ()
}

object StatementVerifier {

  /** Clock skew tolerance. Federations span organisations, and a minute is the
    * customary allowance for statements that are otherwise well within their
    * validity window.
    */
  val defaultLeeway: Duration = Duration.ofSeconds(60)

  def apply[F[_]: MonadThrow](
      verifier: JwsVerifier[F],
      clock: F[Instant],
      leeway: Duration = defaultLeeway
  ): StatementVerifier[F] =
    new StatementVerifier[F](verifier, clock, leeway)
}
