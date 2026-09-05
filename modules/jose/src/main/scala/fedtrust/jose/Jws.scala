package fedtrust.jose

import java.security.PublicKey

import scala.util.Try

import cats.ApplicativeThrow
import com.nimbusds.jose.crypto.factories.{DefaultJWSSignerFactory, DefaultJWSVerifierFactory}
import com.nimbusds.jose.jwk.{AsymmetricJWK, JWK, KeyType}
import com.nimbusds.jose.{JOSEObjectType, JWSAlgorithm, JWSHeader, JWSObject, Payload}
import fedtrust.error.FederationError
import fedtrust.jwk.{Jwk, JwkSet}
import fedtrust.jwt.SignedJwt
import io.circe.{Json, JsonObject}

/** Verification of the signed objects federation exchanges.
  *
  * Abstract over `F` so callers stay in their own effect type; `Nimbus` below
  * is the synchronous implementation everything here delegates to.
  */
trait JwsVerifier[F[_]] {

  /** Verify `signed` against whichever key of `keys` its `kid` selects, and
    * return the verified claims.
    */
  def verify(signed: SignedJwt, keys: JwkSet): F[JsonObject]
}

object JwsVerifier {
  def apply[F[_]](using F: ApplicativeThrow[F]): JwsVerifier[F] =
    new JwsVerifier[F] {
      def verify(signed: SignedJwt, keys: JwkSet): F[JsonObject] =
        F.fromEither(Nimbus.verify(signed, keys))
    }
}

/** Signing, needed by entity implementations and by test fixtures. */
trait JwsSigner[F[_]] {
  def sign(typ: String, claims: JsonObject, key: Jwk): F[SignedJwt]
}

object JwsSigner {
  def apply[F[_]](using F: ApplicativeThrow[F]): JwsSigner[F] =
    new JwsSigner[F] {
      def sign(typ: String, claims: JsonObject, key: Jwk): F[SignedJwt] =
        F.fromEither(Nimbus.sign(typ, claims, key))
    }
}

/** The single place in the library that touches a crypto library.
  *
  * Everything else works in terms of [[JwsVerifier]] and [[JwsSigner]], so
  * swapping this out for a different provider is a matter of supplying other
  * instances rather than editing call sites.
  */
object Nimbus {

  private lazy val verifierFactory = new DefaultJWSVerifierFactory()
  private lazy val signerFactory   = new DefaultJWSSignerFactory()

  def toNimbus(jwk: Jwk): Either[FederationError, JWK] =
    Try(JWK.parse(Json.fromJsonObject(jwk.json).noSpaces)).toEither.left
      .map(e => FederationError.MalformedJwt(s"not a usable JWK: ${e.getMessage}"))

  def verify(signed: SignedJwt, keys: JwkSet): Either[FederationError, JsonObject] =
    for {
      kid       <- signed.headerKid
      jwk       <- keys.forHeaderKid(kid).toRight(FederationError.KeyNotFound(kid))
      nimbusKey <- toNimbus(jwk)
      publicKey <- publicKeyOf(nimbusKey)
      jws       <- parse(signed)
      verifier  <- Try(verifierFactory.createJWSVerifier(jws.getHeader, publicKey)).toEither.left
        .map(e => FederationError.InvalidSignature(e.getMessage))
      ok <- Try(jws.verify(verifier)).toEither.left
        .map(e => FederationError.InvalidSignature(e.getMessage))
      _      <- Either.cond(ok, (), FederationError.InvalidSignature("signature did not verify"))
      claims <- signed.payload
    } yield claims

  def sign(typ: String, claims: JsonObject, key: Jwk): Either[FederationError, SignedJwt] =
    for {
      jwk    <- toNimbus(key)
      alg    <- algorithmOf(jwk)
      signer <- Try(signerFactory.createJWSSigner(jwk, alg)).toEither.left
        .map(e => FederationError.InvalidRequest(s"cannot sign with this key: ${e.getMessage}"))
      header = new JWSHeader.Builder(alg)
        .`type`(new JOSEObjectType(typ))
        .keyID(jwk.getKeyID)
        .build()
      jws = new JWSObject(header, new Payload(Json.fromJsonObject(claims).noSpaces))
      _ <- Try(jws.sign(signer)).toEither.left
        .map(e => FederationError.InvalidRequest(e.getMessage))
    } yield SignedJwt(jws.serialize())

  private def parse(signed: SignedJwt): Either[FederationError, JWSObject] =
    Try(JWSObject.parse(signed.compact)).toEither.left
      .map(e => FederationError.MalformedJwt(e.getMessage))

  private def publicKeyOf(jwk: JWK): Either[FederationError, PublicKey] =
    jwk match {
      case asymmetric: AsymmetricJWK =>
        Try(asymmetric.toPublicKey).toEither.left
          .map(e => FederationError.MalformedJwt(e.getMessage))
      case _ =>
        Left(FederationError.InvalidSignature("federation statements require an asymmetric key"))
    }

  /** The key's own `alg` when it declares one, otherwise the customary default
    * for its key type.
    */
  private def algorithmOf(jwk: JWK): Either[FederationError, JWSAlgorithm] =
    Option(jwk.getAlgorithm)
      .collect { case alg: JWSAlgorithm => alg }
      .orElse {
        jwk.getKeyType match {
          case KeyType.RSA => Some(JWSAlgorithm.RS256)
          case KeyType.EC  => Some(JWSAlgorithm.ES256)
          case KeyType.OKP => Some(JWSAlgorithm.EdDSA)
          case _           => None
        }
      }
      .toRight(FederationError.InvalidRequest("no signing algorithm for this key type"))
}
