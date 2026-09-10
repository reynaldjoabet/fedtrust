package fedtrust.jose

import java.security.PublicKey

import scala.util.Try

import cats.ApplicativeThrow
import com.nimbusds.jose.crypto.factories.{DefaultJWSSignerFactory, DefaultJWSVerifierFactory}
import com.nimbusds.jose.jwk.{AsymmetricJWK, JWK, KeyOperation, KeyType, KeyUse}
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

  /** The signature algorithms this build will accept on a federation statement.
    *
    * Section 3.2 requires the `alg` to be an acceptable signing algorithm and
    * forbids `none`. RFC 8725 section 3.1 is the reason this is an explicit
    * allowlist rather than "whatever the key supports": the acceptable set is
    * the recipient's decision, never the token's.
    *
    * Symmetric MACs are excluded deliberately. Federation statements are always
    * verified with a superior's public key, so an `HS*` header can only be an
    * attempt at key confusion — passing a public key off as an HMAC secret.
    */
  val permittedAlgorithms: Set[JWSAlgorithm] = Set(
    JWSAlgorithm.RS256,
    JWSAlgorithm.RS384,
    JWSAlgorithm.RS512,
    JWSAlgorithm.PS256,
    JWSAlgorithm.PS384,
    JWSAlgorithm.PS512,
    JWSAlgorithm.ES256,
    JWSAlgorithm.ES384,
    JWSAlgorithm.ES512,
    JWSAlgorithm.EdDSA
  )

  /** The RFC 7638 SHA-256 thumbprint of a key.
    *
    * Section 3.1.1 RECOMMENDS that a Federation Entity Key's `kid` be exactly
    * this.
    */
  def thumbprint(jwk: Jwk): Either[FederationError, String] =
    toNimbus(jwk).flatMap { key =>
      Try(key.computeThumbprint().toString).toEither.left
        .map(e => FederationError.MalformedJwt(s"cannot compute thumbprint: ${e.getMessage}"))
    }

  def verify(signed: SignedJwt, keys: JwkSet): Either[FederationError, JsonObject] =
    for {
      kid       <- signed.headerKid
      jwk       <- keys.forHeaderKid(kid).left.map(FederationError.KeyNotFound.apply)
      nimbusKey <- toNimbus(jwk)
      jws       <- parse(signed)
      algorithm <- permittedAlgorithm(jws)
      _         <- usableForVerification(nimbusKey)
      _         <- algorithmAgrees(nimbusKey, algorithm)
      publicKey <- publicKeyOf(nimbusKey)
      verifier  <- Try(verifierFactory.createJWSVerifier(jws.getHeader, publicKey)).toEither.left
        .map(e => FederationError.InvalidSignature(e.getMessage))
      ok <- Try(jws.verify(verifier)).toEither.left
        .map(e => FederationError.InvalidSignature(e.getMessage))
      _      <- Either.cond(ok, (), FederationError.InvalidSignature("signature did not verify"))
      claims <- signed.payload
    } yield claims

  private def permittedAlgorithm(jws: JWSObject): Either[FederationError, JWSAlgorithm] =
    Option(jws.getHeader.getAlgorithm) match {
      case None =>
        Left(FederationError.MalformedJwt("JWS header has no alg"))
      case Some(algorithm) if !permittedAlgorithms.contains(algorithm) =>
        Left(
          FederationError.InvalidSignature(
            s"signature algorithm ${algorithm.getName} is not accepted"
          )
        )
      case Some(algorithm) => Right(algorithm)
    }

  /** RFC 7517 sections 4.2 and 4.3: a key that declares itself for encryption,
    * or whose `key_ops` do not include verification, must not be used to verify
    * a signature.
    */
  private def usableForVerification(jwk: JWK): Either[FederationError, Unit] = {
    val useAllows = Option(jwk.getKeyUse).forall(_ == KeyUse.SIGNATURE)
    val opsAllow  = Option(jwk.getKeyOperations).forall(_.contains(KeyOperation.VERIFY))

    Either.cond(
      useAllows && opsAllow,
      (),
      FederationError.InvalidSignature(
        "the selected key is not designated for signature verification"
      )
    )
  }

  /** RFC 7517 section 4.4: when a key names an algorithm, that is the algorithm
    * the key is intended for. A header asking for a different one is either a
    * misconfiguration or an attempt to reuse a key outside its purpose.
    */
  private def algorithmAgrees(jwk: JWK, algorithm: JWSAlgorithm): Either[FederationError, Unit] =
    Option(jwk.getAlgorithm) match {
      case Some(declared) if declared != algorithm =>
        Left(
          FederationError.InvalidSignature(
            s"key declares alg ${declared.getName} but the JWS header says ${algorithm.getName}"
          )
        )
      case _ => Right(())
    }

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
      // Signing outside the allowlist would produce statements this build
      // refuses to verify, which is a far more confusing failure than
      // declining to sign in the first place.
      .flatMap(algorithm =>
        Either.cond(
          permittedAlgorithms.contains(algorithm),
          algorithm,
          FederationError.InvalidRequest(
            s"signature algorithm ${algorithm.getName} is not accepted"
          )
        )
      )
}
