package fedtrust.jwt

import fedtrust.error.FederationError
import fedtrust.util.Base64Url
import io.circe.{Decoder, Encoder, JsonObject}
import io.circe.parser.decode

/** The `typ` header values federation defines for its signed objects. */
object JwtTyp {
  val EntityStatement              = "entity-statement+jwt"
  val TrustMark                    = "trust-mark+jwt"
  val TrustMarkDelegation          = "trust-mark-delegation+jwt"
  val ResolveResponse              = "resolve-response+jwt"
  val ExplicitRegistrationResponse = "explicit-registration-response+jwt"
  val JwkSet                       = "jwk-set+jwt"
}

/** A JWS in compact serialization.
  *
  * Unpacking the header and payload does not verify anything — that lives in
  * the `jose` module. It is available here because chain building has to read
  * `iss`, `sub` and `kid` to decide what to fetch next, before it is in a
  * position to verify.
  */
final case class SignedJwt(compact: String) {

  def parts: Either[FederationError, (String, String, String)] =
    compact.split('.') match {
      case Array(h, p, s) => Right((h, p, s))
      case _              => Left(FederationError.MalformedJwt("expected three JWS segments"))
    }

  private def segment(
      pick: ((String, String, String)) => String
  ): Either[FederationError, JsonObject] =
    for {
      ps  <- parts
      raw <- Base64Url.decodeString(pick(ps)).left.map(FederationError.MalformedJwt.apply)
      obj <- decode[JsonObject](raw).left.map(e => FederationError.MalformedJwt(e.getMessage))
    } yield obj

  def header: Either[FederationError, JsonObject]  = segment(_._1)
  def payload: Either[FederationError, JsonObject] = segment(_._2)

  def headerKid: Either[FederationError, Option[String]] =
    header.map(_("kid").flatMap(_.asString))

  def headerTyp: Either[FederationError, Option[String]] =
    header.map(_("typ").flatMap(_.asString))

  def claimsAs[A: Decoder]: Either[FederationError, A] =
    payload.flatMap { obj =>
      Decoder[A]
        .decodeJson(io.circe.Json.fromJsonObject(obj))
        .left
        .map(e => FederationError.MalformedJwt(e.getMessage))
    }

  override def toString: String = compact
}

object SignedJwt {
  given Encoder[SignedJwt] = Encoder.encodeString.contramap(_.compact)
  given Decoder[SignedJwt] = Decoder.decodeString.map(SignedJwt.apply)
}
