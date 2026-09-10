package fedtrust.jwt

import fedtrust.error.FederationError
import fedtrust.types.{*, given}
import fedtrust.util.{json, Base64Url}
import io.circe.{Decoder, Encoder, Json, JsonObject}
import io.github.iltotore.iron.*
import io.github.iltotore.iron.constraint.all.*

/** The `typ` header values federation defines for its signed objects.
  *
  * Closed, unlike an entity type identifier: the specification names every one,
  * and explicit typing only works if a value outside the set is rejected rather
  * than guessed at. That is the point of the header — RFC 8725 section 3.11
  * uses it to stop one kind of signed object being accepted where another was
  * expected, and a resolve response accepted as an entity statement would be
  * exactly that failure.
  */
enum JwtTyp(val value: String) {
  case EntityStatement              extends JwtTyp("entity-statement+jwt")
  case TrustMark                    extends JwtTyp("trust-mark+jwt")
  case TrustMarkDelegation          extends JwtTyp("trust-mark-delegation+jwt")
  case ResolveResponse              extends JwtTyp("resolve-response+jwt")
  case ExplicitRegistrationResponse extends JwtTyp("explicit-registration-response+jwt")
  case JwkSet                       extends JwtTyp("jwk-set+jwt")
}

object JwtTyp {

  private lazy val byValue: Map[String, JwtTyp] = values.map(typ => typ.value -> typ).toMap

  /** `None` for a `typ` this build does not define, which callers must treat as
    * a rejection rather than as an absent header.
    */
  def fromValue(raw: String): Option[JwtTyp] = byValue.get(raw)
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
      ps     <- parts
      raw    <- Base64Url.decodeString(pick(ps)).left.map(FederationError.MalformedJwt.apply)
      parsed <- json.parse(raw).left.map(FederationError.MalformedJwt.apply)
      obj    <- parsed.asObject.toRight(
        FederationError.MalformedJwt("JWS segment is not a JSON object")
      )
    } yield obj

  def header: Either[FederationError, JsonObject]  = segment(_._1)
  def payload: Either[FederationError, JsonObject] = segment(_._2)

  /** Section 3.2 requires a non-zero length `kid`. Refining here means a
    * statement carrying `"kid": ""` is reported as the malformed header it is,
    * rather than falling through to a key lookup that cannot match.
    */
  def headerKid: Either[FederationError, Option[KeyId]] =
    header.flatMap { obj =>
      obj("kid").flatMap(_.asString) match {
        case None      => Right(None)
        case Some(raw) =>
          raw
            .refineEither[KeyIdentifier]
            .left
            .map(_ => FederationError.MalformedJwt("kid header parameter must not be blank"))
            .map(Some(_))
      }
    }

  def headerTyp: Either[FederationError, Option[String]] =
    header.map(_("typ").flatMap(_.asString))

  def claimsAs[A: Decoder]: Either[FederationError, A] =
    payload.flatMap { obj =>
      Decoder[A]
        .decodeJson(Json.fromJsonObject(obj))
        .left
        .map(e => FederationError.MalformedJwt(e.getMessage))
    }

  override def toString: String = compact
}

object SignedJwt {
  given Encoder[SignedJwt] = Encoder.encodeString.contramap(_.compact)
  given Decoder[SignedJwt] = Decoder.decodeString.map(SignedJwt.apply)
}
