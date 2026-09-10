package fedtrust.jwk

import fedtrust.types.{*, given}
import io.circe.{Decoder, Encoder, JsonObject}

/** A JWK carried as raw JSON.
  *
  * core's job is to transport keys inside entity statements, not to interpret
  * them; the `jose` module turns these into real key material. Keeping the
  * payload opaque means unknown key types and extension parameters round trip
  * unchanged, which matters because the whole statement is signed.
  */
final case class Jwk(json: JsonObject) {
  private def str(name: String): Option[String] = json(name).flatMap(_.asString)

  def kid: Option[String] = str("kid")
  def kty: Option[String] = str("kty")
  def alg: Option[String] = str("alg")
  def use: Option[String] = str("use")
}

object Jwk {
  given Encoder[Jwk] = Encoder[JsonObject].contramap(_.json)
  given Decoder[Jwk] = Decoder[JsonObject].map(Jwk.apply)
}

final case class JwkSet(keys: List[Jwk]) {

  /** Section 3.1.1: "Every JWK in the JWK Set MUST have a unique kid (Key ID)
    * value."
    */
  def duplicateKeyIds: List[String] =
    keys
      .flatMap(_.kid)
      .groupBy(identity)
      .collect { case (kid, occurrences) if occurrences.sizeIs > 1 => kid }
      .toList

  /** Select by `kid`.
    *
    * A duplicate `kid` is a failure rather than a tie to break. Taking the
    * first match would mean a second key with the same identifier silently
    * never gets tried, so a superior that rotated a key incorrectly would look
    * like a signature failure instead of the malformed key set it is.
    */
  def byKid(kid: KeyId): Either[String, Jwk] =
    keys.filter(_.kid.contains(kid)) match {
      case Nil           => Left(s"no key with kid $kid")
      case single :: Nil => Right(single)
      case _             => Left(s"the JWK Set has more than one key with kid $kid")
    }

  /** Key selection for a JWS header: by `kid` when one is present, otherwise
    * the sole key if the set holds exactly one.
    *
    * With no `kid` and several keys there is no defensible choice — trying each
    * in turn would make a signature verify under a key the issuer never
    * nominated — so this fails rather than guessing.
    */
  def forHeaderKid(kid: Option[KeyId]): Either[String, Jwk] = kid match {
    case Some(k) => byKid(k)
    case None    =>
      keys match {
        case single :: Nil => Right(single)
        case Nil           => Left("the JWK Set is empty")
        case _             => Left("the JWS has no kid and the JWK Set holds more than one key")
      }
  }
}

object JwkSet {
  val empty: JwkSet = JwkSet(Nil)

  given Encoder[JwkSet] = Encoder.forProduct1("keys")(_.keys)
  given Decoder[JwkSet] = Decoder.forProduct1("keys")(JwkSet.apply)
}
