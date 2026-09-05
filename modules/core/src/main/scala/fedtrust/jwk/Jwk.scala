package fedtrust.jwk

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
  def byKid(kid: String): Option[Jwk] = keys.find(_.kid.contains(kid))

  /** Key selection for a JWS header: by `kid` when one is present, otherwise
    * the sole key if the set holds exactly one.
    */
  def forHeaderKid(kid: Option[String]): Option[Jwk] = kid match {
    case Some(k) => byKid(k)
    case None    => Option.when(keys.sizeIs == 1)(keys.head)
  }
}

object JwkSet {
  val empty: JwkSet = JwkSet(Nil)

  given Encoder[JwkSet] = Encoder.forProduct1("keys")(_.keys)
  given Decoder[JwkSet] = Decoder.forProduct1("keys")(JwkSet.apply)
}
