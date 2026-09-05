package fedtrust.testkit

import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.Curve
import fedtrust.jwk.{Jwk, JwkSet}
import io.circe.JsonObject
import io.circe.parser.parse

/** Key material for tests. P-256 because it is small and fast to generate;
  * nothing here is meant to leave a test.
  */
object Keys {

  /** A fresh signing key, as (private, public). */
  def generate(kid: String): (Jwk, Jwk) = {
    val key = new ECKeyGenerator(Curve.P_256).keyID(kid).generate()
    (toJwk(key.toJSONString), toJwk(key.toPublicJWK.toJSONString))
  }

  def publicSet(keys: Jwk*): JwkSet = JwkSet(keys.toList)

  private def toJwk(json: String): Jwk =
    parse(json)
      .flatMap(_.as[JsonObject])
      .fold(e => throw new IllegalStateException(s"generated an unreadable JWK: $e", e), Jwk.apply)
}
