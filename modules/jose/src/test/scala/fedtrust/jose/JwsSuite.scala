package fedtrust.jose

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.{Curve, JWK}
import fedtrust.jwk.{Jwk, JwkSet}
import fedtrust.jwt.JwtTyp
import fedtrust.util.json
import io.circe.{Json, JsonObject}
import munit.FunSuite

/** Verification hardening: the checks that decide whether a signature is
  * accepted, beyond the signature arithmetic itself.
  */
class JwsSuite extends FunSuite {

  private def generate(kid: String): JWK =
    new ECKeyGenerator(Curve.P_256).keyID(kid).generate()

  private def asJwk(key: JWK): Jwk =
    json
      .parse(key.toJSONString)
      .flatMap(_.asObject.toRight("JWK did not serialise to an object"))
      .fold(reason => fail(reason), Jwk.apply)

  private def withField(jwk: Jwk, name: String, value: String): Jwk =
    Jwk(jwk.json.add(name, Json.fromString(value)))

  private val claims: JsonObject =
    JsonObject("iss" -> Json.fromString("https://ta.example.org"))

  private val key        = generate("key-1")
  private val privateJwk = asJwk(key)
  private val publicJwk  = asJwk(key.toPublicJWK)

  private def signed = Nimbus.sign(JwtTyp.EntityStatement.value, claims, privateJwk)

  test("a statement signed with a key verifies against its public half") {
    val verified = signed.flatMap(Nimbus.verify(_, JwkSet(List(publicJwk))))

    assertEquals(verified.map(_("iss").flatMap(_.asString)), Right(Some("https://ta.example.org")))
  }

  test("symmetric and unsecured algorithms are not accepted") {
    // Section 3.2 forbids `none`; RFC 8725 section 3.1 makes the accepted set
    // the recipient's decision. An HS* header against a public key is the
    // classic key-confusion attempt.
    assert(!Nimbus.permittedAlgorithms.contains(JWSAlgorithm.HS256))
    assert(!Nimbus.permittedAlgorithms.contains(JWSAlgorithm.HS384))
    assert(!Nimbus.permittedAlgorithms.contains(JWSAlgorithm.HS512))
    assert(!Nimbus.permittedAlgorithms.exists(_.getName == "none"))

    assert(Nimbus.permittedAlgorithms.contains(JWSAlgorithm.ES256))
    assert(Nimbus.permittedAlgorithms.contains(JWSAlgorithm.RS256))
  }

  test("a key reserved for encryption cannot verify a signature") {
    // RFC 7517 section 4.2.
    val encryptionKey = withField(publicJwk, "use", "enc")
    val result        = signed.flatMap(Nimbus.verify(_, JwkSet(List(encryptionKey))))

    assert(result.isLeft, "a use=enc key must not verify a signature")
  }

  test("a key whose declared alg differs from the header is rejected") {
    // RFC 7517 section 4.4: alg names the algorithm the key is intended for.
    val mismatched = withField(publicJwk, "alg", "ES384")
    val result     = signed.flatMap(Nimbus.verify(_, JwkSet(List(mismatched))))

    assert(result.isLeft, "an alg mismatch between key and header must not verify")
  }

  test("a duplicate kid is an error, not a tie broken by order") {
    // Section 3.1.1 requires kids to be unique within a JWK Set. Taking the
    // first match would leave the second key silently untried.
    val impostor = withField(asJwk(generate("other").toPublicJWK), "kid", "key-1")
    val set      = JwkSet(List(impostor, publicJwk))

    assertEquals(set.duplicateKeyIds, List("key-1"))
    assert(signed.flatMap(Nimbus.verify(_, set)).isLeft)
  }

  test("a header without a kid is ambiguous when the set holds several keys") {
    val other = asJwk(generate("key-2").toPublicJWK)

    assert(JwkSet(List(publicJwk, other)).forHeaderKid(None).isLeft)
    assertEquals(JwkSet(List(publicJwk)).forHeaderKid(None), Right(publicJwk))
    assert(JwkSet(Nil).forHeaderKid(None).isLeft)
  }

  test("an unrelated key does not verify") {
    val stranger   = asJwk(generate("stranger").toPublicJWK)
    val relabelled = withField(stranger, "kid", "key-1")

    assert(signed.flatMap(Nimbus.verify(_, JwkSet(List(relabelled)))).isLeft)
  }

  test("thumbprints are RFC 7638 SHA-256 and stable across public and private") {
    val fromPrivate = Nimbus.thumbprint(privateJwk)
    val fromPublic  = Nimbus.thumbprint(publicJwk)

    assertEquals(fromPrivate, fromPublic, "a thumbprint covers only the public members")

    // base64url of a SHA-256 digest, unpadded.
    assertEquals(fromPublic.map(_.length), Right(43))
  }
}
