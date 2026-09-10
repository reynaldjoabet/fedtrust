package fedtrust

import fedtrust.entity.Constraints
import fedtrust.jwt.SignedJwt
import fedtrust.metadata.Metadata
import fedtrust.types.{*, given}
import fedtrust.util.{json, Base64Url}
import io.github.iltotore.iron.autoRefine
import munit.FunSuite

/** The refinements and parser guards earn their place only if they reject
  * things the unrefined code accepted, so each test here is a value that used
  * to get through.
  */
class RefinementSuite extends FunSuite {

  test("max_path_length is rejected at decode time when negative") {
    assert(json.decode[Constraints]("""{"max_path_length": 0}""").isRight)
    assert(json.decode[Constraints]("""{"max_path_length": 2}""").isRight)

    // Section 6.2.1 requires a value greater than or equal to zero. Before the
    // refinement this decoded fine and every consumer had to re-check it.
    assert(json.decode[Constraints]("""{"max_path_length": -1}""").isLeft)
  }

  test("a blank kid header is malformed, not merely a missing key") {
    def jwt(header: String): SignedJwt =
      SignedJwt(s"${Base64Url.encode(header)}.${Base64Url.encode("{}")}.signature")

    assert(jwt("""{"kid":"abc"}""").headerKid.exists(_.contains("abc")))
    assertEquals(jwt("{}").headerKid, Right(None))

    // Section 3.2: the kid MUST be a non-zero length string. Unrefined, these
    // fell through to a key lookup that could never match, and the failure
    // surfaced as "no such key" rather than as a bad header.
    assert(jwt("""{"kid":""}""").headerKid.isLeft)
    assert(jwt("""{"kid":"   "}""").headerKid.isLeft)
  }

  test("parsing is bounded in depth") {
    // Statements are parsed before anything has verified them, so a hostile
    // payload must not be able to exhaust the stack.
    val deep = ("[" * 200) + ("]" * 200)

    assert(json.parse(deep).isLeft)
    assert(json.parse("""{"a":[1,2,{"b":true}]}""").isRight)
  }

  test("well-formed identifiers are literals the compiler checks") {
    // Not calls to a validator: iron refines these at compile time, so a
    // malformed identifier written here would fail the build rather than the
    // test. That is the whole reason EntityId is a refinement and not an
    // opaque type with a smart constructor.
    val anchor: EntityId         = "https://ta.example.org"
    val tenant: EntityId         = "https://op.example.com/tenant/a"
    val relyingParty: EntityType = "openid_relying_party"

    assertEquals(anchor.value, "https://ta.example.org")
    assertEquals(
      tenant.wellKnownUri,
      "https://op.example.com/.well-known/openid-federation/tenant/a"
    )
    assertEquals(relyingParty, EntityType.OpenIdRelyingParty)
  }

  test("entity identifiers arriving at runtime are validated") {
    assert(EntityId("https://op.example.com/tenant/a").isRight)
    assert(EntityId("http://op.example.com").isLeft, "must be https")
    assert(EntityId("https://op.example.com?x=1").isLeft, "must have no query")
    assert(EntityId("https://op.example.com#f").isLeft, "must have no fragment")
    assert(EntityId("https:///nohost").isLeft, "must have a host")
  }

  test("a blank entity type is rejected, including as a metadata key") {
    assert(EntityType("openid_provider").isRight)
    assert(EntityType("").isLeft)
    assert(EntityType("   ").isLeft)

    assert(json.decode[Metadata]("""{"openid_relying_party": {}}""").isRight)
    assert(json.decode[Metadata]("""{"": {"a": 1}}""").isLeft)
  }

  test("unknown JSON survives a parse and print round trip") {
    // The whole reason this build keeps circe's AST rather than generated
    // codecs: metadata for entity types it has never heard of has to come back
    // out unchanged.
    val raw = """{"unknown_entity_type":{"a":[1,2,3],"b":{"c":null},"d":1.5}}"""

    assertEquals(json.parse(raw).map(json.print), Right(raw))
  }
}
