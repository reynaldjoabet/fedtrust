package fedtrust

import fedtrust.jwt.JwtTyp
import fedtrust.types.{*, given}
import io.github.iltotore.iron.autoRefine
import munit.FunSuite

/** The two closed sets in the model, and the boundary between them and the one
  * open set.
  */
class ClosedSetSuite extends FunSuite {

  test("every declared typ round trips through its value") {
    JwtTyp.values.foreach { typ =>
      assertEquals(JwtTyp.fromValue(typ.value), Some(typ))
    }
  }

  test("a typ outside the set is not recognised") {
    // RFC 8725 section 3.11: explicit typing only prevents cross-JWT confusion
    // if an unrecognised typ is a rejection rather than a shrug.
    assertEquals(JwtTyp.fromValue("application/jwt"), None)
    assertEquals(JwtTyp.fromValue(""), None)
  }

  test("typ values are the ones the specification names") {
    assertEquals(JwtTyp.EntityStatement.value, "entity-statement+jwt")
    assertEquals(JwtTyp.ResolveResponse.value, "resolve-response+jwt")
    assertEquals(JwtTyp.TrustMark.value, "trust-mark+jwt")
  }

  test("well-known entity types map to and from their identifiers") {
    WellKnownEntityType.values.foreach { known =>
      assertEquals(WellKnownEntityType.from(known.identifier), Some(known))
    }

    assertEquals(
      WellKnownEntityType.from(EntityType.OpenIdProvider),
      Some(WellKnownEntityType.OpenIdProvider)
    )
  }

  test("a federation-defined entity type is unknown, not invalid") {
    // Section 5.1 lets a federation define its own identifiers. One of them is
    // a perfectly good EntityType that simply has no enum case - which is why
    // EntityType stays an open string and the enum is only a view over it.
    val custom: EntityType = "openid_credential_issuer"

    assertEquals(WellKnownEntityType.from(custom), None)
    assert(EntityType("openid_credential_issuer").isRight)
    assert(!WellKnownEntityType.identifiers.contains(custom))
  }

  test("the enum covers exactly the identifiers the specification fixes") {
    assertEquals(
      WellKnownEntityType.identifiers,
      Set(
        EntityType.FederationEntity,
        EntityType.OpenIdRelyingParty,
        EntityType.OpenIdProvider,
        EntityType.OAuthAuthorizationServer,
        EntityType.OAuthClient,
        EntityType.OAuthResource
      )
    )
  }
}
