package fedtrust

import java.time.Instant

import fedtrust.entity.EntityStatement
import fedtrust.jwk.JwkSet
import fedtrust.types.EntityId
import io.circe.parser.decode
import io.circe.syntax.*
import munit.FunSuite

class EntityStatementCodecSuite extends FunSuite {

  private val issuedAt = Instant.ofEpochSecond(1700000000L)

  private val statement = EntityStatement(
    iss = EntityId.unsafe("https://ta.example.org"),
    sub = EntityId.unsafe("https://op.example.com"),
    iat = issuedAt,
    exp = issuedAt.plusSeconds(3600),
    jwks = JwkSet.empty,
    authorityHints = Some(List(EntityId.unsafe("https://intermediate.example.org")))
  )

  test("claims use the names the specification defines") {
    val json = statement.asJson

    assert(json.hcursor.downField("authority_hints").succeeded)
    assertEquals(json.hcursor.get[Long]("iat"), Right(issuedAt.getEpochSecond))
  }

  test("statements round trip") {
    assertEquals(decode[EntityStatement](statement.asJson.noSpaces), Right(statement))
  }

  test("iss == sub marks an entity configuration") {
    assert(!statement.isEntityConfiguration)
    assert(statement.copy(sub = statement.iss).isEntityConfiguration)
  }

  test("entity identifiers must be https with no query or fragment") {
    assert(EntityId("https://op.example.com/tenant/a").isRight)
    assert(EntityId("http://op.example.com").isLeft)
    assert(EntityId("https://op.example.com?x=1").isLeft)
    assert(EntityId("https://op.example.com#f").isLeft)
  }

  test("the well-known path goes ahead of the identifier's own path") {
    assertEquals(
      EntityId.unsafe("https://op.example.com/tenant/a").wellKnownUri,
      "https://op.example.com/.well-known/openid-federation/tenant/a"
    )
    assertEquals(
      EntityId.unsafe("https://op.example.com").wellKnownUri,
      "https://op.example.com/.well-known/openid-federation"
    )
  }
}
