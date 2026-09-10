package fedtrust.testkit

import fedtrust.entity.EntityStatement
import fedtrust.jwt.JwtTyp
import fedtrust.jose.Nimbus
import munit.FunSuite

/** Proves the modules compose: core's model and codecs, jose's signing, and
  * the testkit's fixtures, with nothing mocked in between.
  */
class SignAndVerifySuite extends FunSuite {

  private val trustAnchor = TestEntity("https://ta.example.org")
  private val leaf        = TestEntity("https://rp.example.com")

  test("a subordinate statement verifies against the issuer's keys") {
    val result = for {
      signed <- TestFederation.subordinateStatement(issuer = trustAnchor, subject = leaf)
      claims <- Nimbus.verify(signed, trustAnchor.jwks)
      typ    <- signed.headerTyp
      parsed <- signed.claimsAs[EntityStatement]
    } yield (claims, typ, parsed)

    result match {
      case Left(error)             => fail(s"expected a verified statement, got $error")
      case Right((_, typ, parsed)) =>
        assertEquals(typ, Some(JwtTyp.EntityStatement.value))
        assertEquals(parsed.iss, trustAnchor.id)
        assertEquals(parsed.sub, leaf.id)
        assert(!parsed.isEntityConfiguration)
    }
  }

  test("a statement does not verify against an unrelated entity's keys") {
    val result = for {
      signed <- TestFederation.subordinateStatement(issuer = trustAnchor, subject = leaf)
      claims <- Nimbus.verify(signed, leaf.jwks)
    } yield claims

    assert(result.isLeft, "a statement verified against the wrong keys")
  }

  test("an entity configuration is self-issued and carries its own keys") {
    val result = for {
      signed <- TestFederation.entityConfiguration(leaf, authorityHints = List(trustAnchor.id))
      _      <- Nimbus.verify(signed, leaf.jwks)
      parsed <- signed.claimsAs[EntityStatement]
    } yield parsed

    result match {
      case Left(error)   => fail(s"expected a verified configuration, got $error")
      case Right(parsed) =>
        assert(parsed.isEntityConfiguration)
        assertEquals(parsed.hints, List(trustAnchor.id))
    }
  }
}
