package fedtrust.testkit

import java.time.Instant

import fedtrust.entity.EntityStatement
import fedtrust.error.FederationError
import fedtrust.jose.JwsVerifier
import fedtrust.jwk.JwkSet
import fedtrust.jwt.SignedJwt
import fedtrust.resolver.{StatementVerifier, TrustAnchor, TrustChainResolver, TrustChainVerifier}
import fedtrust.types.{*, given}
import munit.FunSuite

/** The root of trust: what a pinned Trust Anchor key protects against, and
  * what it must still allow (spec sections 10 and 10.2).
  */
class TrustAnchorSuite extends FunSuite {

  private type Result[A] = Either[Throwable, A]

  private val now = Instant.parse("2026-01-01T00:00:00Z")

  private val trustAnchor  = TestEntity("https://ta.example.org")
  private val intermediate = TestEntity("https://org.example.org")
  private val leaf         = TestEntity("https://rp.example.org")

  private def expect[A](result: Either[FederationError, A]): A =
    result.fold(error => fail(s"fixture failed: ${error.message}"), identity)

  private def anchorConfiguration(jwks: JwkSet, signWith: TestEntity): SignedJwt =
    expect(
      TestFederation.sign(
        EntityStatement(
          iss = trustAnchor.id,
          sub = trustAnchor.id,
          iat = now,
          exp = now.plusSeconds(3600),
          jwks = jwks,
          metadata = Some(TestFederation.federationEntityMetadata(trustAnchor))
        ),
        signWith.privateKey
      )
    )

  private val intermediateConfiguration = expect(
    TestFederation.entityConfiguration(
      intermediate,
      authorityHints = List(trustAnchor.id),
      metadata = Some(TestFederation.federationEntityMetadata(intermediate)),
      now = now
    )
  )

  private val leafConfiguration = expect(
    TestFederation.entityConfiguration(leaf, authorityHints = List(intermediate.id), now = now)
  )

  private val intermediateAboutLeaf = expect(
    TestFederation.subordinateStatement(intermediate, leaf, now = now)
  )

  private def anchorAboutIntermediate(signWith: TestEntity): SignedJwt =
    expect(
      TestFederation.sign(
        EntityStatement(
          iss = trustAnchor.id,
          sub = intermediate.id,
          iat = now,
          exp = now.plusSeconds(3600),
          jwks = intermediate.jwks
        ),
        signWith.privateKey
      )
    )

  private def resolver(
      anchorEc: SignedJwt,
      anchorStatement: SignedJwt
  ): TrustChainResolver[Result] =
    TrustChainResolver[Result](
      InMemoryEntityStatementFetcher[Result](
        configurations = Map(
          trustAnchor.id  -> anchorEc,
          intermediate.id -> intermediateConfiguration,
          leaf.id         -> leafConfiguration
        ),
        subordinates = Map(
          (TestFederation.fetchEndpointOf(trustAnchor), intermediate.id) -> anchorStatement,
          (TestFederation.fetchEndpointOf(intermediate), leaf.id)        -> intermediateAboutLeaf
        )
      ),
      StatementVerifier[Result](JwsVerifier[Result], Right(now))
    )

  private val honest =
    resolver(
      anchorConfiguration(trustAnchor.jwks, trustAnchor),
      anchorAboutIntermediate(trustAnchor)
    )

  /** The anchor's next signing key. Same entity, distinct kid: section 3.1.1
    * requires kids to be unique within a JWK Set, and a rollover that reused
    * one would be rejected for that before any trust question arose.
    */
  private val rotated: TestEntity = {
    val (privateKey, publicKey) = Keys.generate(s"${trustAnchor.id.value}#2026")
    TestEntity(trustAnchor.id, privateKey, publicKey)
  }

  private val verifier =
    TrustChainVerifier[Result](StatementVerifier[Result](JwsVerifier[Result], Right(now)))

  test("a chain to a pinned anchor resolves") {
    assertEquals(honest.resolve(leaf.id, trustAnchor.asTrustAnchor).map(_.pathLength), Right(2))
  }

  test("an anchor configuration signed with an unpinned key is rejected") {
    // Whoever controls https://ta.example.org/.well-known/openid-federation
    // - by DNS hijack, a mis-issued certificate, or a compromised host - can
    // serve a configuration that is perfectly self-consistent: signed with a
    // key it carries in its own jwks. Before pinning, that was accepted.
    val impostor = TestEntity(trustAnchor.id.value)

    val forged = resolver(
      anchorConfiguration(impostor.jwks, impostor),
      anchorAboutIntermediate(impostor)
    )

    assert(
      forged.resolve(leaf.id, trustAnchor.asTrustAnchor).isLeft,
      "a configuration that only verifies under its own keys must not become the root of trust"
    )
  }

  test("an anchor can roll its keys by publishing the new one under the old") {
    // Section 10.2 verifies the anchor's configuration under the pinned key,
    // then trusts the jwks inside it for what the anchor signs. So a new key
    // published in a configuration signed with the pinned one is usable
    // immediately, before any relying party has re-pinned.
    val rolledOver = resolver(
      anchorConfiguration(
        JwkSet(trustAnchor.jwks.keys ++ rotated.jwks.keys),
        signWith = trustAnchor
      ),
      anchorAboutIntermediate(signWith = rotated)
    )

    assertEquals(
      rolledOver.resolve(leaf.id, trustAnchor.asTrustAnchor).map(_.pathLength),
      Right(2)
    )
  }

  test("a new anchor key not vouched for by a pinned one is not usable") {
    // The rollover above, minus the vouching: the configuration is signed
    // with the new key itself, so nothing pinned ever approved it.
    val unvouched = resolver(
      anchorConfiguration(JwkSet(trustAnchor.jwks.keys ++ rotated.jwks.keys), signWith = rotated),
      anchorAboutIntermediate(signWith = rotated)
    )

    assert(unvouched.resolve(leaf.id, trustAnchor.asTrustAnchor).isLeft)
  }

  test("a resolved chain carries its signed statements as ES[0] to ES[i]") {
    honest.resolve(leaf.id, trustAnchor.asTrustAnchor) match {
      case Left(error)  => fail(s"expected a chain, got $error")
      case Right(chain) =>
        assertEquals(chain.signedStatements.length, chain.statements.length)
        assertEquals(chain.signedStatements.head, leafConfiguration)
        assertEquals(chain.signedStatements(1), intermediateAboutLeaf)
        assertEquals(chain.signedStatements.last.compact.nonEmpty, true)

        // And every one decodes to the statement in the same position.
        assertEquals(
          chain.signedStatements.map(_.claimsAs[EntityStatement].map(_.sub)),
          chain.statements.map(s => Right(s.sub))
        )
    }
  }

  test("a presented chain verifies offline against the pinned anchor") {
    val presented = honest.resolve(leaf.id, trustAnchor.asTrustAnchor).map(_.signedStatements)

    val verified = presented.flatMap(verifier.verify(_, List(trustAnchor.asTrustAnchor)))

    assertEquals(verified.map(_.subject), Right(leaf.id))
    assertEquals(verified.map(_.trustAnchor), Right(trustAnchor.id))
    assertEquals(verified.map(_.pathLength), Right(2))
  }

  test("a presented chain ending at an unconfigured anchor is rejected") {
    val presented = honest.resolve(leaf.id, trustAnchor.asTrustAnchor).map(_.signedStatements)
    val elsewhere = TestEntity("https://other-ta.example.org").asTrustAnchor

    assert(presented.flatMap(verifier.verify(_, List(elsewhere))).isLeft)
  }

  test("a presented chain whose anchor configuration was forged is rejected") {
    val impostor = TestEntity(trustAnchor.id.value)

    val forged = List(
      leafConfiguration,
      intermediateAboutLeaf,
      anchorAboutIntermediate(impostor),
      anchorConfiguration(impostor.jwks, impostor)
    )

    assert(verifier.verify(forged, List(trustAnchor.asTrustAnchor)).isLeft)
  }

  test("a presented chain out of order is rejected") {
    val presented = honest.resolve(leaf.id, trustAnchor.asTrustAnchor).map(_.signedStatements)

    val swapped = presented.map {
      case a :: b :: c :: d :: Nil => List(a, c, b, d); case other => other
    }

    assert(swapped.flatMap(verifier.verify(_, List(trustAnchor.asTrustAnchor))).isLeft)
  }

  test("a presented chain must include the anchor's configuration") {
    // Section 4 lets a presenter omit it; this verifier does not accept that,
    // and says so rather than failing somewhere less obvious.
    val truncated =
      List(leafConfiguration, intermediateAboutLeaf, anchorAboutIntermediate(trustAnchor))

    verifier.verify(truncated, List(trustAnchor.asTrustAnchor)) match {
      case Left(error: FederationError.InvalidTrustChain) =>
        assert(error.message.contains("entity configuration"), error.message)
      case other => fail(s"expected a rejection naming the missing configuration, got $other")
    }
  }

  test("a presented subject not attested by its superior is rejected") {
    // A stranger's self-signed configuration in ES[0], above which sit the
    // genuine statements about the leaf. The stranger's own signature is fine;
    // ES[1] simply does not attest its keys.
    val stranger = TestEntity(leaf.id.value)

    val substituted = List(
      expect(
        TestFederation
          .entityConfiguration(stranger, authorityHints = List(intermediate.id), now = now)
      ),
      intermediateAboutLeaf,
      anchorAboutIntermediate(trustAnchor),
      anchorConfiguration(trustAnchor.jwks, trustAnchor)
    )

    assert(verifier.verify(substituted, List(trustAnchor.asTrustAnchor)).isLeft)
  }

  test("an empty presented chain is rejected") {
    assert(verifier.verify(Nil, List(trustAnchor.asTrustAnchor)).isLeft)
  }

  test("the anchor presenting itself verifies as a zero-length chain") {
    val self = List(anchorConfiguration(trustAnchor.jwks, trustAnchor))

    assertEquals(
      verifier.verify(self, List(TrustAnchor(trustAnchor.id, trustAnchor.jwks))).map(_.pathLength),
      Right(0)
    )
  }
}
