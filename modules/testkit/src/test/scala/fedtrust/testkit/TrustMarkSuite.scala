package fedtrust.testkit

import java.time.Instant

import fedtrust.entity.{
  EntityStatement,
  TrustMarkEntry,
  TrustMarkIssuers,
  TrustMarkOwner,
  TrustMarkOwners
}
import fedtrust.error.FederationError
import fedtrust.jose.JwsVerifier
import fedtrust.jwt.SignedJwt
import fedtrust.resolver.{Resolver, StatementVerifier, TrustChainResolver, TrustMarkValidator}
import fedtrust.types.{*, given}
import io.github.iltotore.iron.autoRefine
import munit.FunSuite

/** Trust Mark validation (spec section 7.3) and delegation (7.2.2), over a real
  * federation with real signatures.
  */
class TrustMarkSuite extends FunSuite {

  private type Result[A] = Either[Throwable, A]

  private val now = Instant.parse("2026-01-01T00:00:00Z")

  private val trustAnchor = TestEntity("https://ta.example.org")
  private val markIssuer  = TestEntity("https://marks.example.org")
  private val owner       = TestEntity("https://owner.example.org")
  private val leaf        = TestEntity("https://rp.example.org")
  private val outsider    = TestEntity("https://evil.example.net")

  private val certified: TrustMarkType     = "https://ta.example.org/marks/certified"
  private val delegatedType: TrustMarkType = "https://ta.example.org/marks/delegated"

  private def expect[A](result: Either[FederationError, A]): A =
    result.fold(error => fail(s"fixture failed: ${error.message}"), identity)

  /** The Trust Anchor's configuration, which is where `trust_mark_issuers` and
    * `trust_mark_owners` live.
    */
  private def anchorStatement(
      issuers: TrustMarkIssuers,
      owners: TrustMarkOwners
  ): EntityStatement =
    EntityStatement(
      iss = trustAnchor.id,
      sub = trustAnchor.id,
      iat = now,
      exp = now.plusSeconds(3600),
      jwks = trustAnchor.jwks,
      metadata = Some(TestFederation.federationEntityMetadata(trustAnchor)),
      trustMarkIssuers = Some(issuers),
      trustMarkOwners = Some(owners)
    )

  private def federation(
      issuers: TrustMarkIssuers = TrustMarkIssuers.empty,
      owners: TrustMarkOwners = TrustMarkOwners.empty,
      clock: Instant = now
  ): (TrustMarkValidator[Result], EntityStatement) = {
    val anchor = anchorStatement(issuers, owners)

    val configurations: Map[EntityId, SignedJwt] = Map(
      trustAnchor.id -> expect(TestFederation.sign(anchor, trustAnchor.privateKey)),
      markIssuer.id  -> expect(
        TestFederation.entityConfiguration(
          markIssuer,
          authorityHints = List(trustAnchor.id),
          now = now
        )
      ),
      leaf.id -> expect(
        TestFederation
          .entityConfiguration(leaf, authorityHints = List(trustAnchor.id), now = now)
      )
    )

    val subordinates: Map[(String, EntityId), SignedJwt] = Map(
      (TestFederation.fetchEndpointOf(trustAnchor), markIssuer.id) -> expect(
        TestFederation.subordinateStatement(trustAnchor, markIssuer, now = now)
      ),
      (TestFederation.fetchEndpointOf(trustAnchor), leaf.id) -> expect(
        TestFederation.subordinateStatement(trustAnchor, leaf, now = now)
      )
    )

    val chains = TrustChainResolver[Result](
      InMemoryEntityStatementFetcher[Result](configurations, subordinates),
      StatementVerifier[Result](JwsVerifier[Result], Right(clock))
    )

    (TrustMarkValidator[Result](chains, JwsVerifier[Result], Right(clock)), anchor)
  }

  private def accepting(issuers: (TrustMarkType, List[EntityId])*): TrustMarkIssuers =
    TrustMarkIssuers(issuers.toMap)

  private def ownedBy(entries: (TrustMarkType, TestEntity)*): TrustMarkOwners =
    TrustMarkOwners(entries.map { case (t, e) => t -> TrustMarkOwner(e.id, e.jwks) }.toMap)

  test("a mark from an accepted issuer validates") {
    val (validator, anchor) = federation(accepting(certified -> List(markIssuer.id)))
    val mark = expect(TestFederation.trustMark(markIssuer, leaf, certified, now = now))

    validator.validate(mark, leaf.id, anchor) match {
      case Left(error)   => fail(s"expected the mark to validate, got $error")
      case Right(claims) =>
        assertEquals(claims.iss, markIssuer.id)
        assertEquals(claims.sub, leaf.id)
        assertEquals(claims.trustMarkType, certified)
    }
  }

  test("an empty issuer list means anyone may issue that type") {
    val (validator, anchor) = federation(accepting(certified -> Nil))
    val mark = expect(TestFederation.trustMark(markIssuer, leaf, certified, now = now))

    assert(validator.validate(mark, leaf.id, anchor).isRight)
  }

  test("an issuer the trust anchor does not accept is rejected") {
    // The federation names an issuer for this type, and it is not this one.
    val (validator, anchor) = federation(accepting(certified -> List(owner.id)))
    val mark = expect(TestFederation.trustMark(markIssuer, leaf, certified, now = now))

    assert(validator.validate(mark, leaf.id, anchor).isLeft)
  }

  test("an issuer with no trust chain to the anchor is rejected") {
    // Section 7.3: trust in the issuer comes before trust in the mark. The
    // outsider is not in the federation at all, so its signature proves
    // nothing however well formed the mark is.
    val (validator, anchor) = federation(accepting(certified -> Nil))
    val mark                = expect(TestFederation.trustMark(outsider, leaf, certified, now = now))

    assert(validator.validate(mark, leaf.id, anchor).isLeft)
  }

  test("a mark about a different subject is rejected") {
    val (validator, anchor) = federation(accepting(certified -> Nil))
    val mark = expect(TestFederation.trustMark(markIssuer, markIssuer, certified, now = now))

    assert(validator.validate(mark, leaf.id, anchor).isLeft)
  }

  test("the advertised type must match the type inside the mark") {
    // Section 3.1.2 requires the two to agree; otherwise an index built from
    // the outer value would not describe the mark it points at.
    val (validator, anchor) = federation(accepting(certified -> Nil))
    val mark        = expect(TestFederation.trustMark(markIssuer, leaf, certified, now = now))
    val mislabelled = TrustMarkEntry(delegatedType, mark.trustMark)

    assert(validator.validate(mislabelled, leaf.id, anchor).isLeft)
  }

  test("an expired mark is rejected, and one without exp does not expire") {
    // Ten minutes on: past the mark's own 60-second lifetime, but well inside
    // the hour the surrounding entity statements are good for, so what fails is
    // the mark and not the chain underneath it.
    val (validator, anchor) =
      federation(accepting(certified -> Nil), clock = now.plusSeconds(600))

    val expiring = expect(
      TestFederation.trustMark(markIssuer, leaf, certified, now = now, lifetimeSeconds = Some(60))
    )
    assert(validator.validate(expiring, leaf.id, anchor).isLeft)

    // exp is OPTIONAL on a trust mark (section 7.1): absent means no expiry.
    val perpetual = expect(
      TestFederation.trustMark(markIssuer, leaf, certified, now = now, lifetimeSeconds = None)
    )
    assert(validator.validate(perpetual, leaf.id, anchor).isRight)
  }

  test("an owned type must carry a delegation") {
    val (validator, anchor) =
      federation(accepting(delegatedType -> Nil), ownedBy(delegatedType -> owner))

    val undelegated = expect(TestFederation.trustMark(markIssuer, leaf, delegatedType, now = now))

    assert(validator.validate(undelegated, leaf.id, anchor).isLeft)
  }

  test("an owned type with a valid delegation validates") {
    val (validator, anchor) =
      federation(accepting(delegatedType -> Nil), ownedBy(delegatedType -> owner))

    val delegation =
      expect(TestFederation.trustMarkDelegation(owner, markIssuer, delegatedType, now = now))

    val mark = expect(
      TestFederation
        .trustMark(markIssuer, leaf, delegatedType, delegation = Some(delegation), now = now)
    )

    assert(validator.validate(mark, leaf.id, anchor).isRight)
  }

  test("a delegation signed by anyone but the registered owner is rejected") {
    val (validator, anchor) =
      federation(accepting(delegatedType -> Nil), ownedBy(delegatedType -> owner))

    // Signed by the outsider, but claiming to come from the owner would fail
    // the signature; signed honestly by the outsider fails the issuer check.
    val forged =
      expect(TestFederation.trustMarkDelegation(outsider, markIssuer, delegatedType, now = now))

    val mark = expect(
      TestFederation
        .trustMark(markIssuer, leaf, delegatedType, delegation = Some(forged), now = now)
    )

    assert(validator.validate(mark, leaf.id, anchor).isLeft)
  }

  test("a delegation covering a different type is rejected") {
    val (validator, anchor) =
      federation(accepting(delegatedType -> Nil), ownedBy(delegatedType -> owner))

    val wrongType =
      expect(TestFederation.trustMarkDelegation(owner, markIssuer, certified, now = now))

    val mark = expect(
      TestFederation
        .trustMark(markIssuer, leaf, delegatedType, delegation = Some(wrongType), now = now)
    )

    assert(validator.validate(mark, leaf.id, anchor).isLeft)
  }

  test("validateAll keeps the marks that verify and drops the rest") {
    val (validator, anchor) = federation(accepting(certified -> List(markIssuer.id)))

    val good             = expect(TestFederation.trustMark(markIssuer, leaf, certified, now = now))
    val fromOutsider     = expect(TestFederation.trustMark(outsider, leaf, certified, now = now))
    val aboutSomeoneElse =
      expect(TestFederation.trustMark(markIssuer, markIssuer, certified, now = now))

    val statement = EntityStatement(
      iss = leaf.id,
      sub = leaf.id,
      iat = now,
      exp = now.plusSeconds(3600),
      jwks = leaf.jwks,
      trustMarks = Some(List(good, fromOutsider, aboutSomeoneElse))
    )

    assertEquals(validator.validateAll(statement, anchor), Right(List(good)))
  }

  test("a resolver without a validator returns no marks rather than unverified ones") {
    // Section 8.3: "The response set MUST include only verified Trust Marks."
    val good = expect(TestFederation.trustMark(markIssuer, leaf, certified, now = now))

    val configurations: Map[EntityId, SignedJwt] = Map(
      trustAnchor.id -> expect(
        TestFederation.sign(
          anchorStatement(accepting(certified -> Nil), TrustMarkOwners.empty),
          trustAnchor.privateKey
        )
      ),
      leaf.id -> expect(
        TestFederation.entityConfiguration(
          leaf,
          authorityHints = List(trustAnchor.id),
          trustMarks = Some(List(good)),
          now = now
        )
      )
    )

    val subordinates: Map[(String, EntityId), SignedJwt] = Map(
      (TestFederation.fetchEndpointOf(trustAnchor), leaf.id) -> expect(
        TestFederation.subordinateStatement(trustAnchor, leaf, now = now)
      )
    )

    val chains = TrustChainResolver[Result](
      InMemoryEntityStatementFetcher[Result](configurations, subordinates),
      StatementVerifier[Result](JwsVerifier[Result], Right(now))
    )

    Resolver.withoutTrustMarks[Result](chains).resolve(leaf.id, trustAnchor.id) match {
      case Left(error)     => fail(s"expected resolution to succeed, got $error")
      case Right(resolved) => assertEquals(resolved.trustMarks, Nil)
    }
  }
}
