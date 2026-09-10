package fedtrust.testkit

import java.time.Instant

import fedtrust.entity.EntityStatement
import fedtrust.error.FederationError
import fedtrust.jose.{JwsVerifier, Nimbus}
import fedtrust.jwt.SignedJwt
import fedtrust.metadata.{Metadata, MetadataPolicy}
import fedtrust.resolver.{EntityStatementFetcher, Resolver, StatementVerifier, TrustChainResolver}
import fedtrust.types.{*, given}
import io.circe.parser.parse
import munit.FunSuite

/** Chain resolution end to end over a real three-level federation: real EC
  * keys, real signatures, real policy merging. Only the transport is replaced.
  *
  * `Either[Throwable, *]` is the effect type because nothing here is
  * asynchronous, and a synchronous effect keeps the failure cases readable.
  */
class TrustChainResolutionSuite extends FunSuite {

  private type Result[A] = Either[Throwable, A]

  private val now = Instant.parse("2026-01-01T00:00:00Z")

  private val trustAnchor  = TestEntity("https://ta.example.org")
  private val intermediate = TestEntity("https://org.example.org")
  private val leaf         = TestEntity("https://rp.example.org")
  private val stranger     = TestEntity("https://evil.example.net")

  private def unsafe[A](result: Either[FederationError, A]): A =
    result.fold(error => fail(s"fixture failed: ${error.message}"), identity)

  private def parseAs[A: io.circe.Decoder](raw: String): A =
    parse(raw).flatMap(_.as[A]).fold(e => fail(s"bad fixture JSON: $e"), identity)

  private val leafMetadata: Metadata = parseAs[Metadata]("""
    {
      "openid_relying_party": {
        "redirect_uris": ["https://rp.example.org/callback"],
        "token_endpoint_auth_method": "self_signed_tls_client_auth",
        "contacts": ["rp_admins@rp.example.org"]
      }
    }
  """)

  private val anchorPolicy: MetadataPolicy = parseAs[MetadataPolicy]("""
    {
      "openid_relying_party": {
        "token_endpoint_auth_method": {
          "one_of": ["private_key_jwt", "self_signed_tls_client_auth"],
          "essential": true
        },
        "contacts": { "add": ["helpdesk@ta.example.org"] }
      }
    }
  """)

  private val intermediatePolicy: MetadataPolicy = parseAs[MetadataPolicy]("""
    {
      "openid_relying_party": {
        "token_endpoint_auth_method": { "one_of": ["self_signed_tls_client_auth"] }
      }
    }
  """)

  private val anchorConfiguration = unsafe(
    TestFederation.entityConfiguration(
      trustAnchor,
      metadata = Some(TestFederation.federationEntityMetadata(trustAnchor)),
      now = now
    )
  )

  private val intermediateConfiguration = unsafe(
    TestFederation.entityConfiguration(
      intermediate,
      authorityHints = List(trustAnchor.id),
      metadata = Some(TestFederation.federationEntityMetadata(intermediate)),
      now = now
    )
  )

  private val leafConfiguration = unsafe(
    TestFederation.entityConfiguration(
      leaf,
      authorityHints = List(intermediate.id),
      metadata = Some(leafMetadata),
      now = now
    )
  )

  private val anchorAboutIntermediate = unsafe(
    TestFederation.subordinateStatement(
      trustAnchor,
      intermediate,
      metadataPolicy = Some(anchorPolicy),
      now = now
    )
  )

  private val intermediateAboutLeaf = unsafe(
    TestFederation.subordinateStatement(
      intermediate,
      leaf,
      metadataPolicy = Some(intermediatePolicy),
      now = now
    )
  )

  private val configurations: Map[EntityId, SignedJwt] = Map(
    trustAnchor.id  -> anchorConfiguration,
    intermediate.id -> intermediateConfiguration,
    leaf.id         -> leafConfiguration
  )

  private val subordinates: Map[(String, EntityId), SignedJwt] = Map(
    (TestFederation.fetchEndpointOf(trustAnchor), intermediate.id) -> anchorAboutIntermediate,
    (TestFederation.fetchEndpointOf(intermediate), leaf.id)        -> intermediateAboutLeaf
  )

  private def resolverOver(
      configurations: Map[EntityId, SignedJwt] = configurations,
      subordinates: Map[(String, EntityId), SignedJwt] = subordinates,
      clock: Instant = now
  ): TrustChainResolver[Result] = {
    val fetcher: EntityStatementFetcher[Result] =
      InMemoryEntityStatementFetcher[Result](configurations, subordinates)

    TrustChainResolver[Result](
      fetcher,
      StatementVerifier[Result](JwsVerifier[Result], Right(clock))
    )
  }

  test("resolves a two-hop chain from the leaf to the trust anchor") {
    resolverOver().resolve(leaf.id, trustAnchor.id) match {
      case Left(error)  => fail(s"expected a chain, got $error")
      case Right(chain) =>
        assertEquals(chain.subject, leaf.id)
        assertEquals(chain.trustAnchor, trustAnchor.id)
        assertEquals(chain.pathLength, 2)
        assertEquals(chain.statements.length, 4)
        assertEquals(chain.policyOrder.map(_.iss), List(trustAnchor.id, intermediate.id))
    }
  }

  test("resolved metadata reflects both superiors' policies") {
    val resolved =
      Resolver.withoutTrustMarks[Result](resolverOver()).resolve(leaf.id, trustAnchor.id)

    resolved match {
      case Left(error)   => fail(s"expected resolved metadata, got $error")
      case Right(entity) =>
        val rp = entity.metadata
          .get(EntityType.OpenIdRelyingParty)
          .getOrElse(fail("no relying party metadata"))

        // The Trust Anchor's `add` reached the leaf's own contacts.
        assertEquals(
          rp("contacts").flatMap(_.asArray).map(_.flatMap(_.asString).toList),
          Some(List("rp_admins@rp.example.org", "helpdesk@ta.example.org"))
        )

        // The Intermediate narrowed one_of; the leaf's value still satisfies it.
        assertEquals(
          rp("token_endpoint_auth_method").flatMap(_.asString),
          Some("self_signed_tls_client_auth")
        )

        assertEquals(entity.trustAnchor, trustAnchor.id)
        assertEquals(entity.expiresAt, now.plusSeconds(TestFederation.defaultLifetimeSeconds))
    }
  }

  test("no chain to an entity that is not a trust anchor of this federation") {
    assert(resolverOver().resolve(leaf.id, stranger.id).isLeft)
  }

  test("a subordinate statement signed with the wrong key is rejected") {
    val forged = unsafe(
      TestFederation.sign(
        EntityStatement(
          iss = intermediate.id,
          sub = leaf.id,
          iat = now,
          exp = now.plusSeconds(3600),
          jwks = leaf.jwks
        ),
        // Signed by a stranger, but published at the Intermediate's endpoint
        // and claiming to come from it.
        stranger.privateKey
      )
    )

    val result = resolverOver(subordinates =
      subordinates.updated((TestFederation.fetchEndpointOf(intermediate), leaf.id), forged)
    ).resolve(leaf.id, trustAnchor.id)

    assert(result.isLeft, "a statement not signed by the issuing superior must not be accepted")
  }

  test("an intermediate cannot introduce a signing key its superior never attested") {
    // The Intermediate republishes its configuration with a fresh key and signs
    // the statement about the leaf with it. Section 4 requires the statement to
    // verify under the keys the Trust Anchor attested, so this must fail even
    // though the configuration is internally consistent.
    val rotated = TestEntity(intermediate.id.value)

    val rotatedConfiguration = unsafe(
      TestFederation.entityConfiguration(
        rotated,
        authorityHints = List(trustAnchor.id),
        metadata = Some(TestFederation.federationEntityMetadata(rotated)),
        now = now
      )
    )

    val signedWithRotatedKey = unsafe(
      TestFederation.subordinateStatement(rotated, leaf, now = now)
    )

    val result = resolverOver(
      configurations = configurations.updated(intermediate.id, rotatedConfiguration),
      subordinates = subordinates
        .updated((TestFederation.fetchEndpointOf(intermediate), leaf.id), signedWithRotatedKey)
    ).resolve(leaf.id, trustAnchor.id)

    assert(result.isLeft, "a self-asserted key rotation must not be enough to sign statements")
  }

  test("expired statements are rejected") {
    val later = now.plusSeconds(TestFederation.defaultLifetimeSeconds + 3600)

    assert(resolverOver(clock = later).resolve(leaf.id, trustAnchor.id).isLeft)
  }

  test("an entity that names an authority which does not vouch for it gets no chain") {
    val unvouched = TestEntity("https://impostor.example.org")

    val configuration = unsafe(
      TestFederation.entityConfiguration(
        unvouched,
        authorityHints = List(trustAnchor.id),
        now = now
      )
    )

    val result = resolverOver(
      configurations = configurations.updated(unvouched.id, configuration)
    ).resolve(unvouched.id, trustAnchor.id)

    assert(result.isLeft, "authority_hints is a claim by the subject, not proof of membership")
  }

  test("the trust anchor resolves to itself as a zero-length chain") {
    resolverOver().resolve(trustAnchor.id, trustAnchor.id) match {
      case Left(error)  => fail(s"expected the trivial chain, got $error")
      case Right(chain) => assertEquals(chain.pathLength, 0)
    }
  }

  test("a statement that verifies still carries the claims that were signed") {
    val claims = for {
      verified  <- Nimbus.verify(intermediateAboutLeaf, intermediate.jwks)
      statement <- intermediateAboutLeaf.claimsAs[EntityStatement]
    } yield (verified.contains("metadata_policy"), statement.sub)

    assertEquals(claims, Right((true, leaf.id)))
  }
}
