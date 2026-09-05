package fedtrust.examples

import java.time.Instant

import fedtrust.endpoints.{Params, ResolveRequest}
import fedtrust.error.FederationError
import fedtrust.jose.JwsVerifier
import fedtrust.jwt.SignedJwt
import fedtrust.metadata.{Metadata, MetadataPolicy}
import fedtrust.resolver.{Resolver, StatementVerifier, TrustChainResolver}
import fedtrust.testkit.{InMemoryEntityStatementFetcher, TestEntity, TestFederation}
import fedtrust.types.{EntityId, EntityType}
import io.circe.parser.parse

/** A federation stood up in memory and resolved end to end.
  *
  * This module exists to be compiled, not published: if using the library
  * takes more ceremony than this, the API is wrong, and the compiler says so
  * before a user has to.
  */
object ResolveExample {

  private type Result[A] = Either[Throwable, A]

  def main(args: Array[String]): Unit = {
    val now = Instant.parse("2026-01-01T00:00:00Z")

    // A three-level federation: a Trust Anchor, one Intermediate, one leaf
    // relying party.
    val trustAnchor  = TestEntity("https://ta.example.org")
    val intermediate = TestEntity("https://org.example.org")
    val relyingParty = TestEntity("https://rp.example.org")

    val leafMetadata = decode[Metadata]("""
      {
        "openid_relying_party": {
          "redirect_uris": ["https://rp.example.org/callback"],
          "token_endpoint_auth_method": "self_signed_tls_client_auth",
          "contacts": ["admins@rp.example.org"]
        }
      }
    """)

    // The Trust Anchor requires an authentication method from a fixed set and
    // adds its own help desk to every subordinate's contacts.
    val anchorPolicy = decode[MetadataPolicy]("""
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

    val configurations: Map[EntityId, SignedJwt] = Map(
      trustAnchor.id -> expect(
        TestFederation.entityConfiguration(
          trustAnchor,
          metadata = Some(TestFederation.federationEntityMetadata(trustAnchor)),
          now = now
        )
      ),
      intermediate.id -> expect(
        TestFederation.entityConfiguration(
          intermediate,
          authorityHints = List(trustAnchor.id),
          metadata = Some(TestFederation.federationEntityMetadata(intermediate)),
          now = now
        )
      ),
      relyingParty.id -> expect(
        TestFederation.entityConfiguration(
          relyingParty,
          authorityHints = List(intermediate.id),
          metadata = Some(leafMetadata),
          now = now
        )
      )
    )

    val subordinates: Map[(String, EntityId), SignedJwt] = Map(
      (TestFederation.fetchEndpointOf(trustAnchor), intermediate.id) -> expect(
        TestFederation.subordinateStatement(
          trustAnchor,
          intermediate,
          metadataPolicy = Some(anchorPolicy),
          now = now
        )
      ),
      (TestFederation.fetchEndpointOf(intermediate), relyingParty.id) -> expect(
        TestFederation.subordinateStatement(intermediate, relyingParty, now = now)
      )
    )

    // Wiring: a fetcher, a statement verifier over it, a chain resolver, and
    // the metadata resolver on top. Swapping the in-memory fetcher for
    // Http4sEntityStatementFetcher is the only change a real deployment makes.
    val chains = TrustChainResolver[Result](
      InMemoryEntityStatementFetcher[Result](configurations, subordinates),
      StatementVerifier[Result](JwsVerifier[Result], Right(now))
    )

    val request = expect(
      ResolveRequest.fromParams(
        Params.of(
          "sub"          -> relyingParty.id.value,
          "trust_anchor" -> trustAnchor.id.value,
          "entity_type"  -> EntityType.OpenIdRelyingParty.value
        )
      )
    )

    Resolver[Result](chains).resolve(request.sub, request.trustAnchors.head) match {
      case Left(error) =>
        println(s"resolution failed: $error")

      case Right(resolved) =>
        println(s"subject      ${resolved.subject.value}")
        println(s"trust anchor ${resolved.trustAnchor.value}")
        println(s"chain length ${resolved.chain.pathLength} intermediate(s)")
        println(s"expires      ${resolved.expiresAt}")
        println()

        request.entityTypes.foreach { entityType =>
          resolved.metadata.get(entityType).foreach { document =>
            println(s"${entityType.value}:")
            document.toList.sortBy(_._1).foreach { case (name, value) =>
              println(s"  $name = ${value.noSpaces}")
            }
          }
        }
    }
  }

  private def expect[A](result: Either[FederationError, A]): A =
    result.fold(error => sys.error(s"example setup failed: ${error.message}"), identity)

  private def decode[A: io.circe.Decoder](raw: String): A =
    parse(raw)
      .flatMap(_.as[A])
      .fold(error => sys.error(s"example JSON is invalid: $error"), identity)
}
