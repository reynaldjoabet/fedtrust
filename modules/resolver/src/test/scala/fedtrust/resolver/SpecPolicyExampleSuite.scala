package fedtrust.resolver

import fedtrust.metadata.MetadataPolicy
import fedtrust.resolver.policy.MetadataPolicyEngine
import fedtrust.types.{*, given}
import io.circe.JsonObject
import io.circe.syntax.*
import munit.FunSuite

/** The worked example from spec section 6.1.5, used as a test vector.
  *
  * The specification gives both intermediate results — the merged policy in
  * Figure 12 and the Resolved Metadata in Figure 14 — so this checks the two
  * halves of the pipeline against text rather than against our own reading of
  * it.
  */
class SpecPolicyExampleSuite extends FunSuite {

  import Fixtures.*

  // Figure 10: the Trust Anchor's policy for relying parties.
  private val trustAnchorPolicy: MetadataPolicy = policy("""
    {
      "openid_relying_party": {
        "grant_types": {
          "default": ["authorization_code"],
          "subset_of": ["authorization_code", "refresh_token"],
          "superset_of": ["authorization_code"]
        },
        "token_endpoint_auth_method": {
          "one_of": ["private_key_jwt", "self_signed_tls_client_auth"],
          "essential": true
        },
        "token_endpoint_auth_signing_alg": {
          "one_of": ["PS256", "ES256"]
        },
        "subject_type": { "value": "pairwise" },
        "contacts": { "add": ["helpdesk@federation.example.org"] }
      }
    }
  """)

  // Figure 11: the Intermediate's policy and the metadata it supplies.
  private val intermediatePolicy: MetadataPolicy = policy("""
    {
      "openid_relying_party": {
        "grant_types": { "subset_of": ["authorization_code"] },
        "token_endpoint_auth_method": { "one_of": ["self_signed_tls_client_auth"] },
        "contacts": { "add": ["helpdesk@org.example.org"] }
      }
    }
  """)

  private val intermediateMetadata = metadata("""
    {
      "openid_relying_party": {
        "sector_identifier_uri": "https://org.example.org/sector-ids.json",
        "policy_uri": "https://org.example.org/policy.html"
      }
    }
  """)

  // Figure 13: what the leaf publishes about itself.
  private val leafMetadata = metadata("""
    {
      "openid_relying_party": {
        "redirect_uris": ["https://rp.example.org/callback"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "self_signed_tls_client_auth",
        "contacts": ["rp_admins@rp.example.org"]
      }
    }
  """)

  private val leaf         = "https://rp.example.org"
  private val intermediate = "https://org.example.org"
  private val trustAnchor  = "https://federation.example.org"

  private val chain = TrustChain(
    subjectConfiguration = statement(leaf, leaf, metadata = Some(leafMetadata)),
    subordinateStatements = List(
      statement(
        intermediate,
        leaf,
        metadata = Some(intermediateMetadata),
        metadataPolicy = Some(intermediatePolicy)
      ),
      statement(trustAnchor, intermediate, metadataPolicy = Some(trustAnchorPolicy))
    ),
    trustAnchorConfiguration = statement(trustAnchor, trustAnchor)
  )

  test("the chain is structurally valid") {
    assertEquals(
      TrustChain
        .validated(
          chain.subjectConfiguration,
          chain.subordinateStatements,
          chain.trustAnchorConfiguration
        )
        .map(_.pathLength),
      Right(2)
    )
  }

  test("merging the Intermediate into the Trust Anchor gives Figure 12") {
    // Figure 12, which is the openid_relying_party policy only.
    val expected = policy("""
      {
        "openid_relying_party": {
          "grant_types": {
            "default": ["authorization_code"],
            "superset_of": ["authorization_code"],
            "subset_of": ["authorization_code"]
          },
          "token_endpoint_auth_method": {
            "one_of": ["self_signed_tls_client_auth"],
            "essential": true
          },
          "token_endpoint_auth_signing_alg": {
            "one_of": ["PS256", "ES256"]
          },
          "subject_type": { "value": "pairwise" },
          "contacts": {
            "add": ["helpdesk@federation.example.org", "helpdesk@org.example.org"]
          }
        }
      }
    """)

    assertEquals(MetadataPolicyEngine.resolve(chain.policyOrder), Right(expected))
  }

  test("applying the merged policy gives the Resolved Metadata of Figure 14") {
    val expected = obj("""
      {
        "redirect_uris": ["https://rp.example.org/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "self_signed_tls_client_auth",
        "subject_type": "pairwise",
        "sector_identifier_uri": "https://org.example.org/sector-ids.json",
        "policy_uri": "https://org.example.org/policy.html",
        "contacts": [
          "rp_admins@rp.example.org",
          "helpdesk@federation.example.org",
          "helpdesk@org.example.org"
        ]
      }
    """)

    val resolved = Resolver.resolvedMetadata(chain)

    assertEquals(
      resolved.map(_.get(EntityType.OpenIdRelyingParty).map(_.asJson)),
      Right(Some(expected.asJson))
    )
  }

  test("token_endpoint_auth_signing_alg stays absent: one_of does not invent a value") {
    val resolved = Resolver.resolvedMetadata(chain).map { m =>
      m.get(EntityType.OpenIdRelyingParty)
        .getOrElse(JsonObject.empty)
        .contains("token_endpoint_auth_signing_alg")
    }

    assertEquals(resolved, Right(false))
  }

  test("the specified merge order fixes the ordering of merged values") {
    // Every standard operator merges symmetrically - intersection, union,
    // equality, logical OR - so the *content* of a merged policy does not
    // depend on the direction of the walk. What the direction fixes is the
    // ordering within merged arrays, and section 6.1.1 requires resolution to
    // be deterministic. Figure 12 pins the expected order down: the Trust
    // Anchor's contact first, the Intermediate's second.
    assertEquals(
      mergedContacts(chain.policyOrder),
      Right(List("helpdesk@federation.example.org", "helpdesk@org.example.org"))
    )

    assertEquals(
      mergedContacts(chain.policyOrder.reverse),
      Right(List("helpdesk@org.example.org", "helpdesk@federation.example.org"))
    )
  }

  private def mergedContacts(statements: List[fedtrust.entity.EntityStatement]) =
    MetadataPolicyEngine.resolve(statements).map { resolved =>
      resolved
        .get(EntityType.OpenIdRelyingParty)
        .get("contacts")
        .flatMap(_(fedtrust.metadata.PolicyOperator.Add))
        .flatMap(_.asArray)
        .map(_.flatMap(_.asString).toList)
        .getOrElse(Nil)
    }
}
