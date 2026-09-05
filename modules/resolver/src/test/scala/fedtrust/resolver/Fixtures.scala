package fedtrust.resolver

import java.time.Instant

import fedtrust.entity.EntityStatement
import fedtrust.jwk.JwkSet
import fedtrust.metadata.{Metadata, MetadataPolicy}
import fedtrust.types.EntityId
import io.circe.{Json, JsonObject}
import io.circe.parser.parse

/** Statements built directly rather than signed, so the policy and constraint
  * suites exercise the logic under test without dragging in key material.
  */
object Fixtures {

  val issuedAt: Instant = Instant.ofEpochSecond(1700000000L)

  def entity(id: String): EntityId = EntityId.unsafe(id)

  def json(raw: String): Json =
    parse(raw).fold(e => throw new IllegalArgumentException(s"bad test JSON: $e", e), identity)

  def obj(raw: String): JsonObject =
    json(raw).asObject.getOrElse(throw new IllegalArgumentException("expected a JSON object"))

  def metadata(raw: String): Metadata =
    json(raw)
      .as[Metadata]
      .fold(e => throw new IllegalArgumentException(s"bad test metadata: $e", e), identity)

  def policy(raw: String): MetadataPolicy =
    json(raw)
      .as[MetadataPolicy]
      .fold(e => throw new IllegalArgumentException(s"bad test policy: $e", e), identity)

  def statement(
      iss: String,
      sub: String,
      metadata: Option[Metadata] = None,
      metadataPolicy: Option[MetadataPolicy] = None,
      constraints: Option[fedtrust.entity.Constraints] = None,
      authorityHints: Option[List[EntityId]] = None
  ): EntityStatement =
    EntityStatement(
      iss = entity(iss),
      sub = entity(sub),
      iat = issuedAt,
      exp = issuedAt.plusSeconds(3600),
      jwks = JwkSet.empty,
      authorityHints = authorityHints,
      metadata = metadata,
      metadataPolicy = metadataPolicy,
      constraints = constraints
    )
}
