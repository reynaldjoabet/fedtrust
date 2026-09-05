package fedtrust.testkit

import java.time.Instant

import fedtrust.entity.{Constraints, EntityStatement}
import fedtrust.error.FederationError
import fedtrust.jose.Nimbus
import fedtrust.jwk.{Jwk, JwkSet}
import fedtrust.jwt.{JwtTyp, SignedJwt}
import fedtrust.metadata.{FederationEntityMetadata, Metadata, MetadataPolicy}
import fedtrust.types.{EntityId, EntityType}
import io.circe.{Encoder, JsonObject}

/** An entity with a signing key, as a test needs it. */
final case class TestEntity(id: EntityId, privateKey: Jwk, publicKey: Jwk) {
  def jwks: JwkSet = JwkSet(List(publicKey))
}

object TestEntity {
  def apply(id: String): TestEntity = {
    val entityId       = EntityId.unsafe(id)
    val (priv, public) = Keys.generate(entityId.value)
    TestEntity(entityId, priv, public)
  }
}

/** Builds the signed statements of a small federation, so chain tests can work
  * against real signatures without any server.
  *
  * Statements are signed synchronously and returned as `Either` — fixtures do
  * not need an effect type, and keeping one out of them keeps the tests that
  * use them readable.
  */
object TestFederation {

  val defaultLifetimeSeconds: Long = 3600

  /** An entity's self-issued configuration. */
  def entityConfiguration(
      entity: TestEntity,
      authorityHints: List[EntityId] = Nil,
      metadata: Option[Metadata] = None,
      now: Instant = Instant.now(),
      lifetimeSeconds: Long = defaultLifetimeSeconds
  ): Either[FederationError, SignedJwt] =
    sign(
      EntityStatement(
        iss = entity.id,
        sub = entity.id,
        iat = now,
        exp = now.plusSeconds(lifetimeSeconds),
        jwks = entity.jwks,
        authorityHints = Option.when(authorityHints.nonEmpty)(authorityHints),
        metadata = metadata
      ),
      entity.privateKey
    )

  /** A statement a superior issues about an entity below it. */
  def subordinateStatement(
      issuer: TestEntity,
      subject: TestEntity,
      metadata: Option[Metadata] = None,
      metadataPolicy: Option[MetadataPolicy] = None,
      constraints: Option[Constraints] = None,
      now: Instant = Instant.now(),
      lifetimeSeconds: Long = defaultLifetimeSeconds
  ): Either[FederationError, SignedJwt] =
    sign(
      EntityStatement(
        iss = issuer.id,
        sub = subject.id,
        iat = now,
        exp = now.plusSeconds(lifetimeSeconds),
        jwks = subject.jwks,
        metadata = metadata,
        metadataPolicy = metadataPolicy,
        constraints = constraints
      ),
      issuer.privateKey
    )

  /** `federation_entity` metadata for an Entity that serves the fetch and list
    * endpoints, which every Intermediate and Trust Anchor must publish.
    */
  def federationEntityMetadata(entity: TestEntity): Metadata =
    Metadata(
      Map(
        EntityType.FederationEntity -> Encoder[FederationEntityMetadata]
          .apply(
            FederationEntityMetadata(
              federationFetchEndpoint = Some(s"${entity.id.value}/fetch"),
              federationListEndpoint = Some(s"${entity.id.value}/list")
            )
          )
          .asObject
          .getOrElse(JsonObject.empty)
      )
    )

  def fetchEndpointOf(entity: TestEntity): String = s"${entity.id.value}/fetch"

  def sign(statement: EntityStatement, key: Jwk): Either[FederationError, SignedJwt] =
    claims(statement).flatMap(Nimbus.sign(JwtTyp.EntityStatement, _, key))

  private def claims(statement: EntityStatement): Either[FederationError, JsonObject] =
    Encoder[EntityStatement]
      .apply(statement)
      .asObject
      .toRight(FederationError.MalformedJwt("entity statement did not encode to an object"))
}
