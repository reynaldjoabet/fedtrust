package fedtrust.testkit

import java.time.Instant

import fedtrust.entity.{
  Constraints,
  EntityStatement,
  TrustMarkClaims,
  TrustMarkDelegationClaims,
  TrustMarkEntry
}
import fedtrust.error.FederationError
import fedtrust.jose.Nimbus
import fedtrust.jwk.{Jwk, JwkSet}
import fedtrust.jwt.{JwtTyp, SignedJwt}
import fedtrust.metadata.{FederationEntityMetadata, Metadata, MetadataPolicy}
import fedtrust.types.{*, given}
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
      trustMarks: Option[List[TrustMarkEntry]] = None,
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
        metadata = metadata,
        trustMarks = trustMarks
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
    claims(statement).flatMap(Nimbus.sign(JwtTyp.EntityStatement.value, _, key))

  /** A Trust Mark issued by `issuer` about `subject` (spec section 7.1).
    *
    * Signed with the issuer's Federation Entity Key, as section 7 requires -
    * the same key that signs its statements, not a separate one.
    */
  def trustMark(
      issuer: TestEntity,
      subject: TestEntity,
      trustMarkType: TrustMarkType,
      delegation: Option[SignedJwt] = None,
      now: Instant = Instant.now(),
      lifetimeSeconds: Option[Long] = Some(defaultLifetimeSeconds)
  ): Either[FederationError, TrustMarkEntry] =
    claims(
      TrustMarkClaims(
        iss = issuer.id,
        sub = subject.id,
        trustMarkType = trustMarkType,
        iat = now,
        exp = lifetimeSeconds.map(now.plusSeconds),
        delegation = delegation
      )
    ).flatMap(Nimbus.sign(JwtTyp.TrustMark.value, _, issuer.privateKey))
      .map(TrustMarkEntry(trustMarkType, _))

  /** A Trust Mark Delegation JWT, by which an owner authorises an issuer to
    * issue marks of a type the owner holds (spec section 7.2.1).
    */
  def trustMarkDelegation(
      owner: TestEntity,
      issuer: TestEntity,
      trustMarkType: TrustMarkType,
      now: Instant = Instant.now(),
      lifetimeSeconds: Option[Long] = Some(defaultLifetimeSeconds)
  ): Either[FederationError, SignedJwt] =
    claims(
      TrustMarkDelegationClaims(
        iss = owner.id,
        sub = issuer.id,
        trustMarkType = trustMarkType,
        iat = now,
        exp = lifetimeSeconds.map(now.plusSeconds)
      )
    ).flatMap(Nimbus.sign(JwtTyp.TrustMarkDelegation.value, _, owner.privateKey))

  private def claims[A: Encoder](value: A): Either[FederationError, JsonObject] =
    Encoder[A]
      .apply(value)
      .asObject
      .toRight(FederationError.MalformedJwt("claims did not encode to a JSON object"))
}
