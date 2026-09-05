package fedtrust.types

import io.circe.{Decoder, Encoder, KeyDecoder, KeyEncoder}

/** An entity type identifier, used as the key of the `metadata` and
  * `metadata_policy` claims.
  *
  * Deliberately not an `enum`: the spec lets a federation define its own entity
  * types, and unknown ones have to survive a decode/encode round trip rather
  * than be dropped.
  */
final case class EntityType(value: String)

object EntityType {
  val FederationEntity: EntityType         = EntityType("federation_entity")
  val OpenIdRelyingParty: EntityType       = EntityType("openid_relying_party")
  val OpenIdProvider: EntityType           = EntityType("openid_provider")
  val OAuthAuthorizationServer: EntityType = EntityType("oauth_authorization_server")
  val OAuthClient: EntityType              = EntityType("oauth_client")
  val OAuthResource: EntityType            = EntityType("oauth_resource")

  /** The types named by the specification. Not exhaustive by design. */
  val specified: Set[EntityType] = Set(
    FederationEntity,
    OpenIdRelyingParty,
    OpenIdProvider,
    OAuthAuthorizationServer,
    OAuthClient,
    OAuthResource
  )

  given Encoder[EntityType]    = Encoder.encodeString.contramap(_.value)
  given Decoder[EntityType]    = Decoder.decodeString.map(EntityType.apply)
  given KeyEncoder[EntityType] = KeyEncoder.encodeKeyString.contramap(_.value)
  given KeyDecoder[EntityType] = KeyDecoder.decodeKeyString.map(EntityType.apply)
}
