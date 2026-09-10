package fedtrust

import java.net.URI

import scala.annotation.targetName

import io.circe.{Decoder, Encoder, KeyDecoder, KeyEncoder}
import io.github.iltotore.iron.*
import io.github.iltotore.iron.constraint.all.*

/** The vocabulary the rest of the library is written in.
  *
  * Everything here is an iron refinement, so a constraint the specification
  * states in prose is checked once — at the boundary where a value is written
  * as a literal or decoded from JSON — instead of at every use site.
  *
  * Extensions and codecs live directly in this object rather than in companions
  * of the individual types. A refined type is a type alias, and an alias has no
  * companion in implicit scope, so `import fedtrust.types.{*, given}` is what
  * brings them in. That import is the one thing every consumer of this object
  * needs.
  */
object types {

  // ---------------------------------------------------------------- entity id

  /** An Entity Identifier: an https URL with a host, and no query or fragment
    * component (OpenID Federation 1.0, section 1.2).
    *
    * Expressed as a regex rather than by parsing, because iron can evaluate a
    * regex at compile time: an identifier written as a literal anywhere in this
    * build — every fixture, every constant — is validated by the compiler, and
    * a bad one is a compile error rather than a test failure.
    */
  type EntityIdentifier =
    Match["https://[^/?#]+(/[^?#]*)?"] DescribedAs
      "entity identifier must be an https URL with a host and no query or fragment"

  type EntityId = String :| EntityIdentifier

  object EntityId {

    /** For identifiers that arrive at runtime, from JSON or a query string. */
    def apply(raw: String): Either[String, EntityId] = raw.refineEither[EntityIdentifier]

    /** For values already known to be well formed. Literals do not need this —
      * they refine at compile time on their own.
      */
    def unsafe(raw: String): EntityId = raw.refineUnsafe[EntityIdentifier]
  }

  extension (id: EntityId) {

    /** The underlying string. Redundant now that `EntityId <: String`, but kept
      * because it says at the use site that the string is an identifier.
      */
    def value: String = id

    /** The entity's federation entity configuration location.
      *
      * The well-known path segment is inserted after the host, ahead of any
      * path the identifier already carries.
      */
    def wellKnownUri: String = {
      val uri  = new URI(id)
      val path = Option(uri.getRawPath).filter(_ != "/").getOrElse("")
      s"${uri.getScheme}://${uri.getRawAuthority}/.well-known/openid-federation$path"
    }
  }

  given Encoder[EntityId]  = Encoder.encodeString.contramap(identity)
  given Decoder[EntityId]  = Decoder.decodeString.emap(EntityId.apply)
  given Ordering[EntityId] = Ordering.String.on(identity)

  // -------------------------------------------------------------- entity type

  /** An entity type identifier, used as the key of the `metadata` and
    * `metadata_policy` claims (section 5.1).
    *
    * Only constrained to be non-blank: the specification lets a federation
    * define its own entity types, so unknown ones have to survive a round trip
    * rather than be rejected.
    */
  type EntityTypeIdentifier =
    Not[Blank] DescribedAs "entity type identifier must not be blank"

  type EntityType = String :| EntityTypeIdentifier

  object EntityType {
    val FederationEntity: EntityType         = "federation_entity"
    val OpenIdRelyingParty: EntityType       = "openid_relying_party"
    val OpenIdProvider: EntityType           = "openid_provider"
    val OAuthAuthorizationServer: EntityType = "oauth_authorization_server"
    val OAuthClient: EntityType              = "oauth_client"
    val OAuthResource: EntityType            = "oauth_resource"

    def apply(raw: String): Either[String, EntityType] =
      raw.refineEither[EntityTypeIdentifier]

    def unsafe(raw: String): EntityType = raw.refineUnsafe[EntityTypeIdentifier]
  }

  // Both refined types erase to String, so the two `value` extensions collide
  // on the JVM unless one is given a distinct name.
  extension (entityType: EntityType) {
    @targetName("entityTypeValue")
    def value: String = entityType
  }

  given Encoder[EntityType] = Encoder.encodeString.contramap(identity)
  given Decoder[EntityType] = Decoder.decodeString.emap(EntityType.apply)

  given KeyEncoder[EntityType] = KeyEncoder.encodeKeyString.contramap(identity)
  given KeyDecoder[EntityType] = KeyDecoder.instance(_.refineOption[EntityTypeIdentifier])

  /** The entity types this specification names, as a closed set.
    *
    * A view over [[EntityType]] rather than a replacement for it. The
    * identifier itself stays an open string because section 5.1 permits
    * federations to define their own, and one arriving in a signed statement
    * must survive resolution whether or not this build knows it. What the enum
    * adds is exhaustive matching and iteration over the types the
    * specification does fix — useful when dispatching to a typed metadata view
    * per protocol, where every known case must be handled.
    *
    * The dependency runs one way, from this enum to the identifiers. Deriving
    * the identifiers back from `values` would be an initialisation cycle.
    */
  enum WellKnownEntityType(val identifier: EntityType) {
    case FederationEntity         extends WellKnownEntityType(EntityType.FederationEntity)
    case OpenIdRelyingParty       extends WellKnownEntityType(EntityType.OpenIdRelyingParty)
    case OpenIdProvider           extends WellKnownEntityType(EntityType.OpenIdProvider)
    case OAuthAuthorizationServer extends WellKnownEntityType(EntityType.OAuthAuthorizationServer)
    case OAuthClient              extends WellKnownEntityType(EntityType.OAuthClient)
    case OAuthResource            extends WellKnownEntityType(EntityType.OAuthResource)
  }

  object WellKnownEntityType {

    private lazy val byIdentifier: Map[EntityType, WellKnownEntityType] =
      values.map(known => known.identifier -> known).toMap

    /** `None` for a federation-defined type this build does not know, which is
      * a normal outcome rather than an error.
      */
    def from(identifier: EntityType): Option[WellKnownEntityType] =
      byIdentifier.get(identifier)

    lazy val identifiers: Set[EntityType] = values.map(_.identifier).toSet
  }

  // ------------------------------------------------------------- other bounds

  /** Section 6.2.1: "The max_path_length constraint MUST have a value greater
    * than or equal to zero."
    *
    * Checked once, when the Subordinate Statement is decoded, instead of by the
    * chain validator on every statement it walks.
    */
  type MaxPathLength = Int :| (GreaterEqual[0] DescribedAs "max_path_length must not be negative")

  given Encoder[MaxPathLength] = Encoder.encodeInt.contramap(identity)

  given Decoder[MaxPathLength] =
    Decoder.decodeInt.emap(
      _.refineEither[GreaterEqual[0] DescribedAs "max_path_length must not be negative"]
    )

  /** How deep a resolver will walk `authority_hints` before giving up. Zero
    * would mean no chain could ever be built, so the bound is positive rather
    * than merely non-negative.
    */
  type SearchDepth = Int :| (Positive DescribedAs "search depth must be positive")

  /** Section 3.2: "The Entity Statement's kid (Key ID) header parameter value
    * MUST be a non-zero length string."
    *
    * Without this a statement carrying `"kid": ""` would be looked up literally
    * and simply not match, reporting a missing key rather than the malformed
    * header it actually is.
    */
  type KeyIdentifier = Not[Blank] DescribedAs "kid header parameter must not be blank"

  type KeyId = String :| KeyIdentifier

  /** Section 7.1: the identifier of a Trust Mark's type, which "MUST be
    * collision-resistant across multiple federations" and is RECOMMENDED to be
    * a URL naming the federation or trust framework.
    *
    * Left open rather than constrained to a URL: the requirement is
    * collision-resistance, not a syntax, and it keys the `trust_mark_issuers`
    * and `trust_mark_owners` claims of Trust Anchors this build has never seen.
    */
  type TrustMarkTypeIdentifier =
    Not[Blank] DescribedAs "trust mark type identifier must not be blank"

  type TrustMarkType = String :| TrustMarkTypeIdentifier

  given Encoder[TrustMarkType] = Encoder.encodeString.contramap(identity)

  given Decoder[TrustMarkType] =
    Decoder.decodeString.emap(_.refineEither[TrustMarkTypeIdentifier])

  given KeyEncoder[TrustMarkType] = KeyEncoder.encodeKeyString.contramap(identity)

  given KeyDecoder[TrustMarkType] =
    KeyDecoder.instance(_.refineOption[TrustMarkTypeIdentifier])
}
