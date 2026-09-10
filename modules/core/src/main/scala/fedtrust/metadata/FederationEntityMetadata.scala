package fedtrust.metadata

import fedtrust.error.FederationError
import fedtrust.types.{*, given}
import io.circe.{Decoder, Encoder}

/** The `federation_entity` metadata type (spec section 5.1.1).
  *
  * This is the federation's endpoint directory, and the one metadata document
  * the resolver itself has to read: walking a chain means asking each superior
  * for a Subordinate Statement, and `federation_fetch_endpoint` is where that
  * request goes. Every other entity type's metadata is opaque to this library
  * and is handed to the caller as JSON.
  */
final case class FederationEntityMetadata(
    federationFetchEndpoint: Option[String] = None,
    federationListEndpoint: Option[String] = None,
    federationResolveEndpoint: Option[String] = None,
    federationTrustMarkStatusEndpoint: Option[String] = None,
    federationTrustMarkListEndpoint: Option[String] = None,
    federationTrustMarkEndpoint: Option[String] = None,
    federationHistoricalKeysEndpoint: Option[String] = None,
    endpointAuthSigningAlgValuesSupported: Option[List[String]] = None,
    organizationName: Option[String] = None
)

object FederationEntityMetadata {

  val empty: FederationEntityMetadata = FederationEntityMetadata()

  /** Read the `federation_entity` document out of a metadata claim.
    *
    * Absent is not an error: leaf entities legitimately have no
    * `federation_entity` metadata at all.
    */
  def from(metadata: Metadata): Either[FederationError, Option[FederationEntityMetadata]] =
    metadata.get(EntityType.FederationEntity) match {
      case None           => Right(None)
      case Some(document) =>
        Decoder[FederationEntityMetadata]
          .decodeJson(io.circe.Json.fromJsonObject(document))
          .fold(
            e =>
              Left(
                FederationError.InvalidMetadata(
                  s"unreadable federation_entity metadata: ${e.getMessage}"
                )
              ),
            parsed => Right(Some(parsed))
          )
    }

  private val names = List(
    "federation_fetch_endpoint",
    "federation_list_endpoint",
    "federation_resolve_endpoint",
    "federation_trust_mark_status_endpoint",
    "federation_trust_mark_list_endpoint",
    "federation_trust_mark_endpoint",
    "federation_historical_keys_endpoint",
    "endpoint_auth_signing_alg_values_supported",
    "organization_name"
  )

  given Encoder[FederationEntityMetadata] =
    Encoder.forProduct9(
      names(0),
      names(1),
      names(2),
      names(3),
      names(4),
      names(5),
      names(6),
      names(7),
      names(8)
    )(m =>
      (
        m.federationFetchEndpoint,
        m.federationListEndpoint,
        m.federationResolveEndpoint,
        m.federationTrustMarkStatusEndpoint,
        m.federationTrustMarkListEndpoint,
        m.federationTrustMarkEndpoint,
        m.federationHistoricalKeysEndpoint,
        m.endpointAuthSigningAlgValuesSupported,
        m.organizationName
      )
    )

  given Decoder[FederationEntityMetadata] =
    Decoder.forProduct9(
      names(0),
      names(1),
      names(2),
      names(3),
      names(4),
      names(5),
      names(6),
      names(7),
      names(8)
    )(FederationEntityMetadata.apply)
}
