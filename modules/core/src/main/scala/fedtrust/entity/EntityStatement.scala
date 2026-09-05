package fedtrust.entity

import java.time.Instant

import fedtrust.jwk.JwkSet
import fedtrust.metadata.{Metadata, MetadataPolicy}
import fedtrust.types.EntityId
import fedtrust.util.NumericDate.given
import io.circe.{Decoder, Encoder}

/** The claims of an entity statement.
  *
  * One type covers both shapes the spec defines, because they differ only in
  * whether the statement is self-issued:
  *
  *   - an Entity Configuration has `iss == sub`, and is what an entity serves
  *     from its own well-known endpoint;
  *   - a Subordinate Statement has `iss != sub`, and is what a superior serves
  *     about an entity below it from its fetch endpoint.
  *
  * Splitting them into two types would duplicate every claim and every codec
  * while giving the chain validator two things to case over; `kind` gives the
  * same discrimination where it is actually needed.
  */
final case class EntityStatement(
    iss: EntityId,
    sub: EntityId,
    iat: Instant,
    exp: Instant,
    jwks: JwkSet,
    authorityHints: Option[List[EntityId]] = None,
    metadata: Option[Metadata] = None,
    metadataPolicy: Option[MetadataPolicy] = None,
    constraints: Option[Constraints] = None,
    crit: Option[List[String]] = None,
    metadataPolicyCrit: Option[List[String]] = None,
    trustMarks: Option[List[TrustMarkEntry]] = None,
    trustMarkIssuers: Option[TrustMarkIssuers] = None,
    sourceEndpoint: Option[String] = None
) {

  def kind: EntityStatement.Kind =
    if (iss == sub) EntityStatement.Kind.EntityConfiguration
    else EntityStatement.Kind.SubordinateStatement

  def isEntityConfiguration: Boolean = kind == EntityStatement.Kind.EntityConfiguration

  def isExpiredAt(now: Instant): Boolean = !now.isBefore(exp)

  def isNotYetValidAt(now: Instant): Boolean = now.isBefore(iat)

  def hints: List[EntityId] = authorityHints.getOrElse(Nil)

  def metadataOrEmpty: Metadata = metadata.getOrElse(Metadata.empty)

  def metadataPolicyOrEmpty: MetadataPolicy = metadataPolicy.getOrElse(MetadataPolicy.empty)
}

object EntityStatement {

  enum Kind {
    case EntityConfiguration, SubordinateStatement
  }

  given Encoder[EntityStatement] =
    Encoder.forProduct14(
      "iss",
      "sub",
      "iat",
      "exp",
      "jwks",
      "authority_hints",
      "metadata",
      "metadata_policy",
      "constraints",
      "crit",
      "metadata_policy_crit",
      "trust_marks",
      "trust_mark_issuers",
      "source_endpoint"
    )(s =>
      (
        s.iss,
        s.sub,
        s.iat,
        s.exp,
        s.jwks,
        s.authorityHints,
        s.metadata,
        s.metadataPolicy,
        s.constraints,
        s.crit,
        s.metadataPolicyCrit,
        s.trustMarks,
        s.trustMarkIssuers,
        s.sourceEndpoint
      )
    )

  given Decoder[EntityStatement] =
    Decoder.forProduct14(
      "iss",
      "sub",
      "iat",
      "exp",
      "jwks",
      "authority_hints",
      "metadata",
      "metadata_policy",
      "constraints",
      "crit",
      "metadata_policy_crit",
      "trust_marks",
      "trust_mark_issuers",
      "source_endpoint"
    )(EntityStatement.apply)
}
