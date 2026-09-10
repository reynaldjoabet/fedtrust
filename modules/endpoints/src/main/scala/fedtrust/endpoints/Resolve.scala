package fedtrust.endpoints

import java.time.Instant

import fedtrust.entity.TrustMarkEntry
import fedtrust.error.FederationError
import fedtrust.jwt.SignedJwt
import fedtrust.metadata.Metadata
import fedtrust.types.{*, given}
import fedtrust.util.NumericDate.given
import io.circe.{Decoder, Encoder}

/** A request to the resolve endpoint (spec section 8.3.1).
  *
  * `trust_anchor` is REQUIRED and may repeat, in which case the resolver may
  * answer using any of them.
  */
final case class ResolveRequest(
    sub: EntityId,
    trustAnchors: List[EntityId],
    entityTypes: List[EntityType] = Nil
)

object ResolveRequest {

  import Params.*

  def fromParams(params: Params): Either[FederationError, ResolveRequest] =
    for {
      sub     <- required(params, "sub")
      anchors <- requiredAll(params, "trust_anchor")
      types   <- entityTypes(params, "entity_type")
    } yield ResolveRequest(sub = sub, trustAnchors = anchors, entityTypes = types)

  /** A blank `entity_type` is rejected rather than carried: it can never match
    * a metadata key, so accepting it would filter the response down to nothing
    * while looking like a successful request.
    */
  private def entityTypes(
      params: Params,
      name: String
  ): Either[FederationError, List[EntityType]] =
    params.all(name).foldLeft[Either[FederationError, List[EntityType]]](Right(Nil)) { (acc, raw) =>
      for {
        parsed <- acc
        next   <- EntityType(raw).left
          .map(reason => FederationError.InvalidRequest(s"invalid [$name]: $reason"))
      } yield parsed :+ next
    }

  def toParams(request: ResolveRequest): Params =
    Params.of(
      (("sub" -> request.sub.value) ::
        request.trustAnchors.map(a => "trust_anchor" -> a.value) ++
        request.entityTypes.map(t => "entity_type" -> t.value))*
    )

  private def required(params: Params, name: String): Either[FederationError, EntityId] =
    params.first(name) match {
      case None =>
        Left(FederationError.InvalidRequest(s"required request parameter [$name] was missing"))
      case Some(raw) => entityId(name, raw)
    }

  private def requiredAll(
      params: Params,
      name: String
  ): Either[FederationError, List[EntityId]] =
    params.all(name) match {
      case Nil =>
        Left(FederationError.InvalidRequest(s"required request parameter [$name] was missing"))
      case values =>
        values.foldLeft[Either[FederationError, List[EntityId]]](Right(Nil)) { (acc, raw) =>
          for {
            parsed <- acc
            next   <- entityId(name, raw)
          } yield parsed :+ next
        }
    }

  private def entityId(name: String, raw: String): Either[FederationError, EntityId] =
    EntityId(raw).left.map(reason => FederationError.InvalidRequest(s"invalid [$name]: $reason"))
}

/** The claims of a resolve response (spec section 8.3.2).
  *
  * Served as a signed JWT with `typ` of `resolve-response+jwt`; section 8.3.2
  * requires responses without that `typ` to be rejected.
  *
  * `trustChain` holds the statements in their signed form, because the point of
  * returning a chain is that the recipient can verify it themselves — decoded
  * claims would be the resolver's word for it. Note that
  * `fedtrust.resolver.TrustChain` currently keeps only decoded statements, so
  * an endpoint assembling a response has to retain the compact JWSs it fetched.
  */
final case class ResolveResponse(
    iss: EntityId,
    sub: EntityId,
    iat: Instant,
    exp: Instant,
    metadata: Metadata,
    trustChain: List[SignedJwt],
    trustMarks: Option[List[TrustMarkEntry]] = None,
    aud: Option[EntityId] = None
)

object ResolveResponse {

  /** Section 8.3.2: `exp` MUST be the minimum of the Trust Chain's expiry and
    * that of every Trust Mark included. A response that outlived the chain it
    * rests on would keep asserting a membership that has lapsed.
    */
  def expiry(chainExpiresAt: Instant, trustMarkExpiries: List[Instant]): Instant =
    (chainExpiresAt :: trustMarkExpiries).min

  private val names =
    List("iss", "sub", "iat", "exp", "metadata", "trust_chain", "trust_marks", "aud")

  given Encoder[ResolveResponse] =
    Encoder.forProduct8(
      names(0),
      names(1),
      names(2),
      names(3),
      names(4),
      names(5),
      names(6),
      names(7)
    )(r => (r.iss, r.sub, r.iat, r.exp, r.metadata, r.trustChain, r.trustMarks, r.aud))

  given Decoder[ResolveResponse] =
    Decoder.forProduct8(
      names(0),
      names(1),
      names(2),
      names(3),
      names(4),
      names(5),
      names(6),
      names(7)
    )(ResolveResponse.apply)
}
