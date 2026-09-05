package fedtrust.endpoints

import fedtrust.error.FederationError
import fedtrust.types.{EntityId, EntityType}
import io.circe.{Decoder, Encoder}

/** A request to the subordinate listing endpoint (spec section 8.2.1).
  *
  * Every filter is optional, and an endpoint that does not implement one MUST
  * answer `unsupported_parameter` rather than ignore it — silently returning an
  * unfiltered list would let a caller believe a filter had been applied. Use
  * [[SubordinateListingRequest.rejectUnsupported]] to say what is supported.
  */
final case class SubordinateListingRequest(
    entityTypes: List[EntityType] = Nil,
    trustMarked: Option[Boolean] = None,
    trustMarkType: Option[String] = None,
    intermediate: Option[Boolean] = None
) {
  def isFiltered: Boolean =
    entityTypes.nonEmpty || trustMarked.isDefined || trustMarkType.isDefined ||
      intermediate.isDefined
}

object SubordinateListingRequest {

  import Params.*

  val entityTypeParam    = "entity_type"
  val trustMarkedParam   = "trust_marked"
  val trustMarkTypeParam = "trust_mark_type"
  val intermediateParam  = "intermediate"

  def fromParams(params: Params): Either[FederationError, SubordinateListingRequest] =
    for {
      trustMarked  <- boolean(params, trustMarkedParam)
      intermediate <- boolean(params, intermediateParam)
    } yield SubordinateListingRequest(
      entityTypes = params.all(entityTypeParam).map(EntityType.apply),
      trustMarked = trustMarked,
      trustMarkType = params.first(trustMarkTypeParam),
      intermediate = intermediate
    )

  def toParams(request: SubordinateListingRequest): Params = {
    val types = request.entityTypes.map(t => entityTypeParam -> t.value)
    val flags = List(
      request.trustMarked.map(v => trustMarkedParam -> v.toString),
      request.trustMarkType.map(v => trustMarkTypeParam -> v),
      request.intermediate.map(v => intermediateParam -> v.toString)
    ).flatten

    Params.of((types ++ flags)*)
  }

  /** Reject any filter this endpoint does not implement, as section 8.2.1
    * requires.
    */
  def rejectUnsupported(
      request: SubordinateListingRequest,
      supported: Set[String]
  ): Either[FederationError, SubordinateListingRequest] = {
    val used = List(
      Option.when(request.entityTypes.nonEmpty)(entityTypeParam),
      request.trustMarked.map(_ => trustMarkedParam),
      request.trustMarkType.map(_ => trustMarkTypeParam),
      request.intermediate.map(_ => intermediateParam)
    ).flatten

    used.filterNot(supported.contains) match {
      case Nil         => Right(request)
      case unsupported =>
        Left(
          FederationError.UnsupportedParameter(
            s"this endpoint does not support: ${unsupported.mkString(", ")}"
          )
        )
    }
  }

  private def boolean(params: Params, name: String): Either[FederationError, Option[Boolean]] =
    params.first(name) match {
      case None          => Right(None)
      case Some("true")  => Right(Some(true))
      case Some("false") => Right(Some(false))
      case Some(other)   =>
        Left(FederationError.InvalidRequest(s"[$name] must be true or false, got '$other'"))
    }
}

/** The listing response (spec section 8.2.2): a bare JSON array of Entity
  * Identifiers, with content type `application/json`.
  */
final case class SubordinateListing(entities: List[EntityId])

object SubordinateListing {
  given Encoder[SubordinateListing] = Encoder[List[EntityId]].contramap(_.entities)
  given Decoder[SubordinateListing] = Decoder[List[EntityId]].map(SubordinateListing.apply)
}
