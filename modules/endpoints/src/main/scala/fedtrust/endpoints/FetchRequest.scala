package fedtrust.endpoints

import fedtrust.error.FederationError
import fedtrust.types.EntityId

/** A request to the fetch endpoint (spec section 8.1.1).
  *
  * The response is a Subordinate Statement as
  * `application/entity-statement+jwt`, so there is no response type here: the
  * body is the compact JWS and nothing may reserialise it.
  */
final case class FetchRequest(sub: EntityId)

object FetchRequest {

  import Params.*

  def fromParams(params: Params): Either[FederationError, FetchRequest] =
    params.first("sub") match {
      case None =>
        Left(FederationError.InvalidRequest("required request parameter [sub] was missing"))
      case Some(raw) =>
        EntityId(raw).left
          .map(reason => FederationError.InvalidRequest(s"invalid [sub]: $reason"))
          .map(FetchRequest.apply)
    }

  def toParams(request: FetchRequest): Params = Params.of("sub" -> request.sub.value)

  /** Section 8.1.2 recommends `invalid_request` rather than `not_found` when an
    * endpoint is asked for a statement about itself: a fetch endpoint serves
    * statements about Subordinates, and its own configuration is published at
    * its well-known location instead.
    */
  def validateFor(
      request: FetchRequest,
      issuer: EntityId
  ): Either[FederationError, FetchRequest] =
    Either.cond(
      request.sub != issuer,
      request,
      FederationError.InvalidRequest(
        "[sub] is the issuing entity itself; request its entity configuration instead"
      )
    )
}
