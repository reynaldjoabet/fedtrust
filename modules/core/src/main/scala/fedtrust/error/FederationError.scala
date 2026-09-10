package fedtrust.error

import scala.util.control.NoStackTrace

import fedtrust.types.{*, given}

/** Failures raised anywhere in the library.
  *
  * `code` is the value that goes in the `error` member of a federation
  * endpoint error response, and `httpStatus` the status the specification
  * recommends alongside it (section 8.9). Carrying both here means an endpoint
  * implementation never has to map exceptions to responses by hand, and a
  * failure raised deep in chain resolution surfaces with the code the
  * specification asks for rather than a generic 500.
  *
  * Internal failures — a malformed JWT, a signature that does not verify —
  * have no code of their own in the specification and report `server_error`,
  * which is what those endpoints are told to return for them.
  */
sealed abstract class FederationError(
    val code: String,
    val httpStatus: Int,
    val message: String
) extends RuntimeException(message)
    with NoStackTrace

object FederationError {

  // Codes defined for the federation endpoints (section 8.9).

  final case class InvalidRequest(detail: String)
      extends FederationError("invalid_request", 400, detail)

  final case class InvalidClient(detail: String)
      extends FederationError("invalid_client", 401, detail)

  final case class InvalidIssuer(issuer: EntityId)
      extends FederationError(
        "invalid_issuer",
        404,
        s"this endpoint does not serve statements issued by ${issuer.value}"
      )

  final case class InvalidSubject(subject: EntityId)
      extends FederationError(
        "invalid_subject",
        404,
        s"this endpoint does not serve statements about ${subject.value}"
      )

  final case class NotFound(subject: EntityId)
      extends FederationError("not_found", 404, s"no statement about ${subject.value}")

  final case class InvalidTrustAnchor(detail: String)
      extends FederationError("invalid_trust_anchor", 404, detail)

  final case class InvalidTrustChain(detail: String)
      extends FederationError("invalid_trust_chain", 400, detail)

  final case class InvalidMetadata(detail: String)
      extends FederationError("invalid_metadata", 400, detail)

  final case class UnsupportedParameter(detail: String)
      extends FederationError("unsupported_parameter", 400, detail)

  final case class TemporarilyUnavailable(detail: String)
      extends FederationError("temporarily_unavailable", 503, detail)

  // Internal failures, reported as server_error at an endpoint boundary.

  final case class MalformedJwt(detail: String) extends FederationError("server_error", 500, detail)

  final case class InvalidSignature(detail: String)
      extends FederationError("server_error", 500, detail)

  /** No key could be selected to verify a statement, or the selection was
    * ambiguous. `detail` says which, because "no such key" and "two keys with
    * that kid" point at very different misconfigurations.
    */
  final case class KeyNotFound(detail: String) extends FederationError("server_error", 500, detail)

  final case class Expired(detail: String) extends FederationError("server_error", 500, detail)

  /** A Trust Mark that did not validate under section 7.3.
    *
    * `server_error` because section 8.9 defines no code for it: at a resolve
    * endpoint an unverifiable mark is omitted from the response rather than
    * failing the request, so this surfaces as a diagnostic rather than as the
    * status a caller sees.
    */
  final case class InvalidTrustMark(detail: String)
      extends FederationError("server_error", 500, detail)

  final case class FetchFailed(detail: String, cause: Option[Throwable] = None)
      extends FederationError("server_error", 500, detail)

  /** A metadata policy that is malformed, self-contradictory, or violated by
    * the subject's metadata. Section 6.1.4 makes all three invalidate the Trust
    * Chain, and section 8.9 gives `invalid_metadata` for exactly that.
    */
  final case class PolicyViolation(detail: String)
      extends FederationError("invalid_metadata", 400, detail)
}
