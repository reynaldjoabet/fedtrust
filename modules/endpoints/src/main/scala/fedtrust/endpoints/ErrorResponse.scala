package fedtrust.endpoints

import fedtrust.error.FederationError
import io.circe.{Decoder, Encoder}

/** The error response every federation endpoint shares (spec section 8.9).
  *
  * `error_description` is REQUIRED, so this cannot be constructed without one.
  */
final case class ErrorResponse(error: String, errorDescription: String)

object ErrorResponse {

  /** Every [[FederationError]] already carries the code and status the
    * specification assigns it, so an endpoint turns a failure into a response
    * without a mapping table of its own.
    */
  def from(error: FederationError): (Int, ErrorResponse) =
    (error.httpStatus, ErrorResponse(error.code, error.message))

  given Encoder[ErrorResponse] =
    Encoder.forProduct2("error", "error_description")(r => (r.error, r.errorDescription))

  given Decoder[ErrorResponse] =
    Decoder.forProduct2("error", "error_description")(ErrorResponse.apply)
}
