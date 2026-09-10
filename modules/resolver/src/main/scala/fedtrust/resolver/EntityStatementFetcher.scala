package fedtrust.resolver

import fedtrust.jwt.SignedJwt
import fedtrust.types.{*, given}

/** How the resolver reaches the network.
  *
  * The abstraction that keeps this module free of any HTTP client: backends
  * (`fedtrust-http4s`, and whatever else) implement it, `fedtrust-testkit`
  * implements it over a map, and chain resolution is written against it.
  *
  * Implementations return the compact JWS untouched. Verification is the
  * resolver's job, and it needs the exact bytes that were signed.
  */
trait EntityStatementFetcher[F[_]] {

  /** GET `{entity}/.well-known/openid-federation`. */
  def entityConfiguration(entity: EntityId): F[SignedJwt]

  /** GET `{fetchEndpoint}?sub={subject}` on a superior's fetch endpoint. */
  def subordinateStatement(fetchEndpoint: String, subject: EntityId): F[SignedJwt]
}
