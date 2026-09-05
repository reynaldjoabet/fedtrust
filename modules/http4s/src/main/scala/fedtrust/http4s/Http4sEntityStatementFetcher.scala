package fedtrust.http4s

import cats.effect.Concurrent
import cats.syntax.all.*
import fedtrust.error.FederationError
import fedtrust.jwt.SignedJwt
import fedtrust.resolver.EntityStatementFetcher
import fedtrust.types.EntityId
import org.http4s.client.Client
import org.http4s.{Method, Request, Uri}

/** An [[EntityStatementFetcher]] over an http4s `Client`.
  *
  * Takes a `Client` rather than building one: connection pooling, timeouts,
  * TLS and retries are the caller's to configure, and a federation resolver is
  * the wrong place to make those decisions on their behalf.
  */
final class Http4sEntityStatementFetcher[F[_]](client: Client[F])(using F: Concurrent[F])
    extends EntityStatementFetcher[F] {

  def entityConfiguration(entity: EntityId): F[SignedJwt] =
    uri(entity.wellKnownUri).flatMap(get)

  def subordinateStatement(fetchEndpoint: String, subject: EntityId): F[SignedJwt] =
    uri(fetchEndpoint).map(_.withQueryParam("sub", subject.value)).flatMap(get)

  /** The body is returned verbatim. It is a compact JWS whose signature covers
    * those exact bytes, so nothing here may normalise it beyond trimming the
    * whitespace a server may pad the response with.
    */
  private def get(target: Uri): F[SignedJwt] =
    client.run(Request[F](Method.GET, target)).use { response =>
      response.bodyText.compile.string.flatMap { body =>
        if (response.status.isSuccess) SignedJwt(body.trim).pure[F]
        else
          F.raiseError(
            FederationError.FetchFailed(s"$target responded ${response.status.code}")
          )
      }
    }

  private def uri(raw: String): F[Uri] =
    Uri
      .fromString(raw)
      .leftMap(e => FederationError.InvalidRequest(s"not a usable URL: $raw (${e.message})"))
      .liftTo[F]
}

object Http4sEntityStatementFetcher {
  def apply[F[_]: Concurrent](client: Client[F]): EntityStatementFetcher[F] =
    new Http4sEntityStatementFetcher[F](client)
}
