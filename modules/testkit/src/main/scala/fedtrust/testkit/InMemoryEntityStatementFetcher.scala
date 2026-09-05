package fedtrust.testkit

import cats.ApplicativeThrow
import cats.syntax.all.*
import fedtrust.error.FederationError
import fedtrust.jwt.SignedJwt
import fedtrust.resolver.EntityStatementFetcher
import fedtrust.types.EntityId

/** An [[EntityStatementFetcher]] backed by maps.
  *
  * This is the reason the fetcher is an abstraction rather than an HTTP call:
  * chain resolution can be tested end to end, against real signatures, without
  * binding a port.
  */
final class InMemoryEntityStatementFetcher[F[_]](
    configurations: Map[EntityId, SignedJwt],
    subordinates: Map[(String, EntityId), SignedJwt]
)(using F: ApplicativeThrow[F])
    extends EntityStatementFetcher[F] {

  def entityConfiguration(entity: EntityId): F[SignedJwt] =
    configurations.get(entity).liftTo[F](FederationError.NotFound(entity))

  def subordinateStatement(fetchEndpoint: String, subject: EntityId): F[SignedJwt] =
    subordinates.get((fetchEndpoint, subject)).liftTo[F](FederationError.NotFound(subject))
}

object InMemoryEntityStatementFetcher {

  def apply[F[_]: ApplicativeThrow](
      configurations: Map[EntityId, SignedJwt] = Map.empty,
      subordinates: Map[(String, EntityId), SignedJwt] = Map.empty
  ): InMemoryEntityStatementFetcher[F] =
    new InMemoryEntityStatementFetcher[F](configurations, subordinates)
}
