package fedtrust.resolver

import java.time.Instant

import cats.MonadThrow
import cats.syntax.all.*
import fedtrust.entity.TrustMarkEntry
import fedtrust.error.FederationError
import fedtrust.metadata.Metadata
import fedtrust.resolver.policy.MetadataPolicyEngine
import fedtrust.types.EntityId

/** What a caller actually wanted when it asked about an entity: the metadata
  * that survived the federation's policies, and the chain that justifies it.
  *
  * This is the payload of a resolve response (spec section 8.3.2).
  */
final case class ResolvedEntity(
    subject: EntityId,
    trustAnchor: EntityId,
    metadata: Metadata,
    trustMarks: List[TrustMarkEntry],
    expiresAt: Instant,
    chain: TrustChain
)

/** Trust Chain resolution end to end: build the chain, then derive the
  * subject's Resolved Metadata from it.
  *
  * Kept separate from [[TrustChainResolver]] because they answer different
  * questions. Building a chain establishes that an entity belongs to a
  * federation; resolving says what the federation permits it to be. Callers
  * doing their own policy handling want the first alone.
  */
trait Resolver[F[_]] {
  def resolve(subject: EntityId, trustAnchor: EntityId): F[ResolvedEntity]
}

object Resolver {

  def apply[F[_]: MonadThrow](chains: TrustChainResolver[F]): Resolver[F] =
    new Resolver[F] {
      def resolve(subject: EntityId, trustAnchor: EntityId): F[ResolvedEntity] =
        chains.resolve(subject, trustAnchor).flatMap(from(_).liftTo[F])
    }

  /** Section 6.1.4.2, in the order the spec fixes.
    *
    * The order is not incidental. The Immediate Superior's `metadata` claim is
    * applied first so that policy sees the values the federation will actually
    * publish; `allowed_entity_types` is applied next, before policy, so that a
    * policy for a type the subject is not permitted to play cannot fail a
    * chain that is otherwise sound.
    */
  def resolvedMetadata(chain: TrustChain): Either[FederationError, Metadata] = {
    val fromSuperior = chain.immediateSuperiorStatement.flatMap(_.metadata)

    val declared = fromSuperior.foldLeft(chain.subjectConfiguration.metadataOrEmpty) {
      (own, supplied) => own.overriddenBy(supplied)
    }

    val permitted = ConstraintChecker.restrictMetadata(chain, declared)

    for {
      policy   <- MetadataPolicyEngine.resolve(chain.policyOrder)
      resolved <- MetadataPolicyEngine.applyTo(policy, permitted)
    } yield resolved
  }

  def from(chain: TrustChain): Either[FederationError, ResolvedEntity] =
    resolvedMetadata(chain).map { metadata =>
      ResolvedEntity(
        subject = chain.subject,
        trustAnchor = chain.trustAnchor,
        metadata = metadata,
        trustMarks = chain.subjectConfiguration.trustMarks.getOrElse(Nil),
        expiresAt = chain.expiresAt,
        chain = chain
      )
    }
}
