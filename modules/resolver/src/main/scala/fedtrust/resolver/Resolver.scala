package fedtrust.resolver

import java.time.Instant

import cats.MonadThrow
import cats.syntax.all.*
import fedtrust.entity.TrustMarkEntry
import fedtrust.error.FederationError
import fedtrust.metadata.Metadata
import fedtrust.resolver.policy.MetadataPolicyEngine
import fedtrust.types.{*, given}

/** What a caller actually wanted when it asked about an entity: the metadata
  * that survived the federation's policies, the Trust Marks that verified, and
  * the chain that justifies both.
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

/** Trust Chain resolution end to end: build the chain, derive the subject's
  * Resolved Metadata from it, and verify the Trust Marks it carries.
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

  /** The full resolver: metadata and verified Trust Marks.
    *
    * Section 8.3 requires a resolver to verify the marks it returns, so a
    * validator is not optional decoration — without one there is nothing
    * honest to put in `trustMarks`, which is why the alternative constructor
    * below returns an empty list rather than an unverified one.
    */
  def apply[F[_]: MonadThrow](
      chains: TrustChainResolver[F],
      trustMarks: TrustMarkValidator[F]
  ): Resolver[F] =
    new Resolver[F] {
      def resolve(subject: EntityId, trustAnchor: EntityId): F[ResolvedEntity] =
        for {
          chain    <- chains.resolve(subject, trustAnchor)
          metadata <- resolvedMetadata(chain).liftTo[F]
          verified <- trustMarks.validateAll(
            chain.subjectConfiguration,
            chain.trustAnchorConfiguration
          )
        } yield resolved(chain, metadata, verified)
    }

  /** Resolution without Trust Mark validation.
    *
    * `ResolvedEntity.trustMarks` is always empty here, and that is the point:
    * section 8.3 says the response set "MUST include only verified Trust
    * Marks", so a resolver that cannot verify them must return none rather
    * than pass along claims it has not checked. Use this when the caller only
    * wants metadata.
    */
  def withoutTrustMarks[F[_]: MonadThrow](chains: TrustChainResolver[F]): Resolver[F] =
    new Resolver[F] {
      def resolve(subject: EntityId, trustAnchor: EntityId): F[ResolvedEntity] =
        for {
          chain    <- chains.resolve(subject, trustAnchor)
          metadata <- resolvedMetadata(chain).liftTo[F]
        } yield resolved(chain, metadata, Nil)
    }

  private def resolved(
      chain: TrustChain,
      metadata: Metadata,
      trustMarks: List[TrustMarkEntry]
  ): ResolvedEntity =
    ResolvedEntity(
      subject = chain.subject,
      trustAnchor = chain.trustAnchor,
      metadata = metadata,
      trustMarks = trustMarks,
      expiresAt = chain.expiresAt,
      chain = chain
    )

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
}
