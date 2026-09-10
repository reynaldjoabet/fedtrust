package fedtrust.resolver

import cats.MonadThrow
import cats.syntax.all.*
import fedtrust.entity.EntityStatement
import fedtrust.error.FederationError
import fedtrust.metadata.FederationEntityMetadata
import fedtrust.types.{*, given}
import io.github.iltotore.iron.*

/** Builds Trust Chains from a subject up to a Trust Anchor (spec section 4).
  *
  * The walk is upwards through `authority_hints`, verifying as it goes: each
  * Subordinate Statement is checked against the keys in the Entity
  * Configuration of the Superior that issued it, and every Entity
  * Configuration is checked against its own `jwks`. A chain is only returned
  * once its structure and constraints have been validated as well.
  */
trait TrustChainResolver[F[_]] {

  /** The shortest valid chain from `subject` to `trustAnchor`. */
  def resolve(subject: EntityId, trustAnchor: EntityId): F[TrustChain]

  /** Every valid chain from `subject` to any of `trustAnchors`, shortest
    * first.
    *
    * More than one is normal: an entity can reach the same anchor by several
    * routes, and a chain that is valid today may be the only one left when a
    * branch's statements expire.
    */
  def resolveAll(subject: EntityId, trustAnchors: Set[EntityId]): F[List[TrustChain]]
}

object TrustChainResolver {

  /** A hostile or misconfigured federation must not be able to make the walk
    * run away. `authority_hints` form an arbitrary graph, and nothing in the
    * protocol bounds its depth.
    */
  final case class Limits(maxPathLength: SearchDepth = 8)

  def apply[F[_]: MonadThrow](
      fetcher: EntityStatementFetcher[F],
      statements: StatementVerifier[F],
      limits: Limits = Limits()
  ): TrustChainResolver[F] =
    new DefaultTrustChainResolver[F](fetcher, statements, limits)
}

private final class DefaultTrustChainResolver[F[_]](
    fetcher: EntityStatementFetcher[F],
    statements: StatementVerifier[F],
    limits: TrustChainResolver.Limits
)(using F: MonadThrow[F])
    extends TrustChainResolver[F] {

  /** Subordinate Statements ordered Immediate-Superior first, paired with the
    * Entity Configuration of the anchor the branch reached.
    */
  private type Branch = (List[EntityStatement], EntityStatement)

  def resolve(subject: EntityId, trustAnchor: EntityId): F[TrustChain] =
    chains(subject, Set(trustAnchor)).flatMap { case (failures, valid) =>
      valid.headOption match {
        case Some(chain) => chain.pure[F]
        case None        =>
          F.raiseError(
            failures.headOption.getOrElse(
              FederationError.InvalidTrustChain(
                s"no trust chain from ${subject.value} to ${trustAnchor.value}"
              )
            )
          )
      }
    }

  def resolveAll(subject: EntityId, trustAnchors: Set[EntityId]): F[List[TrustChain]] =
    chains(subject, trustAnchors).map(_._2)

  private def chains(
      subject: EntityId,
      trustAnchors: Set[EntityId]
  ): F[(List[FederationError], List[TrustChain])] =
    if (trustAnchors.isEmpty)
      F.raiseError(FederationError.InvalidTrustAnchor("no trust anchors were given"))
    else
      for {
        signed    <- fetcher.entityConfiguration(subject)
        subjectEc <- statements.verifySelfIssued(signed, subject)
        branches  <- search(subjectEc, trustAnchors, depth = 0, visited = Set(subject))
        // An entity can be its own anchor: the chain is then just its
        // configuration, which section 4 still treats as a valid chain.
        trivial = if (trustAnchors.contains(subject)) List((List.empty, subjectEc)) else Nil
        built <- (trivial ++ branches).traverse { case (subordinates, anchorEc) =>
          build(signed, subjectEc, subordinates, anchorEc)
        }
      } yield {
        val (failures, valid) = built.partitionMap(identity)
        (failures, valid.sortBy(_.pathLength))
      }

  private def search(
      current: EntityStatement,
      anchors: Set[EntityId],
      depth: Int,
      visited: Set[EntityId]
  ): F[List[Branch]] =
    if (depth >= limits.maxPathLength) List.empty[Branch].pure[F]
    else
      current.hints.filterNot(visited.contains).distinct.flatTraverse { hint =>
        // One unreachable or misbehaving Superior must not sink the whole
        // search: other hints may still lead to the anchor.
        branchesVia(current, hint, anchors, depth, visited).handleError(_ => Nil)
      }

  private def branchesVia(
      current: EntityStatement,
      hint: EntityId,
      anchors: Set[EntityId],
      depth: Int,
      visited: Set[EntityId]
  ): F[List[Branch]] =
    for {
      signedConfiguration <- fetcher.entityConfiguration(hint)
      superiorEc          <- statements.verifySelfIssued(signedConfiguration, hint)
      endpoint            <- fetchEndpointOf(superiorEc)
      signedSubordinate   <- fetcher.subordinateStatement(endpoint, current.sub)

      // A Trust Anchor may itself have Superiors (section 4.1), so reaching one
      // ends a chain without ending the search.
      //
      // When the hint is an anchor, the statement it issued is verified against
      // the keys in its own Entity Configuration, because section 4 makes the
      // anchor's configuration the end of the chain and the root of trust.
      here <-
        if (anchors.contains(hint))
          accept(signedSubordinate, superiorEc.jwks, current, hint)
            .map(subordinate => List((List(subordinate), superiorEc)))
        else List.empty[Branch].pure[F]

      above <- search(superiorEc, anchors, depth + 1, visited + hint)

      // Section 4: ES[j] is signed by a key in ES[j+1]["jwks"] - the keys the
      // Superior's own Superior attests, not the ones it publishes about
      // itself. Verifying against its self-issued configuration instead would
      // let an Intermediate introduce a key its Superior never vouched for and
      // sign whatever it liked with it.
      nested <- above.traverse { case (subordinates, anchorEc) =>
        accept(signedSubordinate, subordinates.head.jwks, current, hint)
          .map(subordinate => (subordinate :: subordinates, anchorEc))
      }
    } yield here ++ nested

  private def accept(
      signed: fedtrust.jwt.SignedJwt,
      keys: fedtrust.jwk.JwkSet,
      current: EntityStatement,
      issuer: EntityId
  ): F[EntityStatement] =
    statements.verify(signed, keys, Some(current.sub)).flatTap { subordinate =>
      F.raiseUnless(subordinate.iss == issuer)(
        FederationError.InvalidTrustChain(
          s"${issuer.value} served a statement issued by ${subordinate.iss.value}"
        )
      )
    }

  private def fetchEndpointOf(configuration: EntityStatement): F[String] =
    FederationEntityMetadata
      .from(configuration.metadataOrEmpty)
      .liftTo[F]
      .flatMap { federationEntity =>
        federationEntity
          .flatMap(_.federationFetchEndpoint)
          .liftTo[F](
            FederationError.InvalidMetadata(
              s"${configuration.sub.value} publishes no federation_fetch_endpoint"
            )
          )
      }

  /** The subject's Entity Configuration is self-signed, but section 4 also
    * requires it to verify under `ES[1]["jwks"]` — the keys its Immediate
    * Superior attests. That second check is what binds the subject to the
    * federation; without it, any entity could publish a configuration naming a
    * Trust Anchor in `authority_hints` and appear to belong to it.
    */
  private def build(
      signedSubject: fedtrust.jwt.SignedJwt,
      subjectEc: EntityStatement,
      subordinates: List[EntityStatement],
      anchorEc: EntityStatement
  ): F[Either[FederationError, TrustChain]] = {
    val structure = TrustChain
      .validated(subjectEc, subordinates, anchorEc)
      .flatMap(chain => ConstraintChecker.check(chain).map(_ => chain))

    subordinates.headOption match {
      case None              => structure.pure[F]
      case Some(attestation) =>
        statements
          .verify(signedSubject, attestation.jwks, Some(subjectEc.sub))
          .attempt
          .map {
            case Right(_)                     => structure
            case Left(error: FederationError) => Left(error)
            case Left(error)                  =>
              Left(FederationError.InvalidTrustChain(error.getMessage))
          }
    }
  }
}
