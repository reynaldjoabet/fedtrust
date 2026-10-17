package fedtrust.resolver

import cats.MonadThrow
import cats.syntax.all.*
import fedtrust.entity.EntityStatement
import fedtrust.error.FederationError
import fedtrust.jwk.JwkSet
import fedtrust.jwt.SignedJwt
import fedtrust.metadata.FederationEntityMetadata
import fedtrust.types.{*, given}
import io.github.iltotore.iron.*
import io.github.iltotore.iron.constraint.numeric.Positive

/** Builds Trust Chains from a subject up to a Trust Anchor (spec sections 4
  * and 10).
  *
  * The walk is upwards through `authority_hints`, verifying as it goes:
  * every statement is checked against the keys of the statement above it, and
  * the anchor's own Entity Configuration is checked against the keys the
  * caller pinned for that anchor out of band. A chain is only returned once its
  * structure and constraints have been validated as well.
  */
trait TrustChainResolver[F[_]] {

  /** The shortest valid chain from `subject` to `trustAnchor`. */
  def resolve(subject: EntityId, trustAnchor: TrustAnchor): F[TrustChain]

  /** Every valid chain from `subject` to any of `trustAnchors`, shortest
    * first.
    *
    * More than one is normal: an entity can reach the same anchor by several
    * routes, and a chain that is valid today may be the only one left when a
    * branch's statements expire. Section 10.3 leaves the choice between them to
    * local policy; shortest first is the rule it suggests.
    */
  def resolveAll(subject: EntityId, trustAnchors: List[TrustAnchor]): F[List[TrustChain]]
}

object TrustChainResolver {

  /** A hostile or misconfigured federation must not be able to make the walk
    * run away. `authority_hints` form an arbitrary graph, and nothing in the
    * protocol bounds its depth.
    */
  final case class Limits(maxPathLength: SearchDepth = Limits.DefaultMaxPathLength)

  object Limits {

    /** `assume` rather than letting the literal auto-refine: 8 is plainly
      * positive, and Metals' presentation compiler cannot discard iron's union
      * and intersection constraint givens for `Positive`, so it reports the
      * auto-refined literal as ambiguous even though sbt compiles it.
      */
    val DefaultMaxPathLength: SearchDepth = 8.assume[Positive]
  }

  def apply[F[_]: MonadThrow](
      fetcher: EntityStatementFetcher[F],
      statements: StatementVerifier[F],
      limits: Limits = Limits()
  ): TrustChainResolver[F] =
    new DefaultTrustChainResolver[F](fetcher, statements, limits)
}

/** A statement that has passed verification, kept beside the compact JWS it
  * was decoded from so the finished chain can carry its evidence.
  */
private[resolver] final case class Verified(statement: EntityStatement, signed: SignedJwt)

private final class DefaultTrustChainResolver[F[_]](
    fetcher: EntityStatementFetcher[F],
    statements: StatementVerifier[F],
    limits: TrustChainResolver.Limits
)(using F: MonadThrow[F])
    extends TrustChainResolver[F] {

  /** Subordinate Statements ordered Immediate-Superior first, paired with the
    * Entity Configuration of the anchor the branch reached.
    */
  private type Branch = (List[Verified], Verified)

  def resolve(subject: EntityId, trustAnchor: TrustAnchor): F[TrustChain] =
    chains(subject, List(trustAnchor)).flatMap { case (failures, valid) =>
      valid.headOption match {
        case Some(chain) => chain.pure[F]
        case None        =>
          F.raiseError(
            failures.headOption.getOrElse(
              FederationError.InvalidTrustChain(
                s"no trust chain from ${subject.value} to ${trustAnchor.id.value}"
              )
            )
          )
      }
    }

  def resolveAll(subject: EntityId, trustAnchors: List[TrustAnchor]): F[List[TrustChain]] =
    chains(subject, trustAnchors).map(_._2)

  private def chains(
      subject: EntityId,
      trustAnchors: List[TrustAnchor]
  ): F[(List[FederationError], List[TrustChain])] =
    if (trustAnchors.isEmpty)
      F.raiseError(FederationError.InvalidTrustAnchor("no trust anchors were given"))
    else {
      val anchors = trustAnchors.map(anchor => anchor.id -> anchor).toMap

      for {
        signed    <- fetcher.entityConfiguration(subject)
        subjectEc <- statements.verifySelfIssued(signed, subject)
        branches  <- search(subjectEc, anchors, depth = 0, visited = Set(subject))
        trivial   <- trivialChain(signed, subject, anchors)
        built     <- branches.traverse { case (subordinates, anchorEc) =>
          build(Verified(subjectEc, signed), subordinates, anchorEc)
        }
      } yield {
        val (failures, valid) = (trivial.toList ++ built).partitionMap(identity)
        (failures, valid.sortBy(_.pathLength))
      }
    }

  /** An entity can be its own anchor: the chain is then just its
    * configuration, which section 4 still treats as a valid chain. It must
    * verify under the pinned keys like any other anchor configuration — being
    * self-signed proves nothing on its own.
    */
  private def trivialChain(
      signed: SignedJwt,
      subject: EntityId,
      anchors: Map[EntityId, TrustAnchor]
  ): F[Option[Either[FederationError, TrustChain]]] =
    anchors.get(subject) match {
      case None         => none[Either[FederationError, TrustChain]].pure[F]
      case Some(anchor) =>
        verifyAnchorConfiguration(signed, anchor).attempt.map { result =>
          Some(
            result.leftMap(asFederationError).flatMap { configuration =>
              TrustChain.validated(configuration, Nil, configuration, List(signed))
            }
          )
        }
    }

  private def search(
      current: EntityStatement,
      anchors: Map[EntityId, TrustAnchor],
      depth: Int,
      visited: Set[EntityId]
  ): F[List[Branch]] =
    if (depth >= limits.maxPathLength) List.empty[Branch].pure[F]
    else
      // Section 10.1: an entity already visited is not fetched again, which is
      // what stops a cycle in authority_hints from looping.
      current.hints.filterNot(visited.contains).distinct.flatTraverse { hint =>
        // One unreachable or misbehaving Superior must not sink the whole
        // search: other hints may still lead to an anchor.
        branchesVia(current, hint, anchors, depth, visited).handleError(_ => Nil)
      }

  private def branchesVia(
      current: EntityStatement,
      hint: EntityId,
      anchors: Map[EntityId, TrustAnchor],
      depth: Int,
      visited: Set[EntityId]
  ): F[List[Branch]] =
    for {
      signedConfiguration <- fetcher.entityConfiguration(hint)
      superiorEc          <- statements.verifySelfIssued(signedConfiguration, hint)
      endpoint            <- fetchEndpointOf(superiorEc)
      signedSubordinate   <- fetcher.subordinateStatement(endpoint, current.sub)

      // When the hint is one of the caller's anchors, the chain can end here.
      // Its configuration must verify under the pinned keys (section 10.2);
      // once it has, its own jwks are authoritative for the statement it
      // issued about `current`. Failing this ends only this route — a Trust
      // Anchor may itself have Superiors (section 4.1), so the search
      // continues above it either way.
      here <- anchors.get(hint) match {
        case None         => List.empty[Branch].pure[F]
        case Some(anchor) =>
          (for {
            anchorEc    <- verifyAnchorConfiguration(signedConfiguration, anchor)
            subordinate <- accept(signedSubordinate, anchorEc.jwks, current, hint)
          } yield List(
            (
              List(Verified(subordinate, signedSubordinate)),
              Verified(anchorEc, signedConfiguration)
            )
          )).handleError(_ => Nil)
      }

      above <- search(superiorEc, anchors, depth + 1, visited + hint)

      // Section 10.2: ES[j] is signed by a key in ES[j+1]["jwks"] - the keys
      // the Superior's own Superior attests, not the ones it publishes about
      // itself. Verifying against its self-issued configuration instead would
      // let an Intermediate introduce a key its Superior never vouched for and
      // sign whatever it liked with it.
      nested <- above.traverse { case (subordinates, anchorEc) =>
        accept(signedSubordinate, subordinates.head.statement.jwks, current, hint)
          .map(subordinate => (Verified(subordinate, signedSubordinate) :: subordinates, anchorEc))
      }
    } yield here ++ nested

  /** Section 10.2: "For ES[i] (the Trust Anchor's Entity Configuration),
    * verify that the issuer matches the Entity Identifier of the Trust Anchor"
    * and "that its signature validates with a public key of the Trust Anchor".
    */
  private def verifyAnchorConfiguration(
      signed: SignedJwt,
      anchor: TrustAnchor
  ): F[EntityStatement] =
    statements.verify(signed, anchor.jwks, Some(anchor.id)).flatTap { configuration =>
      F.raiseUnless(configuration.iss == anchor.id && configuration.isEntityConfiguration)(
        FederationError.InvalidTrustAnchor(
          s"${anchor.id.value} served a configuration issued by ${configuration.iss.value}"
        )
      )
    }

  private def accept(
      signed: SignedJwt,
      keys: JwkSet,
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

  /** The subject's Entity Configuration is self-signed, but section 10.2 also
    * requires it to verify under `ES[1]["jwks"]` — the keys its Immediate
    * Superior attests. That second check is what binds the subject to the
    * federation; without it, any entity could publish a configuration naming a
    * Trust Anchor in `authority_hints` and appear to belong to it.
    */
  private def build(
      subject: Verified,
      subordinates: List[Verified],
      anchorEc: Verified
  ): F[Either[FederationError, TrustChain]] = {
    val structure = TrustChain
      .validated(
        subject.statement,
        subordinates.map(_.statement),
        anchorEc.statement,
        (subject.signed :: subordinates.map(_.signed)) :+ anchorEc.signed
      )
      .flatMap(chain => ConstraintChecker.check(chain).map(_ => chain))

    subordinates.headOption match {
      case None              => structure.pure[F]
      case Some(attestation) =>
        statements
          .verify(subject.signed, attestation.statement.jwks, Some(subject.statement.sub))
          .attempt
          .map(_.leftMap(asFederationError).flatMap(_ => structure))
    }
  }

  private def asFederationError(error: Throwable): FederationError =
    error match {
      case federation: FederationError => federation
      case other                       => FederationError.InvalidTrustChain(other.getMessage)
    }
}
