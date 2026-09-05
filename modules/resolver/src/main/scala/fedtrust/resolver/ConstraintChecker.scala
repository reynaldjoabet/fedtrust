package fedtrust.resolver

import fedtrust.entity.{Constraints, EntityStatement, NamingConstraints}
import fedtrust.error.FederationError
import fedtrust.metadata.Metadata
import fedtrust.types.EntityId

import java.net.URI

/** The `constraints` claim of each Subordinate Statement (spec section 6.2).
  *
  * Every statement's constraints are applied independently, and each one binds
  * only the entities below its issuer in the chain — a Trust Anchor's
  * `max_path_length` of 2 says nothing about how deep some other branch of the
  * federation goes.
  */
object ConstraintChecker {

  /** `max_path_length` and `naming_constraints`. `allowed_entity_types` is not
    * a check but a metadata filter, so it is handled by [[restrictMetadata]].
    */
  def check(chain: TrustChain): Either[FederationError, Unit] = {
    val subordinates = chain.subordinateStatements

    subordinates.zipWithIndex.foldLeft[Either[FederationError, Unit]](Right(())) {
      case (acc, (statement, index)) =>
        for {
          _ <- acc
          constraints = statement.constraints.getOrElse(Constraints.empty)
          _ <- checkPathLength(statement, constraints, index)
          _ <- checkNaming(statement, constraints, subordinates.take(index + 1).map(_.sub))
        } yield ()
    }
  }

  /** Section 6.2.3. Applied after the Immediate Superior's `metadata` claim and
    * before metadata policy. Applying each statement's constraint in turn
    * yields the intersection, which is what nesting them means.
    */
  def restrictMetadata(chain: TrustChain, metadata: Metadata): Metadata =
    chain.subordinateStatements.foldLeft(metadata) { (acc, statement) =>
      acc.restrictedTo(statement.constraints.flatMap(_.allowedEntityTypes))
    }

  /** `index` is the statement's distance from the subject, counting from zero
    * at the Immediate Superior — which is exactly the number of Intermediates
    * between this statement's issuer and the chain subject.
    */
  private def checkPathLength(
      statement: EntityStatement,
      constraints: Constraints,
      index: Int
  ): Either[FederationError, Unit] =
    constraints.maxPathLength match {
      case None                         => Right(())
      case Some(maximum) if maximum < 0 =>
        Left(
          FederationError.InvalidTrustChain(
            s"${statement.iss.value} set a negative max_path_length"
          )
        )
      case Some(maximum) =>
        Either.cond(
          index <= maximum,
          (),
          FederationError.InvalidTrustChain(
            s"${statement.iss.value} allows at most $maximum intermediates " +
              s"between itself and the subject, but the chain has $index"
          )
        )
    }

  private def checkNaming(
      statement: EntityStatement,
      constraints: Constraints,
      subordinates: List[EntityId]
  ): Either[FederationError, Unit] =
    constraints.namingConstraints match {
      case None         => Right(())
      case Some(naming) =>
        subordinates.foldLeft[Either[FederationError, Unit]](Right(())) { (acc, entity) =>
          for {
            _    <- acc
            host <- hostOf(entity)
            _    <- Either.cond(
              permits(naming, host),
              (),
              FederationError.InvalidTrustChain(
                s"${entity.value} is outside the naming constraints set by ${statement.iss.value}"
              )
            )
          } yield ()
        }
    }

  private def hostOf(entity: EntityId): Either[FederationError, String] =
    Option(new URI(entity.value).getHost)
      .toRight(FederationError.InvalidTrustChain(s"${entity.value} has no host component"))

  private def permits(naming: NamingConstraints, host: String): Boolean = {
    val excluded  = naming.excluded.getOrElse(Nil)
    val permitted = naming.permitted.getOrElse(Nil)

    // Section 6.2.2: an excluded match is fatal regardless of the permitted list.
    if (excluded.exists(matches(_, host))) false
    else permitted.isEmpty || permitted.exists(matches(_, host))
  }

  /** RFC 5280 section 4.2.1.10 domain matching, as section 6.2.2 requires: a
    * leading period means "any subdomain of", without matching the bare domain
    * itself; otherwise the constraint names one host exactly.
    */
  private def matches(constraint: String, host: String): Boolean = {
    val c = constraint.toLowerCase
    val h = host.toLowerCase

    if (c.startsWith(".")) h.endsWith(c) && h.length > c.length
    else h == c
  }
}
