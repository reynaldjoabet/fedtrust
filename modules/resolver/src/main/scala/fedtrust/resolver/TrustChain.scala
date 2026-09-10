package fedtrust.resolver

import java.time.Instant

import fedtrust.entity.EntityStatement
import fedtrust.error.FederationError
import fedtrust.jwk.JwkSet
import fedtrust.types.{*, given}

/** A validated trust chain, held in the order the spec defines: the subject's
  * own entity configuration first, then each subordinate statement walking up,
  * then the trust anchor's entity configuration last.
  *
  * The three parts are separate fields rather than one list because they are
  * never interchangeable — the ends are self-issued and the middle is not, and
  * every operation on a chain starts by distinguishing them.
  */
final case class TrustChain(
    subjectConfiguration: EntityStatement,
    subordinateStatements: List[EntityStatement],
    trustAnchorConfiguration: EntityStatement
) {

  def subject: EntityId = subjectConfiguration.sub

  def trustAnchor: EntityId = trustAnchorConfiguration.sub

  /** Number of subordinate statements between subject and anchor. */
  def pathLength: Int = subordinateStatements.length

  def statements: List[EntityStatement] =
    subjectConfiguration :: (subordinateStatements :+ trustAnchorConfiguration)

  /** The Subordinate Statements ordered most-superior first, which is the
    * order metadata policy resolution requires (spec section 6.1.4.1).
    *
    * `subordinateStatements` is stored the other way round — Immediate
    * Superior first — because that is the order a chain is built in and the
    * order `max_path_length` counts in. Policy is the one operation that needs
    * the reverse, so it gets a name of its own rather than a bare `.reverse`
    * at the call site.
    *
    * Every standard operator merges symmetrically, so the direction does not
    * change what a merged policy permits — a Subordinate is stopped from
    * widening its Superior's policy by the intersection and equality rules,
    * not by the order of the walk. What the order fixes is the ordering within
    * merged arrays, which section 6.1.1 requires to be deterministic.
    */
  def policyOrder: List[EntityStatement] = subordinateStatements.reverse

  /** The Subordinate Statement issued by the subject's Immediate Superior, if
    * the chain has one. Its `metadata` claim is applied before policy.
    */
  def immediateSuperiorStatement: Option[EntityStatement] = subordinateStatements.headOption

  /** The subject's keys as its Immediate Superior attests them.
    *
    * Deliberately not `subjectConfiguration.jwks`, which is only what the
    * subject says about itself. Section 4 makes the superior's attestation the
    * authoritative statement of an entity's keys, and chain building has
    * already verified the configuration against it. A chain with no
    * subordinate statements is the subject acting as its own Trust Anchor,
    * where its configuration is the root of trust by definition.
    */
  def attestedSubjectKeys: JwkSet =
    subordinateStatements.headOption.map(_.jwks).getOrElse(subjectConfiguration.jwks)

  /** A chain is only good until its shortest-lived statement expires. */
  def expiresAt: Instant = statements.map(_.exp).min

  def isExpiredAt(now: Instant): Boolean = !now.isBefore(expiresAt)
}

object TrustChain {

  /** Check the structural invariants: self-issued at both ends, and each
    * statement issued by the subject of the one above it.
    */
  def validated(
      subjectConfiguration: EntityStatement,
      subordinateStatements: List[EntityStatement],
      trustAnchorConfiguration: EntityStatement
  ): Either[FederationError, TrustChain] = {
    val chain = TrustChain(subjectConfiguration, subordinateStatements, trustAnchorConfiguration)

    def invalid(why: String) = Left(FederationError.InvalidTrustChain(why))

    if (!subjectConfiguration.isEntityConfiguration)
      invalid("the first statement must be the subject's own entity configuration")
    else if (!trustAnchorConfiguration.isEntityConfiguration)
      invalid("the last statement must be the trust anchor's own entity configuration")
    else if (subordinateStatements.exists(_.isEntityConfiguration))
      invalid("intermediate statements must be subordinate statements")
    else
      linkage(chain).map(_ => chain)
  }

  private def linkage(chain: TrustChain): Either[FederationError, Unit] = {
    val links = chain.statements.sliding(2).collect { case List(lower, upper) => (lower, upper) }

    links
      .collectFirst {
        case (lower, upper) if upper.sub != lower.iss =>
          FederationError.InvalidTrustChain(
            s"${upper.sub.value} does not issue statements for ${lower.iss.value}"
          )
      }
      .toLeft(())
  }
}
