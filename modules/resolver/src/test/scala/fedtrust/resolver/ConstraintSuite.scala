package fedtrust.resolver

import fedtrust.entity.{Constraints, NamingConstraints}
import fedtrust.types.EntityType
import munit.FunSuite

/** Constraints from spec section 6.2, including the worked `max_path_length`
  * cases the specification itself lists in 6.2.1.
  */
class ConstraintSuite extends FunSuite {

  import Fixtures.*

  private val leaf        = "https://le.example.com"
  private val first       = "https://i1.example.com"
  private val second      = "https://i2.example.com"
  private val trustAnchor = "https://ta.example.com"

  /** The chain from section 6.2.1: LE, then I1's statement about LE, I2's about
    * I1, and the Trust Anchor's about I2.
    */
  private def chain(
      byFirst: Option[Constraints] = None,
      bySecond: Option[Constraints] = None,
      byAnchor: Option[Constraints] = None
  ) = TrustChain(
    subjectConfiguration = statement(leaf, leaf),
    subordinateStatements = List(
      statement(first, leaf, constraints = byFirst),
      statement(second, first, constraints = bySecond),
      statement(trustAnchor, second, constraints = byAnchor)
    ),
    trustAnchorConfiguration = statement(trustAnchor, trustAnchor)
  )

  private def pathLength(n: Int) = Some(Constraints.empty.copy(maxPathLength = Some(n)))

  test("the chain is well formed to begin with") {
    assertEquals(ConstraintChecker.check(chain()), Right(()))
  }

  test("6.2.1: a Trust Anchor max_path_length of 2 or more is satisfied") {
    assertEquals(ConstraintChecker.check(chain(byAnchor = pathLength(2))), Right(()))
    assertEquals(ConstraintChecker.check(chain(byAnchor = pathLength(3))), Right(()))
  }

  test("6.2.1: a Trust Anchor max_path_length of 1 is not satisfied") {
    assert(ConstraintChecker.check(chain(byAnchor = pathLength(1))).isLeft)
  }

  test("6.2.1: TA 2, I2 1, I1 omitted is satisfied") {
    assertEquals(
      ConstraintChecker.check(chain(bySecond = pathLength(1), byAnchor = pathLength(2))),
      Right(())
    )
  }

  test("6.2.1: I1 alone with max_path_length 0 is satisfied") {
    assertEquals(ConstraintChecker.check(chain(byFirst = pathLength(0))), Right(()))
  }

  test("each constraint binds only the entities below its own issuer") {
    // I2 permits no intermediates below it, but I1 sits between I2 and the leaf.
    assert(ConstraintChecker.check(chain(bySecond = pathLength(0))).isLeft)
  }

  private def naming(permitted: List[String] = Nil, excluded: List[String] = Nil) =
    Some(
      Constraints.empty.copy(namingConstraints =
        Some(
          NamingConstraints(
            permitted = Option.when(permitted.nonEmpty)(permitted),
            excluded = Option.when(excluded.nonEmpty)(excluded)
          )
        )
      )
    )

  test("a leading period matches subdomains but not the bare domain") {
    assertEquals(
      ConstraintChecker.check(chain(byAnchor = naming(permitted = List(".example.com")))),
      Right(())
    )

    val bare = TrustChain(
      subjectConfiguration = statement("https://example.com", "https://example.com"),
      subordinateStatements = List(
        statement(
          trustAnchor,
          "https://example.com",
          constraints = naming(permitted = List(".example.com"))
        )
      ),
      trustAnchorConfiguration = statement(trustAnchor, trustAnchor)
    )

    assert(
      ConstraintChecker.check(bare).isLeft,
      "'.example.com' must not be satisfied by 'example.com' itself"
    )
  }

  test("a constraint without a leading period names one host exactly") {
    assertEquals(
      ConstraintChecker.check(
        chain(byFirst = naming(permitted = List("le.example.com")))
      ),
      Right(())
    )

    assert(ConstraintChecker.check(chain(byFirst = naming(permitted = List("example.com")))).isLeft)
  }

  test("an excluded match is fatal regardless of the permitted list") {
    assert(
      ConstraintChecker
        .check(
          chain(byAnchor =
            naming(permitted = List(".example.com"), excluded = List("i1.example.com"))
          )
        )
        .isLeft
    )
  }

  test("allowed_entity_types filters metadata and never removes federation_entity") {
    val declared = metadata("""
      {
        "federation_entity": { "organization_name": "Example" },
        "openid_relying_party": { "redirect_uris": [] },
        "openid_provider": { "issuer": "https://le.example.com" }
      }
    """)

    val restricted = ConstraintChecker.restrictMetadata(
      chain(byAnchor =
        Some(
          Constraints.empty.copy(allowedEntityTypes = Some(List(EntityType.OpenIdRelyingParty)))
        )
      ),
      declared
    )

    assertEquals(
      restricted.entityTypes,
      Set(EntityType.FederationEntity, EntityType.OpenIdRelyingParty)
    )
  }

  test("nested allowed_entity_types constraints intersect") {
    val declared = metadata("""
      {
        "openid_relying_party": {},
        "openid_provider": {}
      }
    """)

    val restricted = ConstraintChecker.restrictMetadata(
      chain(
        byFirst =
          Some(Constraints.empty.copy(allowedEntityTypes = Some(List(EntityType.OpenIdProvider)))),
        byAnchor = Some(
          Constraints.empty.copy(allowedEntityTypes = Some(List(EntityType.OpenIdRelyingParty)))
        )
      ),
      declared
    )

    assertEquals(restricted.entityTypes, Set.empty)
  }

  test("an empty allowed_entity_types permits only federation_entity") {
    val declared = metadata("""
      { "federation_entity": {}, "openid_relying_party": {} }
    """)

    val restricted = ConstraintChecker.restrictMetadata(
      chain(byAnchor = Some(Constraints.empty.copy(allowedEntityTypes = Some(Nil)))),
      declared
    )

    assertEquals(restricted.entityTypes, Set(EntityType.FederationEntity))
  }
}
