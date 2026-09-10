package fedtrust.resolver

import fedtrust.error.FederationError
import fedtrust.resolver.policy.MetadataPolicyEngine
import fedtrust.types.{*, given}
import io.circe.Json
import munit.FunSuite

/** Operator semantics from spec section 6.1.3.1, exercised through the engine
  * rather than against the operators directly, so ordering and the
  * absent-parameter handling are covered too.
  */
class PolicyOperatorSuite extends FunSuite {

  import Fixtures.*

  private def resolvedParameter(policyJson: String, metadataJson: String, name: String) =
    MetadataPolicyEngine
      .applyTo(policy(policyJson), metadata(metadataJson))
      .map(_.get(EntityType.OpenIdRelyingParty).flatMap(_(name)))

  private def rpPolicy(parameter: String, operators: String): String =
    s"""{ "openid_relying_party": { "$parameter": $operators } }"""

  private def rpMetadata(body: String): String =
    s"""{ "openid_relying_party": $body }"""

  test("value assigns, and a null value removes the parameter") {
    assertEquals(
      resolvedParameter(rpPolicy("p", """{"value": "x"}"""), rpMetadata("""{"p": "y"}"""), "p"),
      Right(Some(Json.fromString("x")))
    )

    assertEquals(
      resolvedParameter(rpPolicy("p", """{"value": null}"""), rpMetadata("""{"p": "y"}"""), "p"),
      Right(None)
    )
  }

  test("add unions without duplicating, and initialises an absent parameter") {
    assertEquals(
      resolvedParameter(
        rpPolicy("p", """{"add": ["b", "c"]}"""),
        rpMetadata("""{"p": ["a", "b"]}"""),
        "p"
      ),
      Right(Some(json("""["a", "b", "c"]""")))
    )

    assertEquals(
      resolvedParameter(rpPolicy("p", """{"add": ["a"]}"""), rpMetadata("{}"), "p"),
      Right(Some(json("""["a"]""")))
    )
  }

  test("default fills an absent parameter and leaves a present one alone") {
    assertEquals(
      resolvedParameter(rpPolicy("p", """{"default": "d"}"""), rpMetadata("{}"), "p"),
      Right(Some(Json.fromString("d")))
    )

    assertEquals(
      resolvedParameter(rpPolicy("p", """{"default": "d"}"""), rpMetadata("""{"p": "v"}"""), "p"),
      Right(Some(Json.fromString("v")))
    )
  }

  test("one_of rejects a value outside the permitted set and skips an absent one") {
    assert(
      resolvedParameter(
        rpPolicy("p", """{"one_of": ["a", "b"]}"""),
        rpMetadata("""{"p": "c"}"""),
        "p"
      ).isLeft
    )

    assertEquals(
      resolvedParameter(rpPolicy("p", """{"one_of": ["a", "b"]}"""), rpMetadata("{}"), "p"),
      Right(None)
    )
  }

  test("subset_of narrows the parameter rather than rejecting it") {
    assertEquals(
      resolvedParameter(
        rpPolicy("p", """{"subset_of": ["a", "b"]}"""),
        rpMetadata("""{"p": ["a", "z"]}"""),
        "p"
      ),
      Right(Some(json("""["a"]""")))
    )
  }

  test("superset_of checks without modifying") {
    assertEquals(
      resolvedParameter(
        rpPolicy("p", """{"superset_of": ["a"]}"""),
        rpMetadata("""{"p": ["a", "b"]}"""),
        "p"
      ),
      Right(Some(json("""["a", "b"]""")))
    )

    assert(
      resolvedParameter(
        rpPolicy("p", """{"superset_of": ["z"]}"""),
        rpMetadata("""{"p": ["a"]}"""),
        "p"
      ).isLeft
    )
  }

  /** Table 1 of section 6.1.3.1.8, which pins down the interaction that is
    * easiest to get wrong: subset_of is skipped for an absent parameter, so it
    * is essential alone that decides whether absence fails.
    */
  test("Table 1: essential combined with subset_of") {
    val subsetOf = """["a", "b", "c"]"""

    def row(essential: Boolean, input: Option[String]) =
      resolvedParameter(
        rpPolicy("p", s"""{"essential": $essential, "subset_of": $subsetOf}"""),
        rpMetadata(input.fold("{}")(v => s"""{"p": $v}""")),
        "p"
      )

    assertEquals(row(true, Some("""["a", "e"]""")), Right(Some(json("""["a"]"""))))
    assertEquals(row(false, Some("""["a", "e"]""")), Right(Some(json("""["a"]"""))))
    assertEquals(row(true, Some("""["d", "e"]""")), Right(Some(json("[]"))))
    assertEquals(row(false, Some("""["d", "e"]""")), Right(Some(json("[]"))))
    assert(row(true, None).isLeft, "essential=true with an absent parameter must fail")
    assertEquals(row(false, None), Right(None))
  }

  test("operators are applied in the order the spec fixes, not map order") {
    // default must run before subset_of: the other way round, subset_of would
    // see an absent parameter, skip, and the default would survive unfiltered.
    assertEquals(
      resolvedParameter(
        rpPolicy("p", """{"subset_of": ["a"], "default": ["a", "z"]}"""),
        rpMetadata("{}"),
        "p"
      ),
      Right(Some(json("""["a"]""")))
    )
  }

  test("scope is treated as an array of strings and written back as a string") {
    assertEquals(
      resolvedParameter(
        rpPolicy("scope", """{"subset_of": ["openid", "profile"]}"""),
        rpMetadata("""{"scope": "openid profile email"}"""),
        "scope"
      ),
      Right(Some(Json.fromString("openid profile")))
    )
  }

  test("an unknown operator is ignored unless a statement declares it critical") {
    val statements = List(
      statement(
        "https://ta.example.org",
        "https://rp.example.org",
        metadataPolicy = Some(policy(rpPolicy("p", """{"unheard_of": ["a"]}""")))
      )
    )

    assert(MetadataPolicyEngine.resolve(statements).isRight)

    val critical = statements.map(_.copy(metadataPolicyCrit = Some(List("unheard_of"))))

    MetadataPolicyEngine.resolve(critical) match {
      case Left(e: FederationError.PolicyViolation) =>
        assert(e.message.contains("unheard_of"), e.message)
      case other => fail(s"expected a policy violation, got $other")
    }
  }
}
