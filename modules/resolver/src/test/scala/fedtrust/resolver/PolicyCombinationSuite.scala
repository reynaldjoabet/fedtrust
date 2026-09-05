package fedtrust.resolver

import fedtrust.resolver.policy.MetadataPolicyEngine
import munit.FunSuite

/** Operator combination rules from spec section 6.1.3.1.
  *
  * Two kinds of failure are covered: pairs that may never appear together, and
  * pairs that are legal only when their values agree. Both matter because a
  * merge can create a pairing that neither Superior wrote by itself, which is
  * the case the last test covers.
  */
class PolicyCombinationSuite extends FunSuite {

  import Fixtures.*

  private def resolveOne(operators: String) =
    MetadataPolicyEngine.resolve(
      List(
        statement(
          "https://ta.example.org",
          "https://rp.example.org",
          metadataPolicy = Some(policy(s"""{ "openid_relying_party": { "p": $operators } }"""))
        )
      )
    )

  private def rejects(operators: String, because: String): Unit =
    resolveOne(operators) match {
      case Left(_)  => ()
      case Right(p) => fail(s"$because, but the policy was accepted: $p")
    }

  test("add may not be combined with one_of") {
    rejects("""{"add": ["a"], "one_of": ["a", "b"]}""", "neither operator permits the other")
  }

  test("one_of may not be combined with subset_of or superset_of") {
    rejects("""{"one_of": ["a"], "subset_of": ["a"]}""", "one_of permits neither")
    rejects("""{"one_of": ["a"], "superset_of": ["a"]}""", "one_of permits neither")
  }

  test("value combined with one_of requires the value to be permitted") {
    assert(resolveOne("""{"value": "a", "one_of": ["a", "b"]}""").isRight)
    rejects("""{"value": "z", "one_of": ["a", "b"]}""", "z is not among the one_of values")
  }

  test("add combined with value requires add to be a subset of value") {
    assert(resolveOne("""{"value": ["a", "b"], "add": ["a"]}""").isRight)
    rejects("""{"value": ["a"], "add": ["z"]}""", "z is not among the value values")
  }

  test("subset_of combined with superset_of requires subset_of to be the wider set") {
    assert(resolveOne("""{"subset_of": ["a", "b"], "superset_of": ["a"]}""").isRight)
    rejects(
      """{"subset_of": ["a"], "superset_of": ["a", "z"]}""",
      "superset_of is not contained in subset_of"
    )
  }

  test("a null value may not be combined with essential true") {
    assert(resolveOne("""{"value": null, "essential": false}""").isRight)
    rejects(
      """{"value": null, "essential": true}""",
      "a parameter cannot be both removed and required"
    )
  }

  test("value and default may not be combined when the value is null") {
    assert(resolveOne("""{"value": "a", "default": "a"}""").isRight)
    rejects("""{"value": null, "default": "a"}""", "the spec forbids this pairing")
  }

  test("merging can create an illegal combination neither superior wrote") {
    // The Trust Anchor sets subset_of; the Intermediate sets superset_of. Each
    // is fine alone, and the pair is legal only if subset_of is the wider set.
    val statements = List(
      statement(
        "https://ta.example.org",
        "https://org.example.org",
        metadataPolicy =
          Some(policy("""{ "openid_relying_party": { "p": { "subset_of": ["a"] } } }"""))
      ),
      statement(
        "https://org.example.org",
        "https://rp.example.org",
        metadataPolicy =
          Some(policy("""{ "openid_relying_party": { "p": { "superset_of": ["z"] } } }"""))
      )
    )

    assert(
      MetadataPolicyEngine.resolve(statements).isLeft,
      "a subordinate must not be able to require a value its superior excluded"
    )
  }

  test("value and default must be equal to merge, one_of intersects") {
    def merged(superior: String, subordinate: String) =
      MetadataPolicyEngine.resolve(
        List(
          statement(
            "https://ta.example.org",
            "https://org.example.org",
            metadataPolicy = Some(policy(s"""{ "openid_relying_party": { "p": $superior } }"""))
          ),
          statement(
            "https://org.example.org",
            "https://rp.example.org",
            metadataPolicy = Some(policy(s"""{ "openid_relying_party": { "p": $subordinate } }"""))
          )
        )
      )

    assert(merged("""{"value": "a"}""", """{"value": "a"}""").isRight)
    assert(merged("""{"value": "a"}""", """{"value": "b"}""").isLeft)
    assert(merged("""{"default": "a"}""", """{"default": "b"}""").isLeft)

    // Disjoint one_of values leave nothing permitted, which is an error rather
    // than a policy that can never be satisfied.
    assert(merged("""{"one_of": ["a"]}""", """{"one_of": ["b"]}""").isLeft)
    assert(merged("""{"one_of": ["a", "b"]}""", """{"one_of": ["b"]}""").isRight)

    // subset_of is the exception: an empty intersection is legitimate.
    assert(merged("""{"subset_of": ["a"]}""", """{"subset_of": ["b"]}""").isRight)
  }
}
