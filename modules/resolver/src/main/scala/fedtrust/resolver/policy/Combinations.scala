package fedtrust.resolver.policy

import fedtrust.error.FederationError
import fedtrust.metadata.{ParameterPolicy, PolicyOperator}
import fedtrust.metadata.PolicyOperator.*
import io.circe.Json

/** Which operators may appear together in one metadata parameter policy, and
  * under what conditions (spec section 6.1.3.1).
  *
  * Each operator declares the operators it may be combined with, and the pairs
  * nobody declares are errors: `add` with `one_of`, and `one_of` with either
  * `subset_of` or `superset_of`. Several of the legal pairs are conditional —
  * `value` combined with `one_of` is only legal if the value is actually among
  * the permitted ones — so this checks the values too, not just the names.
  *
  * The check runs on merged policies as well as on individual ones, because a
  * merge can produce a pairing that neither superior wrote on its own.
  */
private[policy] object Combinations {

  /** Unordered pairs that may appear together at all. Anything absent here is
    * rejected outright.
    */
  private val permitted: Set[(PolicyOperator, PolicyOperator)] = Set(
    (Value, Add),
    (Value, Default),
    (Value, OneOf),
    (Value, SubsetOf),
    (Value, SupersetOf),
    (Value, Essential),
    (Add, Default),
    (Add, SubsetOf),
    (Add, SupersetOf),
    (Add, Essential),
    (Default, OneOf),
    (Default, SubsetOf),
    (Default, SupersetOf),
    (Default, Essential),
    (OneOf, Essential),
    (SubsetOf, SupersetOf),
    (SubsetOf, Essential),
    (SupersetOf, Essential)
  )

  def check(parameter: String, policy: ParameterPolicy): Either[FederationError, Unit] = {
    val present = policy.known.keys.toList.sorted

    val pairs = present.combinations(2).collect { case List(a, b) => (a, b) }.toList

    val structural = pairs.foldLeft[Either[FederationError, Unit]](Right(())) {
      case (acc, (a, b)) =>
        acc.flatMap(_ =>
          Either.cond(
            permitted.contains((a, b)),
            (),
            FederationError.PolicyViolation(
              s"$parameter: ${a.name} and ${b.name} may not be combined"
            )
          )
        )
    }

    structural.flatMap(_ => conditions(parameter, policy))
  }

  private def conditions(
      parameter: String,
      policy: ParameterPolicy
  ): Either[FederationError, Unit] = {
    def when(a: PolicyOperator, b: PolicyOperator)(
        f: (Json, Json) => Either[FederationError, Unit]
    ): Either[FederationError, Unit] =
      (policy(a), policy(b)) match {
        case (Some(x), Some(y)) => f(x, y).left.map(prefix(parameter))
        case _                  => Right(())
      }

    for {
      _ <- when(Value, Add) { (value, add) =>
        subsetCondition(Add, add, Value, value)
      }
      _ <- when(Value, Default) { (value, _) =>
        Either.cond(
          !value.isNull,
          (),
          Operators.error(Value, "may not be combined with default when it is null")
        )
      }
      _ <- when(Value, OneOf) { (value, oneOf) =>
        Operators.array(OneOf, "operator value", oneOf).flatMap { permittedValues =>
          Either.cond(
            permittedValues.contains(value),
            (),
            Operators.error(Value, "is not among the one_of values")
          )
        }
      }
      _ <- when(Value, SubsetOf) { (value, subsetOf) =>
        subsetCondition(Value, value, SubsetOf, subsetOf)
      }
      _ <- when(Value, SupersetOf) { (value, supersetOf) =>
        subsetCondition(SupersetOf, supersetOf, Value, value)
      }
      _ <- when(Value, Essential) { (value, essential) =>
        Operators.boolean(Essential, "operator value", essential).flatMap { required =>
          Either.cond(
            !(value.isNull && required),
            (),
            Operators.error(Value, "may not be null when essential is true")
          )
        }
      }
      _ <- when(Add, SubsetOf) { (add, subsetOf) =>
        subsetCondition(Add, add, SubsetOf, subsetOf)
      }
      _ <- when(SubsetOf, SupersetOf) { (subsetOf, supersetOf) =>
        subsetCondition(SupersetOf, supersetOf, SubsetOf, subsetOf)
      }
    } yield ()
  }

  /** `inner`'s values must all appear in `outer`'s. */
  private def subsetCondition(
      inner: PolicyOperator,
      innerValue: Json,
      outer: PolicyOperator,
      outerValue: Json
  ): Either[FederationError, Unit] =
    for {
      a <- Operators.array(inner, "operator value", innerValue)
      b <- Operators.array(outer, "operator value", outerValue)
      _ <- Either.cond(
        Operators.isSubset(a, b),
        (),
        Operators.error(inner, s"values must be a subset of the ${outer.name} values")
      )
    } yield ()

  private def prefix(parameter: String)(error: FederationError): FederationError =
    FederationError.PolicyViolation(s"$parameter: ${error.message}")
}
