package fedtrust.resolver.policy

import fedtrust.error.FederationError
import fedtrust.metadata.PolicyOperator
import fedtrust.metadata.PolicyOperator.*
import io.circe.Json

/** The semantics of the seven standard policy operators (spec section
  * 6.1.3.1), in the two situations they are used: merging two superiors'
  * policies for the same parameter, and applying a resolved policy to a
  * metadata parameter.
  *
  * Each operator's merge rule is its own — `add` unions, `one_of` intersects,
  * `value` and `default` demand equality — which is why this is a match on the
  * operator rather than a single generic combine.
  */
private[policy] object Operators {

  def error(operator: PolicyOperator, detail: String): FederationError =
    FederationError.PolicyViolation(s"${operator.name}: $detail")

  /** Merge a subordinate's operator value into a superior's (section 6.1.4.1).
    *
    * A subordinate may only narrow what its superior allows, so this is not a
    * symmetric union: `one_of` intersects and an empty intersection is a hard
    * error, while `subset_of` intersects and an empty result is legitimate.
    */
  def merge(
      operator: PolicyOperator,
      superior: Json,
      subordinate: Json
  ): Either[FederationError, Json] =
    operator match {
      case Value | Default =>
        Either.cond(
          superior == subordinate,
          superior,
          error(operator, "values must be equal to merge")
        )

      case Add =>
        combine(operator, superior, subordinate)(union)

      case SupersetOf =>
        combine(operator, superior, subordinate)(union)

      case SubsetOf =>
        combine(operator, superior, subordinate)(intersection)

      case OneOf =>
        combine(operator, superior, subordinate)(intersection).flatMap { merged =>
          Either.cond(
            !merged.asArray.exists(_.isEmpty),
            merged,
            error(operator, "the merged values have an empty intersection")
          )
        }

      case Essential =>
        for {
          a <- boolean(operator, "superior value", superior)
          b <- boolean(operator, "subordinate value", subordinate)
        } yield Json.fromBoolean(a || b)
    }

  /** Apply one operator to a metadata parameter (section 6.1.3.1).
    *
    * `None` in and out means the parameter is absent: value checks skip an
    * absent parameter — that is what makes `essential` the operator that
    * decides whether absence is fatal, and why it is applied last.
    */
  def applyTo(
      operator: PolicyOperator,
      config: Json,
      parameter: Option[Json]
  ): Either[FederationError, Option[Json]] =
    operator match {
      case Value =>
        Right(if (config.isNull) None else Some(config))

      case Add =>
        array(operator, "operator value", config).flatMap { additions =>
          parameter match {
            case None           => Right(Some(Json.fromValues(additions)))
            case Some(existing) =>
              array(operator, "metadata parameter", existing)
                .map(values => Some(Json.fromValues(union(values, additions))))
          }
        }

      case Default =>
        Right(parameter.orElse(Some(config)))

      case OneOf =>
        parameter match {
          case None        => Right(None)
          case Some(value) =>
            array(operator, "operator value", config).flatMap { permitted =>
              Either.cond(
                permitted.contains(value),
                Some(value),
                error(operator, s"${value.noSpaces} is not among the permitted values")
              )
            }
        }

      case SubsetOf =>
        parameter match {
          case None        => Right(None)
          case Some(value) =>
            for {
              permitted <- array(operator, "operator value", config)
              values    <- array(operator, "metadata parameter", value)
            } yield Some(Json.fromValues(intersection(values, permitted)))
        }

      case SupersetOf =>
        parameter match {
          case None        => Right(None)
          case Some(value) =>
            for {
              required <- array(operator, "operator value", config)
              values   <- array(operator, "metadata parameter", value)
              _        <- Either.cond(
                required.forall(values.contains),
                (),
                error(operator, "the metadata parameter is missing required values")
              )
            } yield Some(value)
        }

      case Essential =>
        boolean(operator, "operator value", config).flatMap { required =>
          Either.cond(
            !required || parameter.isDefined,
            parameter,
            error(operator, "the metadata parameter is required but absent")
          )
        }
    }

  def array(
      operator: PolicyOperator,
      label: String,
      json: Json
  ): Either[FederationError, Vector[Json]] =
    json.asArray.toRight(error(operator, s"$label must be a JSON array"))

  def boolean(
      operator: PolicyOperator,
      label: String,
      json: Json
  ): Either[FederationError, Boolean] =
    json.asBoolean.toRight(error(operator, s"$label must be a JSON boolean"))

  /** Order is preserved and duplicates dropped: the spec leaves merge order
    * undefined, and a stable one makes failures reproducible.
    */
  def union(a: Vector[Json], b: Vector[Json]): Vector[Json] =
    a ++ b.filterNot(a.contains)

  def intersection(a: Vector[Json], b: Vector[Json]): Vector[Json] =
    a.filter(b.contains)

  def isSubset(a: Vector[Json], b: Vector[Json]): Boolean = a.forall(b.contains)

  private def combine(operator: PolicyOperator, superior: Json, subordinate: Json)(
      f: (Vector[Json], Vector[Json]) => Vector[Json]
  ): Either[FederationError, Json] =
    for {
      a <- array(operator, "superior value", superior)
      b <- array(operator, "subordinate value", subordinate)
    } yield Json.fromValues(f(a, b))
}
