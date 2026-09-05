package fedtrust.resolver.policy

import fedtrust.entity.EntityStatement
import fedtrust.error.FederationError
import fedtrust.metadata.{Metadata, MetadataPolicy, ParameterPolicy}
import fedtrust.types.EntityType
import io.circe.{Json, JsonObject}

/** Metadata policy resolution and application (spec section 6.1.4).
  *
  * This lives with chain resolution rather than with the metadata types
  * because a policy is a property of the chain: policies are merged from the
  * Trust Anchor downwards, and only the merged result is applied to the
  * subject's metadata. A policy detached from its position in a chain does not
  * mean anything.
  */
object MetadataPolicyEngine {

  /** Section 6.1.4.1. `subordinateStatements` MUST be ordered most-superior
    * first — the Trust Anchor's statement, down to the one issued by the
    * subject's Immediate Superior.
    *
    * The direction is the whole point: merging is asymmetric, so iterating the
    * other way would let a subordinate loosen what its superior imposed. See
    * [[fedtrust.resolver.TrustChain.policyOrder]], which produces this
    * ordering from a chain.
    */
  def resolve(
      subordinateStatements: List[EntityStatement]
  ): Either[FederationError, MetadataPolicy] = {
    val critical = subordinateStatements.flatMap(_.metadataPolicyCrit.getOrElse(Nil)).toSet

    subordinateStatements
      .flatMap(_.metadataPolicy)
      .foldLeft[Either[FederationError, MetadataPolicy]](Right(MetadataPolicy.empty)) {
        (acc, next) =>
          for {
            current <- acc
            _       <- validate(next, critical)
            merged  <- mergePolicies(current, next)
            _       <- validate(merged, critical)
          } yield merged
      }
  }

  /** Section 6.1.4.2, second half: apply a resolved policy to metadata that has
    * already had the Immediate Superior's `metadata` claim and the
    * `allowed_entity_types` constraint applied to it.
    *
    * Policy is applied only to entity types the subject actually declares. A
    * policy for a type the subject does not play says nothing about it — and
    * applying `essential` to an absent entity type would fail a chain that is
    * perfectly valid.
    */
  def applyTo(
      policy: MetadataPolicy,
      metadata: Metadata
  ): Either[FederationError, Metadata] =
    metadata.byType.toList
      .sortBy(_._1.value)
      .foldLeft[Either[FederationError, Metadata]](Right(metadata)) {
        case (acc, (entityType, document)) =>
          val parameters = policy.get(entityType)
          if (parameters.isEmpty) acc
          else
            for {
              resolved <- acc
              applied  <- applyToDocument(entityType, parameters, document)
            } yield resolved.updated(entityType, applied)
      }

  /** Structural validation of one `metadata_policy` claim: legal operator
    * combinations, and no unsupported operator that a statement declared
    * critical.
    */
  private def validate(
      policy: MetadataPolicy,
      critical: Set[String]
  ): Either[FederationError, Unit] =
    policy.byType.toList.foldLeft[Either[FederationError, Unit]](Right(())) {
      case (acc, (entityType, parameters)) =>
        parameters.toList.foldLeft(acc) { case (inner, (name, parameterPolicy)) =>
          for {
            _ <- inner
            _ <- unsupportedCritical(entityType, name, parameterPolicy, critical)
            _ <- Combinations.check(s"${entityType.value}.$name", parameterPolicy)
          } yield ()
        }
    }

  /** Unknown operators are ignored unless a statement named them in
    * `metadata_policy_crit`, in which case failing to understand one
    * invalidates the chain (section 6.1.3.2).
    */
  private def unsupportedCritical(
      entityType: EntityType,
      parameter: String,
      policy: ParameterPolicy,
      critical: Set[String]
  ): Either[FederationError, Unit] =
    policy.unknown.keys.find(critical.contains) match {
      case Some(operator) =>
        Left(
          FederationError.PolicyViolation(
            s"${entityType.value}.$parameter: critical policy operator '$operator' is not supported"
          )
        )
      case None => Right(())
    }

  private def mergePolicies(
      current: MetadataPolicy,
      next: MetadataPolicy
  ): Either[FederationError, MetadataPolicy] =
    next.byType.toList
      .sortBy(_._1.value)
      .foldLeft[Either[FederationError, MetadataPolicy]](Right(current)) {
        case (acc, (entityType, parameters)) =>
          for {
            resolved <- acc
            merged   <- mergeParameters(entityType, resolved.get(entityType), parameters)
          } yield MetadataPolicy(resolved.byType.updated(entityType, merged))
      }

  private def mergeParameters(
      entityType: EntityType,
      current: Map[String, ParameterPolicy],
      next: Map[String, ParameterPolicy]
  ): Either[FederationError, Map[String, ParameterPolicy]] =
    next.toList
      .sortBy(_._1)
      .foldLeft[Either[FederationError, Map[String, ParameterPolicy]]](
        Right(current)
      ) { case (acc, (name, subordinate)) =>
        for {
          resolved <- acc
          merged   <- resolved.get(name) match {
            case None           => Right(subordinate)
            case Some(superior) => mergeParameter(entityType, name, superior, subordinate)
          }
        } yield resolved.updated(name, merged)
      }

  private def mergeParameter(
      entityType: EntityType,
      parameter: String,
      superior: ParameterPolicy,
      subordinate: ParameterPolicy
  ): Either[FederationError, ParameterPolicy] =
    subordinate.known.toList
      .sortBy(_._1)
      .foldLeft[Either[FederationError, ParameterPolicy]](Right(superior)) {
        case (acc, (operator, subordinateValue)) =>
          for {
            resolved <- acc
            merged   <- resolved(operator) match {
              case None                => Right(subordinateValue)
              case Some(superiorValue) =>
                Operators
                  .merge(operator, superiorValue, subordinateValue)
                  .left
                  .map(e =>
                    FederationError.PolicyViolation(
                      s"${entityType.value}.$parameter: ${e.message}"
                    )
                  )
            }
          } yield resolved.copy(known = resolved.known.updated(operator, merged))
      }
      .map(merged => merged.copy(unknown = merged.unknown ++ subordinate.unknown))

  private def applyToDocument(
      entityType: EntityType,
      parameters: Map[String, ParameterPolicy],
      document: JsonObject
  ): Either[FederationError, JsonObject] =
    parameters.toList.sortBy(_._1).foldLeft[Either[FederationError, JsonObject]](Right(document)) {
      case (acc, (name, policy)) =>
        for {
          current <- acc
          applied <- applyParameter(entityType, name, policy, current)
        } yield applied
    }

  private def applyParameter(
      entityType: EntityType,
      name: String,
      policy: ParameterPolicy,
      document: JsonObject
  ): Either[FederationError, JsonObject] = {
    val initial = document(name).map(Scope.toPolicyValue(name, _))

    policy.known.toList
      .sortBy(_._1)
      .foldLeft[Either[FederationError, Option[Json]]](Right(initial)) {
        case (acc, (operator, config)) =>
          acc.flatMap { parameter =>
            Operators
              .applyTo(operator, config, parameter)
              .left
              .map(e => FederationError.PolicyViolation(s"${entityType.value}.$name: ${e.message}"))
          }
      }
      .map {
        case None        => document.remove(name)
        case Some(value) => document.add(name, Scope.fromPolicyValue(name, value))
      }
  }
}

/** `scope` is a space-separated string in OAuth metadata, but section 6.1.3.1.8
  * requires policy operators to treat it as an array of strings. Converting on
  * the way in and back on the way out keeps every operator unaware of the
  * special case.
  */
private[policy] object Scope {
  private val name = "scope"

  def toPolicyValue(parameter: String, value: Json): Json =
    if (parameter != name) value
    else
      value.asString.fold(value) { raw =>
        Json.fromValues(raw.split(" ").toVector.filter(_.nonEmpty).map(Json.fromString))
      }

  def fromPolicyValue(parameter: String, value: Json): Json =
    if (parameter != name) value
    else
      value.asArray.fold(value) { values =>
        Json.fromString(values.flatMap(_.asString).mkString(" "))
      }
}
