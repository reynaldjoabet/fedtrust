package fedtrust.metadata

import fedtrust.types.{*, given}
import io.circe.{Decoder, Encoder, Json, JsonObject}

/** A metadata policy operator name.
  *
  * The operators are ordered: `value` and `add` modify, the rest check, and
  * `essential` is evaluated last. Merging and applying a policy both depend on
  * this ordering, so it lives with the operator rather than at the use site.
  */
enum PolicyOperator(val name: String, val order: Int) {
  case Value      extends PolicyOperator("value", 0)
  case Add        extends PolicyOperator("add", 1)
  case Default    extends PolicyOperator("default", 2)
  case OneOf      extends PolicyOperator("one_of", 3)
  case SubsetOf   extends PolicyOperator("subset_of", 4)
  case SupersetOf extends PolicyOperator("superset_of", 5)
  case Essential  extends PolicyOperator("essential", 6)
}

object PolicyOperator {
  private val byName: Map[String, PolicyOperator] = values.map(op => op.name -> op).toMap

  def fromName(name: String): Option[PolicyOperator] = byName.get(name)

  given Ordering[PolicyOperator] = Ordering.by(_.order)
}

/** The policy attached to one metadata parameter, e.g. the constraints a
  * superior places on `token_endpoint_auth_method`.
  *
  * `unknown` holds operators this build does not implement. They are kept
  * because a policy naming an unrecognised operator is a hard failure unless
  * the statement's `metadata_policy_crit` says otherwise — dropping them here
  * would silently turn a rejection into an acceptance.
  */
final case class ParameterPolicy(
    known: Map[PolicyOperator, Json],
    unknown: Map[String, Json]
) {
  def apply(op: PolicyOperator): Option[Json] = known.get(op)
}

object ParameterPolicy {
  val empty: ParameterPolicy = ParameterPolicy(Map.empty, Map.empty)

  given Decoder[ParameterPolicy] = Decoder[JsonObject].map { obj =>
    obj.toMap.foldLeft(empty) { case (acc, (key, json)) =>
      PolicyOperator.fromName(key) match {
        case Some(op) => acc.copy(known = acc.known + (op -> json))
        case None     => acc.copy(unknown = acc.unknown + (key -> json))
      }
    }
  }

  given Encoder[ParameterPolicy] = Encoder[JsonObject].contramap { p =>
    JsonObject.fromMap(p.known.map { case (op, j) => op.name -> j } ++ p.unknown)
  }
}

/** The `metadata_policy` claim: entity type -> parameter name -> policy. */
final case class MetadataPolicy(byType: Map[EntityType, Map[String, ParameterPolicy]]) {
  def get(entityType: EntityType): Map[String, ParameterPolicy] =
    byType.getOrElse(entityType, Map.empty)

  def isEmpty: Boolean = byType.isEmpty
}

object MetadataPolicy {
  val empty: MetadataPolicy = MetadataPolicy(Map.empty)

  private type Raw = Map[EntityType, Map[String, ParameterPolicy]]

  given Encoder[MetadataPolicy] = Encoder[Raw].contramap(_.byType)
  given Decoder[MetadataPolicy] = Decoder[Raw].map(MetadataPolicy.apply)
}
