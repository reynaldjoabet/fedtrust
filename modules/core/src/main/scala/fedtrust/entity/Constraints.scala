package fedtrust.entity

import fedtrust.types.{*, given}
import io.circe.{Decoder, Encoder}

/** The `naming_constraints` member of `constraints`. */
final case class NamingConstraints(
    permitted: Option[List[String]],
    excluded: Option[List[String]]
)

object NamingConstraints {
  given Encoder[NamingConstraints] =
    Encoder.forProduct2("permitted", "excluded")(nc => (nc.permitted, nc.excluded))

  given Decoder[NamingConstraints] =
    Decoder.forProduct2("permitted", "excluded")(NamingConstraints.apply)
}

/** The `constraints` claim of a subordinate statement.
  *
  * `maxPathLength` is refined rather than a plain `Int`: section 6.2.1 requires
  * it to be non-negative, and expressing that in the type moves the check to
  * where the statement is decoded. A superior that publishes
  * `"max_path_length": -1` now fails to decode, which is the right moment to
  * reject it — the alternative is every consumer of the claim repeating the
  * check, or forgetting to.
  */
final case class Constraints(
    maxPathLength: Option[MaxPathLength],
    namingConstraints: Option[NamingConstraints],
    allowedEntityTypes: Option[List[EntityType]]
)

object Constraints {
  val empty: Constraints = Constraints(None, None, None)

  given Encoder[Constraints] =
    Encoder.forProduct3("max_path_length", "naming_constraints", "allowed_entity_types")(c =>
      (c.maxPathLength, c.namingConstraints, c.allowedEntityTypes)
    )

  given Decoder[Constraints] =
    Decoder.forProduct3("max_path_length", "naming_constraints", "allowed_entity_types")(
      Constraints.apply
    )
}
