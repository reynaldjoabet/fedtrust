package fedtrust.entity

import fedtrust.types.EntityType
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

/** The `constraints` claim of a subordinate statement. */
final case class Constraints(
    maxPathLength: Option[Int],
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
