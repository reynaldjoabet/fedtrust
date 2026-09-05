package fedtrust.metadata

import fedtrust.types.EntityType
import io.circe.{Decoder, Encoder, JsonObject}

/** The `metadata` claim: entity type -> that type's metadata document.
  *
  * Documents stay as raw JSON. Metadata policy operates on arbitrary parameter
  * names, including ones this library has never heard of, so the policy step
  * has to be able to reach any member. Typed views over the well-known entity
  * types are layered on top — see [[FederationEntityMetadata]].
  */
final case class Metadata(byType: Map[EntityType, JsonObject]) {

  def get(entityType: EntityType): Option[JsonObject] = byType.get(entityType)

  def isEmpty: Boolean = byType.isEmpty

  def entityTypes: Set[EntityType] = byType.keySet

  /** Apply the `metadata` claim of the Immediate Superior's Subordinate
    * Statement to this Entity Configuration's metadata (spec section 3.1.1).
    *
    * Two rules that are easy to get backwards: the superior's parameters
    * override identically named ones here, and the superior can only speak
    * about entity types the subject already declares — a type present only in
    * the Subordinate Statement is not introduced.
    */
  def overriddenBy(fromSuperior: Metadata): Metadata =
    Metadata(byType.map { case (entityType, own) =>
      entityType -> fromSuperior
        .get(entityType)
        .fold(own)(_.toMap.foldLeft(own) { case (acc, (name, value)) => acc.add(name, value) })
    })

  /** Apply the `allowed_entity_types` constraint (spec section 6.2.3).
    *
    * `None` means the constraint is absent and every type is allowed. An empty
    * list allows only `federation_entity`, which is never removed.
    */
  def restrictedTo(allowed: Option[List[EntityType]]): Metadata =
    allowed.fold(this) { permitted =>
      Metadata(byType.filter { case (entityType, _) =>
        entityType == EntityType.FederationEntity || permitted.contains(entityType)
      })
    }

  def updated(entityType: EntityType, document: JsonObject): Metadata =
    Metadata(byType.updated(entityType, document))

  def removed(entityType: EntityType): Metadata = Metadata(byType - entityType)
}

object Metadata {
  val empty: Metadata = Metadata(Map.empty)

  given Encoder[Metadata] = Encoder[Map[EntityType, JsonObject]].contramap(_.byType)
  given Decoder[Metadata] = Decoder[Map[EntityType, JsonObject]].map(Metadata.apply)
}
