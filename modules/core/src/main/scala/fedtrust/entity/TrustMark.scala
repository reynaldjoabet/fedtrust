package fedtrust.entity

import fedtrust.jwt.SignedJwt
import fedtrust.types.EntityId
import io.circe.{Decoder, Encoder}

/** An entry of the `trust_marks` claim: a trust mark identifier plus the signed
  * trust mark JWT that backs it.
  */
final case class TrustMarkEntry(id: String, trustMark: SignedJwt)

object TrustMarkEntry {
  given Encoder[TrustMarkEntry] =
    Encoder.forProduct2("trust_mark_id", "trust_mark")(e => (e.id, e.trustMark))

  given Decoder[TrustMarkEntry] =
    Decoder.forProduct2("trust_mark_id", "trust_mark")(TrustMarkEntry.apply)
}

/** An entry of the `trust_mark_issuers` claim: who a trust anchor accepts as
  * the issuer of a given trust mark. An empty issuer list means any issuer.
  */
final case class TrustMarkIssuers(byId: Map[String, List[EntityId]]) {
  def accepts(trustMarkId: String, issuer: EntityId): Boolean =
    byId.get(trustMarkId).forall(issuers => issuers.isEmpty || issuers.contains(issuer))
}

object TrustMarkIssuers {
  val empty: TrustMarkIssuers = TrustMarkIssuers(Map.empty)

  given Encoder[TrustMarkIssuers] = Encoder[Map[String, List[EntityId]]].contramap(_.byId)
  given Decoder[TrustMarkIssuers] = Decoder[Map[String, List[EntityId]]].map(TrustMarkIssuers.apply)
}
