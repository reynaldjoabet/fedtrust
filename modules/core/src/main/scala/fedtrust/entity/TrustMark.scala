package fedtrust.entity

import java.time.Instant

import fedtrust.jwk.JwkSet
import fedtrust.jwt.SignedJwt
import fedtrust.types.{*, given}
import fedtrust.util.NumericDate.given
import io.circe.{Decoder, Encoder}

/** An entry of the `trust_marks` claim (spec section 3.1.2): a Trust Mark type
  * identifier plus the signed Trust Mark that backs it.
  *
  * The type is repeated outside the JWT so a reader can index the marks without
  * parsing each one. Section 3.1.2 requires the two to agree, and
  * [[fedtrust.resolver.TrustMarkValidator]] checks that they do — an entry
  * advertising one type while carrying a mark of another is exactly the
  * mismatch that check exists to catch.
  */
final case class TrustMarkEntry(trustMarkType: TrustMarkType, trustMark: SignedJwt)

object TrustMarkEntry {
  given Encoder[TrustMarkEntry] =
    Encoder.forProduct2("trust_mark_type", "trust_mark")(e => (e.trustMarkType, e.trustMark))

  given Decoder[TrustMarkEntry] =
    Decoder.forProduct2("trust_mark_type", "trust_mark")(TrustMarkEntry.apply)
}

/** The claims of a Trust Mark (spec section 7.1). */
final case class TrustMarkClaims(
    iss: EntityId,
    sub: EntityId,
    trustMarkType: TrustMarkType,
    iat: Instant,
    exp: Option[Instant] = None,
    logoUri: Option[String] = None,
    ref: Option[String] = None,
    delegation: Option[SignedJwt] = None
) {

  /** `exp` is OPTIONAL here, unlike in an Entity Statement: a Trust Mark
    * without one does not expire, and section 7.3 recommends the Trust Mark
    * Status endpoint as the way to check such a mark is still active.
    */
  def isExpiredAt(now: Instant): Boolean = exp.exists(!now.isBefore(_))
}

object TrustMarkClaims {

  private val names =
    List("iss", "sub", "trust_mark_type", "iat", "exp", "logo_uri", "ref", "delegation")

  given Encoder[TrustMarkClaims] =
    Encoder.forProduct8(
      names(0),
      names(1),
      names(2),
      names(3),
      names(4),
      names(5),
      names(6),
      names(7)
    )(c => (c.iss, c.sub, c.trustMarkType, c.iat, c.exp, c.logoUri, c.ref, c.delegation))

  given Decoder[TrustMarkClaims] =
    Decoder.forProduct8(
      names(0),
      names(1),
      names(2),
      names(3),
      names(4),
      names(5),
      names(6),
      names(7)
    )(
      TrustMarkClaims.apply
    )
}

/** The claims of a Trust Mark Delegation JWT (spec section 7.2.1).
  *
  * A delegation is how a Trust Mark Owner authorises somebody else to issue
  * marks of a type it owns — the accreditation authority and the entity that
  * signs need not be the same organisation.
  */
final case class TrustMarkDelegationClaims(
    iss: EntityId,
    sub: EntityId,
    trustMarkType: TrustMarkType,
    iat: Instant,
    exp: Option[Instant] = None,
    ref: Option[String] = None
) {
  def isExpiredAt(now: Instant): Boolean = exp.exists(!now.isBefore(_))
}

object TrustMarkDelegationClaims {

  private val names = List("iss", "sub", "trust_mark_type", "iat", "exp", "ref")

  given Encoder[TrustMarkDelegationClaims] =
    Encoder.forProduct6(names(0), names(1), names(2), names(3), names(4), names(5))(c =>
      (c.iss, c.sub, c.trustMarkType, c.iat, c.exp, c.ref)
    )

  given Decoder[TrustMarkDelegationClaims] =
    Decoder.forProduct6(names(0), names(1), names(2), names(3), names(4), names(5))(
      TrustMarkDelegationClaims.apply
    )
}

/** The `trust_mark_issuers` claim of a Trust Anchor's Entity Configuration
  * (spec section 3.1.2): which issuers the federation accepts for each Trust
  * Mark type.
  */
final case class TrustMarkIssuers(byType: Map[TrustMarkType, List[EntityId]]) {

  /** An empty list against a type means anyone may issue marks of that type. A
    * type absent altogether is not constrained by this claim at all.
    */
  def accepts(trustMarkType: TrustMarkType, issuer: EntityId): Boolean =
    byType.get(trustMarkType).forall(issuers => issuers.isEmpty || issuers.contains(issuer))

  def constrains(trustMarkType: TrustMarkType): Boolean = byType.contains(trustMarkType)
}

object TrustMarkIssuers {
  val empty: TrustMarkIssuers = TrustMarkIssuers(Map.empty)

  private type Raw = Map[TrustMarkType, List[EntityId]]

  given Encoder[TrustMarkIssuers] = Encoder[Raw].contramap(_.byType)
  given Decoder[TrustMarkIssuers] = Decoder[Raw].map(TrustMarkIssuers.apply)
}

/** One entry of the `trust_mark_owners` claim: who owns a Trust Mark type, and
  * the keys they sign delegations with.
  */
final case class TrustMarkOwner(sub: EntityId, jwks: JwkSet)

object TrustMarkOwner {
  given Encoder[TrustMarkOwner] = Encoder.forProduct2("sub", "jwks")(o => (o.sub, o.jwks))
  given Decoder[TrustMarkOwner] = Decoder.forProduct2("sub", "jwks")(TrustMarkOwner.apply)
}

/** The `trust_mark_owners` claim of a Trust Anchor's Entity Configuration.
  *
  * A type listed here is owned by somebody other than its issuers, which
  * section 7.3 makes load-bearing: a mark of such a type MUST carry a
  * delegation, and a mark without one is invalid however well it is signed.
  */
final case class TrustMarkOwners(byType: Map[TrustMarkType, TrustMarkOwner]) {
  def get(trustMarkType: TrustMarkType): Option[TrustMarkOwner] = byType.get(trustMarkType)

  def requiresDelegation(trustMarkType: TrustMarkType): Boolean = byType.contains(trustMarkType)
}

object TrustMarkOwners {
  val empty: TrustMarkOwners = TrustMarkOwners(Map.empty)

  private type Raw = Map[TrustMarkType, TrustMarkOwner]

  given Encoder[TrustMarkOwners] = Encoder[Raw].contramap(_.byType)
  given Decoder[TrustMarkOwners] = Decoder[Raw].map(TrustMarkOwners.apply)
}
