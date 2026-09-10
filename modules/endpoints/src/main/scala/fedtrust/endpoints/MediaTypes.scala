package fedtrust.endpoints

/** Content types the federation endpoints use (spec section 8).
  *
  * Not decoration. Section 8.3.2 requires a resolve response to be rejected
  * unless it is explicitly typed, and the endpoints are deliberately
  * distinguishable from ordinary JSON so that a signed statement is never
  * mistaken for one. A closed set, for the same reason [[fedtrust.jwt.JwtTyp]]
  * is: a content type outside it is a rejection, not an extension point.
  */
enum MediaType(val value: String) {

  /** Fetch responses, and Entity Configurations served from the well-known
    * location.
    */
  case EntityStatement extends MediaType("application/entity-statement+jwt")

  /** Resolve responses. */
  case ResolveResponse extends MediaType("application/resolve-response+jwt")

  case TrustMark extends MediaType("application/trust-mark+jwt")

  /** Subordinate listings, and every error response. */
  case Json extends MediaType("application/json")
}

object MediaType {

  private lazy val byValue: Map[String, MediaType] =
    values.map(media => media.value -> media).toMap

  def fromValue(raw: String): Option[MediaType] = byValue.get(raw)
}

/** The query parameters of a federation endpoint request.
  *
  * Requests arrive as `application/x-www-form-urlencoded`, in the query string
  * for GET and in the body for the authenticated POST form, and several
  * parameters may repeat. Modelling them as a multimap keeps this module free
  * of any HTTP library while still letting each request type state exactly how
  * it is bound.
  */
type Params = Map[String, List[String]]

object Params {

  val empty: Params = Map.empty

  def of(pairs: (String, String)*): Params =
    pairs.foldLeft(empty) { case (acc, (name, value)) =>
      acc.updated(name, acc.getOrElse(name, Nil) :+ value)
    }

  extension (params: Params) {
    def first(name: String): Option[String] = params.get(name).flatMap(_.headOption)
    def all(name: String): List[String]     = params.getOrElse(name, Nil)
  }
}
