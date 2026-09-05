package fedtrust.endpoints

/** Content types the federation endpoints use (spec section 8).
  *
  * These are not decoration. Section 8.3.2 requires a resolve response to be
  * rejected unless it is explicitly typed, and the endpoints are deliberately
  * distinguishable from ordinary JSON so that a signed statement is never
  * mistaken for one.
  */
object MediaTypes {

  /** Fetch responses, and Entity Configurations served from the well-known
    * location.
    */
  val EntityStatement = "application/entity-statement+jwt"

  /** Resolve responses. */
  val ResolveResponse = "application/resolve-response+jwt"

  val TrustMark = "application/trust-mark+jwt"

  /** Subordinate listings, and every error response. */
  val Json = "application/json"
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
