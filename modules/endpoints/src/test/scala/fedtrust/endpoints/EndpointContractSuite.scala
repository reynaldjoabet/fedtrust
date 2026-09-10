package fedtrust.endpoints

import fedtrust.error.FederationError
import fedtrust.types.{*, given}
import io.github.iltotore.iron.autoRefine
import munit.FunSuite

/** The request bindings and error mapping of spec section 8. */
class EndpointContractSuite extends FunSuite {

  private val leaf: EntityId        = "https://rp.example.org"
  private val trustAnchor: EntityId = "https://ta.example.org"

  test("a fetch request requires sub, and it must be an entity identifier") {
    assert(FetchRequest.fromParams(Params.empty).isLeft, "sub is REQUIRED")

    assertEquals(
      FetchRequest.fromParams(Params.of("sub" -> leaf.value)).map(_.sub),
      Right(leaf)
    )

    assert(FetchRequest.fromParams(Params.of("sub" -> "http://rp.example.org")).isLeft)
  }

  test("a fetch endpoint does not serve statements about itself") {
    // Section 8.1.2 recommends invalid_request here rather than not_found: the
    // issuer's own configuration lives at its well-known location instead.
    assert(FetchRequest.validateFor(FetchRequest(trustAnchor), trustAnchor).isLeft)
    assert(FetchRequest.validateFor(FetchRequest(leaf), trustAnchor).isRight)
  }

  test("a resolve request requires both sub and trust_anchor") {
    assert(ResolveRequest.fromParams(Params.of("sub" -> leaf.value)).isLeft)
    assert(ResolveRequest.fromParams(Params.of("trust_anchor" -> trustAnchor.value)).isLeft)

    val ok = ResolveRequest.fromParams(
      Params.of("sub" -> leaf.value, "trust_anchor" -> trustAnchor.value)
    )

    assertEquals(ok.map(_.sub), Right(leaf))
    assertEquals(ok.map(_.trustAnchors), Right(List(trustAnchor)))
  }

  test("trust_anchor may repeat") {
    val other: EntityId = "https://other.example.org"

    val request = ResolveRequest.fromParams(
      Params.of(
        "sub"          -> leaf.value,
        "trust_anchor" -> trustAnchor.value,
        "trust_anchor" -> other.value
      )
    )

    assertEquals(request.map(_.trustAnchors), Right(List(trustAnchor, other)))
  }

  test("a blank entity_type is rejected, not carried") {
    // Carried, it would match no metadata key and filter the response to
    // nothing while still looking like a successful request.
    val params = Params.of(
      "sub"          -> leaf.value,
      "trust_anchor" -> trustAnchor.value,
      "entity_type"  -> ""
    )

    ResolveRequest.fromParams(params) match {
      case Left(error: FederationError.InvalidRequest) =>
        assert(error.message.contains("entity_type"), error.message)
      case other => fail(s"expected invalid_request, got $other")
    }
  }

  test("resolve requests round trip through their parameters") {
    val request = ResolveRequest(
      sub = leaf,
      trustAnchors = List(trustAnchor),
      entityTypes = List(EntityType.OpenIdRelyingParty)
    )

    assertEquals(ResolveRequest.fromParams(ResolveRequest.toParams(request)), Right(request))
  }

  test("listing filters round trip, and booleans are validated") {
    val request = SubordinateListingRequest(
      entityTypes = List(EntityType.OpenIdProvider),
      trustMarked = Some(true),
      intermediate = Some(false)
    )

    assertEquals(
      SubordinateListingRequest.fromParams(SubordinateListingRequest.toParams(request)),
      Right(request)
    )

    assert(SubordinateListingRequest.fromParams(Params.of("trust_marked" -> "yes")).isLeft)
  }

  test("an endpoint must reject filters it does not implement") {
    // Section 8.2.1: answering unsupported_parameter is required, because
    // silently ignoring a filter tells the caller it was applied.
    val request = SubordinateListingRequest(trustMarked = Some(true))

    assert(SubordinateListingRequest.rejectUnsupported(request, Set.empty).isLeft)
    assert(SubordinateListingRequest.rejectUnsupported(request, Set("trust_marked")).isRight)
  }

  test("errors carry the code and status the specification recommends") {
    assertEquals(ErrorResponse.from(FederationError.InvalidRequest("bad"))._1, 400)
    assertEquals(ErrorResponse.from(FederationError.NotFound(leaf))._1, 404)
    assertEquals(ErrorResponse.from(FederationError.InvalidClient("no"))._1, 401)
    assertEquals(ErrorResponse.from(FederationError.TemporarilyUnavailable("later"))._1, 503)

    // An internal failure has no endpoint code of its own and reports
    // server_error, which is what section 8.9 asks for.
    val (status, body) = ErrorResponse.from(FederationError.MalformedJwt("truncated"))
    assertEquals(status, 500)
    assertEquals(body.error, "server_error")
    assertEquals(body.errorDescription, "truncated")
  }

  test("media types are a closed set") {
    MediaType.values.foreach { media =>
      assertEquals(MediaType.fromValue(media.value), Some(media))
    }

    assertEquals(MediaType.fromValue("application/xml"), None)
    assertEquals(MediaType.EntityStatement.value, "application/entity-statement+jwt")
  }
}
