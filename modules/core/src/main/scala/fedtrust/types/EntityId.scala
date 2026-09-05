package fedtrust.types

import java.net.URI

import scala.util.Try

import io.circe.{Decoder, Encoder}

/** An Entity Identifier: an https URL with no query or fragment component.
  *
  * OpenID Federation 1.0, section 1.2.
  */
opaque type EntityId = String

object EntityId {

  def apply(raw: String): Either[String, EntityId] =
    Try(new URI(raw)).toEither.left
      .map(_ => s"not a valid URI: $raw")
      .flatMap { uri =>
        if (uri.getScheme != "https") Left(s"entity identifier must use https: $raw")
        else if (uri.getHost == null) Left(s"entity identifier must have a host: $raw")
        else if (uri.getRawQuery != null || uri.getRawFragment != null)
          Left(s"entity identifier must have no query or fragment: $raw")
        else Right(raw)
      }

  /** For literals known to be well formed, and for test fixtures. */
  def unsafe(raw: String): EntityId =
    apply(raw).fold(msg => throw new IllegalArgumentException(msg), identity)

  extension (id: EntityId) {
    def value: String = id

    /** The entity's federation entity configuration location.
      *
      * The well-known path segment is inserted after the host, ahead of any
      * path the identifier already carries.
      */
    def wellKnownUri: String = {
      val uri  = new URI(id)
      val path = Option(uri.getRawPath).filter(_ != "/").getOrElse("")
      s"${uri.getScheme}://${uri.getRawAuthority}/.well-known/openid-federation$path"
    }
  }

  given Encoder[EntityId] = Encoder.encodeString.contramap(identity)
  given Decoder[EntityId] = Decoder.decodeString.emap(apply)

  given Ordering[EntityId] = Ordering.String
}
