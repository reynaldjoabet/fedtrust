package fedtrust.util

import java.time.Instant

import io.circe.{Decoder, Encoder}

/** JWT `iat` / `exp` / `nbf` are NumericDate: seconds since the epoch.
  *
  * circe's default `Instant` codecs use ISO-8601 strings, so these are imported
  * explicitly wherever a claim is encoded. An explicit import outranks the
  * companion-scope instance.
  */
object NumericDate {
  given Encoder[Instant] = Encoder.encodeLong.contramap(_.getEpochSecond)
  given Decoder[Instant] = Decoder.decodeLong.map(Instant.ofEpochSecond)
}
