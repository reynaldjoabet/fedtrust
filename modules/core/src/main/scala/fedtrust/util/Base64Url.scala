package fedtrust.util

import java.nio.charset.StandardCharsets.UTF_8
import java.util.Base64

import scala.util.Try

object Base64Url {

  def encode(bytes: Array[Byte]): String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(bytes)

  def encode(s: String): String =
    encode(s.getBytes(UTF_8))

  def decode(s: String): Either[String, Array[Byte]] =
    Try(Base64.getUrlDecoder.decode(s)).toEither.left
      .map(_ => "not valid base64url")

  def decodeString(s: String): Either[String, String] =
    decode(s).map(new String(_, UTF_8))
}
