package fedtrust

import java.nio.charset.StandardCharsets.UTF_8
import java.time.Instant
import java.util.Base64

import scala.util.Try

import com.github.plokhotnyuk.jsoniter_scala.circe.JsoniterScalaCodec
import com.github.plokhotnyuk.jsoniter_scala.core.{
  JsonValueCodec,
  readFromArray,
  readFromString,
  writeToString
}
import io.circe.{Decoder, Encoder}

/** Small helpers with no domain of their own.
  *
  * An object rather than a package - the Scala 3 replacement for a package
  * object - because these are three short vocabularies rather than three
  * concerns worth separate files. Anything here that grows a domain belongs in
  * a module of its own instead.
  */
object util {

  object Base64Url {

    def encode(bytes: Array[Byte]): String =
      Base64.getUrlEncoder.withoutPadding.encodeToString(bytes)

    def encode(s: String): String = encode(s.getBytes(UTF_8))

    def decode(s: String): Either[String, Array[Byte]] =
      Try(Base64.getUrlDecoder.decode(s)).toEither.left.map(_ => "not valid base64url")

    def decodeString(s: String): Either[String, String] =
      decode(s).map(new String(_, UTF_8))
  }

  /** JWT `iat` / `exp` / `nbf` are NumericDate: seconds since the epoch.
    *
    * circe's default `Instant` codecs use ISO-8601 strings, so these are
    * imported explicitly wherever a claim is encoded. An explicit import
    * outranks the companion-scope instance.
    */
  object NumericDate {
    given Encoder[Instant] = Encoder.encodeLong.contramap(_.getEpochSecond)
    given Decoder[Instant] = Decoder.decodeLong.map(Instant.ofEpochSecond)
  }

  /** JSON parsing, on jsoniter-scala.
    *
    * The values this library parses are circe's `Json`, not case classes, and
    * that is a requirement rather than a preference: an entity statement
    * carries metadata for entity types this build has never heard of and policy
    * operators it does not implement, and all of it has to survive being read,
    * carried through resolution, and handed to the caller. A code-generated
    * codec for a closed set of case classes cannot represent that.
    *
    * jsoniter-scala-circe resolves the tension — jsoniter's reader filling
    * circe's AST — so the parser is the fast one while the representation stays
    * open. Every statement in every chain goes through here.
    *
    * Named in lower case so that importing it does not collide with
    * `io.circe.Json`, which callers almost always want in the same scope.
    */
  object json {

    /** Statements are parsed before anything has verified them, so the depth
      * limit is a guard against a hostile payload, not a tuning knob: circe's
      * `Json` is a recursive structure and an unbounded parse of deeply nested
      * input is a stack overflow.
      */
    private val MaxDepth = 64

    private given JsonValueCodec[io.circe.Json] = JsoniterScalaCodec.jsonCodec(MaxDepth)

    def parse(raw: String): Either[String, io.circe.Json] =
      Try(readFromString[io.circe.Json](raw)).toEither.left.map(messageOf)

    def parse(bytes: Array[Byte]): Either[String, io.circe.Json] =
      Try(readFromArray[io.circe.Json](bytes)).toEither.left.map(messageOf)

    def print(value: io.circe.Json): String = writeToString(value)

    def decode[A: Decoder](raw: String): Either[String, A] =
      parse(raw).flatMap(Decoder[A].decodeJson(_).left.map(_.getMessage))

    private def messageOf(error: Throwable): String =
      Option(error.getMessage).getOrElse(error.getClass.getSimpleName)
  }
}
