import sbt.*

object Dependencies {

  object V {
    val cats            = "2.13.0"
    val catsEffect      = "3.7.1"
    val circe           = "0.14.16"
    val http4s          = "0.23.36"
    val nimbusJose      = "10.9.1"
    val munit           = "1.3.6"
    val munitScalacheck = "1.3.1"
    val munitCatsEffect = "2.2.0"
  }

  val catsCore   = "org.typelevel" %% "cats-core"   % V.cats
  val catsEffect = "org.typelevel" %% "cats-effect" % V.catsEffect

  val circeCore   = "io.circe" %% "circe-core"   % V.circe
  val circeParser = "io.circe" %% "circe-parser" % V.circe
  val circe       = Seq(circeCore, circeParser)

  // The only crypto dependency in the build; confined to the `jose` module.
  val nimbusJose = "com.nimbusds" % "nimbus-jose-jwt" % V.nimbusJose

  // Backend modules compile against http4s-client only. ember is test scope:
  // users bring their own client implementation.
  val http4sClient = "org.http4s" %% "http4s-client"       % V.http4s
  val http4sCirce  = "org.http4s" %% "http4s-circe"        % V.http4s
  val http4sEmber  = "org.http4s" %% "http4s-ember-client" % V.http4s

  val munit           = "org.scalameta" %% "munit" % V.munit
  val munitScalacheck =
    "org.scalameta" %% "munit-scalacheck" % V.munitScalacheck
  val munitCatsEffect =
    "org.typelevel" %% "munit-cats-effect" % V.munitCatsEffect

  val testDeps = Seq(munit, munitScalacheck, munitCatsEffect).map(_ % Test)
}
