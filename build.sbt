import Dependencies._

ThisBuild / scalaVersion := "3.3.8"
ThisBuild / version      := "0.1.0-SNAPSHOT"

ThisBuild / scalacOptions := Seq(
  "-encoding",
  "UTF-8",
  "-no-indent",
  "-deprecation",
  "-feature",
  "-unchecked",
  "-source:3.3",
  "-java-output-version:17",
  "-Werror",
  "-Wvalue-discard",
  "-Wnonunit-statement",
  "-Xlint:all",
  "-Xcheck-macros",
  "-Xmax-inlines:64",
  "-Ysafe-init"
)

// Publishing identity. Every module inherits it; `examples` and the root
// aggregate opt out of publishing individually.
ThisBuild / organization     := "io.github.reynaldjoabet"
ThisBuild / organizationName := "fedtrust"
ThisBuild / homepage         := Some(uri("https://github.com/reynaldjoabet/fedtrust"))
ThisBuild / licenses      := Seq("Apache-2.0" -> uri("https://www.apache.org/licenses/LICENSE-2.0"))
ThisBuild / startYear     := Some(2026)
ThisBuild / versionScheme := Some("early-semver")

lazy val commonSettings = Seq(
  libraryDependencies ++= testDeps
)

// The root is an aggregate only: no sources of its own, so nothing outside
// modules/ is ever compiled into a published artifact.
lazy val root = project
  .in(file("."))
  .aggregate(core, jose, resolver, endpoints, http4sBackend, testkit, examples)
  .settings(
    name                                 := "fedtrust",
    publish / skip                       := true,
    Compile / unmanagedSourceDirectories := Nil,
    Test / unmanagedSourceDirectories    := Nil
  )

// Data model, JSON codecs, errors. circe + cats-core only: no I/O and no
// crypto, so core stays cross-buildable to JS/Native if that is ever wanted.
lazy val core = project
  .in(file("modules/core"))
  .settings(commonSettings)
  .settings(
    name := "fedtrust-core",
    libraryDependencies ++= Seq(catsCore, iron, ironCirce, jsoniterCore, jsoniterCirce) ++ circeAll
  )

// Signing and verification. Pins the crypto backend, which is the reason this
// is a module boundary and not a package inside core.
lazy val jose = project
  .in(file("modules/jose"))
  .dependsOn(core)
  .settings(commonSettings)
  .settings(
    name := "fedtrust-jose",
    libraryDependencies += nimbusJoseJwt
  )

// Trust Chain building and validation, metadata policy, constraints, and the
// resolution that turns a chain into Resolved Metadata. Declares the abstract
// EntityStatementFetcher; depends on no concrete HTTP client.
lazy val resolver = project
  .in(file("modules/resolver"))
  .dependsOn(core, jose)
  .settings(commonSettings)
  .settings(
    name := "fedtrust-resolver",
    libraryDependencies ++= Seq(catsEffect, iron)
  )

// Request and response contracts for the federation endpoints (spec section
// 8). Types and bindings only - routes belong to whichever server stack the
// caller runs, the same way fetching belongs to their client stack.
lazy val endpoints = project
  .in(file("modules/endpoints"))
  .dependsOn(core, resolver)
  .settings(commonSettings)
  .settings(name := "fedtrust-endpoints", libraryDependencies += iron)

// One module per HTTP backend; users pick the one matching their stack.
lazy val http4sBackend = project
  .in(file("modules/http4s"))
  .dependsOn(resolver, testkit % Test)
  .settings(commonSettings)
  .settings(
    name := "fedtrust-http4s",
    libraryDependencies ++= Seq(http4sClient, http4sCirce, emberClient % Test)
  )

// In-memory federations for tests: a TA -> intermediate -> leaf tree with no
// servers to stand up. Published, because downstream users testing against
// their own federation need it as much as this build does.
lazy val testkit = project
  .in(file("modules/testkit"))
  .dependsOn(resolver)
  .settings(commonSettings)
  .settings(name := "fedtrust-testkit")

// Compiled, never published. An example that will not compile is an API
// problem reported before a user hits it.
lazy val examples = project
  .in(file("modules/examples"))
  .dependsOn(resolver, endpoints, testkit, http4sBackend)
  .settings(commonSettings)
  .settings(
    name           := "fedtrust-examples",
    publish / skip := true
  )
