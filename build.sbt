import Dependencies._

ThisBuild / scalaVersion     := "2.12.13"
ThisBuild / version          := "1.0.0-dev"
ThisBuild / organization     := "com.cloud-apim"
ThisBuild / organizationName := "Cloud-APIM"

lazy val root = (project in file("."))
  .settings(
    name := "otoroshi-plugin-spiffe",
    resolvers += "jitpack" at "https://jitpack.io",
    assembly / test  := {},
    assembly / assemblyJarName := "otoroshi-plugin-spiffe-assembly_2.12-dev.jar",
    libraryDependencies ++= Seq(
      "fr.maif" %% "otoroshi" % "16.14.0" % "provided",
      "io.spiffe" % "java-spiffe-core" % "0.8.5",
      "io.spiffe" % "grpc-netty-macos-aarch64" % "0.8.5",
      "io.spiffe" % "grpc-netty-macos" % "0.8.5",
      "io.spiffe" % "grpc-netty-linux" % "0.8.5",
      munit % Test
    )
  )