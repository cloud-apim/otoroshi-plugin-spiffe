import Dependencies._

ThisBuild / scalaVersion     := "3.8.4"
ThisBuild / version          := "1.0.0-dev"
ThisBuild / organization     := "com.cloud-apim"
ThisBuild / organizationName := "Cloud-APIM"

lazy val root = (project in file("."))
  .settings(
    name := "otoroshi-plugin-spiffe",
    scalacOptions ++= Seq(
      "-deprecation",
      "-feature",
      // wasm4s-bundle (transitive, provided) embeds an older scala 3 stdlib where `scala.caps` is
      // an object while scala-library 3.8.4 declares it as a package. Same suppression as otoroshi.
      "-Wconf:msg=package scala contains object and package with same name:s",
    ),
    assembly / test  := {},
    assembly / assemblyJarName := "otoroshi-plugin-spiffe-assembly_3-dev.jar",
    assembly / assemblyMergeStrategy := {
      case PathList("io", "spiffe", _ @ _*)                               => MergeStrategy.first
      case PathList(ps @ _*) if ps.contains("module-info.class")          => MergeStrategy.first
      case PathList(ps @ _*) if ps.last == "io.netty.versions.properties" => MergeStrategy.first
      case path                                                          => MergeStrategy.defaultMergeStrategy(path)
    },
    libraryDependencies ++= Seq(
      "fr.maif" %% "otoroshi" % "18.0.0-preview2" % "provided",
      "io.spiffe" % "java-spiffe-core" % "0.8.5",
      "io.spiffe" % "grpc-netty-macos-aarch64" % "0.8.5",
      "io.spiffe" % "grpc-netty-macos" % "0.8.5",
      "io.spiffe" % "grpc-netty-linux" % "0.8.5",
      munit % Test
    )
  )
