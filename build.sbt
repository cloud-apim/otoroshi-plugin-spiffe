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
    assembly / assemblyMergeStrategy := { e =>
      e match {
        case PathList("io", "spiffe", xs @ _*) => MergeStrategy.first
        case PathList(ps @ _*) if ps.contains("module-info.class")          => MergeStrategy.first
        case PathList(ps @ _*) if ps.last == "io.netty.versions.properties" => MergeStrategy.first
        case x =>
          val oldStrategy = (assembly / assemblyMergeStrategy).value
          oldStrategy(x)
      }
    },
    libraryDependencies ++= Seq(
      "fr.maif" %% "otoroshi" % "17.15.0" % "provided",
      "io.spiffe" % "java-spiffe-core" % "0.8.5",
      "io.spiffe" % "grpc-netty-macos-aarch64" % "0.8.5",
      "io.spiffe" % "grpc-netty-macos" % "0.8.5",
      "io.spiffe" % "grpc-netty-linux" % "0.8.5",
      munit % Test
    )
  )