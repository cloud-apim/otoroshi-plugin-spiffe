import Dependencies._

ThisBuild / scalaVersion     := "3.8.4"
ThisBuild / version          := "1.0.0-dev"
ThisBuild / organization     := "com.cloud-apim"
ThisBuild / organizationName := "Cloud-APIM"

// The assembly jar is loaded next to the otoroshi runtime, so any netty it embeds shadows the one
// otoroshi ships. Keep nettyVersion in sync with `nettyVersion` in otoroshi/otoroshi/build.sbt:
// 4.1 and 4.2 publish the same class names with incompatible signatures (netty-codec was split
// into netty-codec-base in 4.2), so a stale copy here fails at runtime, not at build time.
lazy val nettyVersion  = "4.2.17.Final"
// java-spiffe 0.8.5 pinned grpc 1.61.1 / netty 4.1.106; 0.8.17 moved to netty 4.2.
lazy val spiffeVersion = "0.8.17"
// java-spiffe 0.8.17 resolves grpc 1.80.0, which still asks for netty 4.1.130. grpc-java only
// switched to netty 4.2 in the 1.83 line, so bump grpc too rather than dragging 4.1 back in.
lazy val grpcVersion   = "1.83.1"
// otoroshi ships 10.9.1, java-spiffe asks for 10.9.
lazy val nimbusVersion = "10.9.1"

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
    assembly / assemblyPackageScala / assembleArtifact := false,
    assembly / assemblyMergeStrategy := {
      case PathList("io", "spiffe", _ @ _*)                               => MergeStrategy.first
      case PathList(ps @ _*) if ps.contains("module-info.class")          => MergeStrategy.first
      case PathList(ps @ _*) if ps.last == "io.netty.versions.properties" => MergeStrategy.first
      case path                                                          => MergeStrategy.defaultMergeStrategy(path)
    },
    libraryDependencies ++= Seq(
      "fr.maif" %% "otoroshi" % "18.0.0-preview6" % "provided",
      "io.spiffe" % "java-spiffe-core" % spiffeVersion,
      "io.spiffe" % "grpc-netty-macos-aarch64" % spiffeVersion,
      "io.spiffe" % "grpc-netty-macos" % spiffeVersion,
      "io.spiffe" % "grpc-netty-linux" % spiffeVersion,
      munit % Test
    ),
    // java-spiffe pulls grpc/netty transitively at its own pace, so pin both lines here instead of
    // letting the highest transitive wins rule decide.
    dependencyOverrides ++= Seq(
      "io.grpc"      % "grpc-api"                            % grpcVersion,
      "io.grpc"      % "grpc-core"                           % grpcVersion,
      "io.grpc"      % "grpc-netty"                          % grpcVersion,
      "io.grpc"      % "grpc-netty-shaded"                   % grpcVersion,
      "io.grpc"      % "grpc-protobuf"                       % grpcVersion,
      "io.grpc"      % "grpc-protobuf-lite"                  % grpcVersion,
      "io.grpc"      % "grpc-stub"                           % grpcVersion,
      "io.grpc"      % "grpc-util"                           % grpcVersion,
      "io.netty"     % "netty-buffer"                        % nettyVersion,
      "io.netty"     % "netty-codec"                         % nettyVersion,
      "io.netty"     % "netty-codec-base"                    % nettyVersion,
      "io.netty"     % "netty-codec-compression"             % nettyVersion,
      "io.netty"     % "netty-codec-http"                    % nettyVersion,
      "io.netty"     % "netty-codec-http2"                   % nettyVersion,
      "io.netty"     % "netty-codec-socks"                   % nettyVersion,
      "io.netty"     % "netty-common"                        % nettyVersion,
      "io.netty"     % "netty-handler"                       % nettyVersion,
      "io.netty"     % "netty-handler-proxy"                 % nettyVersion,
      "io.netty"     % "netty-resolver"                      % nettyVersion,
      "io.netty"     % "netty-transport"                     % nettyVersion,
      "io.netty"     % "netty-transport-classes-kqueue"      % nettyVersion,
      "io.netty"     % "netty-transport-native-kqueue"       % nettyVersion,
      "io.netty"     % "netty-transport-native-unix-common"  % nettyVersion,
      "com.nimbusds" % "nimbus-jose-jwt"                     % nimbusVersion,
    )
  )
