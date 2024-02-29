package com.cloud.apim.otoroshi.plugins.spiffe.tests

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.cloud.apim.otoroshi.plugins.spiffe.{SpiffeCertSource, SpiffeConfig, SpiffeJwtSource}
import otoroshi.utils.syntax.implicits._

import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.util.concurrent.Executors
import scala.concurrent.ExecutionContext
import scala.concurrent.duration.DurationInt
import scala.jdk.CollectionConverters._

class SpiffeSourcesSpec extends munit.FunSuite {

  implicit val ec = ExecutionContext.fromExecutorService(Executors.newFixedThreadPool(20))

  val config = SpiffeConfig("example.org", "unix:///tmp/spire-agent/public/api.sock".some, 10.seconds.some)
  val jwtSource = SpiffeJwtSource(config)
  val certSource = SpiffeCertSource(config)

  test("SPIFFE Cert Source should fetch bundle and svid") {
    for {
      bundle <- certSource.getBundle()
      svid <- certSource.getSvid()
      _ <- certSource.close()
    } yield {
      println(s"just got a cert bundle of ${bundle.getX509Authorities.size()} authorities: ${bundle.getX509Authorities.asScala.map(_.getSubjectDN.getName)}")
      svid.getLeaf.getSubjectDN.getName.debugPrintln
      svid.getPrivateKey.getFormat.debugPrintln
    }
  }

  test("SPIFFE Jwt Source should fetch bundle and svid") {
    for {
      bundle <- jwtSource.getBundle()
      svid <- jwtSource.getSvid("foo", extraAudience = Seq("bar"))
      _ <- jwtSource.close()
    } yield {

      println(s"just got a jwt bundle of ${bundle.getJwtAuthorities.keySet()}")
      svid.getToken.debugPrintln
      val parts = svid.getToken.split("\\.").take(2).map(_.decodeBase64)
      parts.foreach { part =>
        part.parseJson.prettify.debugPrintln
      }
      val kid = parts(0).parseJson.select("kid").asString
      val alg = parts(0).parseJson.select("alg").asString
      Option(bundle.getJwtAuthorities.get(kid)).map { auth =>
        println(s"auth: ${auth}")
        val decoded = JWT.require(Algorithm.ECDSA256(auth.asInstanceOf[ECPublicKey], null)).acceptLeeway(10).build().verify(svid.getToken)
        println(s"validation ok: ${decoded}")
      }
    }
  }
}