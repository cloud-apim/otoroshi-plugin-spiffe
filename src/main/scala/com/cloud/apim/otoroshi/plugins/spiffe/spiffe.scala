package com.cloud.apim.otoroshi.plugins.spiffe

import com.github.blemale.scaffeine.{Cache, Scaffeine}
import io.spiffe.bundle.jwtbundle.JwtBundle
import io.spiffe.bundle.x509bundle.X509Bundle
import io.spiffe.spiffeid.{SpiffeId, TrustDomain}
import io.spiffe.svid.jwtsvid.JwtSvid
import io.spiffe.svid.x509svid.X509Svid
import io.spiffe.workloadapi.*
import otoroshi.next.plugins.api.NgPluginConfig
import otoroshi.utils.syntax.implicits.*
import play.api.libs.json.*

import java.security.cert.X509Certificate
import java.time.temporal.ChronoUnit
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.atomic.{AtomicBoolean, AtomicReference}
import scala.concurrent.duration.{DurationLong, FiniteDuration}
import scala.concurrent.{ExecutionContext, ExecutionContextExecutorService, Future, Promise}
import scala.util.*

extension (cert: X509Certificate) {
  /** stable otoroshi entity id for a SPIFFE delivered certificate */
  def spiffeCertId: String = s"cert_${Base64.getEncoder.encodeToString(cert.getSignature)}"
}

object SpiffeContext {

  val ec: ExecutionContextExecutorService =
    ExecutionContext.fromExecutorService(Executors.newFixedThreadPool(Runtime.getRuntime.availableProcessors()))

  private val certSourcesCache: Cache[String, SpiffeCertSource] = Scaffeine()
    .maximumSize(100)
    .build[String, SpiffeCertSource]()

  private val jwtSourcesCache: Cache[String, SpiffeJwtSource] = Scaffeine()
    .maximumSize(100)
    .build[String, SpiffeJwtSource]()

  def certSource(config: SpiffeConfig): SpiffeCertSource = certSourcesCache.synchronized {
    certSourcesCache.get(config.cacheKey, _ => SpiffeCertSource(config))
  }

  def jwtSource(config: SpiffeConfig): SpiffeJwtSource = jwtSourcesCache.synchronized {
    jwtSourcesCache.get(config.cacheKey, _ => SpiffeJwtSource(config))
  }
}

case class SpiffeConfig(domain: String, socketPath: Option[String] = None, timeout: Option[FiniteDuration] = None) extends NgPluginConfig {
  override def json: JsValue = SpiffeConfig.format.writes(this)
  def cacheKey: String = s"${domain}:::${socketPath.getOrElse("default")}:::${timeout.fold("default")(_.toMillis.toString)}"
}

object SpiffeConfig {

  val configFlow: Seq[String] = Seq(
    "domain",
    "socket_path",
    "timeout",
  )

  val configSchema: Option[JsObject] = Json.obj(
    "domain" -> Json.obj(
      "type" -> "string",
      "label" -> "SPIFFE domain",
    ),
    "socket_path" -> Json.obj(
      "type" -> "string",
      "label" -> "SPIFFE agent UNIX socket path",
    ),
    "timeout" -> Json.obj(
      "type" -> "number",
      "label" -> "agent timeout",
      "suffix" -> "ms.",
      "props" -> Json.obj(
        "suffix" -> "ms."
      )
    )
  ).some

  val default: SpiffeConfig = SpiffeConfig("example.org", "unix:///tmp/spire-agent/public/api.sock".some, 10.seconds.some)

  given format: Format[SpiffeConfig] = new Format[SpiffeConfig] {

    override def reads(json: JsValue): JsResult[SpiffeConfig] = Try {
      SpiffeConfig(
        domain = json.select("domain").asString,
        socketPath = json.select("socket_path").asOpt[String].filterNot(_.trim.isBlank),
        timeout = json.select("timeout").asOpt[Long].map(_.millis),
      )
    } match {
      case Failure(e) => JsError(e.getMessage)
      case Success(s) => JsSuccess(s)
    }

    override def writes(o: SpiffeConfig): JsValue = Json.obj(
      "domain" -> o.domain,
      "socket_path" -> o.socketPath.map(_.json).getOrElse(JsNull).asValue,
      "timeout" -> o.timeout.map(_.toMillis.json).getOrElse(JsNull).asValue,
    )
  }
}

class SpiffeCertSource(config: SpiffeConfig) {

  private val initialized = new AtomicBoolean(false)
  private val ref = new AtomicReference[DefaultX509Source]()
  private val promise = Promise[DefaultX509Source]()

  private def init(): Unit = {
    // println("[cert] initializing the source ...")
    Future {
      try {
        val options = DefaultX509Source.X509SourceOptions
          .builder()
          .applyOnWithOpt(config.timeout) { (builder, timeout) =>
            builder.initTimeout(java.time.Duration.of(timeout.toMillis, ChronoUnit.MILLIS))
          }
          .applyOnWithOpt(config.socketPath) { (builder, path) =>
            builder.spiffeSocketPath(path)
          }
          .build()
        val x509Source = DefaultX509Source.newSource(options)
        // println("[cert] initialization done !")
        ref.set(x509Source)
        promise.trySuccess(x509Source)
      } catch {
        case e: Throwable =>
          promise.tryFailure(e)
          e.printStackTrace()
      }
    }(using SpiffeContext.ec)
  }

  private def source(): Future[DefaultX509Source] = {
    if (initialized.compareAndSet(false, true)) {
      init()
    }
    promise.future
  }

  def getBundle(domain: String = config.domain)(using ec: ExecutionContext): Future[X509Bundle] = {
    source().map(_.getBundleForTrustDomain(TrustDomain.parse(domain)))
  }

  def getSvid()(using ec: ExecutionContext): Future[X509Svid] = {
    source().map(_.getX509Svid)
  }

  def close(): Future[Unit] = {
    Future {
      if (initialized.get()) {
        // println("[cert] closing the source ...")
        ref.get().close()
      }
    }(using SpiffeContext.ec)
  }
}

class SpiffeJwtSource(config: SpiffeConfig) {

  private val initialized = new AtomicBoolean(false)
  private val ref = new AtomicReference[JwtSource]()
  private val promise = Promise[JwtSource]()

  private def init(): Unit = {
    // println("[jwt] initializing the source ...")
    Future {
      try {
        val options = JwtSourceOptions
          .builder()
          .applyOnWithOpt(config.timeout) { (builder, timeout) =>
            builder.initTimeout(java.time.Duration.of(timeout.toMillis, ChronoUnit.MILLIS))
          }
          .applyOnWithOpt(config.socketPath) { (builder, path) =>
            builder.spiffeSocketPath(path)
          }
          .build()
        val jwtSource = DefaultJwtSource.newSource(options)
        // println("[jwt] initialization done !")
        ref.set(jwtSource)
        promise.trySuccess(jwtSource)
      } catch {
        case e: Throwable =>
          promise.tryFailure(e)
          e.printStackTrace()
      }
    }(using SpiffeContext.ec)
  }

  private def source(): Future[JwtSource] = {
    if (initialized.compareAndSet(false, true)) {
      init()
    }
    promise.future
  }

  def getBundle(domain: String = config.domain)(using ec: ExecutionContext): Future[JwtBundle] = {
    source().map(_.getBundleForTrustDomain(TrustDomain.parse(domain)))
  }

  def getSvid(audience: String, id: Option[String] = None, extraAudience: Seq[String] = Seq.empty)(using ec: ExecutionContext): Future[JwtSvid] = {
    source().map { src =>
      id match {
        case None           => src.fetchJwtSvid(audience, extraAudience*)
        case Some(spiffeId) => src.fetchJwtSvid(SpiffeId.parse(spiffeId), audience, extraAudience*)
      }
    }
  }

  def close(): Future[Unit] = {
    Future {
      if (initialized.get()) {
        // println("[jwt] closing the source ...")
        ref.get().close()
      }
    }(using SpiffeContext.ec)
  }
}
