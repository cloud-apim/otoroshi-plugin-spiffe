package com.cloud.apim.otoroshi.plugins.spiffe

import com.github.blemale.scaffeine.Scaffeine
import io.spiffe.bundle.jwtbundle.JwtBundle
import io.spiffe.bundle.x509bundle.X509Bundle
import io.spiffe.spiffeid.{SpiffeId, TrustDomain}
import io.spiffe.svid.jwtsvid.JwtSvid
import io.spiffe.svid.x509svid.X509Svid
import io.spiffe.workloadapi._
import otoroshi.next.plugins.api.NgPluginConfig
import otoroshi.utils.syntax.implicits._
import play.api.libs.json._

import java.time.temporal.ChronoUnit
import java.util.concurrent.Executors
import java.util.concurrent.atomic.{AtomicBoolean, AtomicReference}
import scala.concurrent.duration.{DurationLong, FiniteDuration}
import scala.concurrent.{ExecutionContext, Future, Promise}
import scala.jdk.CollectionConverters._
import scala.util._

object SpiffeContext {
  val ec = ExecutionContext.fromExecutorService(Executors.newFixedThreadPool(Runtime.getRuntime.availableProcessors()))
  val certSourcesCache = Scaffeine()
    .maximumSize(100)
    .build[String, SpiffeCertSource]()
  val jwtSourcesCache = Scaffeine()
    .maximumSize(100)
    .build[String, SpiffeJwtSource]()
}

case class SpiffeConfig(domain: String, socketPath: Option[String] = None, timeout: Option[FiniteDuration] = None) extends NgPluginConfig {
  override def json: JsValue = SpiffeConfig.format.writes(this)
  def cacheKey: String = s"${domain}:::${socketPath.getOrElse("default")}:::${timeout.getOrElse("default")}"
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
  val default = SpiffeConfig("example.org", "unix:///tmp/spire-agent/public/api.sock".some, 10.seconds.some)
  val format = new Format[SpiffeConfig] {
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

object SpiffeCertSource {
  def apply(config: SpiffeConfig): SpiffeCertSource = new SpiffeCertSource(config)
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
          .applyOnWithOpt(config.timeout) {
            case (builder, timeout) => builder.initTimeout(java.time.Duration.of(timeout.toMillis, ChronoUnit.MILLIS))
          }
          .applyOnWithOpt(config.socketPath) {
            case (builder, path) => builder.spiffeSocketPath(path)
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
    }(SpiffeContext.ec)
  }

  def getBundle(domain: String = config.domain)(implicit ec: ExecutionContext): Future[X509Bundle] = {
    if (initialized.compareAndSet(false, true)) {
      init()
    }
    promise.future.map { source =>
      source.getBundleForTrustDomain(TrustDomain.parse(domain))
    }
  }

  def getSvid()(implicit ec: ExecutionContext): Future[X509Svid] = {
    if (initialized.compareAndSet(false, true)) {
      init()
    }
    promise.future.map { source =>
      source.getX509Svid
    }
  }

  def close(): Future[Unit] = {
    Future {
      if (initialized.get()) {
        // println("[cert] closing the source ...")
        ref.get().close()
      }
    }(SpiffeContext.ec)
  }
}

object SpiffeJwtSource {
  def apply(config: SpiffeConfig): SpiffeJwtSource = new SpiffeJwtSource(config)
}

class SpiffeJwtSource(config: SpiffeConfig) {

  private val initialized = new AtomicBoolean(false)
  private val ref = new AtomicReference[JwtSource]()
  private val promise = Promise[JwtSource]()

  private def init(): Unit = {
    // println("[jwt] initializing the source ...")
    Future {
      try {
        JwtSourceOptions
          .builder().build().toString
        val options = JwtSourceOptions
          .builder()
          .applyOnWithOpt(config.timeout) {
            case (builder, timeout) => builder.initTimeout(java.time.Duration.of(timeout.toMillis, ChronoUnit.MILLIS))
          }
          .applyOnWithOpt(config.socketPath) {
            case (builder, path) => builder.spiffeSocketPath(path)
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
    }(SpiffeContext.ec)
  }

  def getBundle(domain: String = config.domain)(implicit ec: ExecutionContext): Future[JwtBundle] = {
    if (initialized.compareAndSet(false, true)) {
      init()
    }
    promise.future.map { source =>
      source.getBundleForTrustDomain(TrustDomain.parse(domain))
    }
  }

  def getSvid(audience: String, id: Option[String] = None, extraAudience: Seq[String] = Seq.empty)(implicit ec: ExecutionContext): Future[JwtSvid] = {
    if (initialized.compareAndSet(false, true)) {
      init()
    }
    promise.future.map { source =>
      id match {
        case None => source.fetchJwtSvid(audience, extraAudience: _*)
        case Some(id) => source.fetchJwtSvid(SpiffeId.parse(id), audience, extraAudience: _*)
      }
    }
  }

  def close(): Future[Unit] = {
    Future {
      if (initialized.get()) {
        // println("[jwt] closing the source ...")
        ref.get().close()
      }
    }(SpiffeContext.ec)
  }
}
