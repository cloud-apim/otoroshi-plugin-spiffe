package otoroshi_plugins.com.cloud.apim.plugins.spiffe

import akka.stream.Materializer
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.cloud.apim.otoroshi.plugins.spiffe.{SpiffeCertSource, SpiffeConfig, SpiffeContext, SpiffeJwtSource}
import com.google.common.base.Charsets
import io.spiffe.svid.x509svid.X509Svid
import otoroshi.env.Env
import otoroshi.gateway.Errors
import otoroshi.next.plugins.api._
import otoroshi.script._
import otoroshi.ssl.Cert
import otoroshi.ssl.SSLImplicits._
import otoroshi.utils.http.DN
import otoroshi.utils.syntax.implicits._
import play.api.libs.json.{JsObject, JsSuccess, JsValue, Json}
import play.api.mvc.{Result, Results}

import java.security.cert.X509Certificate
import java.security.interfaces.{ECPublicKey, RSAPublicKey}
import java.util.Base64
import scala.concurrent._
import scala.concurrent.duration.{DurationInt, DurationLong, FiniteDuration}
import scala.jdk.CollectionConverters._
import scala.util._

class SpiffeClientCertValidator extends NgAccessValidator {

  override def name: String                                = "Cloud APIM - SPIFFE client cert validator"
  override def description: Option[String]                 = "This plugin validates if the incoming request has been made with a SPIFFE generated client certificate".some
  override def multiInstance: Boolean                      = true
  override def core: Boolean                               = false
  override def visibility: NgPluginVisibility              = NgPluginVisibility.NgUserLand
  override def categories: Seq[NgPluginCategory]           = Seq(NgPluginCategory.AccessControl, NgPluginCategory.Security)
  override def steps: Seq[NgStep]                          = Seq(NgStep.ValidateAccess)
  override def defaultConfigObject: Option[NgPluginConfig] = SpiffeConfig.default.some
  override def noJsForm: Boolean = true
  override def configFlow: Seq[String] = SpiffeConfig.configFlow
  override def configSchema: Option[JsObject] = SpiffeConfig.configSchema

  private def getSource(config: SpiffeConfig): SpiffeCertSource = SpiffeContext.certSourcesCache.synchronized {
    SpiffeContext.certSourcesCache.get(config.cacheKey, _ => {
      SpiffeCertSource(config)
    })
  }

  override def start(env: Env): Future[Unit] = {
    env.logger.info(s"[Cloud APIM] the '${name}' plugin is available !")
    ().vfuture
  }

  override def access(ctx: NgAccessContext)(implicit env: Env, ec: ExecutionContext): Future[NgAccess] = {
    val pluginConfig = ctx
      .cachedConfig(internalName)(SpiffeConfig.format)
      .getOrElse(SpiffeConfig.default)
    ctx.request.clientCertificateChain match {
      case Some(clientCertChain) if clientCertChain.nonEmpty => {
        val clientCert = clientCertChain.head
        val clientDn = DN(clientCert.getSubjectDN.getName)
        val source = getSource(pluginConfig)
        source.getBundle().flatMap { bundle =>
          val exists = bundle.getX509Authorities.asScala.exists(cert => DN(cert.getSubjectDN.getName).isEqualsTo(clientDn))
          if (exists) {
            NgAccess.NgAllowed.vfuture
          } else {
            Errors
              .craftResponseResult(
                "unauthorized",
                Results.Unauthorized,
                ctx.request,
                None,
                None,
                attrs = ctx.attrs,
                maybeRoute = ctx.route.some
              )
              .map(r => NgAccess.NgDenied(r))
          }
        }
      }
      case _ => {
        Errors
          .craftResponseResult(
            "unauthorized",
            Results.Unauthorized,
            ctx.request,
            None,
            None,
            attrs = ctx.attrs,
            maybeRoute = ctx.route.some
          )
          .map(r => NgAccess.NgDenied(r))
      }
    }
  }
}

class SpiffeClientCertRequest extends NgRequestTransformer {

  override def name: String                                = "Cloud APIM - SPIFFE client cert request"
  override def description: Option[String]                 = "This plugin injects a SPIFFE client certificate in the current request".some
  override def multiInstance: Boolean                      = true
  override def core: Boolean                               = false
  override def visibility: NgPluginVisibility              = NgPluginVisibility.NgUserLand
  override def categories: Seq[NgPluginCategory]           = Seq(NgPluginCategory.Security)
  override def steps: Seq[NgStep]                          = Seq(NgStep.TransformRequest)
  override def defaultConfigObject: Option[NgPluginConfig] = SpiffeConfig.default.some
  override def noJsForm: Boolean = true
  override def configFlow: Seq[String] = SpiffeConfig.configFlow
  override def configSchema: Option[JsObject] = SpiffeConfig.configSchema

  private def getSource(config: SpiffeConfig): SpiffeCertSource = SpiffeContext.certSourcesCache.synchronized {
    SpiffeContext.certSourcesCache.get(config.cacheKey, _ => {
      SpiffeCertSource(config)
    })
  }

  private def computeCertId(cert: X509Certificate): String = {
    "cert_" + new String(Base64.getEncoder.encode(cert.getSignature), Charsets.UTF_8)
  }

  private def registerMissingCerts(certs: Seq[X509Certificate])(implicit env: Env, executionContext: ExecutionContext): Unit = {
    certs.foreach { cert =>
      val id = computeCertId(cert)
      if (env.proxyState.certificate(id).isEmpty) {
        val ncert = Cert(
          id = id,
          name = s"SPIFFE temporary cert",
          description = s"SPIFFE temporary cert",
          chain = cert.asPem,
          privateKey = "",
          caRef = None,
          autoRenew = false,
          client = false,
          exposed = false,
          revoked = false,
          entityMetadata = Map("spiffe-gen-cert" -> "true")
        ).enrich()
        val certs = env.proxyState.allCertificates() ++ Seq(ncert)
        env.proxyState.updateCertificates(certs)
        ncert.save().map(_ => ())
      }
    }
  }

  private def registerMissingCert(svid: X509Svid)(implicit env: Env, executionContext: ExecutionContext): Unit = {
    val id = computeCertId(svid.getLeaf)
    if (env.proxyState.certificate(id).isEmpty) {
      val ncert = Cert(
        id = id,
        name = s"SPIFFE temporary cert",
        description = s"SPIFFE temporary cert",
        chain = svid.getChain.asScala.map(_.asPem).mkString("\n\n"),
        privateKey = svid.getPrivateKey.asPem,
        caRef = None,
        autoRenew = false,
        client = false,
        exposed = false,
        revoked = false,
        entityMetadata = Map("spiffe-gen-cert" -> "true")
      ).enrich()
      val certs = env.proxyState.allCertificates() ++ Seq(ncert)
      env.proxyState.updateCertificates(certs)
      ncert.save().map(_ => ())
    }
  }

  override def transformRequest(ctx: NgTransformerRequestContext)(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[Result, NgPluginHttpRequest]] = {
    val pluginConfig = ctx
      .cachedConfig(internalName)(SpiffeConfig.format)
      .getOrElse(SpiffeConfig.default)
    val source = getSource(pluginConfig)
    for {
      bundle <- source.getBundle()
      svid <- source.getSvid()
    } yield {
      registerMissingCerts(bundle.getX509Authorities.asScala.toSeq)
      registerMissingCert(svid)
      val svidId = computeCertId(svid.getLeaf)
      ctx.otoroshiRequest.copy(
        clientCertificateChain = () => {
          svid.getChain.asScala.some
        },
        backend = ctx.otoroshiRequest.backend.map { target =>
          target.copy(
            tlsConfig = target.tlsConfig.copy(
              enabled = true,
              certs = Seq(svidId),
              trustedCerts = bundle.getX509Authorities.asScala.toSeq.map(c => computeCertId(c))
            )
          )
        }
      ).right
    }
  }
}

class SpiffeJwtValidator extends NgAccessValidator {

  override def name: String                                = "Cloud APIM - SPIFFE JWT validator"
  override def description: Option[String]                 = "This plugin validates if the incoming request has been made with a SPIFFE generated JWT token".some
  override def multiInstance: Boolean                      = true
  override def core: Boolean                               = false
  override def visibility: NgPluginVisibility              = NgPluginVisibility.NgUserLand
  override def categories: Seq[NgPluginCategory]           = Seq(NgPluginCategory.AccessControl, NgPluginCategory.Security)
  override def steps: Seq[NgStep]                          = Seq(NgStep.ValidateAccess)
  override def defaultConfigObject: Option[NgPluginConfig] = JsonNgPluginConfig(SpiffeConfig.default.json.asObject ++ Json.obj(
    "header_name" -> "Authorization",
    "header_prefix" -> "Bearer ",
  )).some
  override def noJsForm: Boolean = true
  override def configFlow: Seq[String] = SpiffeConfig.configFlow ++ Seq(
    "audience",
    "extra_audience",
    "header_name",
    "header_prefix",
  )
  override def configSchema: Option[JsObject] = SpiffeConfig.configSchema.map(_.asObject ++ Json.obj(
    "audience" -> Json.obj(
      "type" -> "string",
      "label" -> "JWT audience",
    ),
    "extra_audience" -> Json.obj(
      "type" -> "array",
      "label" -> "JWT extra audience",
    ),
    "header_name" -> Json.obj(
      "type" -> "string",
      "label" -> "JWT header name",
    ),
    "header_prefix" -> Json.obj(
      "type" -> "string",
      "label" -> "JWT header prefix",
    ),
  ))

  private def getSource(config: SpiffeConfig): SpiffeJwtSource = SpiffeContext.jwtSourcesCache.synchronized {
    SpiffeContext.jwtSourcesCache.get(config.cacheKey, _ => {
      SpiffeJwtSource(config)
    })
  }

  override def start(env: Env): Future[Unit] = {
    env.logger.info(s"[Cloud APIM] the '${name}' plugin is available !")
    ().vfuture
  }

  override def access(ctx: NgAccessContext)(implicit env: Env, ec: ExecutionContext): Future[NgAccess] = {
    val pluginConfig = ctx
      .cachedConfig(internalName)(SpiffeConfig.format)
      .getOrElse(SpiffeConfig.default)
    val moreConfig = ctx
      .cachedConfigFn(internalName)(v => v.some)
      .getOrElse(Json.obj())
    val audience = moreConfig.select("audience").asOpt[String].filterNot(_.trim.isBlank)
    val extraAudience = moreConfig.select("extra_audience").asOpt[Seq[String]].getOrElse(Seq.empty)
    ctx.request.headers.get("Authorization").map(_.replace("Bearer ", "").replace("bearer ", "")) match {
      case Some(bearer) if bearer.split("\\.").length == 3 => {
        val source = getSource(pluginConfig)
        source.getBundle().flatMap { bundle =>
          val parts = bearer.split("\\.").take(2).map(_.decodeBase64)
          val header = parts(0).parseJson
          val kid = header.select("kid").asString
          val alg = header.select("alg").asString
          Option(bundle.getJwtAuthorities.get(kid)) match {
            case None => {
              Errors
                .craftResponseResult(
                  "unauthorized",
                  Results.Unauthorized,
                  ctx.request,
                  None,
                  None,
                  attrs = ctx.attrs,
                  maybeRoute = ctx.route.some
                )
                .map(r => NgAccess.NgDenied(r))
            }
            case Some(auth) => {
              val algo = alg match {
                case "ES256" => Algorithm.ECDSA256(auth.asInstanceOf[ECPublicKey], null).some
                case "ES384" => Algorithm.ECDSA384(auth.asInstanceOf[ECPublicKey], null).some
                case "ES512" => Algorithm.ECDSA512(auth.asInstanceOf[ECPublicKey], null).some
                case "RS256" => Algorithm.RSA256(auth.asInstanceOf[RSAPublicKey], null).some
                case "RS384" => Algorithm.RSA384(auth.asInstanceOf[RSAPublicKey], null).some
                case "RS512" => Algorithm.RSA512(auth.asInstanceOf[RSAPublicKey], null).some
                case _ => None
              }
              val audiences: Seq[String] = (Seq.empty ++ extraAudience ++ audience).distinct
              Try(JWT.require(algo.get).acceptLeeway(10).applyOnIf(audiences.nonEmpty)(_.withAudience(audiences:_*)).build().verify(bearer)) match {
                case Success(s) => NgAccess.NgAllowed.vfuture
                case Failure(e) => {
                  Errors
                    .craftResponseResult(
                      "unauthorized",
                      Results.Unauthorized,
                      ctx.request,
                      None,
                      None,
                      attrs = ctx.attrs,
                      maybeRoute = ctx.route.some
                    )
                    .map(r => NgAccess.NgDenied(r))
                }
              }
            }
          }
        }
      }
      case _ => {
        Errors
          .craftResponseResult(
            "unauthorized",
            Results.Unauthorized,
            ctx.request,
            None,
            None,
            attrs = ctx.attrs,
            maybeRoute = ctx.route.some
          )
          .map(r => NgAccess.NgDenied(r))
      }
    }
  }
}

case class JsonNgPluginConfig(raw: JsValue) extends NgPluginConfig {
  def json: JsValue = raw
}

class SpiffeJwtRequest extends NgRequestTransformer {

  override def name: String                                = "Cloud APIM - SPIFFE JWT request"
  override def description: Option[String]                 = "This plugin injects a SPIFFE client certificate in the current request".some
  override def multiInstance: Boolean                      = true
  override def core: Boolean                               = false
  override def visibility: NgPluginVisibility              = NgPluginVisibility.NgUserLand
  override def categories: Seq[NgPluginCategory]           = Seq(NgPluginCategory.Security)
  override def steps: Seq[NgStep]                          = Seq(NgStep.TransformRequest)
  override def defaultConfigObject: Option[NgPluginConfig] = JsonNgPluginConfig(SpiffeConfig.default.json.asObject ++ Json.obj(
    "header_name" -> "Authorization",
    "header_prefix" -> "Bearer ",
  )).some
  override def noJsForm: Boolean = true
  override def configFlow: Seq[String] = SpiffeConfig.configFlow ++ Seq(
    "audience",
    "extra_audience",
    "header_name",
    "header_prefix",
  )
  override def configSchema: Option[JsObject] = SpiffeConfig.configSchema.map(_.asObject ++ Json.obj(
    "audience" -> Json.obj(
      "type" -> "string",
      "label" -> "JWT audience",
    ),
    "extra_audience" -> Json.obj(
      "type" -> "array",
      "label" -> "JWT extra audience",
    ),
    "header_name" -> Json.obj(
      "type" -> "string",
      "label" -> "JWT header name",
    ),
    "header_prefix" -> Json.obj(
      "type" -> "string",
      "label" -> "JWT header prefix",
    ),
  ))


   override def start(env: Env): Future[Unit] = {
     env.logger.info(s"[Cloud APIM] the '${name}' plugin is available !")
     ().vfuture
   }

  private def getSource(config: SpiffeConfig): SpiffeJwtSource = SpiffeContext.jwtSourcesCache.synchronized {
    SpiffeContext.jwtSourcesCache.get(config.cacheKey, _ => {
      SpiffeJwtSource(config)
    })
  }

  override def transformRequest(ctx: NgTransformerRequestContext)(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[Result, NgPluginHttpRequest]] = {
    val pluginConfig = ctx
      .cachedConfig(internalName)(SpiffeConfig.format)
      .getOrElse(SpiffeConfig.default)
    val moreConfig = ctx
      .cachedConfigFn(internalName)(v => v.some)
      .getOrElse(Json.obj())
    val source = getSource(pluginConfig)
    val audience = moreConfig.select("audience").asOpt[String].filterNot(_.trim.isBlank).getOrElse(ctx.route.name)
    val extraAudience = moreConfig.select("extra_audience").asOpt[Seq[String]].getOrElse(Seq.empty)
    val headerName = moreConfig.select("header_name").asOpt[String].filterNot(_.trim.isBlank).getOrElse("Authorization")
    val headerPrefix = moreConfig.select("header_prefix").asOpt[String].filterNot(_.trim.isBlank).getOrElse("Bearer ")
    source.getSvid(audience, extraAudience = extraAudience).flatMap { svid =>
      ctx.otoroshiRequest.copy(
        headers = ctx.otoroshiRequest.headers ++ Map(
          headerName -> s"${headerPrefix}${svid.getToken}"
        )
      ).rightf
    }
  }

}

class SpiffeCertPreloadJob extends Job {

  override def uniqueId: JobId = JobId("com.cloud-apim.plugins.spiffe.SpiffeCertPreloadJob")

  override def name: String = "Cloud APIM - SPIFFE CA Cert preloader"

  override def defaultConfig: Option[JsObject] = Some(Json.obj("domains" -> Json.arr()))
  override def configFlow: Seq[String] = Seq("domains")
  override def configSchema: Option[JsObject] = Some(Json.obj(
    "domains" -> Json.obj(
      "type" -> "array",
      "label" -> "SPIFFE domains",
    ),
  ))

  override def description: Option[String] =
    Some(
      s"""This job preload SPIFFE CA into Otoroshi certs. It's mandatory if you want to perform mTLS request with SPIFFE client certificate.
         |
         |```json
         |${Json.prettyPrint(defaultConfig.get)}
         |```
      """.stripMargin
    )

  override def jobVisibility: JobVisibility = JobVisibility.UserLand
  override def kind: JobKind = JobKind.ScheduledEvery
  override def starting: JobStarting = JobStarting.FromConfiguration
  override def instantiation(ctx: JobContext, env: Env): JobInstantiation = JobInstantiation.OneInstancePerOtoroshiCluster
  override def initialDelay(ctx: JobContext, env: Env): Option[FiniteDuration] = 1.seconds.some
  override def interval(ctx: JobContext, env: Env): Option[FiniteDuration] = 10.seconds.some

   override def start(env: Env): Future[Unit] = {
     env.logger.info(s"[Cloud APIM] the '${name}' plugin is available !")
     ().vfuture
   }

  private def getSource(config: SpiffeConfig): SpiffeCertSource = SpiffeContext.certSourcesCache.synchronized {
    SpiffeContext.certSourcesCache.get(config.cacheKey, _ => {
      SpiffeCertSource(config)
    })
  }

  private def storeCurrentSvid(source: SpiffeCertSource)(implicit env: Env, ec: ExecutionContext): Future[Unit] = {
    source.getSvid().flatMap { svid =>
      val leaf = svid.getLeaf
      val id = "cert_" + new String(Base64.getEncoder.encode(leaf.getSignature), Charsets.UTF_8)
      val cert = Cert(
        id = id,
        name = s"SPIFFE SVID",
        description = s"SPIFFE SVID",
        chain = svid.getChain.asScala.map(_.asPem).mkString("\n\n"),
        privateKey = svid.getPrivateKey.asPem,
        caRef = None,
        autoRenew = false,
        client = false,
        exposed = false,
        revoked = false,
        entityMetadata = Map("spiffe-gen-cert" -> "true")
      )
      .enrich()
      if (env.proxyState.certificate(id).isEmpty) {
        val certs = env.proxyState.allCertificates() ++ Seq(cert)
        env.proxyState.updateCertificates(certs)
        cert.save().map(_ => ())
      } else {
        ().vfuture
      }
    }.map(_ => ())
  }

  private def storeAuthorities(source: SpiffeCertSource, config: SpiffeConfig)(implicit env: Env, ec: ExecutionContext): Future[Unit] = {
    source.getBundle().flatMap { bundle =>
      Future.sequence(bundle.getX509Authorities.asScala.toSeq.map { authority =>
        val id = "cert_" + new String(Base64.getEncoder.encode(authority.getSignature), Charsets.UTF_8)
        val cert = Cert(
          id = id,
          name = s"SPIFFE CA for ${config.domain}",
          description = s"SPIFFE CA for ${config.domain}",
          chain = authority.asPem,
          privateKey = "",
          caRef = None,
          autoRenew = false,
          client = false,
          exposed = false,
          revoked = false,
          entityMetadata = Map("spiffe-gen-cert" -> "true")
        ).enrich()
        if (env.proxyState.certificate(id).isEmpty) {
          // TODO: use hasCert/addCert
          val certs = env.proxyState.allCertificates() ++ Seq(cert)
          env.proxyState.updateCertificates(certs)
          cert.save().map(_ => ())
        } else {
          ().vfuture
        }
      })
    }.map(_ => ())
  }

  private def cleanupExpiredSpiffeCerts()(implicit env: Env, ec: ExecutionContext): Unit = {
    env.proxyState.allCertificates().foreach { cert =>
      if (cert.expired && cert.entityMetadata.get("spiffe-gen-cert").contains("true")) {
        // TODO: use removeCert
        val certs = env.proxyState.allCertificates().filterNot(_.id == cert.id)
        env.proxyState.updateCertificates(certs)
        cert.delete()
      }
    }
  }

  override def jobRun(ctx: JobContext)(implicit env: Env, ec: ExecutionContext): Future[Unit] = {
    val configDomains = ctx.config.select("domains").asOpt[Seq[String]].getOrElse(Seq.empty).map { domain =>
      SpiffeConfig(
        domain = domain,
        socketPath = ctx.config.select("socket_path").asOpt[String].filterNot(_.trim.isBlank),
        timeout = ctx.config.select("timeout").asOpt[Long].map(_.millis),
      )
    }
    val routeDomains = env.proxyState.allRoutes().flatMap(_.plugins.slots)
      .filter(pi => pi.plugin == "cp:otoroshi_plugins.com.cloud.apim.plugins.spiffe.SpiffeClientCertValidator" || pi.plugin == "cp:otoroshi_plugins.com.cloud.apim.plugins.spiffe.SpiffeClientCertRequest")
      .map(_.config.raw)
      .map(o => SpiffeConfig.format.reads(o))
      .collect {
        case JsSuccess(value, path) => value
      }
    val configs: Seq[SpiffeConfig] = (configDomains ++ routeDomains).distinct

    cleanupExpiredSpiffeCerts()
    Future.sequence(configs.map { config =>
      val source = getSource(config)
      for {
        _ <- storeCurrentSvid(source)
        _ <- storeAuthorities(source, config)
      } yield ()
    }).map(_ => ())
  }

}
