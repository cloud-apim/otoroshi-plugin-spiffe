package otoroshi_plugins.com.cloud.apim.plugins.spiffe

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.cloud.apim.otoroshi.plugins.spiffe.*
import io.spiffe.bundle.x509bundle.X509Bundle
import io.spiffe.svid.x509svid.X509Svid
import org.apache.pekko.stream.Materializer
import otoroshi.env.Env
import otoroshi.gateway.Errors
import otoroshi.next.plugins.api.*
import otoroshi.script.*
import otoroshi.ssl.Cert
import otoroshi.ssl.SSLImplicits.*
import otoroshi.utils.http.DN
import otoroshi.utils.syntax.implicits.*
import play.api.libs.json.{JsObject, JsSuccess, JsValue, Json}
import play.api.mvc.{Result, Results}

import java.security.PublicKey
import java.security.interfaces.{ECPublicKey, RSAPublicKey}
import scala.concurrent.duration.{DurationInt, DurationLong, FiniteDuration}
import scala.concurrent.{ExecutionContext, Future}
import scala.jdk.CollectionConverters.*
import scala.util.*

private val TemporaryCertName = "SPIFFE temporary cert"
private val SvidCertName      = "SPIFFE SVID"

private def unauthorized(ctx: NgAccessContext)(using env: Env, ec: ExecutionContext): Future[NgAccess] = {
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

private def jwtAlgorithm(alg: String, key: PublicKey): Option[Algorithm] = alg match {
  case "ES256" => Algorithm.ECDSA256(key.asInstanceOf[ECPublicKey], null).some
  case "ES384" => Algorithm.ECDSA384(key.asInstanceOf[ECPublicKey], null).some
  case "ES512" => Algorithm.ECDSA512(key.asInstanceOf[ECPublicKey], null).some
  case "RS256" => Algorithm.RSA256(key.asInstanceOf[RSAPublicKey], null).some
  case "RS384" => Algorithm.RSA384(key.asInstanceOf[RSAPublicKey], null).some
  case "RS512" => Algorithm.RSA512(key.asInstanceOf[RSAPublicKey], null).some
  case _       => None
}

private def saveCertIfMissing(id: String, name: String, chain: String, privateKey: String)(using env: Env, ec: ExecutionContext): Future[Unit] = {
  if (env.proxyState.certificate(id).isEmpty) {
    val cert = Cert(
      id = id,
      name = name,
      description = name,
      chain = chain,
      privateKey = privateKey,
      caRef = None,
      autoRenew = false,
      client = false,
      exposed = false,
      revoked = false,
      entityMetadata = Map("spiffe-gen-cert" -> "true")
    ).enrich()
    // TODO: use hasCert/addCert
    env.proxyState.updateCertificates(env.proxyState.allCertificates() :+ cert)
    cert.save().map(_ => ())
  } else {
    ().vfuture
  }
}

private def saveAuthorities(bundle: X509Bundle, name: String)(using env: Env, ec: ExecutionContext): Future[Unit] = {
  Future
    .sequence(bundle.getX509Authorities.asScala.toSeq.map { authority =>
      saveCertIfMissing(authority.spiffeCertId, name, authority.asPem, "")
    })
    .map(_ => ())
}

private def saveSvid(svid: X509Svid, name: String)(using env: Env, ec: ExecutionContext): Future[Unit] = {
  saveCertIfMissing(
    id = svid.getLeaf.spiffeCertId,
    name = name,
    chain = svid.getChain.asScala.map(_.asPem).mkString("\n\n"),
    privateKey = svid.getPrivateKey.asPem
  )
}

class SpiffeClientCertValidator extends NgAccessValidator {

  override def name: String                                = "Cloud APIM - SPIFFE client cert validator"
  override def description: Option[String]                 = "This plugin validates if the incoming request has been made with a SPIFFE generated client certificate".some
  override def multiInstance: Boolean                      = true
  override def core: Boolean                               = false
  override def visibility: NgPluginVisibility              = NgPluginVisibility.NgUserLand
  override def categories: Seq[NgPluginCategory]           = Seq(NgPluginCategory.AccessControl, NgPluginCategory.Security, NgPluginCategory.Custom("Cloud APIM"))
  override def steps: Seq[NgStep]                          = Seq(NgStep.ValidateAccess)
  override def defaultConfigObject: Option[NgPluginConfig] = SpiffeConfig.default.some
  override def noJsForm: Boolean = true
  override def configFlow: Seq[String] = SpiffeConfig.configFlow
  override def configSchema: Option[JsObject] = SpiffeConfig.configSchema

  override def start(env: Env): Future[Unit] = {
    env.logger.info(s"[Cloud APIM] the '${name.replaceFirst("Cloud APIM - ", "")}' plugin is available !")
    ().vfuture
  }

  override def access(ctx: NgAccessContext)(using env: Env, ec: ExecutionContext): Future[NgAccess] = {
    val pluginConfig = ctx
      .cachedConfig(internalName)(SpiffeConfig.format)
      .getOrElse(SpiffeConfig.default)
    ctx.request.clientCertificateChain.flatMap(_.headOption) match {
      case Some(clientCert) => {
        val clientDn = DN(clientCert.getSubjectX500Principal.getName)
        SpiffeContext.certSource(pluginConfig).getBundle().flatMap { bundle =>
          val exists = bundle.getX509Authorities.asScala.exists(cert => DN(cert.getSubjectX500Principal.getName).isEqualsTo(clientDn))
          if (exists) {
            NgAccess.NgAllowed.vfuture
          } else {
            unauthorized(ctx)
          }
        }
      }
      case None => unauthorized(ctx)
    }
  }
}

class SpiffeClientCertRequest extends NgRequestTransformer {

  override def name: String                                = "Cloud APIM - SPIFFE client cert request"
  override def description: Option[String]                 = "This plugin injects a SPIFFE client certificate in the current request".some
  override def multiInstance: Boolean                      = true
  override def core: Boolean                               = false
  override def visibility: NgPluginVisibility              = NgPluginVisibility.NgUserLand
  override def categories: Seq[NgPluginCategory]           = Seq(NgPluginCategory.Security, NgPluginCategory.Custom("Cloud APIM"))
  override def steps: Seq[NgStep]                          = Seq(NgStep.TransformRequest)
  override def defaultConfigObject: Option[NgPluginConfig] = SpiffeConfig.default.some
  override def noJsForm: Boolean = true
  override def configFlow: Seq[String] = SpiffeConfig.configFlow
  override def configSchema: Option[JsObject] = SpiffeConfig.configSchema

  override def start(env: Env): Future[Unit] = {
    env.logger.info(s"[Cloud APIM] the '${name.replaceFirst("Cloud APIM - ", "")}' plugin is available !")
    ().vfuture
  }

  override def transformRequest(ctx: NgTransformerRequestContext)(using env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[Result, NgPluginHttpRequest]] = {
    val pluginConfig = ctx
      .cachedConfig(internalName)(SpiffeConfig.format)
      .getOrElse(SpiffeConfig.default)
    val source = SpiffeContext.certSource(pluginConfig)
    for {
      bundle <- source.getBundle()
      svid   <- source.getSvid()
      // registration of the certs in otoroshi is done in the background, on purpose
      _ = saveAuthorities(bundle, TemporaryCertName)
      _ = saveSvid(svid, TemporaryCertName)
    } yield {
      val svidId = svid.getLeaf.spiffeCertId
      ctx.otoroshiRequest.copy(
        clientCertificateChain = () => svid.getChain.asScala.toSeq.some,
        backend = ctx.otoroshiRequest.backend.map { target =>
          target.copy(
            tlsConfig = target.tlsConfig.copy(
              enabled = true,
              certs = Seq(svidId),
              trustedCerts = bundle.getX509Authorities.asScala.toSeq.map(_.spiffeCertId)
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
  override def categories: Seq[NgPluginCategory]           = Seq(NgPluginCategory.AccessControl, NgPluginCategory.Security, NgPluginCategory.Custom("Cloud APIM"))
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

  override def start(env: Env): Future[Unit] = {
    env.logger.info(s"[Cloud APIM] the '${name.replaceFirst("Cloud APIM - ", "")}' plugin is available !")
    ().vfuture
  }

  override def access(ctx: NgAccessContext)(using env: Env, ec: ExecutionContext): Future[NgAccess] = {
    val pluginConfig = ctx
      .cachedConfig(internalName)(SpiffeConfig.format)
      .getOrElse(SpiffeConfig.default)
    val moreConfig = ctx
      .cachedConfigFn(internalName)(_.some)
      .getOrElse(Json.obj())
    val audience = moreConfig.select("audience").asOpt[String].filterNot(_.trim.isBlank)
    val extraAudience = moreConfig.select("extra_audience").asOpt[Seq[String]].getOrElse(Seq.empty)
    ctx.request.headers.get("Authorization").map(_.replace("Bearer ", "").replace("bearer ", "")) match {
      case Some(bearer) if bearer.split("\\.").length == 3 => {
        SpiffeContext.jwtSource(pluginConfig).getBundle().flatMap { bundle =>
          val header = bearer.split("\\.").head.decodeBase64.parseJson
          val kid = header.select("kid").asString
          val alg = header.select("alg").asString
          val audiences: Seq[String] = (extraAudience ++ audience.toSeq).distinct
          val decoded = for {
            authority <- Option(bundle.getJwtAuthorities.get(kid))
            algorithm <- jwtAlgorithm(alg, authority)
            token     <- Try(
                           JWT
                             .require(algorithm)
                             .acceptLeeway(10)
                             .applyOnIf(audiences.nonEmpty)(_.withAudience(audiences*))
                             .build()
                             .verify(bearer)
                         ).toOption
          } yield token
          decoded match {
            case Some(_) => NgAccess.NgAllowed.vfuture
            case None    => unauthorized(ctx)
          }
        }
      }
      case _ => unauthorized(ctx)
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
  override def categories: Seq[NgPluginCategory]           = Seq(NgPluginCategory.Security, NgPluginCategory.Custom("Cloud APIM"))
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
    env.logger.info(s"[Cloud APIM] the '${name.replaceFirst("Cloud APIM - ", "")}' plugin is available !")
    ().vfuture
  }

  override def transformRequest(ctx: NgTransformerRequestContext)(using env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[Result, NgPluginHttpRequest]] = {
    val pluginConfig = ctx
      .cachedConfig(internalName)(SpiffeConfig.format)
      .getOrElse(SpiffeConfig.default)
    val moreConfig = ctx
      .cachedConfigFn(internalName)(_.some)
      .getOrElse(Json.obj())
    val audience = moreConfig.select("audience").asOpt[String].filterNot(_.trim.isBlank).getOrElse(ctx.route.name)
    val extraAudience = moreConfig.select("extra_audience").asOpt[Seq[String]].getOrElse(Seq.empty)
    val headerName = moreConfig.select("header_name").asOpt[String].filterNot(_.trim.isBlank).getOrElse("Authorization")
    val headerPrefix = moreConfig.select("header_prefix").asOpt[String].filterNot(_.trim.isBlank).getOrElse("Bearer ")
    SpiffeContext.jwtSource(pluginConfig).getSvid(audience, extraAudience = extraAudience).flatMap { svid =>
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

  private def cleanupExpiredSpiffeCerts()(using env: Env, ec: ExecutionContext): Unit = {
    env.proxyState.allCertificates().foreach { cert =>
      if (cert.expired && cert.entityMetadata.get("spiffe-gen-cert").contains("true")) {
        // TODO: use removeCert
        env.proxyState.updateCertificates(env.proxyState.allCertificates().filterNot(_.id == cert.id))
        cert.delete()
      }
    }
  }

  override def jobRun(ctx: JobContext)(using env: Env, ec: ExecutionContext): Future[Unit] = {
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
        case JsSuccess(value, _) => value
      }
    val configs: Seq[SpiffeConfig] = (configDomains ++ routeDomains).distinct

    cleanupExpiredSpiffeCerts()
    Future.sequence(configs.map { config =>
      val source = SpiffeContext.certSource(config)
      for {
        svid   <- source.getSvid()
        _      <- saveSvid(svid, SvidCertName)
        bundle <- source.getBundle()
        _      <- saveAuthorities(bundle, s"SPIFFE CA for ${config.domain}")
      } yield ()
    }).map(_ => ())
  }
}
