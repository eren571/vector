use std::{
    collections::HashMap,
    convert::Infallible,
    io::Read,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use uuid::Uuid;

use bytes::{Buf, Bytes};
use chrono::{DateTime, TimeZone, Utc};
use flate2::read::MultiGzDecoder;
use futures::FutureExt;
use http::StatusCode;
use hyper::{Server, service::make_service_fn};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{
    Deserializer, Value as JsonValue,
    de::{Read as JsonRead, StrRead},
};
use snafu::Snafu;
use tokio::net::TcpStream;
use tower::ServiceBuilder;
use tracing::Span;
use vector_lib::{
    EstimatedJsonEncodedSizeOf,
    config::{LegacyKey, LogNamespace},
    configurable::configurable_component,
    event::BatchNotifier,
    internal_event::{CountByteSize, InternalEventHandle as _, Registered},
    lookup::{self, event_path, lookup_v2::OptionalValuePath, owned_value_path},
    schema::meaning,
    sensitive_string::SensitiveString,
    source_sender::SendError,
    tls::MaybeTlsIncomingStream,
};
use vrl::{
    path::OwnedTargetPath,
    value::{Kind, kind::Collection},
};
use warp::{
    Filter, Reply,
    filters::BoxedFilter,
    http::header::{CONTENT_TYPE, HeaderValue},
    path,
    reject::Rejection,
    reply::Response,
};

use self::{
    acknowledgements::{
        HecAckStatusRequest, HecAckStatusResponse, HecAcknowledgementsConfig,
        IndexerAcknowledgement,
    },
    splunk_response::{HecResponse, HecResponseMetadata, HecStatusCode},
};
use crate::{
    SourceSender,
    config::{DataType, Resource, SourceConfig, SourceContext, SourceOutput, log_schema},
    event::{Event, LogEvent, Value},
    http::{KeepaliveConfig, MaxConnectionAgeLayer, build_http_trace_layer},
    internal_events::{EventsReceived, HttpBytesReceived},
    serde::bool_or_struct,
    tls::{MaybeTlsSettings, TlsEnableableConfig},
};

mod acknowledgements;

// Event fields unique to splunk_hec_full source (same as splunk_hec for compatibility)
pub const CHANNEL: &str = "splunk_channel";
pub const INDEX: &str = "splunk_index";
pub const SOURCE: &str = "splunk_source";
pub const SOURCETYPE: &str = "splunk_sourcetype";

const X_SPLUNK_REQUEST_CHANNEL: &str = "x-splunk-request-channel";

/// Configuration for the `splunk_hec_full` source.
///
/// Full-featured Splunk HEC receiver with token binding, URL query authentication,
/// raw endpoint metadata extraction, and transparent forwarding support.
#[configurable_component(source(
    "splunk_hec_full",
    "Full-featured Splunk HEC receiver with token binding and transparent forwarding."
))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct SplunkHecFullConfig {
    /// The socket address to listen for connections on.
    ///
    /// The address _must_ include a port.
    #[serde(default = "default_socket_address")]
    pub address: SocketAddr,

    /// Optional authorization token.
    ///
    /// If supplied, incoming requests must supply this token in the `Authorization` header, just as a client would if
    /// it was communicating with the Splunk HEC endpoint directly.
    ///
    /// If _not_ supplied, the `Authorization` header is ignored and requests are not authenticated.
    #[configurable(deprecated = "This option has been deprecated, use `valid_tokens` instead.")]
    token: Option<SensitiveString>,

    /// A list of valid authorization tokens.
    ///
    /// If supplied, incoming requests must supply one of these tokens in the `Authorization` header, just as a client
    /// would if it was communicating with the Splunk HEC endpoint directly.
    ///
    /// If _not_ supplied, the `Authorization` header is ignored and requests are not authenticated.
    #[configurable(metadata(docs::examples = "A94A8FE5CCB19BA61C4C08"))]
    valid_tokens: Option<Vec<SensitiveString>>,

    /// Whether or not to forward the Splunk HEC authentication token with events.
    ///
    /// If set to `true`, when incoming requests contain a Splunk HEC token, the token used is kept in the
    /// event metadata and preferentially used if the event is sent to a Splunk HEC sink.
    store_hec_token: bool,

    #[configurable(derived)]
    tls: Option<TlsEnableableConfig>,

    #[configurable(derived)]
    #[serde(deserialize_with = "bool_or_struct")]
    acknowledgements: HecAcknowledgementsConfig,

    /// The namespace to use for logs. This overrides the global settings.
    #[configurable(metadata(docs::hidden))]
    #[serde(default)]
    log_namespace: Option<bool>,

    #[configurable(derived)]
    #[serde(default)]
    keepalive: KeepaliveConfig,

    // === New features for splunk_hec_full ===
    /// Whether to allow authentication via URL query parameter `?token=`.
    ///
    /// When enabled, clients can pass the HEC token as a URL query parameter
    /// instead of (or in addition to) the `Authorization` header.
    /// Header token takes precedence over URL token when both are present.
    /// URL token is only used when the header is missing.
    #[serde(default = "default_false")]
    allow_query_string_auth: bool,

    /// Automatically write metadata fields (index, sourcetype, source) as
    /// event-level fields without the `splunk_` prefix, in addition to the
    /// standard prefixed fields.
    ///
    /// This enables zero-config transparent forwarding to a `splunk_hec_logs` sink
    /// when the sink uses templates like `index: "{{ index }}"`.
    #[serde(default = "default_true")]
    auto_forward_metadata: bool,

    /// Fix bare string events in the Vector log namespace.
    ///
    /// When enabled, string events (e.g., `{"event": "hello"}`) are wrapped
    /// as `{"message": "hello"}` instead of being stored as raw bytes.
    /// This prevents serialization issues where bare strings render as `{"event":{}}`.
    #[serde(default = "default_true")]
    fix_bare_string_events: bool,

    /// Whether to require a channel ID on the raw endpoint.
    ///
    /// Splunk HEC requires a channel for the raw endpoint, but some legacy
    /// clients may not send one. Set to `false` to accept raw events without a channel.
    /// When false, events without a channel will have an auto-generated channel ID.
    #[serde(default = "default_true")]
    raw_require_channel: bool,

    /// Whether to split raw endpoint body by newlines into multiple events.
    ///
    /// When enabled, raw endpoint requests with multiline bodies are split
    /// by newline characters (`\n`) into separate events, matching Splunk's
    /// LINE_BREAKER behavior. Empty lines are skipped.
    ///
    /// When disabled (default), the entire raw body is treated as a single event.
    #[serde(default)]
    raw_line_splitting: bool,
}

const fn default_true() -> bool {
    true
}

const fn default_false() -> bool {
    false
}

impl_generate_config_from_default!(SplunkHecFullConfig);

impl Default for SplunkHecFullConfig {
    fn default() -> Self {
        SplunkHecFullConfig {
            address: default_socket_address(),
            token: None,
            valid_tokens: None,
            tls: None,
            acknowledgements: Default::default(),
            store_hec_token: false,
            log_namespace: None,
            keepalive: Default::default(),
            allow_query_string_auth: false,
            auto_forward_metadata: true,
            fix_bare_string_events: true,
            raw_require_channel: true,
            raw_line_splitting: false,
        }
    }
}

fn default_socket_address() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 8088)
}

#[async_trait::async_trait]
#[typetag::serde(name = "splunk_hec_full")]
impl SourceConfig for SplunkHecFullConfig {
    async fn build(&self, cx: SourceContext) -> crate::Result<super::Source> {
        let tls = MaybeTlsSettings::from_config(self.tls.as_ref(), true)?;
        let shutdown = cx.shutdown.clone();
        let out = cx.out.clone();
        let source = SplunkSource::new(self, tls.http_protocol_name(), cx)?;

        let event_service = source.event_service(out.clone());
        let raw_service = source.raw_service(out.clone());
        let _ = out;
        let health_service = source.health_service();
        let ack_service = source.ack_service();
        let options = SplunkSource::options();

        let services = path!("services" / "collector" / ..)
            .and(
                event_service
                    .or(raw_service)
                    .unify()
                    .or(health_service)
                    .unify()
                    .or(ack_service)
                    .unify()
                    .or(options)
                    .unify(),
            )
            .or_else(finish_err);

        let listener = tls.bind(&self.address).await?;

        let keepalive_settings = self.keepalive.clone();
        Ok(Box::pin(async move {
            let span = Span::current();
            let make_svc = make_service_fn(move |conn: &MaybeTlsIncomingStream<TcpStream>| {
                let svc = ServiceBuilder::new()
                    .layer(build_http_trace_layer(span.clone()))
                    .option_layer(keepalive_settings.max_connection_age_secs.map(|secs| {
                        MaxConnectionAgeLayer::new(
                            Duration::from_secs(secs),
                            keepalive_settings.max_connection_age_jitter_factor,
                            conn.peer_addr(),
                        )
                    }))
                    .service(warp::service(services.clone()));
                futures_util::future::ok::<_, Infallible>(svc)
            });

            Server::builder(hyper::server::accept::from_stream(listener.accept_stream()))
                .serve(make_svc)
                .with_graceful_shutdown(shutdown.map(|_| ()))
                .await
                .map_err(|err| {
                    error!("An error occurred: {:?}.", err);
                })?;

            Ok(())
        }))
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        let log_namespace = global_log_namespace.merge(self.log_namespace);

        let schema_definition = match log_namespace {
            LogNamespace::Legacy => {
                let definition = vector_lib::schema::Definition::empty_legacy_namespace()
                    .with_event_field(
                        &owned_value_path!("line"),
                        Kind::object(Collection::empty())
                            .or_array(Collection::empty())
                            .or_undefined(),
                        None,
                    );

                if let Some(message_key) = log_schema().message_key() {
                    definition.with_event_field(
                        message_key,
                        Kind::bytes().or_undefined(),
                        Some(meaning::MESSAGE),
                    )
                } else {
                    definition
                }
            }
            LogNamespace::Vector => vector_lib::schema::Definition::new_with_default_metadata(
                Kind::bytes().or_object(Collection::empty()),
                [log_namespace],
            )
            .with_meaning(OwnedTargetPath::event_root(), meaning::MESSAGE),
        }
        .with_standard_vector_source_metadata()
        .with_source_metadata(
            SplunkHecFullConfig::NAME,
            log_schema()
                .host_key()
                .cloned()
                .map(LegacyKey::InsertIfEmpty),
            &owned_value_path!("host"),
            Kind::bytes(),
            Some(meaning::HOST),
        )
        .with_source_metadata(
            SplunkHecFullConfig::NAME,
            Some(LegacyKey::Overwrite(owned_value_path!(CHANNEL))),
            &owned_value_path!("channel"),
            Kind::bytes(),
            None,
        )
        .with_source_metadata(
            SplunkHecFullConfig::NAME,
            Some(LegacyKey::Overwrite(owned_value_path!(INDEX))),
            &owned_value_path!("index"),
            Kind::bytes(),
            None,
        )
        .with_source_metadata(
            SplunkHecFullConfig::NAME,
            Some(LegacyKey::Overwrite(owned_value_path!(SOURCE))),
            &owned_value_path!("source"),
            Kind::bytes(),
            Some(meaning::SERVICE),
        )
        // Not to be confused with `source_type`.
        .with_source_metadata(
            SplunkHecFullConfig::NAME,
            Some(LegacyKey::Overwrite(owned_value_path!(SOURCETYPE))),
            &owned_value_path!("sourcetype"),
            Kind::bytes(),
            None,
        );

        vec![SourceOutput::new_maybe_logs(
            DataType::Log,
            schema_definition,
        )]
    }

    fn resources(&self) -> Vec<Resource> {
        vec![Resource::tcp(self.address)]
    }

    fn can_acknowledge(&self) -> bool {
        true
    }
}

/// Query parameters for the raw endpoint.
#[derive(Debug, Default, Deserialize)]
struct RawQueryParams {
    channel: Option<String>,
    index: Option<String>,
    sourcetype: Option<String>,
    source: Option<String>,
    host: Option<String>,
    time: Option<String>,
    #[allow(dead_code)]
    token: Option<String>,
}

/// Query parameters for the health endpoint.
#[derive(Debug, Default, Deserialize)]
struct HealthQueryParams {
    token: Option<String>,
    ack: Option<String>,
}

impl HealthQueryParams {
    /// Returns true if ack check is requested (?ack=true or ?ack=1)
    fn ack_enabled(&self) -> bool {
        self.ack
            .as_deref()
            .is_some_and(|v| v == "true" || v == "1")
    }
}

/// Query parameters for the event endpoint.
#[derive(Debug, Default, Deserialize)]
struct EventQueryParams {
    channel: Option<String>,
    #[allow(dead_code)]
    token: Option<String>,
    auto_extract_timestamp: Option<String>,
}

impl EventQueryParams {
    fn auto_extract_timestamp_enabled(&self) -> bool {
        self.auto_extract_timestamp
            .as_deref()
            .is_some_and(|v| v == "true" || v == "1")
    }
}

/// Shared data for responding to requests.
struct SplunkSource {
    valid_credentials: Vec<String>,
    protocol: &'static str,
    idx_ack: Option<Arc<IndexerAcknowledgement>>,
    store_hec_token: bool,
    log_namespace: LogNamespace,
    events_received: Registered<EventsReceived>,
    allow_query_string_auth: bool,
    auto_forward_metadata: bool,
    fix_bare_string_events: bool,
    raw_require_channel: bool,
    raw_line_splitting: bool,
}

impl SplunkSource {
    fn new(
        config: &SplunkHecFullConfig,
        protocol: &'static str,
        cx: SourceContext,
    ) -> crate::Result<Self> {
        let log_namespace = cx.log_namespace(config.log_namespace);
        let acknowledgements = cx.do_acknowledgements(config.acknowledgements.enabled.into());
        let shutdown = cx.shutdown;
        let valid_tokens = config
            .valid_tokens
            .iter()
            .flatten()
            .chain(config.token.iter());

        let idx_ack = acknowledgements.then(|| {
            Arc::new(IndexerAcknowledgement::new(
                config.acknowledgements.clone(),
                shutdown,
            ))
        });

        Ok(SplunkSource {
            valid_credentials: valid_tokens
                .map(|token| format!("Splunk {}", token.inner()))
                .collect(),
            protocol,
            idx_ack,
            store_hec_token: config.store_hec_token,
            log_namespace,
            events_received: register!(EventsReceived),
            allow_query_string_auth: config.allow_query_string_auth,
            auto_forward_metadata: config.auto_forward_metadata,
            fix_bare_string_events: config.fix_bare_string_events,
            raw_require_channel: config.raw_require_channel,
            raw_line_splitting: config.raw_line_splitting,
        })
    }

    fn event_service(&self, out: SourceSender) -> BoxedFilter<(Response,)> {
        let splunk_channel_header = warp::header::optional::<String>(X_SPLUNK_REQUEST_CHANNEL);

        let event_query_params =
            warp::query::<EventQueryParams>().or_else(|_| async {
                Ok::<(EventQueryParams,), Rejection>((EventQueryParams::default(),))
            });

        let splunk_channel = splunk_channel_header
            .and(event_query_params)
            .map(
                |header: Option<String>, params: EventQueryParams| {
                    let auto_extract_ts = params.auto_extract_timestamp_enabled();
                    let channel = header.or(params.channel);
                    (channel, auto_extract_ts)
                },
            );

        let protocol = self.protocol;
        let idx_ack = self.idx_ack.clone();
        let store_hec_token = self.store_hec_token;
        let log_namespace = self.log_namespace;
        let events_received = self.events_received.clone();
        let auto_forward_metadata = self.auto_forward_metadata;
        let fix_bare_string_events = self.fix_bare_string_events;

        warp::post()
            .and(
                path!("event")
                    .or(path!("event" / "1.0"))
                    .or(warp::path::end()),
            )
            .and(self.authorization())
            .and(splunk_channel)
            .and(warp::addr::remote())
            .and(warp::header::optional::<String>("X-Forwarded-For"))
            .and(self.gzip())
            .and(warp::body::bytes())
            .and(warp::path::full())
            .and_then(
                move |_,
                      token: Option<String>,
                      (channel, auto_extract_ts): (Option<String>, bool),
                      remote: Option<SocketAddr>,
                      remote_addr: Option<String>,
                      gzip: bool,
                      body: Bytes,
                      path: warp::path::FullPath| {
                    let mut out = out.clone();
                    let idx_ack = idx_ack.clone();
                    let events_received = events_received.clone();

                    async move {
                        if idx_ack.is_some() && channel.is_none() {
                            return Err(Rejection::from(ApiError::MissingChannel));
                        }

                        let mut data = Vec::new();
                        let (byte_size, body) = if gzip {
                            MultiGzDecoder::new(body.reader())
                                .read_to_end(&mut data)
                                .map_err(|_| Rejection::from(ApiError::BadRequest))?;
                            (data.len(), String::from_utf8_lossy(data.as_slice()))
                        } else {
                            (body.len(), String::from_utf8_lossy(body.as_ref()))
                        };
                        emit!(HttpBytesReceived {
                            byte_size,
                            http_path: path.as_str(),
                            protocol,
                        });

                        let (batch, receiver) =
                            BatchNotifier::maybe_new_with_receiver(idx_ack.is_some());
                        let maybe_ack_id = match (idx_ack, receiver, channel.clone()) {
                            (Some(idx_ack), Some(receiver), Some(channel_id)) => {
                                match idx_ack.get_ack_id_from_channel(channel_id, receiver).await {
                                    Ok(ack_id) => Some(ack_id),
                                    Err(rej) => return Err(rej),
                                }
                            }
                            _ => None,
                        };

                        let mut error = None;
                        let mut events = Vec::new();

                        let iter: EventIterator<'_, StrRead<'_>> = EventIteratorGenerator {
                            deserializer: Deserializer::from_str(&body).into_iter::<JsonValue>(),
                            channel,
                            remote,
                            remote_addr,
                            batch,
                            token: token.filter(|_| store_hec_token).map(Into::into),
                            log_namespace,
                            events_received,
                            auto_forward_metadata,
                            fix_bare_string_events,
                            auto_extract_timestamp: auto_extract_ts,
                        }
                        .into();

                        for result in iter {
                            match result {
                                Ok(event) => events.push(event),
                                Err(err) => {
                                    error = Some(err);
                                    break;
                                }
                            }
                        }

                        if !events.is_empty() {
                            match out.send_batch(events).await {
                                Ok(()) => (),
                                Err(SendError::Closed) => {
                                    return Err(Rejection::from(ApiError::ServerShutdown));
                                }
                                Err(SendError::Timeout) => {
                                    unreachable!("No timeout is configured for this source.")
                                }
                            }
                        }

                        if let Some(error) = error {
                            Err(error)
                        } else {
                            Ok(maybe_ack_id)
                        }
                    }
                },
            )
            .map(finish_ok)
            .boxed()
    }

    fn raw_service(&self, out: SourceSender) -> BoxedFilter<(Response,)> {
        let protocol = self.protocol;
        let idx_ack = self.idx_ack.clone();
        let store_hec_token = self.store_hec_token;
        let events_received = self.events_received.clone();
        let log_namespace = self.log_namespace;
        let auto_forward_metadata = self.auto_forward_metadata;
        let fix_bare_string_events = self.fix_bare_string_events;
        let raw_require_channel = self.raw_require_channel;
        let raw_line_splitting = self.raw_line_splitting;

        warp::post()
            .and(path!("raw" / "1.0").or(path!("raw")))
            .and(self.authorization())
            .and(warp::query::<RawQueryParams>().or_else(|_| async {
                Ok::<(RawQueryParams,), Rejection>((RawQueryParams::default(),))
            }))
            .and(warp::header::optional::<String>(X_SPLUNK_REQUEST_CHANNEL))
            .and(warp::addr::remote())
            .and(warp::header::optional::<String>("X-Forwarded-For"))
            .and(self.gzip())
            .and(warp::body::bytes())
            .and(warp::path::full())
            .and_then(
                move |_,
                      token: Option<String>,
                      query_params: RawQueryParams,
                      channel_header: Option<String>,
                      remote: Option<SocketAddr>,
                      xff: Option<String>,
                      gzip: bool,
                      body: Bytes,
                      path: warp::path::FullPath| {
                    let mut out = out.clone();
                    let idx_ack = idx_ack.clone();
                    let events_received = events_received.clone();

                    emit!(HttpBytesReceived {
                        byte_size: body.len(),
                        http_path: path.as_str(),
                        protocol,
                    });

                    async move {
                        // Channel: header takes priority over query param
                        let channel_id = channel_header.or(query_params.channel);

                        // Raw endpoint channel handling
                        let channel_id = match channel_id {
                            Some(ch) => ch,
                            None => {
                                if raw_require_channel {
                                    return Err(Rejection::from(ApiError::MissingChannel));
                                }
                                // Auto-generate a channel ID for events without one
                                Uuid::new_v4().to_string()
                            }
                        };

                        let (batch, receiver) =
                            BatchNotifier::maybe_new_with_receiver(idx_ack.is_some());
                        let maybe_ack_id = match (idx_ack, receiver) {
                            (Some(idx_ack), Some(receiver)) => Some(
                                idx_ack
                                    .get_ack_id_from_channel(channel_id.clone(), receiver)
                                    .await?,
                            ),
                            _ => None,
                        };

                        // Build raw event(s)
                        // When raw_line_splitting is enabled, split body by newlines into multiple events
                        let mut events = if raw_line_splitting {
                            raw_events_split(
                                body,
                                gzip,
                                channel_id,
                                remote,
                                xff,
                                batch,
                                log_namespace,
                                &events_received,
                                fix_bare_string_events,
                            )?
                        } else {
                            vec![raw_event(
                                body,
                                gzip,
                                channel_id,
                                remote,
                                xff,
                                batch,
                                log_namespace,
                                &events_received,
                                fix_bare_string_events,
                            )?]
                        };

                        // Compute final metadata values (shared across all events)
                        let final_host = query_params.host;
                        let final_index = query_params.index;
                        let final_sourcetype = query_params.sourcetype;
                        let final_source = query_params.source;

                        // Apply metadata + token + time to each event
                        for event in events.iter_mut() {
                            let log = event.as_mut_log();

                            if let Some(ref host_val) = final_host {
                                log_namespace.insert_source_metadata(
                                    SplunkHecFullConfig::NAME,
                                    log,
                                    log_schema().host_key().map(LegacyKey::InsertIfEmpty),
                                    lookup::path!("host"),
                                    host_val.clone(),
                                );
                                if auto_forward_metadata {
                                    log.insert(event_path!("host"), Value::from(host_val.clone()));
                                }
                            }

                            if let Some(ref index_val) = final_index {
                                log_namespace.insert_source_metadata(
                                    SplunkHecFullConfig::NAME,
                                    log,
                                    Some(LegacyKey::Overwrite(&owned_value_path!(INDEX))),
                                    lookup::path!("index"),
                                    index_val.clone(),
                                );
                                if auto_forward_metadata {
                                    log.insert(event_path!("index"), Value::from(index_val.clone()));
                                }
                            }

                            if let Some(ref sourcetype_val) = final_sourcetype {
                                log_namespace.insert_source_metadata(
                                    SplunkHecFullConfig::NAME,
                                    log,
                                    Some(LegacyKey::Overwrite(&owned_value_path!(SOURCETYPE))),
                                    lookup::path!("sourcetype"),
                                    sourcetype_val.clone(),
                                );
                                if auto_forward_metadata {
                                    log.insert(event_path!("sourcetype"), Value::from(sourcetype_val.clone()));
                                }
                            }

                            if let Some(ref source_val) = final_source {
                                log_namespace.insert_source_metadata(
                                    SplunkHecFullConfig::NAME,
                                    log,
                                    Some(LegacyKey::Overwrite(&owned_value_path!(SOURCE))),
                                    lookup::path!("source"),
                                    source_val.clone(),
                                );
                                if auto_forward_metadata {
                                    log.insert(event_path!("source"), Value::from(source_val.clone()));
                                }
                            }

                            if let Some(ref token_str) = token {
                                if store_hec_token {
                                    event.metadata_mut().set_splunk_hec_token(token_str.clone().into());
                                }
                            }

                            // Apply time from URL query params (?time=epoch)
                            if let Some(ref time_str) = query_params.time {
                                let log = event.as_mut_log();
                                if let Ok(time_f64) = time_str.parse::<f64>() {
                                    let secs = time_f64.floor() as i64;
                                    let nsecs = ((time_f64.fract()) * 1_000_000_000.0) as u32;
                                    if let Some(timestamp) = Utc.timestamp_opt(secs, nsecs).single() {
                                        log_namespace.insert_source_metadata(
                                            SplunkHecFullConfig::NAME,
                                            log,
                                            log_schema().timestamp_key().map(LegacyKey::Overwrite),
                                            lookup::path!("timestamp"),
                                            timestamp,
                                        );
                                    }
                                } else if let Ok(time_i64) = time_str.parse::<i64>()
                                    && let Some(timestamp) = parse_timestamp(time_i64) {
                                        log_namespace.insert_source_metadata(
                                            SplunkHecFullConfig::NAME,
                                            log,
                                            log_schema().timestamp_key().map(LegacyKey::Overwrite),
                                            lookup::path!("timestamp"),
                                            timestamp,
                                        );
                                }
                            }
                        }

                        let res = out.send_batch(events).await;
                        match res {
                            Ok(()) => Ok(maybe_ack_id),
                            Err(SendError::Closed) => Err(Rejection::from(ApiError::ServerShutdown)),
                            Err(SendError::Timeout) => {
                                unreachable!("No timeout is configured for this source.")
                            }
                        }
                    }
                },
            )
            .map(finish_ok)
            .boxed()
    }

    fn health_service(&self) -> BoxedFilter<(Response,)> {
        let valid_credentials = self.valid_credentials.clone();
        let idx_ack = self.idx_ack.clone();

        warp::get()
            .and(path!("health" / "1.0").or(path!("health")))
            .and(
                warp::query::<HealthQueryParams>().or_else(|_| async {
                    Ok::<(HealthQueryParams,), Rejection>((HealthQueryParams::default(),))
                }),
            )
            .map(move |_, params: HealthQueryParams| {
                // 1. Token validation: if ?token= is provided, validate it
                if let Some(token_val) = &params.token
                    && !valid_credentials.is_empty()
                {
                    let credential = format!("Splunk {}", token_val);
                    if !valid_credentials.contains(&credential) {
                        return response_json(
                            StatusCode::BAD_REQUEST,
                            serde_json::json!({"text": "Invalid token", "code": 4}),
                        );
                    }
                }

                // 2. ACK service check: if ?ack=true or ?ack=1
                if params.ack_enabled() && idx_ack.is_none() {
                    return response_json(
                        StatusCode::SERVICE_UNAVAILABLE,
                        serde_json::json!({"text": "ACK is disabled", "code": 14}),
                    );
                }

                // 3. Default: healthy
                response_json(
                    StatusCode::OK,
                    serde_json::json!({"text": "HEC is healthy", "code": 17}),
                )
            })
            .boxed()
    }

    fn lenient_json_content_type_check<T>() -> impl Filter<Extract = (T,), Error = Rejection> + Clone
    where
        T: Send + DeserializeOwned + 'static,
    {
        warp::header::optional::<HeaderValue>(CONTENT_TYPE.as_str())
            .and(warp::body::bytes())
            .and_then(
                |ctype: Option<HeaderValue>, body: bytes::Bytes| async move {
                    let ok = ctype
                        .as_ref()
                        .and_then(|v| v.to_str().ok())
                        .map(|h| h.to_ascii_lowercase().contains("application/json"))
                        .unwrap_or(true);

                    if !ok {
                        return Err(warp::reject::custom(ApiError::UnsupportedContentType));
                    }

                    let value = serde_json::from_slice::<T>(&body)
                        .map_err(|_| warp::reject::custom(ApiError::BadRequest))?;

                    Ok(value)
                },
            )
    }

    fn ack_service(&self) -> BoxedFilter<(Response,)> {
        let idx_ack = self.idx_ack.clone();

        warp::post()
            .and(warp::path!("ack"))
            .and(self.authorization())
            .and(SplunkSource::required_channel())
            .and(Self::lenient_json_content_type_check::<HecAckStatusRequest>())
            .and_then(move |_, channel: String, req: HecAckStatusRequest| {
                let idx_ack = idx_ack.clone();
                async move {
                    if let Some(idx_ack) = idx_ack {
                        let acks = idx_ack
                            .get_acks_status_from_channel(channel, &req.acks)
                            .await?;
                        Ok(warp::reply::json(&HecAckStatusResponse { acks }).into_response())
                    } else {
                        Err(warp::reject::custom(ApiError::AckIsDisabled))
                    }
                }
            })
            .boxed()
    }

    fn options() -> BoxedFilter<(Response,)> {
        let post = warp::options()
            .and(
                path!("event")
                    .or(path!("event" / "1.0"))
                    .or(path!("raw" / "1.0"))
                    .or(path!("raw")),
            )
            .map(|_| warp::reply::with_header(warp::reply(), "Allow", "POST").into_response());

        let get = warp::options()
            .and(path!("health").or(path!("health" / "1.0")))
            .map(|_| warp::reply::with_header(warp::reply(), "Allow", "GET").into_response());

        post.or(get).unify().boxed()
    }

    /// Authorize request - supports both Authorization header and URL ?token= query parameter
    fn authorization(&self) -> BoxedFilter<(Option<String>,)> {
        let valid_credentials = self.valid_credentials.clone();
        let allow_query_string_auth = self.allow_query_string_auth;

        warp::header::optional("Authorization")
            .and(
                warp::query::<HashMap<String, String>>()
                    .map(|qs: HashMap<String, String>| qs.get("token").cloned())
                    .or_else(|_| async { Ok::<(Option<String>,), Rejection>((None,)) }),
            )
            .and_then(
                move |header_token: Option<String>, url_token: Option<String>| {
                    let valid_credentials = valid_credentials.clone();
                    async move {
                        // Determine effective token:
                        // If allow_query_string_auth is enabled, header takes precedence.
                        let token = if allow_query_string_auth {
                            header_token
                                .or_else(|| url_token.map(|t| format!("Splunk {}", t)))
                        } else {
                            header_token
                        };

                        // Normalize token: support both "Splunk <token>" and "Basic <base64>" formats
                        // Splunk HEC docs (RFC 1945): curl -u x:<token> sends "Basic base64(x:token)"
                        let token = token.map(|t| {
                            if let Some(b64) = t.strip_prefix("Basic ") {
                                use base64::prelude::{BASE64_STANDARD, Engine as _};
                                if let Ok(decoded) = BASE64_STANDARD.decode(b64) {
                                    if let Ok(s) = String::from_utf8(decoded) {
                                        // Format: "x:token" or "username:token"
                                        if let Some((_user, pass)) = s.split_once(':') {
                                            return format!("Splunk {}", pass);
                                        }
                                    }
                                }
                            }
                            t
                        });

                        match (token, valid_credentials.is_empty()) {
                            // No tokens configured - pass through, strip prefix
                            (token, true) => Ok(token
                                .map(|t| t.strip_prefix("Splunk ").map(Into::into).unwrap_or(t))),
                            // Token matches configured credentials
                            (Some(token), false) if valid_credentials.contains(&token) => Ok(Some(
                                token
                                    .strip_prefix("Splunk ")
                                    .map(Into::into)
                                    .unwrap_or(token),
                            )),
                            // Invalid token
                            (Some(_), false) => {
                                Err(Rejection::from(ApiError::InvalidAuthorization))
                            }
                            // Missing token when required
                            (None, false) => Err(Rejection::from(ApiError::MissingAuthorization)),
                        }
                    }
                },
            )
            .boxed()
    }

    /// Is body encoded with gzip
    fn gzip(&self) -> BoxedFilter<(bool,)> {
        warp::header::optional::<String>("Content-Encoding")
            .and_then(|encoding: Option<String>| async move {
                match encoding {
                    Some(s) if s.as_bytes() == b"gzip" => Ok(true),
                    Some(_) => Err(Rejection::from(ApiError::UnsupportedEncoding)),
                    None => Ok(false),
                }
            })
            .boxed()
    }

    fn required_channel() -> BoxedFilter<(String,)> {
        let splunk_channel_query_param = warp::query::<HashMap<String, String>>()
            .map(|qs: HashMap<String, String>| qs.get("channel").map(|v| v.to_owned()));
        let splunk_channel_header = warp::header::optional::<String>(X_SPLUNK_REQUEST_CHANNEL);

        splunk_channel_header
            .and(splunk_channel_query_param)
            .and_then(|header: Option<String>, query_param| async move {
                header
                    .or(query_param)
                    .ok_or_else(|| Rejection::from(ApiError::MissingChannel))
            })
            .boxed()
    }
}

/// Constructs one or more events from json-s coming from reader.
/// If errors, it's done with input.
struct EventIterator<'de, R: JsonRead<'de>> {
    /// Remaining request with JSON events
    deserializer: serde_json::StreamDeserializer<'de, R, JsonValue>,
    /// Count of sent events
    events: usize,
    /// Optional channel from headers
    channel: Option<Value>,
    /// Default time
    time: Time,
    /// Remaining extracted default values
    extractors: [DefaultExtractor; 4],
    /// Event finalization
    batch: Option<BatchNotifier>,
    /// Splunk HEC Token for passthrough
    token: Option<Arc<str>>,
    /// Lognamespace to put the events in
    log_namespace: LogNamespace,
    /// handle to EventsReceived registry
    events_received: Registered<EventsReceived>,
    /// Whether to auto-forward metadata as event-level fields
    auto_forward_metadata: bool,
    /// Whether to fix bare string events
    fix_bare_string_events: bool,
    /// Whether auto_extract_timestamp was requested via URL query param
    auto_extract_timestamp: bool,
}

/// Intermediate struct to generate an `EventIterator`
struct EventIteratorGenerator<'de, R: JsonRead<'de>> {
    deserializer: serde_json::StreamDeserializer<'de, R, JsonValue>,
    channel: Option<String>,
    batch: Option<BatchNotifier>,
    token: Option<Arc<str>>,
    log_namespace: LogNamespace,
    events_received: Registered<EventsReceived>,
    remote: Option<SocketAddr>,
    remote_addr: Option<String>,
    auto_forward_metadata: bool,
    fix_bare_string_events: bool,
    auto_extract_timestamp: bool,
}

impl<'de, R: JsonRead<'de>> From<EventIteratorGenerator<'de, R>> for EventIterator<'de, R> {
    fn from(f: EventIteratorGenerator<'de, R>) -> Self {
        Self {
            deserializer: f.deserializer,
            events: 0,
            channel: f.channel.map(Value::from),
            time: Time::Now(Utc::now()),
            extractors: [
                DefaultExtractor::new_with(
                    "host",
                    log_schema().host_key().cloned().into(),
                    f.remote_addr
                        .or_else(|| f.remote.map(|addr| addr.to_string()))
                        .map(Value::from),
                    f.log_namespace,
                ),
                DefaultExtractor::new("index", OptionalValuePath::new(INDEX), f.log_namespace),
                DefaultExtractor::new("source", OptionalValuePath::new(SOURCE), f.log_namespace),
                DefaultExtractor::new(
                    "sourcetype",
                    OptionalValuePath::new(SOURCETYPE),
                    f.log_namespace,
                ),
            ],
            batch: f.batch,
            token: f.token,
            log_namespace: f.log_namespace,
            events_received: f.events_received,
            auto_forward_metadata: f.auto_forward_metadata,
            fix_bare_string_events: f.fix_bare_string_events,
            auto_extract_timestamp: f.auto_extract_timestamp,
        }
    }
}

impl<'de, R: JsonRead<'de>> EventIterator<'de, R> {
    fn build_event(&mut self, mut json: JsonValue) -> Result<Event, Rejection> {
        // Construct Event from parsed json event
        let mut log = match self.log_namespace {
            LogNamespace::Vector => self.build_log_vector(&mut json)?,
            LogNamespace::Legacy => self.build_log_legacy(&mut json)?,
        };

        // Add source type
        self.log_namespace.insert_vector_metadata(
            &mut log,
            log_schema().source_type_key(),
            &owned_value_path!("source_type"),
            SplunkHecFullConfig::NAME,
        );

        // Process channel field
        let channel_path = owned_value_path!(CHANNEL);
        if let Some(JsonValue::String(guid)) = json.get_mut("channel").map(JsonValue::take) {
            self.log_namespace.insert_source_metadata(
                SplunkHecFullConfig::NAME,
                &mut log,
                Some(LegacyKey::Overwrite(&channel_path)),
                lookup::path!(CHANNEL),
                guid,
            );
        } else if let Some(guid) = self.channel.as_ref() {
            self.log_namespace.insert_source_metadata(
                SplunkHecFullConfig::NAME,
                &mut log,
                Some(LegacyKey::Overwrite(&channel_path)),
                lookup::path!(CHANNEL),
                guid.clone(),
            );
        }

        // Process fields field
        if let Some(JsonValue::Object(object)) = json.get_mut("fields").map(JsonValue::take) {
            for (key, value) in object {
                self.log_namespace.insert_source_metadata(
                    SplunkHecFullConfig::NAME,
                    &mut log,
                    Some(LegacyKey::Overwrite(&owned_value_path!(key.as_str()))),
                    lookup::path!(key.as_str()),
                    value,
                );
            }
        }

        // Process time field
        let parsed_time = match json.get_mut("time").map(JsonValue::take) {
            Some(JsonValue::Number(time)) => Some(Some(time)),
            Some(JsonValue::String(time)) => Some(time.parse::<serde_json::Number>().ok()),
            _ => None,
        };

        match parsed_time {
            None => (),
            Some(Some(t)) => {
                if let Some(t) = t.as_u64() {
                    let time = parse_timestamp(t as i64)
                        .ok_or(ApiError::InvalidDataFormat { event: self.events })?;

                    self.time = Time::Provided(time);
                } else if let Some(t) = t.as_f64() {
                    self.time = Time::Provided(
                        Utc.timestamp_opt(
                            t.floor() as i64,
                            (t.fract() * 1000.0 * 1000.0 * 1000.0) as u32,
                        )
                        .single()
                        .expect("invalid timestamp"),
                    );
                } else {
                    return Err(ApiError::InvalidDataFormat { event: self.events }.into());
                }
            }
            Some(None) => return Err(ApiError::InvalidDataFormat { event: self.events }.into()),
        }

        // Add time field
        let timestamp = match self.time.clone() {
            Time::Provided(time) => time,
            Time::Now(time) => time,
        };

        self.log_namespace.insert_source_metadata(
            SplunkHecFullConfig::NAME,
            &mut log,
            log_schema().timestamp_key().map(LegacyKey::Overwrite),
            lookup::path!("timestamp"),
            timestamp,
        );

        // Extract default extracted fields
        for de in self.extractors.iter_mut() {
            de.extract(&mut log, &mut json);
        }

        // Auto-forward metadata as event-level fields (without splunk_ prefix)
        if self.auto_forward_metadata {
            // index
            let index_val = self.extractors[1].value.clone();
            if let Some(val) = index_val {
                log.insert(event_path!("index"), val);
            }
            // source
            let source_val = self.extractors[2].value.clone();
            if let Some(val) = source_val {
                log.insert(event_path!("source"), val);
            }
            // sourcetype
            let sourcetype_val = self.extractors[3].value.clone();
            if let Some(val) = sourcetype_val {
                log.insert(event_path!("sourcetype"), val);
            }
        }

        // Add passthrough token if present
        if let Some(token) = &self.token {
            log.metadata_mut().set_splunk_hec_token(Arc::clone(token));
        }

        // Write auto_extract_timestamp flag as event-level field for downstream sinks
        if self.auto_extract_timestamp {
            log.insert(
                event_path!("auto_extract_timestamp"),
                Value::from(true),
            );
        }

        if let Some(batch) = self.batch.clone() {
            log = log.with_batch_notifier(&batch);
        }

        self.events += 1;

        Ok(log.into())
    }

    /// Build the log event for the vector namespace.
    /// With fix_bare_string_events: wraps non-object events into {"message": value}.
    /// This prevents scalar values (string, integer, float, boolean, array)
    /// from being destroyed when metadata fields (index, sourcetype, etc.) are
    /// inserted at the event root level.
    fn build_log_vector(&mut self, json: &mut JsonValue) -> Result<LogEvent, Rejection> {
        match json.get("event") {
            Some(event) => {
                // Reject null events (Splunk returns code 13)
                if event.is_null() {
                    return Err(ApiError::EmptyEventField { event: self.events }.into());
                }
                // Reject empty string events (Splunk returns code 13)
                if let Some(s) = event.as_str() {
                    if s.is_empty() {
                        return Err(ApiError::EmptyEventField { event: self.events }.into());
                    }
                }
                // Reject empty object events
                if let Some(obj) = event.as_object() {
                    if obj.is_empty() {
                        return Err(ApiError::EmptyEventField { event: self.events }.into());
                    }
                }
                // Reject empty array events
                if let Some(arr) = event.as_array() {
                    if arr.is_empty() {
                        return Err(ApiError::EmptyEventField { event: self.events }.into());
                    }
                }

                let event: Value = event.into();

                // Determine if the event needs wrapping.
                // Object events can safely have metadata fields inserted at root.
                // All other types (string, integer, float, boolean, array) must be
                // wrapped as {"message": value} to prevent metadata insertion from
                // overwriting the scalar value at root.
                let is_object = event.is_object();
                let mut log = if self.fix_bare_string_events && !is_object {
                    let mut l = LogEvent::default();
                    l.insert(event_path!("message"), event);
                    l
                } else {
                    LogEvent::from(event)
                };

                // EstimatedJsonSizeOf must be calculated before enrichment
                self.events_received
                    .emit(CountByteSize(1, log.estimated_json_encoded_size_of()));

                // The timestamp is extracted from the message for the Legacy namespace.
                self.log_namespace.insert_vector_metadata(
                    &mut log,
                    log_schema().timestamp_key(),
                    lookup::path!("ingest_timestamp"),
                    chrono::Utc::now(),
                );

                Ok(log)
            }
            None => Err(ApiError::MissingEventField { event: self.events }.into()),
        }
    }

    /// Build the log event for the legacy namespace.
    fn build_log_legacy(&mut self, json: &mut JsonValue) -> Result<LogEvent, Rejection> {
        let mut log = LogEvent::default();
        match json.get_mut("event") {
            Some(event) => match event.take() {
                JsonValue::String(string) => {
                    if string.is_empty() {
                        return Err(ApiError::EmptyEventField { event: self.events }.into());
                    }
                    log.maybe_insert(log_schema().message_key_target_path(), string);
                }
                JsonValue::Object(mut object) => {
                    if object.is_empty() {
                        return Err(ApiError::EmptyEventField { event: self.events }.into());
                    }

                    // Add 'line' value as 'event::schema().message_key'
                    if let Some(line) = object.remove("line") {
                        match line {
                            JsonValue::Array(_) | JsonValue::Object(_) => {
                                log.insert(event_path!("line"), line);
                            }
                            _ => {
                                log.maybe_insert(log_schema().message_key_target_path(), line);
                            }
                        }
                    }

                    for (key, value) in object {
                        log.insert(event_path!(key.as_str()), value);
                    }
                }
                _ => return Err(ApiError::InvalidDataFormat { event: self.events }.into()),
            },
            None => return Err(ApiError::MissingEventField { event: self.events }.into()),
        };

        // EstimatedJsonSizeOf must be calculated before enrichment
        self.events_received
            .emit(CountByteSize(1, log.estimated_json_encoded_size_of()));

        Ok(log)
    }
}

impl<'de, R: JsonRead<'de>> Iterator for EventIterator<'de, R> {
    type Item = Result<Event, Rejection>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.deserializer.next() {
            Some(Ok(json)) => Some(self.build_event(json)),
            None => {
                if self.events == 0 {
                    Some(Err(ApiError::NoData.into()))
                } else {
                    None
                }
            }
            Some(Err(error)) => {
                emit!(SplunkHecRequestBodyInvalidError {
                    error: error.into()
                });
                Some(Err(
                    ApiError::InvalidDataFormat { event: self.events }.into()
                ))
            }
        }
    }
}

/// Parse a `i64` unix timestamp that can either be in seconds, milliseconds or
/// nanoseconds.
fn parse_timestamp(t: i64) -> Option<DateTime<Utc>> {
    const SEC_CUTOFF: i64 = 13569465600;
    const MILLISEC_CUTOFF: i64 = 253402300800000;

    if t < 0 {
        return None;
    }

    let ts = if t < SEC_CUTOFF {
        Utc.timestamp_opt(t, 0).single().expect("invalid timestamp")
    } else if t < MILLISEC_CUTOFF {
        Utc.timestamp_millis_opt(t)
            .single()
            .expect("invalid timestamp")
    } else {
        Utc.timestamp_nanos(t)
    };

    Some(ts)
}

/// Maintains last known extracted value of field and uses it in the absence of field.
struct DefaultExtractor {
    field: &'static str,
    to_field: OptionalValuePath,
    value: Option<Value>,
    log_namespace: LogNamespace,
}

impl DefaultExtractor {
    const fn new(
        field: &'static str,
        to_field: OptionalValuePath,
        log_namespace: LogNamespace,
    ) -> Self {
        DefaultExtractor {
            field,
            to_field,
            value: None,
            log_namespace,
        }
    }

    fn new_with(
        field: &'static str,
        to_field: OptionalValuePath,
        value: impl Into<Option<Value>>,
        log_namespace: LogNamespace,
    ) -> Self {
        DefaultExtractor {
            field,
            to_field,
            value: value.into(),
            log_namespace,
        }
    }

    fn extract(&mut self, log: &mut LogEvent, value: &mut JsonValue) {
        // Process json_field
        if let Some(JsonValue::String(new_value)) = value.get_mut(self.field).map(JsonValue::take) {
            self.value = Some(new_value.into());
        }

        // Add data field
        if let Some(index) = self.value.as_ref()
            && let Some(metadata_key) = self.to_field.path.as_ref()
        {
            self.log_namespace.insert_source_metadata(
                SplunkHecFullConfig::NAME,
                log,
                Some(LegacyKey::Overwrite(metadata_key)),
                &self.to_field.path.clone().unwrap_or(owned_value_path!("")),
                index.clone(),
            )
        }
    }
}

/// For tracking origin of the timestamp
#[derive(Clone, Debug)]
enum Time {
    /// Backup
    Now(DateTime<Utc>),
    /// Provided in the request
    Provided(DateTime<Utc>),
}

/// Creates event from raw request
#[allow(clippy::too_many_arguments)]
fn raw_event(
    bytes: Bytes,
    gzip: bool,
    channel: String,
    remote: Option<SocketAddr>,
    xff: Option<String>,
    batch: Option<BatchNotifier>,
    log_namespace: LogNamespace,
    events_received: &Registered<EventsReceived>,
    fix_bare_string_events: bool,
) -> Result<Event, Rejection> {
    // Process gzip
    let message: Value = if gzip {
        let mut data = Vec::new();
        match MultiGzDecoder::new(bytes.reader()).read_to_end(&mut data) {
            Ok(0) => return Err(ApiError::NoData.into()),
            Ok(_) => Value::from(Bytes::from(data)),
            Err(error) => {
                emit!(SplunkHecRequestBodyInvalidError { error });
                return Err(ApiError::InvalidDataFormat { event: 0 }.into());
            }
        }
    } else {
        if bytes.is_empty() {
            return Err(ApiError::NoData.into());
        }
        bytes.into()
    };

    // Construct event
    let mut log = match log_namespace {
        LogNamespace::Vector => {
            // Fix bare string events: wrap string values as {"message": "..."} instead of raw bytes
            // This prevents serialization issues where bare strings render as {"event":{}}
            if fix_bare_string_events && message.is_bytes() {
                let mut l = LogEvent::default();
                l.insert(event_path!("message"), message);
                l
            } else {
                LogEvent::from(message)
            }
        }
        LogNamespace::Legacy => {
            let mut log = LogEvent::default();
            log.maybe_insert(log_schema().message_key_target_path(), message);
            log
        }
    };
    // We need to calculate the estimated json size of the event BEFORE enrichment.
    events_received.emit(CountByteSize(1, log.estimated_json_encoded_size_of()));

    // Add channel
    log_namespace.insert_source_metadata(
        SplunkHecFullConfig::NAME,
        &mut log,
        Some(LegacyKey::Overwrite(&owned_value_path!(CHANNEL))),
        lookup::path!(CHANNEL),
        channel,
    );

    // host-field priority for raw endpoint:
    // - x-forwarded-for is set to `host` field first, if present. If not present:
    // - set remote addr to host field
    let host = if let Some(remote_address) = xff {
        Some(remote_address)
    } else {
        remote.map(|remote| remote.to_string())
    };

    if let Some(host) = host {
        log_namespace.insert_source_metadata(
            SplunkHecFullConfig::NAME,
            &mut log,
            log_schema().host_key().map(LegacyKey::InsertIfEmpty),
            lookup::path!("host"),
            host,
        );
    }

    log_namespace.insert_standard_vector_source_metadata(
        &mut log,
        SplunkHecFullConfig::NAME,
        Utc::now(),
    );

    if let Some(batch) = batch {
        log = log.with_batch_notifier(&batch);
    }

    Ok(Event::from(log))
}

/// Creates multiple events from raw request by splitting on newlines.
/// Each non-empty line becomes a separate event, matching Splunk's LINE_BREAKER behavior.
#[allow(clippy::too_many_arguments)]
fn raw_events_split(
    bytes: Bytes,
    gzip: bool,
    channel: String,
    remote: Option<SocketAddr>,
    xff: Option<String>,
    batch: Option<BatchNotifier>,
    log_namespace: LogNamespace,
    events_received: &Registered<EventsReceived>,
    fix_bare_string_events: bool,
) -> Result<Vec<Event>, Rejection> {
    // Decompress if needed
    let raw_bytes: Bytes = if gzip {
        let mut data = Vec::new();
        match MultiGzDecoder::new(bytes.reader()).read_to_end(&mut data) {
            Ok(0) => return Err(ApiError::NoData.into()),
            Ok(_) => Bytes::from(data),
            Err(error) => {
                emit!(SplunkHecRequestBodyInvalidError { error });
                return Err(ApiError::InvalidDataFormat { event: 0 }.into());
            }
        }
    } else {
        if bytes.is_empty() {
            return Err(ApiError::NoData.into());
        }
        bytes
    };

    // Split by newlines, filter empty lines
    let text = String::from_utf8_lossy(&raw_bytes);
    let lines: Vec<&str> = text.split('\n').filter(|l| !l.trim().is_empty()).collect();

    if lines.is_empty() {
        return Err(ApiError::NoData.into());
    }

    // If only one line, delegate to raw_event for efficiency
    if lines.len() == 1 {
        let event = raw_event(
            raw_bytes,
            false, // already decompressed
            channel,
            remote,
            xff,
            batch,
            log_namespace,
            events_received,
            fix_bare_string_events,
        )?;
        return Ok(vec![event]);
    }

    // Build an event per line
    let host = if let Some(ref remote_address) = xff {
        Some(remote_address.clone())
    } else {
        remote.map(|r| r.to_string())
    };

    let mut events = Vec::with_capacity(lines.len());
    for line in lines {
        let message: Value = Value::from(Bytes::from(line.to_owned()));

        let mut log = match log_namespace {
            LogNamespace::Vector => {
                if fix_bare_string_events && message.is_bytes() {
                    let mut l = LogEvent::default();
                    l.insert(event_path!("message"), message);
                    l
                } else {
                    LogEvent::from(message)
                }
            }
            LogNamespace::Legacy => {
                let mut l = LogEvent::default();
                l.maybe_insert(log_schema().message_key_target_path(), message);
                l
            }
        };

        events_received.emit(CountByteSize(1, log.estimated_json_encoded_size_of()));

        // Add channel (same for all lines in this request)
        log_namespace.insert_source_metadata(
            SplunkHecFullConfig::NAME,
            &mut log,
            Some(LegacyKey::Overwrite(&owned_value_path!(CHANNEL))),
            lookup::path!(CHANNEL),
            channel.clone(),
        );

        if let Some(ref host) = host {
            log_namespace.insert_source_metadata(
                SplunkHecFullConfig::NAME,
                &mut log,
                log_schema().host_key().map(LegacyKey::InsertIfEmpty),
                lookup::path!("host"),
                host.clone(),
            );
        }

        log_namespace.insert_standard_vector_source_metadata(
            &mut log,
            SplunkHecFullConfig::NAME,
            Utc::now(),
        );

        if let Some(ref batch) = batch {
            log = log.with_batch_notifier(batch);
        }

        events.push(Event::from(log));
    }

    Ok(events)
}

// === Internal Events (inline to avoid coupling with splunk_hec's internal_events) ===

#[derive(Debug, vector_lib::NamedInternalEvent)]
struct SplunkHecRequestBodyInvalidError {
    pub error: std::io::Error,
}

impl vector_lib::internal_event::InternalEvent for SplunkHecRequestBodyInvalidError {
    fn emit(self) {
        error!(
            message = "Invalid request body.",
            error = ?self.error,
            error_code = "invalid_request_body",
            error_type = vector_lib::internal_event::error_type::PARSER_FAILED,
            stage = vector_lib::internal_event::error_stage::PROCESSING
        );
        metrics::counter!(
            "component_errors_total",
            "error_code" => "invalid_request_body",
            "error_type" => vector_lib::internal_event::error_type::PARSER_FAILED,
            "stage" => vector_lib::internal_event::error_stage::PROCESSING,
        )
        .increment(1);
    }
}

#[derive(Debug, vector_lib::NamedInternalEvent)]
struct SplunkHecRequestError {
    pub error: ApiError,
}

impl vector_lib::internal_event::InternalEvent for SplunkHecRequestError {
    fn emit(self) {
        error!(
            message = "Error processing request.",
            error = ?self.error,
            error_type = vector_lib::internal_event::error_type::REQUEST_FAILED,
            stage = vector_lib::internal_event::error_stage::RECEIVING
        );
        metrics::counter!(
            "component_errors_total",
            "error_type" => vector_lib::internal_event::error_type::REQUEST_FAILED,
            "stage" => vector_lib::internal_event::error_stage::RECEIVING,
        )
        .increment(1);
    }
}

// === Error types and response handling ===

#[derive(Clone, Copy, Debug, Snafu)]
pub(crate) enum ApiError {
    MissingAuthorization,
    InvalidAuthorization,
    UnsupportedEncoding,
    UnsupportedContentType,
    MissingChannel,
    NoData,
    InvalidDataFormat { event: usize },
    ServerShutdown,
    EmptyEventField { event: usize },
    MissingEventField { event: usize },
    BadRequest,
    ServiceUnavailable,
    AckIsDisabled,
}

impl warp::reject::Reject for ApiError {}

/// Cached bodies for common responses
mod splunk_response {
    use serde::Serialize;

    // https://docs.splunk.com/Documentation/Splunk/8.2.3/Data/TroubleshootHTTPEventCollector#Possible_error_codes
    pub enum HecStatusCode {
        Success = 0,
        TokenIsRequired = 2,
        InvalidAuthorization = 3,
        NoData = 5,
        InvalidDataFormat = 6,
        ServerIsBusy = 9,
        DataChannelIsMissing = 10,
        EventFieldIsRequired = 12,
        EventFieldCannotBeBlank = 13,
        AckIsDisabled = 14,
    }

    #[derive(Serialize)]
    pub enum HecResponseMetadata {
        #[serde(rename = "ackId")]
        AckId(u64),
        #[serde(rename = "invalid-event-number")]
        InvalidEventNumber(usize),
    }

    #[derive(Serialize)]
    pub struct HecResponse {
        text: &'static str,
        code: u8,
        #[serde(skip_serializing_if = "Option::is_none", flatten)]
        pub metadata: Option<HecResponseMetadata>,
    }

    impl HecResponse {
        pub const fn new(code: HecStatusCode) -> Self {
            let text = match code {
                HecStatusCode::Success => "Success",
                HecStatusCode::TokenIsRequired => "Token is required",
                HecStatusCode::InvalidAuthorization => "Invalid authorization",
                HecStatusCode::NoData => "No data",
                HecStatusCode::InvalidDataFormat => "Invalid data format",
                HecStatusCode::DataChannelIsMissing => "Data channel is missing",
                HecStatusCode::EventFieldIsRequired => "Event field is required",
                HecStatusCode::EventFieldCannotBeBlank => "Event field cannot be blank",
                HecStatusCode::ServerIsBusy => "Server is busy",
                HecStatusCode::AckIsDisabled => "Ack is disabled",
            };

            Self {
                text,
                code: code as u8,
                metadata: None,
            }
        }

        pub const fn with_metadata(mut self, metadata: HecResponseMetadata) -> Self {
            self.metadata = Some(metadata);
            self
        }
    }

    pub const INVALID_AUTHORIZATION: HecResponse =
        HecResponse::new(HecStatusCode::InvalidAuthorization);
    pub const TOKEN_IS_REQUIRED: HecResponse = HecResponse::new(HecStatusCode::TokenIsRequired);
    pub const NO_DATA: HecResponse = HecResponse::new(HecStatusCode::NoData);
    pub const SUCCESS: HecResponse = HecResponse::new(HecStatusCode::Success);
    pub const SERVER_IS_BUSY: HecResponse = HecResponse::new(HecStatusCode::ServerIsBusy);
    pub const NO_CHANNEL: HecResponse = HecResponse::new(HecStatusCode::DataChannelIsMissing);
    pub const ACK_IS_DISABLED: HecResponse = HecResponse::new(HecStatusCode::AckIsDisabled);
}

fn finish_ok(maybe_ack_id: Option<u64>) -> Response {
    let body = if let Some(ack_id) = maybe_ack_id {
        HecResponse::new(HecStatusCode::Success).with_metadata(HecResponseMetadata::AckId(ack_id))
    } else {
        splunk_response::SUCCESS
    };
    response_json(StatusCode::OK, body)
}

fn response_plain(code: StatusCode, msg: &'static str) -> Response {
    warp::reply::with_status(
        warp::reply::with_header(msg, http::header::CONTENT_TYPE, "text/plain; charset=utf-8"),
        code,
    )
    .into_response()
}

async fn finish_err(rejection: Rejection) -> Result<(Response,), Rejection> {
    if let Some(&error) = rejection.find::<ApiError>() {
        emit!(SplunkHecRequestError { error });
        Ok((match error {
            ApiError::MissingAuthorization => {
                response_json(StatusCode::UNAUTHORIZED, splunk_response::TOKEN_IS_REQUIRED)
            }
            ApiError::InvalidAuthorization => response_json(
                StatusCode::UNAUTHORIZED,
                splunk_response::INVALID_AUTHORIZATION,
            ),
            ApiError::UnsupportedEncoding => empty_response(StatusCode::UNSUPPORTED_MEDIA_TYPE),
            ApiError::UnsupportedContentType => response_plain(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "The request's content-type is not supported",
            ),
            ApiError::MissingChannel => {
                response_json(StatusCode::BAD_REQUEST, splunk_response::NO_CHANNEL)
            }
            ApiError::NoData => response_json(StatusCode::BAD_REQUEST, splunk_response::NO_DATA),
            ApiError::ServerShutdown => empty_response(StatusCode::SERVICE_UNAVAILABLE),
            ApiError::InvalidDataFormat { event } => response_json(
                StatusCode::BAD_REQUEST,
                HecResponse::new(HecStatusCode::InvalidDataFormat)
                    .with_metadata(HecResponseMetadata::InvalidEventNumber(event)),
            ),
            ApiError::EmptyEventField { event } => response_json(
                StatusCode::BAD_REQUEST,
                HecResponse::new(HecStatusCode::EventFieldCannotBeBlank)
                    .with_metadata(HecResponseMetadata::InvalidEventNumber(event)),
            ),
            ApiError::MissingEventField { event } => response_json(
                StatusCode::BAD_REQUEST,
                HecResponse::new(HecStatusCode::EventFieldIsRequired)
                    .with_metadata(HecResponseMetadata::InvalidEventNumber(event)),
            ),
            ApiError::BadRequest => empty_response(StatusCode::BAD_REQUEST),
            ApiError::ServiceUnavailable => response_json(
                StatusCode::SERVICE_UNAVAILABLE,
                splunk_response::SERVER_IS_BUSY,
            ),
            ApiError::AckIsDisabled => {
                response_json(StatusCode::BAD_REQUEST, splunk_response::ACK_IS_DISABLED)
            }
        },))
    } else {
        Err(rejection)
    }
}

/// Response without body
fn empty_response(code: StatusCode) -> Response {
    let mut res = Response::default();
    *res.status_mut() = code;
    res
}

/// Response with body
fn response_json(code: StatusCode, body: impl Serialize) -> Response {
    warp::reply::with_status(warp::reply::json(&body), code).into_response()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use futures_util::Stream;
    use reqwest::Response;
    use vector_lib::{event::EventStatus, sensitive_string::SensitiveString};

    use super::*;
    use crate::{
        SourceSender,
        config::{SourceConfig, SourceContext},
        event::Event,
        test_util::{
            addr::{PortGuard, next_addr},
            collect_n, wait_for_tcp,
        },
    };

    /// Splunk token
    const TOKEN: &str = "token";

    async fn source_with(
        token: Option<SensitiveString>,
        valid_tokens: Option<&[&str]>,
        acknowledgements: Option<HecAcknowledgementsConfig>,
        store_hec_token: bool,
    ) -> (
        impl Stream<Item = Event> + Unpin + use<>,
        SocketAddr,
        PortGuard,
    ) {
        source_with_query_auth(
            token,
            valid_tokens,
            acknowledgements,
            store_hec_token,
            true,
        )
        .await
    }

    async fn source_with_query_auth(
        token: Option<SensitiveString>,
        valid_tokens: Option<&[&str]>,
        acknowledgements: Option<HecAcknowledgementsConfig>,
        store_hec_token: bool,
        allow_query_string_auth: bool,
    ) -> (
        impl Stream<Item = Event> + Unpin + use<>,
        SocketAddr,
        PortGuard,
    ) {
        let (sender, recv) = SourceSender::new_test_finalize(EventStatus::Delivered);
        let (_guard, address) = next_addr();
        let valid_tokens =
            valid_tokens.map(|tokens| tokens.iter().map(|v| v.to_string().into()).collect());
        let cx = SourceContext::new_test(sender, None);
        tokio::spawn(async move {
            SplunkHecFullConfig {
                address,
                token,
                valid_tokens,
                tls: None,
                acknowledgements: acknowledgements.unwrap_or_default(),
                store_hec_token,
                log_namespace: None,
                keepalive: Default::default(),
                allow_query_string_auth,
                auto_forward_metadata: true,
                fix_bare_string_events: true,
                raw_require_channel: true,
                raw_line_splitting: false,
            }
            .build(cx)
            .await
            .unwrap()
            .await
            .unwrap()
        });
        wait_for_tcp(address).await;
        (recv, address, _guard)
    }

    async fn source() -> (impl Stream<Item = Event> + Unpin, SocketAddr, PortGuard) {
        source_with(
            Some(TOKEN.to_owned().into()),
            None,
            None,
            false,
        )
        .await
    }

    async fn source_with_full(
        token: Option<SensitiveString>,
        valid_tokens: Option<&[&str]>,
        acknowledgements: Option<HecAcknowledgementsConfig>,
        store_hec_token: bool,
        raw_require_channel: bool,
    ) -> (
        impl Stream<Item = Event> + Unpin + use<>,
        SocketAddr,
        PortGuard,
    ) {
        source_with_full_opts(
            token,
            valid_tokens,
            acknowledgements,
            store_hec_token,
            raw_require_channel,
            false, // raw_line_splitting default off
        )
        .await
    }

    async fn source_with_full_opts(
        token: Option<SensitiveString>,
        valid_tokens: Option<&[&str]>,
        acknowledgements: Option<HecAcknowledgementsConfig>,
        store_hec_token: bool,
        raw_require_channel: bool,
        raw_line_splitting: bool,
    ) -> (
        impl Stream<Item = Event> + Unpin + use<>,
        SocketAddr,
        PortGuard,
    ) {
        let (sender, recv) = SourceSender::new_test_finalize(EventStatus::Delivered);
        let (_guard, address) = next_addr();
        let valid_tokens =
            valid_tokens.map(|tokens| tokens.iter().map(|v| v.to_string().into()).collect());
        let cx = SourceContext::new_test(sender, None);
        tokio::spawn(async move {
            SplunkHecFullConfig {
                address,
                token,
                valid_tokens,
                tls: None,
                acknowledgements: acknowledgements.unwrap_or_default(),
                store_hec_token,
                log_namespace: None,
                keepalive: Default::default(),
                allow_query_string_auth: true,
                auto_forward_metadata: true,
                fix_bare_string_events: true,
                raw_require_channel,
                raw_line_splitting,
            }
            .build(cx)
            .await
            .unwrap()
            .await
            .unwrap()
        });
        wait_for_tcp(address).await;
        (recv, address, _guard)
    }

    async fn send_req(
        address: SocketAddr,
        api: &str,
        body: &str,
        token: &str,
        channel: Option<&str>,
        query_params: &[(&str, &str)],
    ) -> Response {
        let mut builder = reqwest::Client::new()
            .post(format!("http://{address}/services/collector/{api}"))
            .header("Authorization", format!("Splunk {token}"))
            .body(body.to_string());

        if let Some(ch) = channel {
            builder = builder.header("x-splunk-request-channel", ch);
        }

        if !query_params.is_empty() {
            builder = builder.query(query_params);
        }

        builder.send().await.unwrap()
    }

    // Test: URL token defaults disabled
    #[tokio::test]
    async fn url_token_defaults_disabled() {
        let (source, address, _guard) = source_with_query_auth(
            Some(TOKEN.to_owned().into()),
            None,
            None,
            false,
            SplunkHecFullConfig::default().allow_query_string_auth,
        )
        .await;

        let resp = reqwest::Client::new()
            .post(format!(
                "http://{address}/services/collector/event?token={TOKEN}"
            ))
            .header("x-splunk-request-channel", "test-channel")
            .body(r#"{"event":"hello via url token"}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 401);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["code"], 2);
        drop(source);
    }

    // Test: URL token is accepted when query auth is enabled and header is missing
    #[tokio::test]
    async fn url_used_when_header_missing() {
        let (source, address, _guard) = source_with_query_auth(
            Some(TOKEN.to_owned().into()),
            None,
            None,
            false,
            true,
        )
        .await;

        let resp = reqwest::Client::new()
            .post(format!(
                "http://{address}/services/collector/event?token={TOKEN}"
            ))
            .header("x-splunk-request-channel", "test-channel")
            .body(r#"{"event":"hello via url token"}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 1).await;
        assert_eq!(events.len(), 1);
    }

    // Test: Header token takes precedence over URL token when query auth is enabled
    #[tokio::test]
    async fn header_priority_over_url_when_enabled() {
        let (source, address, _guard) = source_with_query_auth(
            None,
            Some(&["url-token", "header-token"]),
            None,
            true,
            true,
        )
        .await;

        let resp = reqwest::Client::new()
            .post(format!(
                "http://{address}/services/collector/event?token=wrong-token"
            ))
            .header("Authorization", "Splunk header-token")
            .header("x-splunk-request-channel", "test-channel")
            .body(r#"{"event":"precedence test"}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 1).await;
        let log = events[0].as_log();
        // The stored token should be the header token (header has precedence)
        assert_eq!(
            log.metadata().splunk_hec_token().unwrap().as_ref(),
            "header-token"
        );
    }

    // Test: URL token is ignored when query auth is disabled
    #[tokio::test]
    async fn url_ignored_when_disabled() {
        let (_source, address, _guard) = source_with_query_auth(
            Some(TOKEN.to_owned().into()),
            None,
            None,
            false,
            false,
        )
        .await;

        let resp = reqwest::Client::new()
            .post(format!(
                "http://{address}/services/collector/event?token={TOKEN}"
            ))
            .header("x-splunk-request-channel", "test-channel")
            .body(r#"{"event":"url token ignored"}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 401);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["code"], 2);
    }

    // Test: Raw endpoint with URL metadata parameters
    #[tokio::test]
    async fn test_raw_endpoint_url_metadata() {
        let (source, address, _guard) = source().await;

        let resp = reqwest::Client::new()
            .post(format!(
                "http://{address}/services/collector/raw?channel=test-ch&index=my_index&sourcetype=my_type&source=my_source"
            ))
            .header("Authorization", format!("Splunk {TOKEN}"))
            .body("raw event data")
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 1).await;
        let log = events[0].as_log();

        // Check that metadata was extracted from URL params
        assert_eq!(
            log.get("splunk_index").unwrap().to_string_lossy(),
            "my_index"
        );
        assert_eq!(
            log.get("splunk_sourcetype").unwrap().to_string_lossy(),
            "my_type"
        );
        assert_eq!(
            log.get("splunk_source").unwrap().to_string_lossy(),
            "my_source"
        );
        // Auto-forward metadata should also set un-prefixed fields
        assert_eq!(log.get("index").unwrap().to_string_lossy(), "my_index");
        assert_eq!(log.get("sourcetype").unwrap().to_string_lossy(), "my_type");
        assert_eq!(log.get("source").unwrap().to_string_lossy(), "my_source");
    }

    // Test: Bare string fix in vector namespace
    #[tokio::test]
    async fn test_bare_string_fix() {
        let (sender, recv) = SourceSender::new_test_finalize(EventStatus::Delivered);
        let (_guard, address) = next_addr();
        let cx = SourceContext::new_test(sender, None);
        tokio::spawn(async move {
            SplunkHecFullConfig {
                address,
                token: Some(TOKEN.to_owned().into()),
                valid_tokens: None,
                tls: None,
                acknowledgements: Default::default(),
                store_hec_token: false,
                log_namespace: Some(true), // Vector namespace
                keepalive: Default::default(),
                allow_query_string_auth: true,
                auto_forward_metadata: true,
                fix_bare_string_events: true,
                raw_require_channel: true,
                raw_line_splitting: false,
            }
            .build(cx)
            .await
            .unwrap()
            .await
            .unwrap()
        });
        wait_for_tcp(address).await;

        let resp = send_req(
            address,
            "event",
            r#"{"event":"bare string event"}"#,
            TOKEN,
            Some("ch"),
            &[],
        )
        .await;
        assert_eq!(resp.status(), 200);

        let events = collect_n(recv, 1).await;
        let log = events[0].as_log();
        // With fix_bare_string_events=true, the string should be in the "message" field
        assert_eq!(
            log.get("message").unwrap().to_string_lossy(),
            "bare string event"
        );
    }

    // Test: Health endpoint
    #[tokio::test]
    async fn test_health_endpoint() {
        let (_source, address, _guard) = source().await;

        let resp = reqwest::Client::new()
            .get(format!("http://{address}/services/collector/health"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["text"], "HEC is healthy");
        assert_eq!(body["code"], 17);
    }

    // Test: Basic event endpoint
    #[tokio::test]
    async fn test_basic_event() {
        let (source, address, _guard) = source().await;

        let resp = send_req(
            address,
            "event",
            r#"{"event":"hello world"}"#,
            TOKEN,
            Some("test-channel"),
            &[],
        )
        .await;
        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 1).await;
        assert_eq!(events.len(), 1);
    }

    // Test: Missing auth returns 401
    #[tokio::test]
    async fn test_missing_auth() {
        let (_source, address, _guard) = source().await;

        let resp = reqwest::Client::new()
            .post(format!("http://{address}/services/collector/event"))
            .header("x-splunk-request-channel", "ch")
            .body(r#"{"event":"no auth"}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 401);
    }

    // === Improvement 1: Health endpoint tests ===

    // Test: Health with valid token returns 200
    #[tokio::test]
    async fn test_health_with_valid_token() {
        let (_source, address, _guard) = source().await;
        let resp = reqwest::Client::new()
            .get(format!(
                "http://{address}/services/collector/health?token={TOKEN}"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    // Test: Health with invalid token returns 400
    #[tokio::test]
    async fn test_health_with_invalid_token() {
        let (_source, address, _guard) = source().await;
        let resp = reqwest::Client::new()
            .get(format!(
                "http://{address}/services/collector/health?token=bad-token"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    // Test: Health with ack=true when ack disabled returns 503
    #[tokio::test]
    async fn test_health_with_ack_disabled() {
        let (_source, address, _guard) = source().await; // default: ack disabled
        let resp = reqwest::Client::new()
            .get(format!(
                "http://{address}/services/collector/health?ack=true"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 503);
    }

    // Test: Health no params returns 200
    #[tokio::test]
    async fn test_health_no_params() {
        let (_source, address, _guard) = source().await;
        let resp = reqwest::Client::new()
            .get(format!("http://{address}/services/collector/health"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["code"], 17);
    }

    // === Improvement 2: Raw channel optional tests ===

    // Test: Raw without channel when required returns 400
    #[tokio::test]
    async fn test_raw_without_channel_required() {
        let (_source, address, _guard) = source().await; // raw_require_channel=true by default
        let resp = reqwest::Client::new()
            .post(format!("http://{address}/services/collector/raw"))
            .header("Authorization", format!("Splunk {TOKEN}"))
            .body("raw data without channel")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400); // Missing channel
    }

    // Test: Raw without channel when optional succeeds
    #[tokio::test]
    async fn test_raw_without_channel_optional() {
        let (source, address, _guard) = source_with_full(
            Some(TOKEN.to_owned().into()),
            None,
            None,
            false,
            false, // raw_require_channel = false
        )
        .await;

        let resp = reqwest::Client::new()
            .post(format!("http://{address}/services/collector/raw"))
            .header("Authorization", format!("Splunk {TOKEN}"))
            .body("raw data without channel")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 1).await;
        assert_eq!(events.len(), 1);
        // The event should have an auto-generated channel
        let log = events[0].as_log();
        assert!(log.get("splunk_channel").is_some());
    }

    // === Improvement 3: Raw ?time= tests ===

    // Test: Raw endpoint with integer epoch time
    #[tokio::test]
    async fn test_raw_endpoint_time_param() {
        let (source, address, _guard) = source().await;
        let resp = reqwest::Client::new()
            .post(format!(
                "http://{address}/services/collector/raw?channel=ch1&time=1609459200"
            ))
            .header("Authorization", format!("Splunk {TOKEN}"))
            .body("event with time")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 1).await;
        let log = events[0].as_log();
        // Verify timestamp was set to 2021-01-01T00:00:00Z
        let ts = log.get("timestamp").unwrap();
        let ts_str = ts.to_string_lossy();
        assert!(
            ts_str.contains("2021-01-01"),
            "Expected timestamp containing 2021-01-01, got: {}",
            ts_str
        );
    }

    // Test: Raw endpoint with float epoch time
    #[tokio::test]
    async fn test_raw_endpoint_time_param_float() {
        let (source, address, _guard) = source().await;
        let resp = reqwest::Client::new()
            .post(format!(
                "http://{address}/services/collector/raw?channel=ch1&time=1609459200.123"
            ))
            .header("Authorization", format!("Splunk {TOKEN}"))
            .body("event with float time")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 1).await;
        let log = events[0].as_log();
        let ts = log.get("timestamp").unwrap();
        let ts_str = ts.to_string_lossy();
        assert!(
            ts_str.contains("2021-01-01"),
            "Expected timestamp containing 2021-01-01, got: {}",
            ts_str
        );
    }

    // === Improvement 4: auto_extract_timestamp tests ===

    // Test: auto_extract_timestamp=true is passed through to event
    #[tokio::test]
    async fn test_event_auto_extract_timestamp_param() {
        let (source, address, _guard) = source().await;
        let resp = reqwest::Client::new()
            .post(format!(
                "http://{address}/services/collector/event?auto_extract_timestamp=true"
            ))
            .header("Authorization", format!("Splunk {TOKEN}"))
            .header("x-splunk-request-channel", "ch1")
            .body(r#"{"event":"test auto extract"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 1).await;
        let log = events[0].as_log();
        assert_eq!(
            log.get("auto_extract_timestamp").unwrap().to_string_lossy(),
            "true"
        );
    }

    // Test: auto_extract_timestamp not set when not in query
    #[tokio::test]
    async fn test_event_no_auto_extract_timestamp() {
        let (source, address, _guard) = source().await;
        let resp = send_req(
            address,
            "event",
            r#"{"event":"no auto extract"}"#,
            TOKEN,
            Some("ch1"),
            &[],
        )
        .await;
        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 1).await;
        let log = events[0].as_log();
        assert!(log.get("auto_extract_timestamp").is_none());
    }

    // Test: Generate config
    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<SplunkHecFullConfig>();
    }

    // ===================================================================
    // Audit fix tests — based on Splunk HEC API official documentation
    // ===================================================================

    // Test: Raw endpoint with URL metadata preserves raw text body
    #[tokio::test]
    async fn test_raw_with_url_metadata_preserves_body() {
        let (source, address, _guard) = source_with_full(
            Some(TOKEN.to_owned().into()),
            None,
            None,
            false,
            false, // raw_require_channel = false
        )
        .await;

        let resp = reqwest::Client::new()
            .post(format!(
                "http://{address}/services/collector/raw?channel=ch1&index=test_idx&sourcetype=test_type&source=test_src&host=test_host"
            ))
            .header("Authorization", format!("Splunk {TOKEN}"))
            .body("THIS IS THE RAW TEXT")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 1).await;
        let log = events[0].as_log();

        // Raw text MUST be preserved in the "message" field
        assert_eq!(
            log.get("message").unwrap().to_string_lossy(),
            "THIS IS THE RAW TEXT",
            "Raw text body must be preserved when URL metadata params are present"
        );

        // URL metadata must also be present
        assert_eq!(log.get("index").unwrap().to_string_lossy(), "test_idx");
        assert_eq!(log.get("sourcetype").unwrap().to_string_lossy(), "test_type");
        assert_eq!(log.get("source").unwrap().to_string_lossy(), "test_src");
    }

    // Test: Raw endpoint without URL metadata preserves raw text body
    #[tokio::test]
    async fn test_raw_without_url_metadata_preserves_body() {
        let (source, address, _guard) = source_with_full(
            Some(TOKEN.to_owned().into()),
            None,
            None,
            false,
            false,
        )
        .await;

        let resp = reqwest::Client::new()
            .post(format!("http://{address}/services/collector/raw?channel=ch1"))
            .header("Authorization", format!("Splunk {TOKEN}"))
            .body("simple raw text")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 1).await;
        let log = events[0].as_log();

        // With fix_bare_string_events=true, raw text should be in "message" field
        assert_eq!(
            log.get("message").unwrap().to_string_lossy(),
            "simple raw text"
        );
    }

    // Test: Empty string event rejected (Splunk code 13)
    #[tokio::test]
    async fn test_empty_string_event_rejected() {
        let (_source, address, _guard) = source().await;
        let resp = send_req(
            address,
            "event",
            r#"{"event":""}"#,
            TOKEN,
            Some("ch1"),
            &[],
        )
        .await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["code"], 13, "Empty string event should return code 13");
    }

    // Test: Empty object event rejected
    #[tokio::test]
    async fn test_empty_object_event_rejected() {
        let (_source, address, _guard) = source().await;
        let resp = send_req(
            address,
            "event",
            r#"{"event":{}}"#,
            TOKEN,
            Some("ch1"),
            &[],
        )
        .await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["code"], 13, "Empty object event should return code 13");
    }

    // Test: Empty raw body rejected
    #[tokio::test]
    async fn test_empty_raw_body_rejected() {
        let (_source, address, _guard) = source_with_full(
            Some(TOKEN.to_owned().into()),
            None,
            None,
            false,
            false,
        )
        .await;
        let resp = reqwest::Client::new()
            .post(format!("http://{address}/services/collector/raw?channel=ch1"))
            .header("Authorization", format!("Splunk {TOKEN}"))
            .body("")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "Empty raw body should be rejected");
    }

    // Test: Basic auth (RFC 1945) support
    #[tokio::test]
    async fn test_basic_auth_rfc1945() {
        let (source, address, _guard) = source().await;
        use base64::prelude::{BASE64_STANDARD, Engine as _};
        let cred = BASE64_STANDARD.encode(format!("x:{TOKEN}"));
        let resp = reqwest::Client::new()
            .post(format!("http://{address}/services/collector/event"))
            .header("Authorization", format!("Basic {cred}"))
            .header("x-splunk-request-channel", "ch1")
            .body(r#"{"event":"basic auth works"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "Basic auth (RFC 1945) should be accepted");

        let events = collect_n(source, 1).await;
        assert_eq!(events.len(), 1);
    }

    // Test: Basic auth with invalid token rejected
    #[tokio::test]
    async fn test_basic_auth_invalid_rejected() {
        let (_source, address, _guard) = source().await;
        use base64::prelude::{BASE64_STANDARD, Engine as _};
        let cred = BASE64_STANDARD.encode("x:invalid-token");
        let resp = reqwest::Client::new()
            .post(format!("http://{address}/services/collector/event"))
            .header("Authorization", format!("Basic {cred}"))
            .header("x-splunk-request-channel", "ch1")
            .body(r#"{"event":"should fail"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    // Test: Batch of mixed string and object events
    #[tokio::test]
    async fn test_batch_mixed_string_object_events() {
        let (source, address, _guard) = source().await;
        let batch = r#"{"event":"string event"}{"event":{"key":"object event"}}{"event":"another string"}"#;
        let resp = send_req(address, "event", batch, TOKEN, Some("ch1"), &[]).await;
        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 3).await;
        assert_eq!(events.len(), 3);

        // First event: string should have "message" field
        let log0 = events[0].as_log();
        assert!(
            log0.get("message").is_some(),
            "String event should have 'message' field"
        );

        // Second event: object should have "key" field
        let log1 = events[1].as_log();
        assert_eq!(log1.get("key").unwrap().to_string_lossy(), "object event");

        // Third event: string should have "message" field
        let log2 = events[2].as_log();
        assert!(
            log2.get("message").is_some(),
            "String event should have 'message' field"
        );
    }

    // Test: Integer event preserved (not corrupted by metadata)
    #[tokio::test]
    async fn test_integer_event_preserved() {
        let (source, address, _guard) = source().await;
        let resp = send_req(
            address,
            "event",
            r#"{"event": 42, "index": "test_idx", "sourcetype": "metric"}"#,
            TOKEN,
            Some("ch1"),
            &[],
        )
        .await;
        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 1).await;
        let log = events[0].as_log();
        // Integer should be wrapped in "message" field to prevent metadata corruption
        let msg = log.get("message").expect("Integer event should be wrapped in 'message' field");
        assert_eq!(msg, &Value::Integer(42), "Integer value should be preserved as 42");
        // Metadata should also be present
        assert!(log.get("index").is_some(), "index metadata should be present");
    }

    // Test: Float event preserved
    #[tokio::test]
    async fn test_float_event_preserved() {
        let (source, address, _guard) = source().await;
        let resp = send_req(
            address,
            "event",
            r#"{"event": 3.14, "index": "metrics"}"#,
            TOKEN,
            Some("ch1"),
            &[],
        )
        .await;
        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 1).await;
        let log = events[0].as_log();
        let msg = log.get("message").expect("Float event should be wrapped in 'message' field");
        // Float 3.14 should be preserved
        match msg {
            Value::Float(f) => assert!((f.into_inner() - 3.14).abs() < 0.001),
            _ => panic!("Expected float value, got {:?}", msg),
        }
    }

    // Test: Boolean event preserved
    #[tokio::test]
    async fn test_boolean_event_preserved() {
        let (source, address, _guard) = source().await;
        let resp = send_req(
            address,
            "event",
            r#"{"event": true, "index": "flags"}"#,
            TOKEN,
            Some("ch1"),
            &[],
        )
        .await;
        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 1).await;
        let log = events[0].as_log();
        let msg = log.get("message").expect("Boolean event should be wrapped in 'message' field");
        assert_eq!(msg, &Value::Boolean(true), "Boolean true should be preserved");
    }

    // Test: Array event preserved
    #[tokio::test]
    async fn test_array_event_preserved() {
        let (source, address, _guard) = source().await;
        let resp = send_req(
            address,
            "event",
            r#"{"event": [1, "two", 3.0], "index": "arrays"}"#,
            TOKEN,
            Some("ch1"),
            &[],
        )
        .await;
        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 1).await;
        let log = events[0].as_log();
        let msg = log.get("message").expect("Array event should be wrapped in 'message' field");
        assert!(msg.is_array(), "Array value should be preserved as array");
    }

    // Test: Null event rejected
    #[tokio::test]
    async fn test_null_event_rejected() {
        let (_source, address, _guard) = source().await;
        let resp = send_req(
            address,
            "event",
            r#"{"event": null}"#,
            TOKEN,
            Some("ch1"),
            &[],
        )
        .await;
        assert_eq!(resp.status(), 400, "Null event should be rejected");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["code"], 13, "Null event should return code 13");
    }

    // Test: Empty array event rejected
    #[tokio::test]
    async fn test_empty_array_event_rejected() {
        let (_source, address, _guard) = source().await;
        let resp = send_req(
            address,
            "event",
            r#"{"event": []}"#,
            TOKEN,
            Some("ch1"),
            &[],
        )
        .await;
        assert_eq!(resp.status(), 400, "Empty array event should be rejected");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["code"], 13, "Empty array event should return code 13");
    }

    // Test: Batch with mixed data types all preserve values
    #[tokio::test]
    async fn test_batch_all_types_preserved() {
        let (source, address, _guard) = source().await;
        let batch = r#"{"event":"string val"}{"event":42}{"event":true}{"event":{"k":"v"}}{"event":[1,2]}"#;
        let resp = send_req(address, "event", batch, TOKEN, Some("ch1"), &[]).await;
        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 5).await;
        assert_eq!(events.len(), 5, "All 5 batch events should be received");

        // String -> message
        assert!(events[0].as_log().get("message").is_some());
        // Integer -> message
        assert_eq!(events[1].as_log().get("message").unwrap(), &Value::Integer(42));
        // Boolean -> message
        assert_eq!(events[2].as_log().get("message").unwrap(), &Value::Boolean(true));
        // Object -> keys at root
        assert_eq!(events[3].as_log().get("k").unwrap().to_string_lossy(), "v");
        // Array -> message
        assert!(events[4].as_log().get("message").unwrap().is_array());
    }

    // Test: Raw line splitting splits multiline body into separate events
    #[tokio::test]
    async fn test_raw_line_splitting() {
        let (source, address, _guard) = source_with_full_opts(
            Some(TOKEN.to_owned().into()),
            None,
            None,
            false,
            false, // raw_require_channel
            true,  // raw_line_splitting
        )
        .await;

        let resp = reqwest::Client::new()
            .post(format!("http://{address}/services/collector/raw?channel=ch1"))
            .header("Authorization", format!("Splunk {TOKEN}"))
            .body("line_one\nline_two\nline_three")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 3).await;
        assert_eq!(events.len(), 3, "Multiline raw body should produce 3 events");

        assert_eq!(
            events[0].as_log().get("message").unwrap().to_string_lossy(),
            "line_one"
        );
        assert_eq!(
            events[1].as_log().get("message").unwrap().to_string_lossy(),
            "line_two"
        );
        assert_eq!(
            events[2].as_log().get("message").unwrap().to_string_lossy(),
            "line_three"
        );
    }

    // Test: Raw line splitting with URL metadata applies to all lines
    #[tokio::test]
    async fn test_raw_line_splitting_with_metadata() {
        let (source, address, _guard) = source_with_full_opts(
            Some(TOKEN.to_owned().into()),
            None,
            None,
            false,
            false,
            true, // raw_line_splitting
        )
        .await;

        let resp = reqwest::Client::new()
            .post(format!(
                "http://{address}/services/collector/raw?channel=ch1&index=split_idx&sourcetype=split_type"
            ))
            .header("Authorization", format!("Splunk {TOKEN}"))
            .body("alpha\nbeta")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 2).await;
        assert_eq!(events.len(), 2);

        // Both events should have the URL metadata applied
        for (i, event) in events.iter().enumerate() {
            let log = event.as_log();
            assert_eq!(
                log.get("index").unwrap().to_string_lossy(),
                "split_idx",
                "Event {i} should have index metadata"
            );
            assert_eq!(
                log.get("sourcetype").unwrap().to_string_lossy(),
                "split_type",
                "Event {i} should have sourcetype metadata"
            );
        }
        assert_eq!(events[0].as_log().get("message").unwrap().to_string_lossy(), "alpha");
        assert_eq!(events[1].as_log().get("message").unwrap().to_string_lossy(), "beta");
    }

    // Test: Raw line splitting disabled (default) keeps single event
    #[tokio::test]
    async fn test_raw_line_splitting_disabled() {
        let (source, address, _guard) = source_with_full_opts(
            Some(TOKEN.to_owned().into()),
            None,
            None,
            false,
            false,
            false, // raw_line_splitting OFF
        )
        .await;

        let resp = reqwest::Client::new()
            .post(format!("http://{address}/services/collector/raw?channel=ch1"))
            .header("Authorization", format!("Splunk {TOKEN}"))
            .body("line_A\nline_B\nline_C")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let events = collect_n(source, 1).await;
        assert_eq!(events.len(), 1, "With splitting disabled, should be 1 event");
        // The single event should contain all lines
        let msg = events[0].as_log().get("message").unwrap().to_string_lossy();
        assert!(msg.contains("line_A"), "Single event should contain all text");
        assert!(msg.contains("line_C"));
    }
}
