use headers::authorization::Credentials;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use opentelemetry::trace::TracerProvider;
use opentelemetry_http::hyper::HyperClient;
use opentelemetry_otlp::WithExportConfig;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{prelude::*, EnvFilter};

pub use opentelemetry;
pub use tracing;

pub struct SetupConfiguration {
    app_name: &'static str,
    default_logging_level: LevelFilter,
    exporter_timeout: Option<std::time::Duration>,
}

impl SetupConfiguration {
    pub fn new(app_name: &'static str, default_logging_level: LevelFilter) -> Self {
        Self {
            app_name,
            default_logging_level,
            exporter_timeout: None,
        }
    }

    pub fn with_exporter_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.exporter_timeout = Some(timeout);
        self
    }
}

/// Register with the configured OTEL collector and setup sending metrics and traces to it.
///
/// # Arguments
///
/// * `default_logging_level` - The default logging level to use.
/// * `app_name` - The name of the application (forwarded to the OTEL collector).
///
/// # Environment Variables
///
/// * `OTEL_EXPORTER_OTLP_ENDPOINT` - URL of the OTEL collector (base URL, i.e. no `/v1/traces`).
/// * `DS_OPENTELEMETRY_USERNAME` - The username to use for basic authentication.
/// * `DS_OPENTELEMETRY_PASSWORD` - The password to use for basic authentication.
pub fn setup(setup_configuration: &SetupConfiguration) {
    setup_traces(setup_configuration);
    setup_metrics(setup_configuration);
}

/// Register with the configured OTEL collector and setup sending traces to it.
///
/// # Arguments
///
/// * `default_logging_level` - The default logging level to use.
/// * `app_name` - The name of the application (forwarded to the OTEL collector).
///
/// # Environment Variables
///
/// * `OTEL_EXPORTER_OTLP_ENDPOINT` - URL of the OTEL collector (base URL, i.e. no `/v1/traces`).
/// * `DS_OPENTELEMETRY_USERNAME` - The username to use for basic authentication.
/// * `DS_OPENTELEMETRY_PASSWORD` - The password to use for basic authentication.
pub fn setup_traces(setup_configuration: &SetupConfiguration) {
    let env_filter = EnvFilter::builder()
        .with_default_directive(setup_configuration.default_logging_level.into())
        .from_env_lossy();

    let fmt_layer = tracing_subscriber::fmt::layer();
    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer);

    if let Some(exporter) = build_exporter() {
        let provider = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(exporter)
            .install_batch(opentelemetry_sdk::runtime::Tokio)
            .unwrap();

        opentelemetry::global::set_tracer_provider(provider.clone());
        let tracer = provider.tracer(setup_configuration.app_name);
        let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        tracing::subscriber::set_global_default(registry.with(telemetry_layer)).unwrap();
        tracing::info!("OTEL exporter configured for traces");
    } else {
        tracing::subscriber::set_global_default(registry).unwrap();
        tracing::warn!("No OTEL exporter configured for traces");
    }
}

/// Register with the configured OTEL collector and setup sending metrics to it.
///
/// # Arguments
///
/// * `app_name` - The name of the application (forwarded to the OTEL collector).
///
/// # Environment Variables
///
/// * `OTEL_EXPORTER_OTLP_ENDPOINT` - URL of the OTEL collector (base URL, i.e. no `/v1/traces`).
/// * `DS_OPENTELEMETRY_USERNAME` - The username to use for basic authentication.
/// * `DS_OPENTELEMETRY_PASSWORD` - The password to use for basic authentication.
pub fn setup_metrics(setup_configuration: &SetupConfiguration) {
    if let Some(exporter) = build_exporter(setup_configuration) {
        let metrics = opentelemetry_otlp::new_pipeline()
            .metrics(opentelemetry_sdk::runtime::Tokio)
            .with_exporter(exporter)
            .with_resource(opentelemetry_sdk::Resource::new(vec![
                opentelemetry::KeyValue::new(
                    "service_name".to_string(),
                    setup_configuration.app_name,
                ),
            ]))
            .build()
            .unwrap();

        opentelemetry::global::set_meter_provider(metrics);
        tracing::info!("OTEL exporter configured for metrics");
    } else {
        tracing::warn!("No OTEL exporter configured for metrics");
    }
}

fn build_exporter(
    setup_configuration: &SetupConfiguration,
) -> Option<opentelemetry_otlp::HttpExporterBuilder> {
    if let Ok(tracing_url) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
        let username = std::env::var("DS_OPENTELEMETRY_USERNAME");
        let password = std::env::var("DS_OPENTELEMETRY_PASSWORD");
        let https = hyper_tls::HttpsConnector::new();
        let http_timeout = std::time::Duration::from_secs(5);
        let hyper_client = Client::builder(TokioExecutor::new()).build(https);

        let oltp_http_client = if let (Ok(username), Ok(password)) = (username, password) {
            let auth = headers::Authorization::basic(username.as_str(), password.as_str());
            HyperClient::new_with_timeout_and_authorization_header(
                hyper_client,
                http_timeout,
                auth.0.encode(),
            )
        } else {
            HyperClient::new_with_timeout(hyper_client, http_timeout)
        };
        let mut exporter = opentelemetry_otlp::new_exporter()
            .http()
            .with_http_client(oltp_http_client)
            .with_endpoint(tracing_url);

        if let Some(timeout) = setup_configuration.exporter_timeout {
            exporter = exporter.with_timeout(timeout);
        }

        Some(exporter)
    } else {
        None
    }
}
