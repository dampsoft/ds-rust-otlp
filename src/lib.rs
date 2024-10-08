use headers::authorization::Credentials;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use opentelemetry::trace::TracerProvider;
use opentelemetry_http::hyper::HyperClient;
use opentelemetry_otlp::WithExportConfig;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{prelude::*, EnvFilter};

pub use opentelemetry;
pub use tracing;

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
pub fn setup(default_logging_level: LevelFilter, app_name: &'static str) {
    let env_filter = EnvFilter::builder()
        .with_default_directive(default_logging_level.into())
        .from_env_lossy();

    let fmt_layer = tracing_subscriber::fmt::layer();
    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer);

    if let Ok(tracing_url) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
        let username = std::env::var("DS_OPENTELEMETRY_USERNAME");
        let password = std::env::var("DS_OPENTELEMETRY_PASSWORD");
        let timeout = std::time::Duration::from_secs(5);
        let https = hyper_tls::HttpsConnector::new();
        let hyper_client = Client::builder(TokioExecutor::new()).build(https);

        let oltp_http_client = if let (Ok(username), Ok(password)) = (username, password) {
            let auth = headers::Authorization::basic(username.as_str(), password.as_str());
            HyperClient::new_with_timeout_and_authorization_header(
                hyper_client,
                timeout,
                auth.0.encode(),
            )
        } else {
            HyperClient::new_with_timeout(hyper_client, timeout)
        };

        let provider = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .http()
                    .with_http_client(oltp_http_client)
                    .with_endpoint(tracing_url),
            )
            .install_batch(opentelemetry_sdk::runtime::Tokio)
            .unwrap();

        opentelemetry::global::set_tracer_provider(provider.clone());
        let tracer = provider.tracer(app_name);
        let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        tracing::subscriber::set_global_default(registry.with(telemetry_layer)).unwrap();
    } else {
        tracing::subscriber::set_global_default(registry).unwrap();
    }
}
