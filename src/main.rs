use std::convert::Infallible;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Either, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::rt::{TokioExecutor, TokioIo};
use notify_rust::Notification;
use rcgen::{CertificateParams, KeyPair, Issuer};
use regex::Regex;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, rustls};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Deserialize, Debug)]
struct Config {
    secrets: SecretsConfig,
}

#[derive(Deserialize, Debug)]
struct SecretsConfig {
    custom_keywords: Vec<String>,
}

#[derive(Clone)]
struct FirewallState {
    standard_regexes: Vec<(Regex, &'static str)>,
    custom_regexes: Vec<Regex>,
    ca_params: Arc<rcgen::CertificateParams>,
    ca_key: Arc<rcgen::KeyPair>,
    https_client: Client<HttpsConnector<HttpConnector>, Either<hyper::body::Incoming, Full<Bytes>>>,
}

impl FirewallState {
    fn new() -> Self {
        let standard_patterns = vec![
            (r"AKIA[0-9A-Z]{16}", "AWS_KEY"),                   
            (r"ghp_[a-zA-Z0-9]{36}", "GITHUB_TOKEN"),                
            (r"sk_live_[0-9a-zA-Z]{24}", "STRIPE_KEY"),            
            (r"xoxb-[a-zA-Z0-9\-]{10,}", "SLACK_TOKEN"),            
            (r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", "JWT"),
        ];

        let mut standard_regexes = Vec::new();
        for (pat, name) in standard_patterns {
            standard_regexes.push((Regex::new(pat).unwrap(), name));
        }

        let mut custom_regexes = Vec::new();
        if let Ok(content) = fs::read_to_string(".dlp-proxy.toml") {
            if let Ok(config) = toml::from_str::<Config>(&content) {
                println!("✅ Loaded {} custom company secrets from .dlp-proxy.toml", config.secrets.custom_keywords.len());
                for keyword in config.secrets.custom_keywords {
                    let escaped = regex::escape(&keyword);
                    if let Ok(re) = Regex::new(&escaped) {
                        custom_regexes.push(re);
                    }
                }
            }
        }

        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["AI Firewall Local CA".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = params.self_signed(&key_pair).unwrap();
        
        let ca_pem = ca_cert.pem();
        fs::write("/tmp/ai-firewall-ca.pem", ca_pem).unwrap();
        println!("🔐 Generated Local Certificate Authority at /tmp/ai-firewall-ca.pem");

        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("no native root CA certificates found")
            .https_or_http()
            .enable_http1()
            .build();

        let client = Client::builder(TokioExecutor::new()).build(https);

        FirewallState {
            standard_regexes,
            custom_regexes,
            ca_params: Arc::new(params),
            ca_key: Arc::new(key_pair),
            https_client: client,
        }
    }

    fn redact_secrets(&self, text: &str) -> (String, Vec<String>) {
        let mut result = text.to_string();
        let mut redacted_types = Vec::new();

        for (re, name) in &self.standard_regexes {
            if re.is_match(&result) {
                redacted_types.push(name.to_string());
                let placeholder = format!("[REDACTED_{}]", name);
                result = re.replace_all(&result, placeholder.as_str()).to_string();
            }
        }

        for re in &self.custom_regexes {
            if re.is_match(&result) {
                if !redacted_types.contains(&"COMPANY_SECRET".to_string()) {
                    redacted_types.push("COMPANY_SECRET".to_string());
                }
                result = re.replace_all(&result, "[REDACTED_COMPANY_SECRET]").to_string();
            }
        }

        (result, redacted_types)
    }

    fn generate_domain_cert(&self, domain: &str) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key_pair = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec![domain.to_string()]).unwrap();
        
        let issuer = rcgen::Issuer::new(self.ca_params.as_ref().clone(), self.ca_key.as_ref());
        let cert = params.signed_by(&key_pair, &issuer).unwrap();
        
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        
        (vec![cert_der], key_der)
    }
}

fn send_desktop_alert(secrets_found: &[String]) {
    let message = format!("Redacted: {}", secrets_found.join(", "));
    std::thread::spawn(move || {
        let _ = Notification::new()
            .summary("🚨 AI Firewall")
            .body(&message)
            .show();
    });
}

async fn inner_proxy_handler(
    mut req: Request<hyper::body::Incoming>,
    host: String,
    state: FirewallState,
) -> Result<Response<hyper::body::Incoming>, Infallible> {
    
    let path_and_query = req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/");
    let uri_string = format!("https://{}{}", host, path_and_query);
    if let Ok(new_uri) = Uri::from_str(&uri_string) {
        *req.uri_mut() = new_uri;
    }

    if req.method() == Method::POST {
        let (mut parts, incoming_body) = req.into_parts();
        let body_bytes = incoming_body.collect().await.unwrap().to_bytes();
        
        if let Ok(body_text) = std::str::from_utf8(&body_bytes) {
            let (redacted_text, secrets_found) = state.redact_secrets(body_text);
            
            if !secrets_found.is_empty() {
                println!("🚨 REDACTED: {} in HTTPS payload to {}!", secrets_found.join(", "), host);
                send_desktop_alert(&secrets_found);

                parts.headers.remove(hyper::header::CONTENT_LENGTH);
                let new_body = Either::Right(Full::new(Bytes::from(redacted_text)));
                let new_req = Request::from_parts(parts, new_body);
                
                let res = state.https_client.request(new_req).await.unwrap();
                return Ok(res);
            }
        }
        
        let new_body = Either::Right(Full::new(body_bytes));
        let new_req = Request::from_parts(parts, new_body);
        let res = state.https_client.request(new_req).await.unwrap();
        return Ok(res);
    } else {
        let (parts, incoming_body) = req.into_parts();
        let new_body = Either::Left(incoming_body);
        let new_req = Request::from_parts(parts, new_body);
        let res = state.https_client.request(new_req).await.unwrap();
        return Ok(res);
    }
}

async fn outer_proxy_handler(
    req: Request<hyper::body::Incoming>,
    state: FirewallState,
) -> Result<Response<Either<Full<Bytes>, hyper::body::Incoming>>, Infallible> {
    
    if req.method() == Method::CONNECT {
        let host = req.uri().authority().map(|a| a.to_string()).unwrap_or_default();
        let host_without_port = host.split(':').next().unwrap_or(&host).to_string();

        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let (certs, key) = state.generate_domain_cert(&host_without_port);
                    let mut server_config = rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(certs, key)
                        .unwrap();
                    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                    
                    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
                    let upgraded_io = TokioIo::new(upgraded);
                    
                    match tls_acceptor.accept(upgraded_io).await {
                        Ok(tls_stream) => {
                            let tls_io = TokioIo::new(tls_stream);
                            let inner_state = state.clone();
                            let inner_host = host.clone();
                            
                            if let Err(e) = http1::Builder::new()
                                .serve_connection(
                                    tls_io,
                                    service_fn(move |inner_req| {
                                        inner_proxy_handler(inner_req, inner_host.clone(), inner_state.clone())
                                    }),
                                )
                                .await
                            {
                                eprintln!("Inner server error: {}", e);
                            }
                        }
                        Err(e) => eprintln!("TLS handshake failed: {}", e),
                    }
                }
                Err(e) => eprintln!("Upgrade error: {}", e),
            }
        });
        
        let mut response = Response::new(Either::Left(Full::new(Bytes::from(""))));
        *response.status_mut() = StatusCode::OK;
        return Ok(response);
    }

    let response = Response::new(Either::Left(Full::new(Bytes::from("Only HTTPS via CONNECT is supported for interception."))));
    Ok(response)
}

fn run_index_command(file_path: &str) {
    println!("🔍 Scanning file: {}", file_path);
    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(e) => { eprintln!("❌ Failed to read {}: {}", file_path, e); return; }
    };

    let mut found_secrets = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if let Some((key, value)) = line.split_once('=') {
            let val = value.trim_matches(|c| c == '"' || c == '\'').trim();
            if !val.is_empty() {
                let masked = if val.len() > 4 { format!("{}...", &val[0..3]) } else { "***".to_string() };
                println!("  - {} (starts with '{}')", key.trim(), masked);
                found_secrets.push(val.to_string());
            }
        }
    }

    if found_secrets.is_empty() {
        println!("✅ No secrets found to import.");
        return;
    }

    println!("\nFound {} values. Do you want to add these to your local blocklist in .dlp-proxy.toml? [y/N]", found_secrets.len());
    let mut input = String::new();
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();
    
    if input.trim().eq_ignore_ascii_case("y") {
        let mut config_content = match fs::read_to_string(".dlp-proxy.toml") {
            Ok(c) => c,
            Err(_) => "[secrets]\ncustom_keywords = [\n]".to_string()
        };
        
        let mut new_lines = Vec::new();
        for secret in found_secrets {
            let safe_secret = secret.replace("\"", "\\\"");
            new_lines.push(format!("    \"{}\",", safe_secret));
        }

        if config_content.contains("custom_keywords = [") {
            let insertion_point = config_content.rfind(']').unwrap_or(config_content.len());
            let mut final_content = config_content[..insertion_point].to_string();
            if !final_content.ends_with('\n') { final_content.push('\n'); }
            final_content.push_str(&new_lines.join("\n"));
            final_content.push('\n');
            final_content.push(']');
            fs::write(".dlp-proxy.toml", final_content).unwrap();
        } else {
            let mut final_content = "[secrets]\ncustom_keywords = [\n".to_string();
            final_content.push_str(&new_lines.join("\n"));
            final_content.push_str("\n]\n");
            fs::write(".dlp-proxy.toml", final_content).unwrap();
        }

        println!("✅ Added secrets to local blocklist.");
    } else {
        println!("Skipped importing secrets.");
    }
}

fn run_wrapper_command(command_args: &[String]) {
    if command_args.is_empty() { return; }
    let target_command = &command_args[0];
    let target_args = &command_args[1..];
    let proxy_url = "http://127.0.0.1:8080";

    println!("🛡️ Wrapping command: {} {:?}", target_command, target_args);

    let mut child = Command::new(target_command)
        .args(target_args)
        .env("HTTP_PROXY", proxy_url)
        .env("http_proxy", proxy_url)
        .env("HTTPS_PROXY", proxy_url)
        .env("https_proxy", proxy_url)
        .env("NODE_EXTRA_CA_CERTS", "/tmp/ai-firewall-ca.pem") 
        .env("REQUESTS_CA_BUNDLE", "/tmp/ai-firewall-ca.pem")
        .spawn()
        .expect("Failed to execute wrapped command");

    let _ = child.wait();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() > 1 {
        match args[1].as_str() {
            "index" => {
                if args.len() < 3 {
                    eprintln!("Usage: {} index <path-to-file>", args[0]);
                    std::process::exit(1);
                }
                run_index_command(&args[2]);
                return Ok(());
            },
            "run" => {
                if args.len() < 3 { std::process::exit(1); }
                run_wrapper_command(&args[2..]);
                return Ok(());
            },
            _ => {
                run_wrapper_command(&args[1..]);
                return Ok(());
            }
        }
    }

    println!("🛡️ Starting AI Firewall Proxy Daemon with MITM TLS...");
    let state = FirewallState::new();

    let addr = SocketAddr::from_str("127.0.0.1:8080")?;
    let listener = TcpListener::bind(addr).await?;

    println!("🚀 Proxy listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state_clone = state.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| outer_proxy_handler(req, state_clone.clone())),
                )
                .with_upgrades()
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
