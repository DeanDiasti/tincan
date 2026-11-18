use std::{env, net::SocketAddr};

use anyhow::{Context, Result, ensure};
use url::Url;

pub struct Config {
    pub database_url: String,
    pub bind: SocketAddr,
    pub public_url: Url,
    pub workspace_domain: String,
    pub google_client_id: String,
    pub google_client_secret: String,
    pub mcp_issuer: String,
    pub mcp_jwks_url: Url,
    pub mcp_scope: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let public_url = parse_endpoint("TINCAN_PUBLIC_URL", &required("TINCAN_PUBLIC_URL")?)?;
        ensure!(
            public_url.path() == "/",
            "TINCAN_PUBLIC_URL must be the service origin"
        );
        let mcp_scope = env::var("TINCAN_MCP_SCOPE").unwrap_or_else(|_| "tincan".into());
        ensure!(
            !mcp_scope.is_empty()
                && mcp_scope
                    .bytes()
                    .all(|b| matches!(b, 0x21 | 0x23..=0x5b | 0x5d..=0x7e)),
            "TINCAN_MCP_SCOPE must be one OAuth scope token"
        );
        let workspace_domain = required("TINCAN_WORKSPACE_DOMAIN")?;
        ensure!(
            workspace_domain.contains('.')
                && workspace_domain
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
            "TINCAN_WORKSPACE_DOMAIN must be a Workspace domain"
        );
        let mcp_issuer = required("TINCAN_MCP_ISSUER")?;
        parse_endpoint("TINCAN_MCP_ISSUER", &mcp_issuer)?;
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            bind: env::var("TINCAN_BIND")
                .unwrap_or_else(|_| "127.0.0.1:3000".into())
                .parse()
                .context("invalid TINCAN_BIND")?,
            public_url,
            workspace_domain,
            google_client_id: required("GOOGLE_CLIENT_ID")?,
            google_client_secret: required("GOOGLE_CLIENT_SECRET")?,
            mcp_issuer,
            mcp_jwks_url: parse_endpoint("TINCAN_MCP_JWKS_URL", &required("TINCAN_MCP_JWKS_URL")?)?,
            mcp_scope,
        })
    }

    pub fn url(&self, path: &str) -> Url {
        self.public_url.join(path).expect("static path")
    }
}

fn required(name: &str) -> Result<String> {
    let value = env::var(name).with_context(|| format!("{name} is required"))?;
    ensure!(!value.trim().is_empty(), "{name} is required");
    Ok(value)
}

fn parse_endpoint(name: &str, raw: &str) -> Result<Url> {
    let url = Url::parse(raw).with_context(|| format!("invalid {name}"))?;
    let loopback = match url.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    ensure!(
        url.has_host()
            && (url.scheme() == "https" || (url.scheme() == "http" && loopback))
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "{name} must be an HTTPS URL, or HTTP on loopback for development"
    );
    Ok(url)
}
