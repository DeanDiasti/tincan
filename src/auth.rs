use std::time::{Duration, Instant};

use anyhow::Error;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use url::Url;

use crate::store::Identity;

pub const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

pub struct JwtVerifier {
    audience: String,
    validation: Validation,
    jwks_url: Url,
    keys: Mutex<Option<(Instant, JwkSet)>>,
}

pub enum VerifyError {
    Invalid,
    InsufficientScope,
    Unavailable(Error),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    aud: Audience,
    hd: String,
    email: String,
    email_verified: bool,
    name: String,
    azp: Option<String>,
    nonce: Option<String>,
    google_sub: Option<String>,
    scope: Option<String>,
}

impl JwtVerifier {
    pub fn new(issuers: &[&str], audience: String, jwks_url: Url) -> Self {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(issuers);
        validation.set_audience(&[&audience]);
        validation.set_required_spec_claims(&["sub", "iss", "exp", "aud"]);
        validation.validate_nbf = true;
        validation.leeway = 15;
        Self {
            audience,
            validation,
            jwks_url,
            keys: Mutex::new(None),
        }
    }

    async fn claims(&self, client: &reqwest::Client, token: &str) -> Result<Claims, VerifyError> {
        let header = decode_header(token).map_err(|_| VerifyError::Invalid)?;
        let Some(kid) = header.kid.filter(|_| header.alg == Algorithm::RS256) else {
            return Err(VerifyError::Invalid);
        };
        let key = {
            let mut cache = self.keys.lock().await;
            if cache
                .as_ref()
                .is_none_or(|(until, _)| Instant::now() >= *until)
            {
                let jwks = fetch_keys(client, &self.jwks_url)
                    .await
                    .map_err(VerifyError::Unavailable)?;
                *cache = Some((Instant::now() + Duration::from_secs(300), jwks));
            }
            let jwk = cache
                .as_ref()
                .and_then(|(_, keys)| keys.find(&kid))
                .ok_or(VerifyError::Invalid)?;
            let usage = &jwk.common;
            if usage
                .key_algorithm
                .is_some_and(|alg| alg != KeyAlgorithm::RS256)
                || usage
                    .public_key_use
                    .as_ref()
                    .is_some_and(|usage| *usage != PublicKeyUse::Signature)
                || usage
                    .key_operations
                    .as_ref()
                    .is_some_and(|ops| !ops.contains(&KeyOperations::Verify))
            {
                return Err(VerifyError::Invalid);
            }
            DecodingKey::from_jwk(jwk).map_err(|_| VerifyError::Invalid)?
        };
        decode::<Claims>(token, &key, &self.validation)
            .map(|data| data.claims)
            .map_err(|_| VerifyError::Invalid)
    }

    pub async fn google_identity(
        &self,
        client: &reqwest::Client,
        token: &str,
        domain: &str,
        nonce: &str,
    ) -> Result<Identity, VerifyError> {
        let claims = self.claims(client, token).await?;
        let single_audience = match &claims.aud {
            Audience::Single(aud) => aud == &self.audience,
            Audience::Multiple(aud) => aud.as_slice() == [self.audience.as_str()],
        };
        if claims.nonce.as_deref() != Some(nonce)
            || (!single_audience && claims.azp.is_none())
            || claims.azp.as_ref().is_some_and(|azp| azp != &self.audience)
        {
            return Err(VerifyError::Invalid);
        }
        let google_sub = claims.sub.clone();
        claims.identity(domain, google_sub)
    }

    pub async fn mcp_identity(
        &self,
        client: &reqwest::Client,
        token: &str,
        domain: &str,
        scope: &str,
    ) -> Result<Identity, VerifyError> {
        let claims = self.claims(client, token).await?;
        let has_scope = claims
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_ascii_whitespace()
            .any(|s| s == scope);
        let google_sub = claims.google_sub.clone().ok_or(VerifyError::Invalid)?;
        let identity = claims.identity(domain, google_sub)?;
        if !has_scope {
            return Err(VerifyError::InsufficientScope);
        }
        Ok(identity)
    }
}

impl Claims {
    fn identity(self, domain: &str, google_sub: String) -> Result<Identity, VerifyError> {
        if self.hd != domain
            || !self.email_verified
            || self.sub.is_empty()
            || google_sub.trim().is_empty()
            || self.email.trim().is_empty()
            || self.name.trim().is_empty()
        {
            return Err(VerifyError::Invalid);
        }
        Ok(Identity {
            google_sub,
            email: self.email,
            name: self.name,
        })
    }
}

async fn fetch_keys(client: &reqwest::Client, url: &Url) -> anyhow::Result<JwkSet> {
    let response = client.get(url.clone()).send().await?.error_for_status()?;
    Ok(response.json().await?)
}

pub fn random_token() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|err| anyhow::anyhow!("OS randomness unavailable: {err}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(token_hash(verifier))
}
