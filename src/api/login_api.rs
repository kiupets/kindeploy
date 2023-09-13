use actix_web::http::header::ContentType;
use actix_web::{
    get, post,
    web::{Data, Json, Path},
    HttpResponse,
};
use secrecy::Secret;
use serde::{Deserialize, Deserializer};
#[derive(serde::Deserialize)]
pub struct FormData {
    username: String,
    #[serde(deserialize_with = "secret_from_string")]
    password: Secret<String>,
}
fn secret_from_string<'de, D>(deserializer: D) -> Result<Secret<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let password = String::deserialize(deserializer)?;
    Ok(Secret::new(password))
}
#[post("/login")]
pub async fn login() -> HttpResponse {
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(include_str!("login.html"))
}
