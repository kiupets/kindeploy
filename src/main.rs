use actix::Actor;
use actix::{Addr, Running, StreamHandler};
use actix_cors::Cors;
use actix_files::{Files, NamedFile};
use actix_web::{get, post, web, web::Data, web::Payload, Error, HttpRequest, HttpResponse};
use actix_web::{middleware, App, HttpServer, Responder, Result};
use actix_web_actors::ws;
use kinhotelrust::configuration::get_configuration;
use std::env;
use std::path::PathBuf;
mod api;
mod models;
mod repository;
mod websocket;
mod websocket2;
use crate::repository::mongodb_repo::MongoRepo;
use actix_session::storage::RedisSessionStore;
use actix_session::SessionMiddleware;
use actix_web::cookie::Key;
use actix_web::dev::Server;
use kinhotelrust::configuration;

use kinhotelrust::configuration::{DatabaseSettings, Settings};
use kinhotelrust::routes::{
    admin_dashboard, change_password, change_password_form, confirm, health_check, home, log_out,
    login, login_form, publish_newsletter, publish_newsletter_form, subscribe,
};

use websocket::web_server::ws_index;
use websocket2::web_server2::ws_index_drag;

use actix_web::http::header::{ContentDisposition, DispositionType};
use actix_web_flash_messages::storage::CookieMessageStore;
use actix_web_flash_messages::FlashMessagesFramework;
use actix_web_lab::middleware::from_fn;
use api::rented_api::{create_rented, get_all, get_rented, update_rented};
use api::user_api::{create_user, get_user};
use secrecy::{ExposeSecret, Secret};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::net::TcpListener;
use tracing_actix_web::TracingLogger;
// mod websocket;
// mod websocket2;

pub(crate) struct ApplicationBaseUrl(pub String);
// pub fn routes(cfg: &mut web::ServiceConfig) {
//     cfg.service(web::resource("/ws").route(web::get().to(ws_index)));
// }
// pub struct ApplicationBaseUrl(pub String);
pub fn get_connection_pool(configuration: &DatabaseSettings) -> PgPool {
    PgPoolOptions::new().connect_lazy_with(configuration.with_db())
}
#[derive(Clone)]
pub struct HmacSecret(pub Secret<String>);
#[actix_web::main]

async fn main() -> Result<(), anyhow::Error> {
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

    // let HOST = env::var("HOST").expect("Host not set");
    // let PORT = env::var("PORT").expect("Port not set");
    let configuration = get_configuration().expect("Failed to read configuration.");
    let connection_pool = get_connection_pool(&configuration.database);
    let email_client = configuration.email_client.client();

    let address = format!(
        "{}:{}",
        configuration.application.host, configuration.application.port
    );
    let listener = TcpListener::bind(address)?;
    let port = listener.local_addr().unwrap().port();
    let server_s = websocket::server::Server::new().start();

    let server_s2 = websocket2::server_shit::Server2::new().start();
    let db = MongoRepo::init().await;
    let db_data = Data::new(db);

    let db_pool = Data::new(connection_pool);
    // let db_data = Data::new(db);
    let email_client = Data::new(email_client);
    let base_url = Data::new(ApplicationBaseUrl(configuration.application.base_url));
    let secret_key = Key::from(
        configuration
            .application
            .hmac_secret
            .expose_secret()
            .as_bytes(),
    );

    let message_store = CookieMessageStore::builder(secret_key.clone()).build();
    let message_framework = FlashMessagesFramework::builder(message_store).build();
    let redis_store = RedisSessionStore::new(configuration.redis_uri.expose_secret()).await?;
    HttpServer::new(move || {
        let cors = Cors::permissive();

        App::new()
            .wrap(cors)
            .wrap(message_framework.clone())
            .wrap(SessionMiddleware::new(
                redis_store.clone(),
                secret_key.clone(),
            ))
            .wrap(middleware::Logger::default())
            // .route("/", web::get().to(index))
            .route("/", web::get().to(home))
            // .service(Files::new("/hotel", "./build").index_file("index.html"))
            .app_data(db_data.clone())
            .data(server_s.clone())
            .data(server_s2.clone())
            .service(create_user)
            .route("/ws", web::get().to(ws_index))
            .route("/wss", web::get().to(ws_index_drag))
            .service(
                web::scope("/admin")
                    // .wrap(from_fn(reject_anonymous_users))
                    .route("/dashboard", web::get().to(admin_dashboard))
                    .route("/newsletters", web::get().to(publish_newsletter_form))
                    .route("/newsletters", web::post().to(publish_newsletter))
                    .route("/password", web::get().to(change_password_form))
                    .route("/password", web::post().to(change_password))
                    // .service(Files::new("/hotel", "./build").index_file("index.html"))
                    .route("/logout", web::post().to(log_out)),
            )
            .route("/login", web::get().to(login_form))
            .route("/login", web::post().to(login))
            .route("/health_check", web::get().to(health_check))
            .route("/subscriptions", web::post().to(subscribe))
            .route("/subscriptions/confirm", web::get().to(confirm))
            .route("/newsletters", web::post().to(publish_newsletter))
            // .service(Files::new("/hotel", "./build").index_file("index.html"))
            .app_data(db_pool.clone())
            .app_data(db_data.clone())
            .app_data(email_client.clone())
            .app_data(base_url.clone())
            .app_data(Data::new(HmacSecret(
                configuration.application.hmac_secret.clone(),
            )))
            .service(get_user)
            .service(create_rented)
            .service(update_rented)
            .service(get_rented)
            .service(get_all)
            // .route("/hotel", web::get().to(single_page_app))
            .service(Files::new("/", "./build").index_file("index.html"))

        // .service(Files::new("/hotel", "./build").index_file("index.html"))
    })
    // .bind(format!("{}:{}", HOST, PORT))?
    // .bind("127.0.0.1:8000")?
    .listen(listener)?
    .run()
    .await;
    Ok(())
}
