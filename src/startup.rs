// use crate::authentication::reject_anonymous_users;
// use crate::email_client::EmailClient;
// use actix::prelude::Addr;
// use actix::Actor;
// use actix_cors::Cors;
// use actix_files::Files;
// use actix_web::middleware::Logger;
// use actix_web::{web, web::Data, Error};
// use actix_web::{App, HttpResponse, HttpServer};
// use std::env;
// use std::ops::Add;
// // use actix_web_actors::ws;
// // use crate::email_client::EmailClient;
// use crate::routes::{
//     admin_dashboard, change_password, change_password_form, confirm, health_check, home, log_out,
//     login, login_form, publish_newsletter, publish_newsletter_form, subscribe,
// };
// // mod api;
// // use crate::pos_routes;
// // use crate::routes::health_check::*;
// // use crate::routes::subscriptions::*;
// use crate::websocket;
// use crate::websocket::server::Server as WebSocketServer;
// use crate::websocket2;
// use actix_web::cookie::Key;
// // mod configuration;
// // use crate::api::login_api::login;
// use crate::api::rented_api::{create_rented, get_all, get_rented, update_rented};
// use crate::api::user_api::{create_user, get_user};
// use crate::configuration::{DatabaseSettings, Settings};
// use crate::repository::mongodb_repo::MongoRepo;
// use actix_session::SessionMiddleware;
// // mod settings;

// use actix_web::dev::Server;
// use secrecy::{ExposeSecret, Secret};
// use sqlx::postgres::PgPoolOptions;
// use sqlx::PgConnection;
// use sqlx::PgPool;
// use std::net::TcpListener;
// use tracing_actix_web::TracingLogger;
// // use crate::email_client::EmailClient;

// use actix_session::storage::RedisSessionStore;

// use actix_web_flash_messages::storage::CookieMessageStore;
// use actix_web_flash_messages::FlashMessagesFramework;
// use actix_web_lab::middleware::from_fn;

// pub struct Application {
//     port: u16,
//     server: Server,
// }

// impl Application {
//     pub async fn build(configuration: Settings) -> Result<Self, anyhow::Error> {
//         let connection_pool = get_connection_pool(&configuration.database);
//         let db = MongoRepo::init().await;

//         let email_client = configuration.email_client.client();
//         // let web_socket_server = WebSocketServer::new().start();
//         let address = format!(
//             "{}:{}",
//             configuration.application.host, configuration.application.port
//         );
//         let listener = TcpListener::bind(address)?;
//         let port = listener.local_addr().unwrap().port();

//         let server = run(
//             listener,
//             connection_pool,
//             email_client,
//             // db,
//             // web_socket_server,
//             configuration.application.base_url,
//             configuration.application.hmac_secret,
//             configuration.redis_uri,
//         )
//         .await?;

//         Ok(Self { port, server })
//     }

//     pub fn port(&self) -> u16 {
//         self.port
//     }

//     pub async fn run_until_stopped(self) -> Result<(), std::io::Error> {
//         self.server.await
//     }
// }

// pub fn get_connection_pool(configuration: &DatabaseSettings) -> PgPool {
//     PgPoolOptions::new().connect_lazy_with(configuration.with_db())
// }

// pub struct ApplicationBaseUrl(pub String);

// pub async fn run(
//     listener: TcpListener,
//     db_pool: PgPool,
//     // db: MongoRepo,
//     email_client: EmailClient,
//     base_url: String,

//     hmac_secret: Secret<String>,
//     redis_uri: Secret<String>,
// ) -> Result<Server, anyhow::Error> {
//     // let HOST = env::var("HOST").expect("Host not set");
//     // let PORT = env::var("PORT").expect("Port not set");
//     // let server = websocket::Server::new().start();
//     // let server2 = websocket2::Server2::new().start();
//     // let db = MongoRepo::init().await;
//     // let db_data = Data::new(db);
//     // let db_pool = Data::new(db_pool);
//     let db_pool = Data::new(db_pool);
//     let email_client = Data::new(email_client);
//     let base_url = Data::new(ApplicationBaseUrl(base_url));
//     let secret_key = Key::from(hmac_secret.expose_secret().as_bytes());
//     let message_store = CookieMessageStore::builder(secret_key.clone()).build();
//     let message_framework = FlashMessagesFramework::builder(message_store).build();
//     let redis_store = RedisSessionStore::new(redis_uri.expose_secret()).await?;
//     let server = HttpServer::new(move || {
//         let cors = Cors::permissive();

//         App::new()
//             .wrap(cors)
//             .wrap(Logger::default())
//             .wrap(SessionMiddleware::new(
//                 redis_store.clone(),
//                 secret_key.clone(),
//             ))
//             .wrap(TracingLogger::default())
//             .route("/", web::get().to(home))
//             // .service(Files::new("/", "./build").index_file("index.html"))
//             .service(
//                 web::scope("/admin")
//                     .wrap(from_fn(reject_anonymous_users))
//                     .route("/dashboard", web::get().to(admin_dashboard))
//                     .route("/newsletters", web::get().to(publish_newsletter_form))
//                     .route("/newsletters", web::post().to(publish_newsletter))
//                     .route("/password", web::get().to(change_password_form))
//                     .route("/password", web::post().to(change_password))
//                     .route("/logout", web::post().to(log_out)),
//             )
//             .route("/login", web::get().to(login_form))
//             .route("/login", web::post().to(login))
//             .route("/health_check", web::get().to(health_check))
//             .route("/subscriptions", web::post().to(subscribe))
//             .route("/subscriptions/confirm", web::get().to(confirm))
//             .route("/newsletters", web::post().to(publish_newsletter))
//             .app_data(db_pool.clone())
//             .app_data(email_client.clone())
//             .app_data(base_url.clone())
//             .app_data(Data::new(HmacSecret(hmac_secret.clone())))
//         // .app_data(db_data.clone())
//         // .app_data(socket_server.clone())
//         // .app_data(socket_server2.clone())
//         // .service(create_user)
//         // .route("/ws", web::get().to(websocket::ws_index))
//         // .route("/wss", web::get().to(ws_index_drag))
//         // .service(get_user)
//         // .service(create_rented)
//         // .service(get_rented)
//         // .service(update_rented)
//         // .service(get_all)
//         // .service(Files::new("/hotel", "./build").index_file("index.html"))
//     })
//     // .workers(4)
//     // .bind(format!("{}:{}", HOST, PORT))?
//     .listen(listener)?
//     .run();
//     Ok(server)
// }
// #[derive(Clone)]
// pub struct HmacSecret(pub Secret<String>);

use crate::authentication::reject_anonymous_users;
use crate::configuration::{DatabaseSettings, Settings};
use crate::email_client::EmailClient;
use crate::repository::mongodb_repo::MongoRepo;
use crate::routes::{
    admin_dashboard, change_password, change_password_form, confirm, health_check, home, log_out,
    login, login_form, publish_newsletter, publish_newsletter_form, subscribe,
};
use crate::websocket;
use crate::websocket2;
use actix::prelude::Addr;
use actix::Actor;
use actix_cors::Cors;
use actix_files::Files;
use actix_session::storage::RedisSessionStore;
use actix_session::SessionMiddleware;
use actix_web::cookie::Key;
use actix_web::dev::Server;
use actix_web::web::Data;
use actix_web::{web, App, HttpServer};
use actix_web_flash_messages::storage::CookieMessageStore;
use actix_web_flash_messages::FlashMessagesFramework;
use actix_web_lab::middleware::from_fn;
use secrecy::{ExposeSecret, Secret};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::net::TcpListener;
use tracing_actix_web::TracingLogger;

pub struct Application {
    port: u16,
    server: Server,
}

impl Application {
    pub async fn build(
        configuration: Settings,
        // wsS: Option<Addr<websocket::server::Server>>,
    ) -> Result<Self, anyhow::Error> {
        let connection_pool = get_connection_pool(&configuration.database);
        let email_client = configuration.email_client.client();
        let db = MongoRepo::init().await;
        let address = format!(
            "{}:{}",
            configuration.application.host, configuration.application.port
        );
        let listener = TcpListener::bind(address)?;
        let port = listener.local_addr().unwrap().port();

        let server = run(
            // wsS,
            listener,
            connection_pool,
            email_client,
            db,
            configuration.application.base_url,
            configuration.application.hmac_secret,
            configuration.redis_uri,
        )
        .await?;

        Ok(Self { port, server })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub async fn run_until_stopped(self) -> Result<(), std::io::Error> {
        self.server.await
    }
}

pub fn get_connection_pool(configuration: &DatabaseSettings) -> PgPool {
    PgPoolOptions::new().connect_lazy_with(configuration.with_db())
}

pub struct ApplicationBaseUrl(pub String);

async fn run(
    // wss: Option<Addr<websocket::server::Server>>,
    listener: TcpListener,
    db_pool: PgPool,
    email_client: EmailClient,
    db: MongoRepo,
    base_url: String,
    hmac_secret: Secret<String>,
    redis_uri: Secret<String>,
) -> Result<Server, anyhow::Error> {
    let db_pool = Data::new(db_pool);
    let db_data = Data::new(db);
    let email_client = Data::new(email_client);
    let base_url = Data::new(ApplicationBaseUrl(base_url));
    let secret_key = Key::from(hmac_secret.expose_secret().as_bytes());
    let message_store = CookieMessageStore::builder(secret_key.clone()).build();
    let message_framework = FlashMessagesFramework::builder(message_store).build();
    let redis_store = RedisSessionStore::new(redis_uri.expose_secret()).await?;
    let server_s = websocket::server::Server::new().start();
    let server_s2 = websocket2::server_shit::Server2::new().start();
    println!("{:?}", listener);
    let server = HttpServer::new(move || {
        let cors = Cors::permissive();

        App::new()
            // .service(Files::new("/hotel", "./build").index_file("index.html"))
            .wrap(cors)
            // .wrap(message_framework.clone())
            // .wrap(SessionMiddleware::new(
            //     redis_store.clone(),
            //     secret_key.clone(),
            // ))
            // .wrap(TracingLogger::default())
            // .route("/", web::get().to(home))
            .data(server_s.clone())
            .service(Files::new("/hotel", "./build").index_file("index.html"))
            .route("/ws", web::get().to(websocket::web_server::ws_index))
            .route(
                "/wss",
                web::get().to(websocket2::web_server2::ws_index_drag),
            )
        // .service(
        //     web::scope("/admin")
        //         .wrap(from_fn(reject_anonymous_users))
        //         .route("/dashboard", web::get().to(admin_dashboard))
        //         .route("/newsletters", web::get().to(publish_newsletter_form))
        //         .route("/newsletters", web::post().to(publish_newsletter))
        //         .route("/password", web::get().to(change_password_form))
        //         .route("/password", web::post().to(change_password))
        //         .route("/logout", web::post().to(log_out)),
        // )
        // .route("/login", web::get().to(login_form))
        // .route("/login", web::post().to(login))
        // .route("/health_check", web::get().to(health_check))
        // .route("/subscriptions", web::post().to(subscribe))
        // .route("/subscriptions/confirm", web::get().to(confirm))
        // .route("/newsletters", web::post().to(publish_newsletter))
        // // .service(Files::new("/hotel", "./build").index_file("index.html"))
        // .app_data(db_pool.clone())
        // .app_data(db_data.clone())
        // .app_data(email_client.clone())
        // .app_data(base_url.clone())
        // .app_data(Data::new(HmacSecret(hmac_secret.clone())))
    })
    .listen(listener)?
    .run();
    Ok(server)
}

#[derive(Clone)]
pub struct HmacSecret(pub Secret<String>);
