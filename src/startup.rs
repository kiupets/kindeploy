use actix::Actor;

use actix::prelude::Addr;
use actix_cors::Cors;
use actix_files::Files;
use actix_web::middleware::Logger;
use actix_web::{web, web::Data, Error};
use actix_web::{App, HttpResponse, HttpServer};
use std::env;
use std::ops::Add;
// use actix_web_actors::ws;

// mod api;
// use crate::pos_routes;
// use crate::routes::health_check::*;
// use crate::routes::subscriptions::*;
use crate::websocket;
use crate::websocket::server::Server as WebSocketServer;
use crate::websocket2;

// mod configuration;
use crate::api::login_api::login;
use crate::api::rented_api::{create_rented, get_all, get_rented, update_rented};
use crate::api::user_api::{create_user, get_user};
use crate::configuration::{DatabaseSettings, Settings};
use crate::repository::mongodb_repo::MongoRepo;
use actix_session::SessionMiddleware;
// mod settings;
use crate::routes::{
    change_password_form, confirm, health_check, home, log_out, login_form,
    publish_newsletter_form, subscribe,
};
use actix_web::dev::Server;
use secrecy::{ExposeSecret, Secret};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgConnection;
use sqlx::PgPool;
use std::net::TcpListener;
pub struct Application {
    port: u16,
    server: Server,
}

impl Application {
    pub async fn build(configuration: Settings) -> Result<Self, anyhow::Error> {
        let connection_pool = get_connection_pool(&configuration.database);
        let db = MongoRepo::init().await;

        // let email_client = configuration.email_client.client();
        // let web_socket_server = WebSocketServer::new().start();
        let address = format!(
            "{}:{}",
            configuration.application.host, configuration.application.port
        );
        let listener = TcpListener::bind(address)?;
        let port = listener.local_addr().unwrap().port();
        let server = run(
            listener,
            connection_pool,
            db, // web_socket_server, // email_client,
                // configuration.application.base_url,
                // configuration.application.hmac_secret,
                // configuration.redis_uri,
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
    PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_lazy_with(configuration.with_db())
}

pub struct ApplicationBaseUrl(pub String);

pub async fn run(
    listener: TcpListener,
    db_pool: PgPool,
    db: MongoRepo,
    // socket_server: Addr<WebSocketServer>,
) -> Result<Server, std::io::Error> {
    // let HOST = env::var("HOST").expect("Host not set");
    // let PORT = env::var("PORT").expect("Port not set");
    // let server = websocket::Server::new().start();
    // let server2 = websocket2::Server2::new().start();
    // let db = MongoRepo::init().await;
    let db_data = Data::new(db);

    let db_pool = Data::new(db_pool);
    let server = HttpServer::new(move || {
        // let cors = Cors::permissive();

        App::new()
            .wrap(Logger::default())
            // .wrap(cors)
            // .wrap(SessionMiddleware::new(
            //     redis_store.clone(),
            //     secret_key.clone(),
            // ))
            // .wrap(TracingLogger::default())
            .route("/", web::get().to(home))
            // .service(Files::new("/", "./build").index_file("index.html"))
            .service(
                web::scope("/admin")
                    // .wrap(from_fn(reject_anonymous_users))
                    // .route("/dashboard", web::get().to(admin_dashboard))
                    .route("/newsletters", web::get().to(publish_newsletter_form))
                    // .route("/newsletters", web::post().to(publish_newsletter))
                    .route("/password", web::get().to(change_password_form))
                    // .route("/password", web::post().to(change_password))
                    .route("/logout", web::post().to(log_out)),
            )
            .route("/login", web::get().to(login_form))
            // .route("/login", web::post().to(login))
            .route("/health_check", web::get().to(health_check))
            .route("/subscriptions", web::post().to(subscribe))
            .route("/subscriptions/confirm", web::get().to(confirm))
            // .route("/newsletters", web::post().to(publish_newsletter))
            // .app_data(db_pool.clone())
            // .app_data(email_client.clone())
            // .app_data(base_url.clone())
            // .app_data(Data::new(HmacSecret(hmac_secret.clone())))
            .route("/subscriptions", web::post().to(subscribe))
            .app_data(db_pool.clone())
            .app_data(db_data.clone())
            // .app_data(socket_server.clone())
            // .app_data(socket_server2.clone())
            .service(create_user)
            // .route("/ws", web::get().to(websocket::ws_index))
            // .route("/wss", web::get().to(ws_index_drag))
            .service(get_user)
            .service(create_rented)
            .service(get_rented)
            .service(update_rented)
            .service(get_all)
            // .service(login)
            .service(Files::new("/hotel", "./build").index_file("index.html"))
    })
    // .workers(4)
    // .bind(format!("{}:{}", HOST, PORT))?
    .listen(listener)?
    .run();
    Ok(server)
}
#[derive(Clone)]
pub struct HmacSecret(pub Secret<String>);
