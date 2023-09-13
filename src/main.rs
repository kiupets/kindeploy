use kinhotelrust::websocket;
// use crate::websocket2;
use actix::prelude::{Actor, Context, Handler, Message as ActixMessage, Recipient};
use env_logger::Env;
use kinhotelrust::configuration::get_configuration;
// use kinhotelrust::issue_delivery_worker::run_worker_until_stopped;
use kinhotelrust::repository::mongodb_repo::MongoRepo;
use kinhotelrust::startup::run;
use kinhotelrust::startup::Application;
use kinhotelrust::websocket::server::Server;
use kinhotelrust::websocket2::server_shit::Server2;
use sqlx::PgPool;
use std::fmt::{Debug, Display};
use std::net::TcpListener;
use tokio::task::JoinError;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    // let websocket_task = websocket::server::Server::new().start();
    // let socket_server2 = Server2::new().start();
    // let websocket_task = tokio::spawn(websocket::server::Server::new().start());
    // let db = MongoRepo::init().await;
    // Panic if we can't read configuration
    let configuration = get_configuration().expect("Failed to read configuration.");
    let application = Application::build(configuration.clone()).await?;
    let application_task = tokio::spawn(application.run_until_stopped());
    // let application_task = tokio::spawn(application.run_until_stopped());
    // let worker_task = tokio::spawn(run_worker_until_stopped(configuration));
    // tokio::spawn(async move {
    //     let _ = websocket::server::Server::new().start();
    // });
    tokio::select! {
        o = application_task => report_exit("API", o),
        // o = worker_task =>  report_exit("Background worker", o),
    };
    // let connection_pool = PgPool::connect(&configuration.database.connection_string())
    // .await
    // .expect("Failed to connect to postgress");
    // We have removed the hard-coded `8000` - it's now coming from our settings!
    // let address = format!("127.0.0.1:{}", configuration.application_port);
    // let listener = TcpListener::bind(address)?;
    // run(listener, connection_pool, db, websocket_task)?.await
    Ok(())
}
fn report_exit(task_name: &str, outcome: Result<Result<(), impl Debug + Display>, JoinError>) {
    match outcome {
        Ok(Ok(())) => {
            tracing::info!("{} has exited", task_name)
        }
        Ok(Err(e)) => {
            tracing::error!(
                error.cause_chain = ?e,
                error.message = %e,
                "{} failed",
                task_name
            )
        }
        Err(e) => {
            tracing::error!(
                error.cause_chain = ?e,
                error.message = %e,
                "{}' task failed to complete",
                task_name
            )
        }
    }
}
