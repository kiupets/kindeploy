// database.rs

use crate::repository::mongodb_repo::MongoRepo;

pub async fn init() -> Result<MongoRepo, mongodb::error::Error> {
    let db = MongoRepo::init().await;

    Ok(db)
}
