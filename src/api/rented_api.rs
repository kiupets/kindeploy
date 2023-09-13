// use crate::lobby::Lobby;
// use crate::messages::BroadcastMessage;
use crate::websocket::server::{MessageToClient, Server};
use crate::{models::rented_model::Rented, repository::mongodb_repo::MongoRepo};
use actix::Addr;
use actix_web::{
    get, post, put,
    web::{Data, Json, Path},
    HttpResponse,
};
use mongodb::bson::oid::ObjectId;

// use serde_json::json;
use serde_json::to_value;
// use uuid::Uuid;
#[post("/rented")]
pub async fn create_rented(
    db: Data<MongoRepo>,
    params: Json<Rented>,
    srv: Data<Addr<Server>>,
    // params: Json<Vec<StatisticRecord>>,
) -> HttpResponse {
    println!("rented api");
    let data = Rented {
        id: None,
        name: params.name.to_owned(),
        start: params.start.to_owned(),
        end: params.end.to_owned(),
        room: params.room.to_owned(),
        email: params.email.to_owned(),
        phone: params.phone.to_owned(),
        nights: params.nights.to_owned(),

        price: params.price.to_owned(),
        // interval_rented_array: params.interval_rented_array.to_owned(),
    };
    // if let Ok(data) = to_value(data.clone()) {
    //     println!("{:?}renteddddddd apiiiiiiiiiiiiiiiiiii", data);
    //     let msg = MessageToClient::new("rented", data);
    //     srv.do_send(msg);
    // }

    let rented_detail = db.create_rented(data).await;
    match rented_detail {
        Ok(rented) => HttpResponse::Ok().json(rented),
        Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
    }
}

#[get("/rented/{id}")]
pub async fn get_rented(db: Data<MongoRepo>, path: Path<String>) -> HttpResponse {
    let id = path.into_inner();
    if id.is_empty() {
        return HttpResponse::BadRequest().body("invalid ID");
    }
    let rented_detail = db.get_rented(&id).await;
    match rented_detail {
        Ok(rented) => HttpResponse::Ok().json(rented),
        Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
    }
}

#[put("/rented/{id}")]
pub async fn update_rented(
    db: Data<MongoRepo>,
    path: Path<String>,
    new_rented: Json<Rented>,
) -> HttpResponse {
    let id = path.into_inner();
    println!("{} maaaaaaaaaaaaaaaaamaaaaaaaaaaaaaaaaaaaaa", id);

    if id.is_empty() {
        println!("hola mama esto esta vacio");
        return HttpResponse::BadRequest().body("invalid ID");
    };
    let data = Rented {
        id: new_rented.id.to_owned(),
        name: new_rented.name.to_owned(),
        start: new_rented.start.to_owned(),
        end: new_rented.end.to_owned(),
        room: new_rented.room.to_owned(),
        email: new_rented.email.to_owned(),
        phone: new_rented.phone.to_owned(),
        nights: new_rented.nights.to_owned(),
        price: new_rented.price.to_owned(),
        // interval_rented_array: new_rented.interval_rented_array.to_owned(),
    };

    let update_result = db.update_rented(&id, data).await;

    match update_result {
        Ok(update) => {
            println!("{:?}", update);
            if update.matched_count == 1 {
                println!("dddddddddddddddddddddddddddddddddddddddddddddd{}", id);
                let updated_rented_info = db.get_rented(&id).await;
                return match updated_rented_info {
                    Ok(rented) => HttpResponse::Ok().json(rented),
                    Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
                };
            } else {
                return HttpResponse::NotFound().body("No rented found with specified ID");
            }
        }
        Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
    }
}

#[get("/all")]
pub async fn get_all(db: Data<MongoRepo>) -> HttpResponse {
    println!("mammmmmmmmmmmmmmmmmmmmmmmmmm");
    let rents = db.get_all().await;
    println!("{:?}", rents);

    match rents {
        Ok(rents) => HttpResponse::Ok().json(rents),
        Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
    }
}
