use std::env;
extern crate dotenv;
use dotenv::dotenv;

use crate::models::rented_model::Rented;
use crate::models::user_model::User;

use futures::stream::TryStreamExt;
use mongodb::{
    bson::{doc, extjson::de::Error, oid::ObjectId},
    results::{InsertOneResult, UpdateResult},
    Client, Collection,
};

pub struct MongoRepo {
    col: Collection<User>,
    col_rented: Collection<Rented>,
}

impl MongoRepo {
    pub async fn init() -> Self {
        dotenv().ok();
        // let uri = match env::var("MONGO_URI") {
        //     Ok(v) => v.to_string(),
        //     Err(_) => format!("Error loading env variable"),
        // };
        let client = Client::with_uri_str(
            "mongodb+srv://kiupets:ShDpcBGLRhvAuwAh@cluster0.cpgytzo.mongodb.net/?retryWrites=true",
        )
        .await
        .unwrap();
        let db = client.database("kinhotelrust");
        let col: Collection<User> = db.collection("User");
        let col_rented: Collection<Rented> = db.collection("Rented");

        MongoRepo { col, col_rented }
    }

    pub async fn create_user(&self, new_user: User) -> Result<InsertOneResult, Error> {
        let new_doc = User {
            id: None,
            name: new_user.name,
            email: new_user.email,
            phone: new_user.phone,
            password_hash: new_user.password_hash,
        };
        let user = self
            .col
            .insert_one(new_doc, None)
            .await
            .ok()
            .expect("Error creating user");
        Ok(user)
    }

    pub async fn get_user(&self, id: &String) -> Result<User, Error> {
        let obj_id = ObjectId::parse_str(id).unwrap();
        let filter = doc! {"_id": obj_id};
        let user_detail = self
            .col
            .find_one(filter, None)
            .await
            .ok()
            .expect("Error getting user's detail");
        Ok(user_detail.unwrap())
    }

    pub async fn create_rented(&self, new_rented: Rented) -> Result<InsertOneResult, Error> {
        println!("mongo repo");
        let new_doc = Rented {
            id: None,
            name: new_rented.name,
            email: new_rented.email,
            phone: new_rented.phone,
            room: new_rented.room,
            start: new_rented.start,
            end: new_rented.end,
            nights: new_rented.nights,
            price: new_rented.price,
            // interval_rented_array: new_rented.interval_rented_array,
        };

        let rented = self
            .col_rented
            .insert_one(new_doc, None)
            .await
            .ok()
            .expect("Error creating rented");
        Ok(rented)
    }

    pub async fn get_rented(&self, id: &String) -> Result<Rented, Error> {
        let obj_id = ObjectId::parse_str(id).unwrap();
        let filter = doc! {"_id": obj_id};
        let rented_detail = self
            .col_rented
            .find_one(filter, None)
            .await
            .ok()
            .expect("Error getting rented's detail");
        Ok(rented_detail.expect("bad ok"))
    }
    pub async fn update_rented(
        &self,
        id: &String,
        new_rented: Rented,
    ) -> Result<UpdateResult, Error> {
        let obj_id = ObjectId::parse_str(id).unwrap();
        let filter = doc! {"_id": obj_id};
        println!("fffffffffffffffffffffffffffffffffffffffffff{}", filter);
        let new_doc = doc! {
            "$set":
                {
            "id":new_rented.id,
            "name": new_rented.name,
            "email": new_rented.email,
            "phone": new_rented.phone,
            "room": new_rented.room,
            "start": new_rented.start,
            "end": new_rented.end,
            "nights": new_rented.nights,
            "price": new_rented.price,
            // "interval_rented_array": new_rented.interval_rented_array,
                },
        };
        let updated_doc = self
            .col_rented
            .update_one(filter, new_doc, None)
            .await
            .ok()
            .expect("Error updating rented");
        Ok(updated_doc)
    }

    pub async fn get_all(&self) -> Result<Vec<Rented>, Error> {
        println!("mongo repo");
        let mut cursors = self
            .col_rented
            .find(None, None)
            .await
            .ok()
            .expect("Error getting list of users");
        let mut rents: Vec<Rented> = Vec::new();
        while let Some(rent) = cursors
            .try_next()
            .await
            .ok()
            .expect("Error mapping throu cursor")
        {
            rents.push(rent)
        }
        Ok(rents)
    }
}
