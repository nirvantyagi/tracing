#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;

use rocket_contrib::databases::redis;
use rocket_contrib::databases::redis::Commands;

#[database("redis")]
struct DbConn(redis::Connection);

#[get("/")]
fn index() -> &'static str {
    "Hello, world!\n"
}

#[get("/<key>")]
fn get_key(conn: DbConn, key: String) -> String {
    let value: Result<String, redis::RedisError> = conn.get(key);
    match value {
        Ok(v) => format!("{}\n", v),
        Err(e) => format!("Key does not exist: {}\n", e),
    }
}

fn main() {
    rocket::ignite()
        .attach(DbConn::fairing())
        .mount("/", routes![index, get_key])
        .launch();
}
