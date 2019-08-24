#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;

use rocket::response::status::BadRequest;
use rocket_contrib::databases::redis;
use rocket_contrib::json::Json;
use serde::{Deserialize, Serialize};

use tracing::path::*;

#[database("redis")]
struct DbConn(redis::Connection);

#[derive(Serialize, Deserialize)]
struct ProcessRequestData {
    stag: SenderTraceTag,
    sid: u32,
    rid: u32,
}

#[derive(Serialize, Deserialize)]
struct TraceRequestData {
    m: String,
    tmd: TraceMetadata,
    uid: u32,
}

#[post("/process", format = "json", data = "<data>")]
fn process(
    conn: DbConn,
    data: Json<ProcessRequestData>,
) -> Result<Json<RecTraceTag>, BadRequest<String>> {
    let data = data.into_inner();
    let rec_tag = svr_process(&*conn, &data.stag, data.sid, data.rid);
    match rec_tag {
        Some(t) => Ok(Json(t)),
        None => Err(BadRequest(None)),
    }
}

// TODO: Spawn off trace in separate thread and return polling id
#[post("/trace", format = "json", data = "<data>")]
fn trace(conn: DbConn, data: Json<TraceRequestData>) -> Result<Json<Vec<u32>>, BadRequest<String>> {
    let data = data.into_inner();
    let tr = svr_trace(&*conn, &data.m.as_bytes(), &data.tmd, data.uid);
    Ok(Json(tr))
}

fn main() {
    rocket::ignite()
        .attach(DbConn::fairing())
        .mount("/", routes![process, trace])
        .launch();
}
