use actix_web::{middleware, web, App, HttpResponse, HttpServer};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
struct MyObj {
    name: String,
    number: i32,
}

/// This handler uses json extractor
async fn greeting(item: web::Json<MyObj>) -> HttpResponse {
    println!("model: {:?}", &item);
    HttpResponse::Ok().json(item.0) // <- send response
}

async fn smoke() -> HttpResponse {
    HttpResponse::Ok().into()
}

async fn trace() -> HttpResponse {
    HttpResponse::Ok().into()
}

async fn large() -> HttpResponse {
    let data = fs::read_to_string("mid_data.json").expect("Unable to read mid_data.json file");
    HttpResponse::Ok().body(data)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("key.pem", SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file("cert.pem").unwrap();

    log::info!("starting HTTPS server at http://localhost:8490");

    HttpServer::new(|| {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            .app_data(web::JsonConfig::default().limit(800000)) // <- limit size of the payload (global configuration)
            .service(web::resource("/greeting").route(web::post().to(greeting)))
            .service(web::resource("/smoke").route(web::get().to(smoke)))
            .service(web::resource("/trace").route(web::get().to(trace)))
            .service(web::resource("/large").route(web::get().to(large)))
    })
    .bind_openssl(("0.0.0.0", 8490), builder)?
    .run()
    .await
}
