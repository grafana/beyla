use actix_web::{middleware, web, App, HttpResponse, HttpServer};
use actix_web::http::header::ContentType;
use serde::{Deserialize, Serialize};

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
    HttpResponse::Ok().content_type(ContentType::plaintext()).body("hello")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("starting HTTP server at http://localhost:8090");

    HttpServer::new(|| {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            .app_data(web::JsonConfig::default().limit(800000)) // <- limit size of the payload (global configuration)
            .service(web::resource("/greeting").route(web::post().to(greeting)))
            .service(web::resource("/smoke").route(web::get().to(smoke)))
    })
    .bind(("0.0.0.0", 8090))?
    .run()
    .await
}
