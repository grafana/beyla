use actix_files::NamedFile;
use actix_web::{middleware, web, App, HttpResponse, HttpServer, Result, Responder};
use actix_web::http::header::ContentDisposition;
use actix_web::http::header::DispositionType;
use mime::Mime;
use serde::{Deserialize, Serialize};
use rand::Rng;
use std::time::Duration;
use std::thread;
use std::fs;
use std::io::Read;
use reqwest;
use tokio;

#[derive(Debug, Serialize, Deserialize)]
struct MyObj {
    name: String,
    number: i32,
}

/// This handler uses json extractor
async fn greeting(item: web::Json<MyObj>) -> HttpResponse {
    //println!("model: {:?}", &item);
    HttpResponse::Ok().json(item.0) // <- send response
}

async fn smoke() -> HttpResponse {
    let mut rng = rand::thread_rng();
    let sleep_time = rng.gen_range(100..500);
    thread::sleep(Duration::from_millis(sleep_time));
    HttpResponse::Ok().into()
}

async fn trace() -> HttpResponse {
    HttpResponse::Ok().into()
}

async fn large() -> HttpResponse {
    let data = fs::read_to_string("large_data.json").expect("Unable to read large_data.json file");
    HttpResponse::Ok().body(data)
}

async fn download1() -> Result<NamedFile> {
    let file = NamedFile::open("large_data.json")?;

    let content_disposition = ContentDisposition {
        disposition: DispositionType::Attachment,
        parameters: vec![],
    };

    let content_type: Mime = "application/json".parse().unwrap();

    Ok(file
        .set_content_disposition(content_disposition)
        .set_content_type(content_type))
}

async fn download2() -> impl Responder {
    if let Ok(mut file) = NamedFile::open("large_data.json") {
        let my_data_stream = async_stream::stream! {
        let mut chunk = vec![0u8; 10 * 1024 *1024]; // I decalare the chunk size here as 10 mb 
   
        loop {
            match file.read(&mut chunk) {
                Ok(n) => {
                    if n == 0 {
                        break;
                    }
                    yield Result::<web::Bytes, std::io::Error>::Ok(web::Bytes::from(chunk[..n].to_vec())); // Yielding the chunk here
                }

                Err(e) => {
                    yield Result::<web::Bytes, std::io::Error>::Err(e);
                    break;
                }
            }
        }
    };
   
    HttpResponse::Ok()
        .content_type("application/octet-stream")
        .streaming(my_data_stream)  // Streaming my response here
    } else {
        HttpResponse::NotFound().finish()
    }
}

async fn dist() -> HttpResponse {
    let handle = tokio::task::spawn_blocking(move || {
        let r = reqwest::blocking::get("http://jtestserver:8085/jtrace").unwrap().text();        
        r
    });

    let result = handle.await.unwrap();

    match result {
        Ok(value) => {
            //println!("Result: {:?}", value);
            HttpResponse::Ok().body(value)
        }
        Err(_) => {
            HttpResponse::Ok().body("ERROR")
        }
    }
}

async fn dist2() -> HttpResponse {
    let handle = tokio::task::spawn(async {
        let r = reqwest::get("http://jtestserver:8085/jtrace2").await.unwrap().text().await.unwrap();
        r
    });

    let result = handle.await.unwrap();
    //println!("Result: {:?}", result);
    
    HttpResponse::Ok().body(result)
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
            .service(web::resource("/trace").route(web::get().to(trace)))
            .service(web::resource("/dist").route(web::get().to(dist)))
            .service(web::resource("/dist2").route(web::get().to(dist2)))
            .service(web::resource("/large").route(web::get().to(large)))
            .service(web::resource("/download1").route(web::get().to(download1)))
            .service(web::resource("/download2").route(web::get().to(download2)))
    })
    .bind(("0.0.0.0", 8090))?
    .run()
    .await
}
