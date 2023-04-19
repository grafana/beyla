extern crate iron;

use std::collections::HashMap;
use std::process;

use iron::prelude::*;
use iron::Handler;
use iron::status;

struct Router {
    // Routes here are simply matched with the url path.
    routes: HashMap<String, Box<dyn Handler>>
}

impl Router {
    fn new() -> Self {
        Router { routes: HashMap::new() }
    }

    fn add_route<H>(&mut self, path: String, handler: H) where H: Handler {
        self.routes.insert(path, Box::new(handler));
    }
}

impl Handler for Router {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {
        match self.routes.get(&req.url.path().join("/")) {
            Some(handler) => handler.handle(req),
            None => Ok(Response::with(status::NotFound))
        }
    }
}

fn main() {
    let mut router = Router::new();

    router.add_route("ping".to_string(), |_: &mut Request| {
        Ok(Response::with((status::Ok, "PONG!")))
    });

    println!("Running server: port=8080, process_id={}", process::id());

    Iron::new(router).http("0.0.0.0:8080").unwrap();
}