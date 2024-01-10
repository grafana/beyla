#include <iostream>
#include "httplib.h"

// Simple web service that just returns Ok to any path.

int main() {
    std::cout << "Listening on http://localhost:8080" << std::endl;
    httplib::Server svr;

    svr.Get(R"(.*)", [&](const httplib::Request &req, httplib::Response &res) {
        std::cout << "received request " << req.path << std::endl;
        res.set_content("Hello!", "text/plain");
    });

    svr.listen("0.0.0.0", 8080);

    return 0;
}