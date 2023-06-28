var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/ping", () => "PONG!");
app.MapGet("/smoke", () => "");

app.Run();
