var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/greeting", () => "PONG!");
app.MapGet("/smoke", () => "");

app.Run();
