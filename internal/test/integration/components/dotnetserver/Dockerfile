FROM mcr.microsoft.com/dotnet/sdk:7.0@sha256:d32bd65cf5843f413e81f5d917057c82da99737cb1637e905a1a4bc2e7ec6c8d AS builder

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY internal/test/integration/components/dotnetserver .

RUN dotnet dev-certs https
RUN dotnet build


# Create final image from minimal + built binary
FROM mcr.microsoft.com/dotnet/aspnet:7.0@sha256:c7d9ee6cd01afe9aa80642e577c7cec9f5d87f88e5d70bd36fd61072079bc55b

WORKDIR /
COPY --from=builder /build/bin/Debug/net7.0/* .
COPY --from=builder /root/.dotnet/corefx/cryptography/x509stores/my/* /root/.dotnet/corefx/cryptography/x509stores/my/
ENV ASPNETCORE_URLS="https://0.0.0.0:7033;http://0.0.0.0:5266"

EXPOSE 7033
EXPOSE 5266

# Run the .net app
CMD [ "/dotnetserver"]
