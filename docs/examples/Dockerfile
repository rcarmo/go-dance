FROM golang:1.27.4 AS build
WORKDIR /src
COPY . .
RUN mkdir -p /out && CGO_ENABLED=0 go build -o /out/ ./cmd/dance

FROM debian:stable-slim
RUN useradd -r -d /app -s /usr/sbin/nologin dance
WORKDIR /app
COPY --from=build /out/dance /usr/local/bin/dance
USER dance
EXPOSE 8088
ENTRYPOINT ["/usr/local/bin/dance"]
