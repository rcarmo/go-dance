FROM golang:1.25 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/dance ./cmd/dance

FROM debian:stable-slim
RUN useradd -r -d /app -s /usr/sbin/nologin dance
WORKDIR /app
COPY --from=build /out/dance /usr/local/bin/dance
USER dance
EXPOSE 8088
ENTRYPOINT ["/usr/local/bin/dance"]
