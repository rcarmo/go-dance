FROM golang:1.27.2 AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/dance ./cmd/dance

RUN mkdir -p /out/data && chown 65532:65532 /out/data

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
ENV DANCE_DB_PATH=/data/dance.sqlite
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build /out/dance /dance
EXPOSE 8088
ENTRYPOINT ["/dance"]
