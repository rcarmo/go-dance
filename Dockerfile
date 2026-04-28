FROM golang:1.25 AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/dance ./cmd/dance

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/dance /dance
EXPOSE 8088
ENTRYPOINT ["/dance"]
