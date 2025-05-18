# Dockerfile za projects servis
FROM golang:alpine as build_container

# Setovanje radnog direktorijuma
WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build -o projects-service .

FROM alpine
WORKDIR /usr/bin
COPY --from=build_container /app/projects-service .
COPY --from=build_container /app/.env .env
EXPOSE 8003
ENTRYPOINT ["projects-service"]
