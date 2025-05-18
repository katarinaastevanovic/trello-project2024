# Dockerfile za tasks servis
FROM golang:alpine as build_container

# Setovanje radnog direktorijuma
WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build -o tasks-service .

FROM alpine
WORKDIR /usr/bin
COPY --from=build_container /app/tasks-service .
COPY --from=build_container /app/.env .env
EXPOSE 8002
ENTRYPOINT ["tasks-service"]