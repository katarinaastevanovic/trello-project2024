FROM golang:alpine as build_container

WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build -o users-service .

FROM alpine
RUN apk add --no-cache ca-certificates && update-ca-certificates

WORKDIR /usr/bin
COPY --from=build_container /app/users-service .
COPY --from=build_container /app/.env .env

EXPOSE 8001
RUN chmod +x /usr/bin/users-service 
ENTRYPOINT ["users-service"]