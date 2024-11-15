#TODO: Use hardened images

#build stage
FROM golang:1.23-alpine3.20 AS builder
# FROM chainguard/go:latest AS builder

WORKDIR /go/src/app

COPY . .

RUN go get -d -v .

RUN go build -o /go/bin/app/ -v .

#final stage
FROM alpine:3.20
# FROM chainguard/static:latest

COPY --from=builder /go/bin/app/sport-matchmaking-auth-service /app

ENTRYPOINT [ "/app", "--port", "8080" ]

EXPOSE 8080

LABEL Name="sport-matchmaking-auth-service"