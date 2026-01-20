FROM golang:1.21 AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o /out/user-center main.go

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=build /out/user-center /usr/local/bin/user-center
VOLUME ["/data"]
ENV DB_PATH=/data/user-center.db
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/user-center"]
