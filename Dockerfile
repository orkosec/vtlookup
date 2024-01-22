FROM golang:1.19.2-bullseye

ENV APP_NAME vtchecker

WORKDIR /app

COPY go.mod go.sum ./
COPY api/api.go ./api/
COPY main.go ./


RUN go mod download

RUN go build -o /$APP_NAME

EXPOSE 8080

CMD [ "/vtchecker" ]