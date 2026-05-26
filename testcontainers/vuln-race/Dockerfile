FROM golang:1.22-alpine AS build
WORKDIR /src
COPY main.go go.mod /src/
RUN go build -o /out/server .

FROM alpine:3.20
COPY --from=build /out/server /server
EXPOSE 8084
CMD ["/server"]
