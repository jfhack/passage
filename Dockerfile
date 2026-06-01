# syntax=docker/dockerfile:1
FROM golang:1.26.3-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/passage ./cmd/passage \
 && apk add --no-cache libcap \
 && setcap cap_net_bind_service=+ep /out/passage

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/jfhack/passage"
LABEL org.opencontainers.image.licenses="MIT"
COPY --from=build /out/passage /usr/local/bin/passage
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/passage"]
