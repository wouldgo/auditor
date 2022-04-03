FROM golang:1.17-alpine3.14 AS builder

RUN apk add --no-cache \
  build-base \
  make \
  curl

WORKDIR /workspace
RUN mkdir _out
COPY cmd cmd
COPY handling handling
COPY meta meta
COPY prometheus prometheus
COPY sni sni

COPY go.mod go.sum Makefile ./
RUN make clean-compile-auditor

FROM scratch
COPY --from=builder /workspace/_out/auditor /usr/local/bin/auditor

ENTRYPOINT ["auditor"]
