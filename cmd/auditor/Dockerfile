FROM golang:1.18.0-alpine3.14 AS builder

RUN apk add --no-cache \
  build-base \
  make \
  curl

WORKDIR /workspace
RUN mkdir _out
COPY cmd cmd
COPY handling handling
COPY healthiness healthiness
COPY meta meta
COPY model model
COPY options options
COPY sni sni

COPY go.mod go.sum Makefile ./
RUN touch LOCAL_ENV
RUN make clean-compile-auditor

FROM scratch
COPY --from=builder /workspace/_out/auditor /usr/local/bin/auditor

ENTRYPOINT ["auditor"]
