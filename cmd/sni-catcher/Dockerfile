FROM golang:1.18.0-alpine3.14 AS builder

RUN apk add --no-cache \
  build-base \
  make \
  curl \
  flex \
  bison

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
RUN make clean-compile-sni-catcher

FROM scratch
COPY --from=builder /workspace/_out/sni-catcher /usr/local/bin/sni-catcher

ENTRYPOINT ["sni-catcher"]
