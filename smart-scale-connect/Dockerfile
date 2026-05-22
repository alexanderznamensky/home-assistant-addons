# syntax=docker/dockerfile:1

ARG BUILD_FROM
ARG SSC_REF=master

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG SSC_REF

ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}
ENV CGO_ENABLED=0

WORKDIR /build

RUN apk add --no-cache git ca-certificates

RUN git clone --depth 1 --branch "${SSC_REF}" https://github.com/AlexxIT/SmartScaleConnect.git .

COPY patches/pkg/garmin/auth.go pkg/garmin/auth.go
COPY patches/pkg/garmin/client.go pkg/garmin/client.go

RUN go fmt ./pkg/garmin
RUN go build -ldflags "-s -w -X main.version=0.4.5-garmin-di-config-v2" -trimpath -o /out/scaleconnect

FROM ${BUILD_FROM}

RUN apk add --no-cache tini jq tzdata ca-certificates

COPY run.sh /run.sh
COPY --from=build /out/scaleconnect /usr/local/bin/scaleconnect

RUN chmod a+x /run.sh

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/run.sh"]
