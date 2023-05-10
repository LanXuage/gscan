FROM --platform=$BUILDPLATFORM crazymax/goxx:1.19 AS base
ENV GO111MODULE=on
ENV CGO_ENABLED=1
ENV GOPROXY=https://goproxy.cn,direct
COPY . /mnt
WORKDIR /mnt

FROM --platform=$BUILDPLATFORM crazymax/osxcross:11.3 AS osxcross
FROM base AS build
COPY --from=osxcross /osxcross /osxcross
ARG TARGETPLATFORM
RUN --mount=type=cache,sharing=private,target=/var/cache/apt \
  --mount=type=cache,sharing=private,target=/var/lib/apt/lists \
  goxx-apt-get install -y binutils gcc g++ pkg-config libpcap-dev
RUN --mount=type=bind,source=. \
  --mount=type=cache,target=/root/.cache \
  --mount=type=cache,target=/go/pkg/mod \
  goxx-go build -o /out/gscan ./cli/main.go

FROM scratch AS artifact
COPY --from=build /out /

FROM scratch
COPY --from=build /out/gscan /gscan
ENTRYPOINT [ "/gscan" ]
