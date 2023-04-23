FROM registry.access.redhat.com/ubi8/go-toolset:1.18 as build-stage

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

RUN go build

FROM registry.access.redhat.com/ubi8-minimal:8.7

COPY --from=build-stage /opt/app-root/src/plugin-token-exchange /usr/bin/plugin-token-exchange

EXPOSE 8080
#EXPOSE 8443

USER 1001

ENTRYPOINT ["/usr/bin/plugin-token-exchange"]