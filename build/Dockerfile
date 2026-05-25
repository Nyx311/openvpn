FROM golang:1.25.4-alpine AS web-builder

ARG VERSION=dev
ENV CGO_ENABLED=0

WORKDIR /src/openvpn-web

COPY src/openvpn-web/go.mod src/openvpn-web/go.sum ./
RUN go mod download

COPY src/openvpn-web/ ./
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/openvpn-web .

FROM alpine:3.23.4

RUN apk add --no-cache openssl openvpn iptables iptables-legacy bash supervisor curl sqlite grep mailcap coreutils jq nftables
#RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2

COPY build/docker-entrypoint.sh /usr/bin
COPY build/openvpn-auth /usr/lib/openvpn/plugins/openvpn-auth
COPY build/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY --from=web-builder /out/openvpn-web /usr/local/bin/openvpn-web

RUN wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.2.6/EasyRSA-3.2.6.tgz && tar -ozxf EasyRSA-3.2.6.tgz && mv EasyRSA-3.2.6 /usr/share/easy-rsa && rm -rf EasyRSA-3.2.6.tgz
RUN for file in /usr/bin/docker-entrypoint.sh /usr/lib/openvpn/plugins/openvpn-auth /etc/supervisor/conf.d/supervisord.conf; do tr -d '\015' < "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"; done \
    && chmod +x /usr/local/bin/openvpn-web /usr/bin/docker-entrypoint.sh /usr/lib/openvpn/plugins/openvpn-auth
RUN ln -s /usr/share/easy-rsa/easyrsa /usr/local/bin

VOLUME ["/data"]

ENV GIN_MODE=release
ENV OVPN_DATA=/data

EXPOSE 1194/udp 8833

USER root

WORKDIR /data


ENTRYPOINT  ["/usr/bin/docker-entrypoint.sh"]

CMD ["/usr/bin/supervisord"]
