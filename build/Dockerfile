FROM golang:1.25-alpine AS builder
ENV GOPROXY=https://goproxy.cn,direct
COPY src/openvpn-web /src
RUN cd /src && CGO_ENABLED=0 go build -o /openvpn-web .

FROM alpine:3.23.3

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk add --no-cache openssl openvpn iptables iptables-legacy bash supervisor curl sqlite grep mailcap coreutils jq nftables

COPY build/docker-entrypoint.sh /usr/bin
RUN sed -i 's/\r$//' /usr/bin/docker-entrypoint.sh
COPY build/openvpn-auth /usr/lib/openvpn/plugins/openvpn-auth
RUN sed -i 's/\r$//' /usr/lib/openvpn/plugins/openvpn-auth
COPY build/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY --from=builder /openvpn-web /usr/local/bin/openvpn-web

COPY build/EasyRSA-3.2.5.tgz /tmp/EasyRSA-3.2.5.tgz
RUN tar -ozxf /tmp/EasyRSA-3.2.5.tgz && mv EasyRSA-3.2.5 /usr/share/easy-rsa && rm -rf /tmp/EasyRSA-3.2.5.tgz
RUN chmod +x /usr/local/bin/openvpn-web /usr/bin/docker-entrypoint.sh /usr/lib/openvpn/plugins/openvpn-auth
RUN ln -s /usr/share/easy-rsa/easyrsa /usr/local/bin

VOLUME ["/data"]

ENV GIN_MODE=release
ENV OVPN_DATA=/data

EXPOSE 1194/udp 8833

USER root

WORKDIR /data

ENTRYPOINT  ["docker-entrypoint.sh"]

CMD ["/usr/bin/supervisord"]