ARG BASE_IMAGE=debian:12

# Reuse the Docker Official Image's static engine/CLI binaries, but exercise all
# installer logic and package interactions in the distribution named above.
FROM docker:dind AS docker_dist

FROM ${BASE_IMAGE}

ENV container=docker
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        dbus \
        git \
        iproute2 \
        iptables \
        jq \
        kmod \
        openssl \
        procps \
        systemd \
        systemd-sysv \
        xxd; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=docker_dist /usr/local/bin/ /usr/local/bin/
COPY --from=docker_dist /usr/local/libexec/docker/cli-plugins/ /usr/local/libexec/docker/cli-plugins/
COPY docker.service /etc/systemd/system/docker.service
COPY fake-certbot /usr/local/bin/certbot
COPY fake-nfqws /opt/zapret/nfq/nfqws

RUN chmod 0755 /usr/local/bin/certbot /opt/zapret/nfq/nfqws \
    && docker compose version \
    && dockerd --version

STOPSIGNAL SIGRTMIN+3
VOLUME ["/sys/fs/cgroup", "/var/lib/docker"]
CMD ["/sbin/init"]
