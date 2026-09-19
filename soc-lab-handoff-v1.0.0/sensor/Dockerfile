ARG SURICATA_IMAGE=jasonish/suricata:7.0
FROM ${SURICATA_IMAGE}

USER root

COPY entrypoint.sh /usr/local/bin/soc-suricata-entrypoint
COPY local.rules /opt/soc/local.rules

RUN chmod 0755 /usr/local/bin/soc-suricata-entrypoint \
    && chmod 0644 /opt/soc/local.rules \
    && mkdir -p /var/lib/suricata/rules /var/log/suricata /run

ENTRYPOINT ["/usr/local/bin/soc-suricata-entrypoint"]
