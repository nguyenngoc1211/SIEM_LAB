# Reuse the already provisioned v3 tool image (nmap, curl, Python, tini)
# and replace only the scenario implementation. This keeps v2 builds
# deterministic and offline in the lab.
FROM soc-attacker-advanced:v3.0.0

USER root
WORKDIR /opt/soc
COPY --chmod=0755 src/ /opt/soc/
COPY scenarios/ /opt/soc/scenarios/
COPY wordlists/ /opt/soc/wordlists/
COPY tests/ /opt/soc/tests/

ENV PYTHONPATH=/opt/soc

USER soc
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sleep", "infinity"]
