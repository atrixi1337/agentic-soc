# Linux endpoint image: Wazuh agent + auditd + Falco libs.
# Runs privileged so auditd and Falco kernel collectors work.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Base tooling
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg lsb-release auditd audispd-plugins procps \
    && rm -rf /var/lib/apt/lists/*

# Install Wazuh agent (4.9.0) — matches manager version
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update && apt-get install -y wazuh-agent=4.9.0-1 \
    && rm -rf /var/lib/apt/lists/*

# Enable auditd-based command monitoring + FIM via ossec.conf
COPY endpoint/ossec.conf /var/ossec/etc/ossec.conf
COPY endpoint/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Sample "victim" directories to attack
RUN mkdir -p /home/victim/Downloads /home/victim/Desktop /tmp/quarantine

EXPOSE 1514/udp 1515
ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/dev/null"]
