FROM vault:1.0.2

# /vault/logs is made available to use as a location to store audit logs, if
# desired; /vault/file is made available to use as a location with the file
# storage backend, if desired; the server will be started with /vault/config as
# the configuration directory so you can add additional config files in that
# location.
RUN mkdir -p /tools && \
    mkdir -p /vault/logs /vault/file /vault/config && \
    chown -R vault:vault /vault

# Expose the logs directory as a volume since there's potentially long-running
# state in there
VOLUME /vault/logs

# Expose the file directory as a volume since there's potentially long-running
# state in there
VOLUME /vault/file

ADD pkg/bin/vault-pki-monitor-venafi /vault_plugin/vault-pki-monitor-venafi

#Add helper scripts
ADD scripts /scripts

#Add consul configs
ADD scripts/vault-config-with-consul.hcl /config/


# 8200/tcp is the primary interface that applications use to interact with
# Vault.
EXPOSE 8200

# By default you'll get a single-node development server that stores everything
# in RAM and bootstraps itself. Don't use this configuration for production.
CMD ["server", "-dev"]

