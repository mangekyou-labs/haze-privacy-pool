# Multi-stage production Keycloak build pinning version 26.7.1 per official container guidance
FROM quay.io/keycloak/keycloak:26.7.1 as builder

ENV KC_HEALTH_ENABLED=true
ENV KC_HTTP_MANAGEMENT_HEALTH_ENABLED=false
ENV KC_METRICS_ENABLED=true
ENV KC_DB=postgres

# Optimized build
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.7.1
COPY --from=builder /opt/keycloak/ /opt/keycloak/
COPY haze/dev/keycloak/realm-export.json /opt/keycloak/data/import/realm-export.json

ENV KC_HEALTH_ENABLED=true
ENV KC_HTTP_MANAGEMENT_HEALTH_ENABLED=false
ENV KC_METRICS_ENABLED=true
ENV KC_DB=postgres
ENV KC_HTTP_RELATIVE_PATH=/auth

EXPOSE 8080

ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start", "--optimized", "--import-realm"]
