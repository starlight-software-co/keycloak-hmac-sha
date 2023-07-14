ARG keycloak_version

FROM quay.io/keycloak/keycloak:${keycloak_version}

ARG keycloak_hmac_version=1.0.0

COPY ./keycloak-hmac-sha1-${keycloak_hmac_version}.jar /opt/keycloak/providers/
COPY ./keycloak-hmac-sha256-${keycloak_hmac_version}.jar /opt/keycloak/providers/
COPY ./keycloak-hmac-sha384-${keycloak_hmac_version}.jar /opt/keycloak/providers/
COPY ./keycloak-hmac-sha512-${keycloak_hmac_version}.jar /opt/keycloak/providers/
