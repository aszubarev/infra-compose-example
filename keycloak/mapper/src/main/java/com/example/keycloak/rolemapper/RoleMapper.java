package com.example.keycloak.rolemapper;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Custom protocol mapper: fetches the user's roles from an external role
 * service on every token issuance and injects them as a claim.
 *
 * Keycloak does NOT manage roles here — the role service is the single source
 * of truth. The lookup key is the username (unique per realm).
 *
 * Failure policy: if the role service is unreachable / returns non-200 / the
 * response is malformed, no roles are injected (empty list). That is
 * fail-closed for authorization: a token without roles grants no role-based
 * access, but authentication (login) still succeeds.
 */
public class RoleMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper {

    private static final Logger LOG = Logger.getLogger(RoleMapper.class);

    public static final String PROVIDER_ID = "custom-role-mapper";
    private static final String CONFIG_ROLE_SERVICE_URL = "role-service-url";
    private static final String CONFIG_CLAIM_NAME = "claim-name";
    private static final String DEFAULT_CLAIM_NAME = "roles";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty url = new ProviderConfigProperty();
        url.setName(CONFIG_ROLE_SERVICE_URL);
        url.setLabel("Role service base URL");
        url.setType(ProviderConfigProperty.STRING_TYPE);
        url.setHelpText("Base URL of the role service, e.g. http://role-service:8080");
        CONFIG_PROPERTIES.add(url);

        ProviderConfigProperty claim = new ProviderConfigProperty();
        claim.setName(CONFIG_CLAIM_NAME);
        claim.setLabel("Token claim name");
        claim.setType(ProviderConfigProperty.STRING_TYPE);
        claim.setDefaultValue(DEFAULT_CLAIM_NAME);
        claim.setHelpText("Token claim that receives the user's roles");
        CONFIG_PROPERTIES.add(claim);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Roles from external service";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Fetches the user's roles from an external role service on each "
                + "token issuance and adds them as a claim.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
                            KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        String serviceUrl = mappingModel.getConfig().get(CONFIG_ROLE_SERVICE_URL);
        String claimName = mappingModel.getConfig().getOrDefault(CONFIG_CLAIM_NAME, DEFAULT_CLAIM_NAME);
        String username = userSession.getUser().getUsername();

        List<String> roles = fetchRoles(serviceUrl, username);
        token.getOtherClaims().put(claimName, roles);
        LOG.debugf("Injected roles %s for user %s", roles, username);
    }

    private List<String> fetchRoles(String serviceUrl, String username) {
        if (serviceUrl == null || serviceUrl.isBlank()) {
            LOG.warnf("Role mapper: role-service-url is not configured; injecting no roles");
            return Collections.emptyList();
        }
        String url = serviceUrl + "/users/" + URLEncoder.encode(username, StandardCharsets.UTF_8) + "/roles";
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(2))
                    .build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(3))
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                LOG.warnf("Role service returned HTTP %d for user %s; injecting no roles",
                        response.statusCode(), username);
                return Collections.emptyList();
            }
            return parseRoles(response.body());
        } catch (Exception e) {
            LOG.warnf(e, "Failed to fetch roles for user %s from %s; injecting no roles", username, url);
            return Collections.emptyList();
        }
    }

    /**
     * Minimal parser for {@code {"roles":["a","b"]}} to avoid a JSON dependency
     * in the provider JAR. The response format is under our control.
     */
    private List<String> parseRoles(String body) {
        if (body == null) {
            return Collections.emptyList();
        }
        try {
            int idx = body.indexOf("\"roles\"");
            if (idx < 0) {
                return Collections.emptyList();
            }
            idx = body.indexOf('[', idx);
            if (idx < 0) {
                return Collections.emptyList();
            }
            int end = body.indexOf(']', idx);
            if (end < 0) {
                return Collections.emptyList();
            }
            String inner = body.substring(idx + 1, end);
            List<String> roles = new ArrayList<>();
            for (String part : inner.split(",")) {
                String v = part.trim();
                if (v.length() >= 2 && v.startsWith("\"") && v.endsWith("\"")) {
                    v = v.substring(1, v.length() - 1);
                }
                if (!v.isEmpty()) {
                    roles.add(v);
                }
            }
            return roles;
        } catch (Exception e) {
            LOG.warnf(e, "Failed to parse role service response: %s", body);
            return Collections.emptyList();
        }
    }
}
