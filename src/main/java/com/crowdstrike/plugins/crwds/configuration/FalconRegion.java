package com.crowdstrike.plugins.crwds.configuration;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Falcon regions and their API Gateway base URLs.
 *
 * <p>The {@code falconCloud} config field stores a region slug (e.g. {@code us-1}). Older configs
 * stored the full cloud domain (e.g. {@code us-1.crowdstrike.com}); those values still resolve.
 */
public final class FalconRegion {

    private FalconRegion() {
    }

    /** Region slug -> API Gateway base URL. Add or update a region here. */
    private static final Map<String, String> API_BASE_URL_BY_REGION;

    /** Legacy cloud domain -> region slug, for backward compatibility with saved configs. */
    private static final Map<String, String> REGION_BY_LEGACY_DOMAIN;

    static {
        Map<String, String> apiBaseUrls = new LinkedHashMap<>();
        apiBaseUrls.put("us-1", "https://api.crowdstrike.com");
        apiBaseUrls.put("us-2", "https://api.us-2.crowdstrike.com");
        apiBaseUrls.put("us-3", "https://api.us-3.crowdstrike.com");
        apiBaseUrls.put("eu-1", "https://api.eu-1.crowdstrike.com");
        apiBaseUrls.put("us-gov-1", "https://api.laggar.gcw.crowdstrike.com");
        apiBaseUrls.put("us-gov-2", "https://api.us-gov-2.crowdstrike.mil");
        apiBaseUrls.put("sa-1", "https://api.sa-1.crowdstrike.com");
        API_BASE_URL_BY_REGION = Collections.unmodifiableMap(apiBaseUrls);

        Map<String, String> legacyDomains = new HashMap<>();
        legacyDomains.put("us-1.crowdstrike.com", "us-1");
        legacyDomains.put("us-2.crowdstrike.com", "us-2");
        legacyDomains.put("eu-1.crowdstrike.com", "eu-1");
        legacyDomains.put("laggar.gcw.crowdstrike.com", "us-gov-1");
        legacyDomains.put("us-gov-2.crowdstrike.com", "us-gov-2");
        REGION_BY_LEGACY_DOMAIN = Collections.unmodifiableMap(legacyDomains);
    }

    /**
     * Resolves a stored config value (region slug or legacy cloud domain) to an API Gateway base URL.
     *
     * @param value the stored {@code falconCloud} value
     * @return the API Gateway base URL, or {@code null} if the value is not a recognized region
     */
    public static String resolveApiBaseUrl(String value) {
        if (value == null) {
            return null;
        }
        final String normalized = value.trim().toLowerCase(Locale.ROOT);
        final String region = REGION_BY_LEGACY_DOMAIN.getOrDefault(normalized, normalized);
        return API_BASE_URL_BY_REGION.get(region);
    }
}
