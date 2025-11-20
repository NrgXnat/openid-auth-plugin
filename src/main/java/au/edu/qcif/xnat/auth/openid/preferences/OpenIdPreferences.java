/*
 * xnat-openid-auth-plugin: au.edu.qcif.xnat.auth.openid.preferences.OpenIdPreferences
 * XNAT http://www.xnat.org
 * Copyright (c) 2017, Washington University School of Medicine
 * All Rights Reserved
 *
 * Released under the Simplified BSD.
 */

package au.edu.qcif.xnat.auth.openid.preferences;

import lombok.extern.slf4j.Slf4j;
import org.nrg.framework.configuration.ConfigPaths;
import org.nrg.framework.utilities.OrderedProperties;
import org.nrg.prefs.annotations.NrgPreferenceBean;
import org.nrg.prefs.beans.AbstractPreferenceBean;
import org.nrg.prefs.exceptions.InvalidPreferenceName;
import org.nrg.prefs.services.NrgPreferenceService;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Manages persistent settings for OpenID authentication.
 * Encryption keys are stored in the XNAT database and automatically shared across all nodes
 * in load-balanced environments.
 */
@NrgPreferenceBean(toolId = OpenIdPreferences.OPENID_TOOL_ID,
                   toolName = "OpenID Authentication",
                   description = "Manages settings for OpenID authentication",
                   strict = false)
@Slf4j
@SuppressWarnings("unused")
public class OpenIdPreferences extends AbstractPreferenceBean {
    public static final String OPENID_TOOL_ID = "openid";
    public static final String INVALID_PREFERENCE_NAME_TEMPLATE = "Invalid preference name {}: something is very wrong here.";

    // Preference key prefix for JWK storage
    private static final String JWK_PREFIX = "jwk-";

    @Autowired
    public OpenIdPreferences(final NrgPreferenceService preferenceService,
                             final ConfigPaths configPaths,
                             final OrderedProperties initPrefs) {
        super(preferenceService, configPaths, initPrefs);
    }

    /**
     * Retrieves the JWK (JSON Web Key) for the specified algorithm.
     *
     * @param algorithm The JWE algorithm (e.g., "RSA-OAEP-256")
     * @return The JWK as a JSON string, or null if not found
     */
    public String getJwk(final String algorithm) {
        if (algorithm == null || algorithm.trim().isEmpty()) {
            log.warn("Attempted to get JWK with null or empty algorithm");
            return null;
        }
        final String key = getPreferenceKey(algorithm);
        return getValue(key);
    }

    /**
     * Stores the JWK (JSON Web Key) for the specified algorithm.
     *
     * @param algorithm The JWE algorithm (e.g., "RSA-OAEP-256")
     * @param jwkJson The JWK as a JSON string
     * @throws IllegalArgumentException if algorithm or jwkJson is null or empty
     */
    public void setJwk(final String algorithm, final String jwkJson) {
        if (algorithm == null || algorithm.trim().isEmpty()) {
            throw new IllegalArgumentException("Algorithm cannot be null or empty");
        }
        if (jwkJson == null || jwkJson.trim().isEmpty()) {
            throw new IllegalArgumentException("JWK JSON cannot be null or empty for algorithm: " + algorithm);
        }
        final String key = getPreferenceKey(algorithm);
        safeSet(jwkJson, key);
        log.info("Stored JWK for algorithm: {}", algorithm);
    }

    /**
     * Checks if a JWK exists for the specified algorithm.
     *
     * @param algorithm The JWE algorithm (e.g., "RSA-OAEP-256")
     * @return true if a JWK exists for this algorithm, false otherwise
     */
    public boolean hasJwk(final String algorithm) {
        if (algorithm == null || algorithm.trim().isEmpty()) {
            return false;
        }
        final String jwk = getJwk(algorithm);
        return jwk != null && !jwk.trim().isEmpty();
    }

    /**
     * Generates the preference key for storing a JWK.
     *
     * @param algorithm The JWE algorithm (e.g., "RSA-OAEP-256")
     * @return The preference key (e.g., "jwk-RSA-OAEP-256")
     */
    private String getPreferenceKey(final String algorithm) {
        return JWK_PREFIX + algorithm;
    }

    /**
     * Helper method to safely set a string value.
     */
    private void safeSet(final String value, final String name) {
        try {
            set(value, name);
        } catch (InvalidPreferenceName e) {
            log.error(INVALID_PREFERENCE_NAME_TEMPLATE, name, e);
        }
    }
}
