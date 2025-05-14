package com.crowdstrike.plugins.crwds.credentials;

import com.cloudbees.jenkins.plugins.kubernetes_credentials_provider.CredentialsConvertionException;
import com.cloudbees.jenkins.plugins.kubernetes_credentials_provider.SecretToCredentialConverter;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import hudson.Extension;
import io.fabric8.kubernetes.api.model.Secret;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Converts Kubernetes secrets to CrowdStrike credentials.
 * <p>
 * This converter integrates with the Kubernetes Credentials Provider Plugin to enable
 * automatic creation of CrowdStrike credentials from Kubernetes secrets. It looks for
 * secrets with the type {@code com.crowdstrike.plugins.crwds.credentials.CredentialsDefault}
 * and extracts the client ID and client secret to create CrowdStrike credentials in Jenkins.
 * </p>
 * <p>
 * Example Kubernetes secret:
 * </p>
 * <pre>
 * apiVersion: v1
 * kind: Secret
 * metadata:
 *   name: crowdstrike-creds
 *   annotations:
 *     jenkins.io/credentials-description: "CrowdStrike API Credentials"
 *     jenkins.io/credentials-type: "com.crowdstrike.plugins.crwds.credentials.CredentialsDefault"
 * type: Opaque
 * data:
 *   clientId: &lt;base64-encoded-client-id&gt;
 *   clientSecret: &lt;base64-encoded-client-secret&gt;
 * </pre>
 *
 * @since 1.0
 */
@Extension(optional = true)
public class KubernetesCredentialConverter extends SecretToCredentialConverter {
    private static final Logger LOGGER = Logger.getLogger(KubernetesCredentialConverter.class.getName());

    /** The credential type this converter handles */
    private static final String CREDENTIALS_TYPE = "com.crowdstrike.plugins.crwds.credentials.CredentialsDefault";

    /** Field name for client ID in the Kubernetes secret */
    private static final String CLIENT_ID_FIELD = "clientId";

    /** Field name for client secret in the Kubernetes secret */
    private static final String CLIENT_SECRET_FIELD = "clientSecret";

    /** Annotation key for credential description */
    private static final String DESCRIPTION_ANNOTATION = "jenkins.io/credentials-description";

    /**
     * Determines if this converter can convert the given credential type.
     *
     * @param type The credential type to check
     * @return true if this converter can handle the given type
     */
    @Override
    public boolean canConvert(String type) {
        LOGGER.log(Level.FINE, "Checking if can convert type: {0}", type);
        return CREDENTIALS_TYPE.equals(type);
    }

    /**
     * Converts a Kubernetes secret to a Jenkins credential.
     *
     * @param secret The Kubernetes secret to convert
     * @return The converted Jenkins credential
     * @throws CredentialsConvertionException if the conversion fails
     */
    @Override
    public IdCredentials convert(Secret secret) throws CredentialsConvertionException {
        validateSecret(secret);

        String secretName = secret.getMetadata().getName();
        LOGGER.log(Level.FINE, "Converting secret: {0}", secretName);

        try {
            // Extract basic information from the secret
            String id = secretName;
            String description = getDescription(secret);
            Map<String, String> data = getSecretData(secret);

            // Extract credential-specific information
            String clientId = decodeSecretField(data, CLIENT_ID_FIELD, secretName);
            String clientSecret = decodeSecretField(data, CLIENT_SECRET_FIELD, secretName);

            LOGGER.log(Level.FINE, "Successfully converted secret: {0}", secretName);

            // Create an actual CredentialsDefault instance
            return new CredentialsDefault(
                CredentialsScope.GLOBAL,
                id,
                description,
                clientId,
                clientSecret
            );
        } catch (IllegalArgumentException e) {
            LOGGER.log(Level.WARNING, "Invalid base64 encoding in secret: {0}", secretName);
            throw new CredentialsConvertionException("Invalid base64 encoding in secret: " + e.getMessage());
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to convert secret: {0}", e.getMessage());
            throw new CredentialsConvertionException("Failed to convert credentials: " + e.getMessage());
        }
    }

    /**
     * Validates that the secret and its metadata are not null.
     *
     * @param secret The secret to validate
     * @throws CredentialsConvertionException if the secret or its metadata is null
     */
    private void validateSecret(Secret secret) throws CredentialsConvertionException {
        if (secret == null || secret.getMetadata() == null) {
            throw new CredentialsConvertionException("Secret or its metadata is null");
        }
    }

    /**
     * Gets the description from the secret's annotations.
     *
     * @param secret The secret containing the description
     * @return The description, or an empty string if not found
     */
    private String getDescription(Secret secret) {
        Map<String, String> annotations = secret.getMetadata().getAnnotations();
        return annotations != null ?
               Optional.ofNullable(annotations.get(DESCRIPTION_ANNOTATION)).orElse("") :
               "";
    }

    /**
     * Gets the secret data and validates it's not null.
     *
     * @param secret The secret containing the data
     * @return The secret data
     * @throws CredentialsConvertionException if the data is null
     */
    private Map<String, String> getSecretData(Secret secret) throws CredentialsConvertionException {
        Map<String, String> data = secret.getData();
        if (data == null) {
            throw new CredentialsConvertionException(
                "Secret data is null for secret: " + secret.getMetadata().getName());
        }
        return data;
    }

    /**
     * Decodes a field from the secret data.
     *
     * @param data The secret data
     * @param fieldName The name of the field to decode
     * @param secretName The name of the secret (for error reporting)
     * @return The decoded field value
     * @throws CredentialsConvertionException if the field is not found
     */
    private String decodeSecretField(Map<String, String> data, String fieldName, String secretName)
            throws CredentialsConvertionException {
        String encodedValue = Optional.ofNullable(data.get(fieldName))
                .orElseThrow(() -> new CredentialsConvertionException(
                        String.format("No %s found in secret: %s", fieldName, secretName)));
        return new String(Base64.getDecoder().decode(encodedValue));
    }
}
