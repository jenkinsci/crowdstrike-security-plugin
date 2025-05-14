package com.crowdstrike.plugins.crwds.credentials;

import com.cloudbees.jenkins.plugins.kubernetes_credentials_provider.CredentialsConvertionException;
import com.cloudbees.jenkins.plugins.kubernetes_credentials_provider.SecretToCredentialConverter;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.Extension;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Converts Kubernetes secrets to CrowdStrike credentials.
 * This converter integrates with the Kubernetes Credentials Provider Plugin to enable
 * automatic creation of CrowdStrike credentials from Kubernetes secrets.
 */
@Extension(optional = true)
public class KubernetesCredentialConverter extends SecretToCredentialConverter {
    private static final Logger LOGGER = Logger.getLogger(KubernetesCredentialConverter.class.getName());
    private static final String CREDENTIALS_TYPE = "com.crowdstrike.plugins.crwds.credentials.CredentialsDefault";
    private static final String CLIENT_ID_FIELD = "clientId";
    private static final String CLIENT_SECRET_FIELD = "clientSecret";
    private static final String DESCRIPTION_ANNOTATION = "jenkins.io/credentials-description";

    @Override
    public boolean canConvert(String type) {
        LOGGER.log(Level.FINE, "Checking if can convert type: {0}", type);
        return CREDENTIALS_TYPE.equals(type);
    }

    @Override
    public IdCredentials convert(io.fabric8.kubernetes.api.model.Secret secret) throws CredentialsConvertionException {
        if (secret == null || secret.getMetadata() == null) {
            throw new CredentialsConvertionException("Secret or its metadata is null");
        }

        String secretName = secret.getMetadata().getName();
        LOGGER.log(Level.FINE, "Converting secret: {0}", secretName);

        try {
            String id = secretName;
            Map<String, String> annotations = secret.getMetadata().getAnnotations();
            String description = annotations != null ? annotations.get(DESCRIPTION_ANNOTATION) : "";

            Map<String, String> data = secret.getData();
            if (data == null) {
                throw new CredentialsConvertionException("Secret data is null for secret: " + secretName);
            }

            // Get clientId
            String clientIdBase64 = Optional.ofNullable(data.get(CLIENT_ID_FIELD))
                    .orElseThrow(() -> new CredentialsConvertionException(
                            String.format("No %s found in secret: %s", CLIENT_ID_FIELD, secretName)));
            String clientId = new String(Base64.getDecoder().decode(clientIdBase64));

            // Get clientSecret
            String clientSecretBase64 = Optional.ofNullable(data.get(CLIENT_SECRET_FIELD))
                    .orElseThrow(() -> new CredentialsConvertionException(
                            String.format("No %s found in secret: %s", CLIENT_SECRET_FIELD, secretName)));
            String clientSecret = new String(Base64.getDecoder().decode(clientSecretBase64));

            LOGGER.log(Level.FINE, "Successfully converted secret: {0}", secretName);

            // Create a wrapper credential that will be converted to CredentialsDefault
            return new CredentialsDefaultWrapper(
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
     * Wrapper class for CredentialsDefault to avoid Secret type issues.
     */
    public static class CredentialsDefaultWrapper extends UsernamePasswordCredentialsImpl
                                                   implements StandardUsernamePasswordCredentials {
        private final String clientId;
        private final String clientSecret;

        public CredentialsDefaultWrapper(CredentialsScope scope, String id, String description,
                                        String clientId, String clientSecret) {
            super(scope, id, description, clientId, clientSecret);
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }

        public String getClientId() {
            return clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        /**
         * Descriptor for CredentialsDefaultWrapper.
         */
        @Extension
        public static class DescriptorImpl extends CredentialsDescriptor {
            @Override
            public String getDisplayName() {
                return "CrowdStrike Credentials (Kubernetes)";
            }
        }
    }
}
