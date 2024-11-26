package com.crowdstrike.plugins.crwds.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.Secret;
import org.kohsuke.stapler.DataBoundConstructor;

public class CredentialsDefault extends BaseStandardCredentials implements FalconClientIdAndToken {

    private static final long serialVersionUID = 1L;

    private final String clientID;

    private final Secret secret;

    @DataBoundConstructor
    public CredentialsDefault(
            @CheckForNull CredentialsScope scope,
            @CheckForNull String id,
            @CheckForNull String description,
            @NonNull String clientID,
            @NonNull String secret
    ) {
        super(scope, id, description);
        this.clientID = clientID;
        this.secret = Secret.fromString(secret);
    }


    @NonNull
    @Override
    public String getClientID() {
        return clientID;
    }

    @NonNull
    @Override
    public Secret getSecret(){
        return secret;
    }

    @NonNull
    @Override
    public String getUsername() {
        return "cs-user";
    }

    @Override
    public boolean isUsernameSecret() {
        return FalconClientIdAndToken.super.isUsernameSecret();
    }

    @NonNull
    @Override
    public Secret getPassword() {
        return secret;
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @NonNull
        @Override
        public String getDisplayName() {
            return "CrowdStrike Falcon API";
        }
    }
}