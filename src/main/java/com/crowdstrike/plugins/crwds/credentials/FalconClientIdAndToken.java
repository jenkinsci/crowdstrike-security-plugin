package com.crowdstrike.plugins.crwds.credentials;

import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.crowdstrike.plugins.crwds.FalconContext;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;
import hudson.util.Secret;
import java.io.IOException;
import java.util.Optional;

import static com.cloudbees.plugins.credentials.CredentialsProvider.findCredentialById;

public interface FalconClientIdAndToken extends StandardUsernamePasswordCredentials {

    @NonNull
    Secret getSecret() throws IOException, InterruptedException;

    @NonNull
    String getClientID();

    class NameProvider extends CredentialsNameProvider<FalconClientIdAndToken>{
        @NonNull
        @Override
        public String getName(FalconClientIdAndToken credentials)
        {
            String description = Util.fixEmptyAndTrim(credentials.getDescription());
            return description != null ? description : credentials.getId();
        }
    }

    static String getSecret(FalconContext context, String FalconCredentialId) throws IOException, InterruptedException {
        return getCredentialsById(context, FalconCredentialId)
                .getSecret()
                .getPlainText();
    }

    static String getClientID(FalconContext context, String FalconCredentialId) throws IOException {
        return getCredentialsById(context, FalconCredentialId)
                .getClientID();
    }

    static FalconClientIdAndToken getCredentialsById(FalconContext context, String FalconCredentialId) throws IOException {
        return Optional.ofNullable(findCredentialById(FalconCredentialId, FalconClientIdAndToken.class, context.getRun()))
                .orElseThrow(() -> new IOException("Falcon client Id and credential Id '" + FalconCredentialId + "' was not found. Please configure the build properly and retry."));
    }
}

