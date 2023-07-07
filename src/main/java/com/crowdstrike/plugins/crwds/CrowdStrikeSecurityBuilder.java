package com.crowdstrike.plugins.crwds;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.crowdstrike.plugins.crwds.configuration.DescriptorConfiguration;
import com.crowdstrike.plugins.crwds.configuration.FalconConfiguration;
import com.crowdstrike.plugins.crwds.credentials.FalconClientIdAndToken;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.*;

import java.io.IOException;

public class CrowdStrikeSecurityBuilder extends Builder implements SimpleBuildStep, FalconConfiguration {

    private boolean enforce;

    private boolean skipImageUpload;

    private String imageName;

    private String imageTag;

    private Integer timeout;

    @DataBoundConstructor
    public CrowdStrikeSecurityBuilder(String imageName, String imageTag, boolean enforce, boolean skipImageUpload, Integer timeout){
        this.imageName = imageName;
        this.imageTag = imageTag;
        this.enforce = enforce;
        this.skipImageUpload = skipImageUpload;
        this.timeout = timeout;
    }

    public boolean getEnforce() { return enforce; }

    public boolean getSkipImageUpload() { return skipImageUpload; }

    public String getImageName() { return imageName; }

    public String getImageTag() { return imageTag; }

    public Integer getTimeout() { return timeout; }

    @DataBoundSetter
    public void setImageName(String imageName) {
        this.imageName = imageName;
    }

    @DataBoundSetter
    public void setImageTag(String imageTag) {
        this.imageTag = imageTag;
    }
    @DataBoundSetter
    public void setEnforce(boolean enforce) {
        this.enforce = enforce;
    }

    @DataBoundSetter
    public void setSkipImageUpload(boolean skipImageUpload) {
        this.skipImageUpload = skipImageUpload;
    }

    @DataBoundSetter
    public void setTimeout(Integer timeout) {
        this.timeout = timeout;
    }

    @Override
    public FalconStepBuilderDescriptor getDescriptor() {
        return (FalconStepBuilderDescriptor) super.getDescriptor();
    }

    @Override
    public String getFalconCloud() {
        return getDescriptor().getFalconCloud();
    }

    @Override
    public String getFalconCredentialId() {
        return getDescriptor().getFalconCredentialId();
    }

    // Below function is used by config.jelly to display the current status(values) in the per-build configuration page
    public boolean getValueOfNonCompliance(boolean currentState) {

        return this.enforce == currentState;

    }

    // This is the starting point of the build process
    @Override
    public void perform(@NonNull Run<?, ?> run, @NonNull FilePath workspace, @NonNull EnvVars env, @NonNull Launcher launcher, @NonNull TaskListener listener) throws IOException, InterruptedException {
        FalconStepFlow.perform(this, () -> FalconContext.forJenkinsProject(run, workspace, launcher, listener));
    }

    @Symbol("crowdStrikeSecurity")
    @Extension
    public static final class FalconStepBuilderDescriptor extends BuildStepDescriptor<Builder> implements DescriptorConfiguration {

        private String falconCloud;

        private String falconCredentialId;

        public FalconStepBuilderDescriptor() {
            load();
        }

        public FormValidation doCheckImageName(@QueryParameter String value)
        {
            if(value.matches("^\\$?[a-zA-Z\\d]+(?:[._-]{1,2}[a-zA-Z\\d]+)*") && value.length() < 4096)
                return FormValidation.ok();
            else
                return FormValidation.warning("Image Name is required. Please check Helper Texts(?) for details.");
        }

        public FormValidation doCheckImageTag(@QueryParameter String value)
        {
            if(value.matches("^\\$?[a-zA-Z\\d_.-]{1,127}"))
                return FormValidation.ok();
            else
                return FormValidation.warning("Image Tag is required. Please check Helper Texts(?) for details.");
        }

        public FormValidation doCheckTimeout(@QueryParameter String value) {
            try{
                int number = Integer.parseInt(value);
                if(number < 1 || number > 1799){
                    return FormValidation.warning("Timeout is required. Please check Helper Texts(?) for details.");
                }
                else{
                    return FormValidation.ok();
                }
            }
            catch (NumberFormatException e) {
                return FormValidation.warning("Timeout is required. Please check Helper Texts(?) for details.");
            }
        }

        /**
        Below method is used for configuring, reading/loading global config values
         */
        @Override
        public boolean configure(StaplerRequest request, JSONObject formData) throws FormException {
            request.bindJSON(this, formData);
            save();
            return super.configure(request, formData);
        }

        public ListBoxModel doFillFalconCloudItems() {
            ListBoxModel items = new ListBoxModel();

            items.add("us-1.crowdstrike.com", "us-1.crowdstrike.com");
            items.add("eu-1.crowdstrike.com", "eu-1.crowdstrike.com");
            items.add("us-2.crowdstrike.com", "us-2.crowdstrike.com");
            items.add("laggar.gcw.crowdstrike.com", "laggar.gcw.crowdstrike.com");
            items.add("us-gov-2.crowdstrike.com", "us-gov-2.crowdstrike.com");

            return items;
        }

        public String getFalconCloud() {
            return falconCloud;
        }

        public String getFalconCredentialId() { return falconCredentialId; }

        @DataBoundSetter
        public void setFalconCloud(String falconCloud) {
            this.falconCloud = falconCloud;
        }

        @DataBoundSetter
        public void setFalconCredentialId(String falconCredentialId) {
            this.falconCredentialId = falconCredentialId;
        }

        public ListBoxModel doFillFalconCredentialIdItems(@AncestorInPath Item item, @QueryParameter String falconCredentialId) {
            StandardListBoxModel model = new StandardListBoxModel();
            if (item == null) {
                Jenkins jenkins = Jenkins.get();
                if (!jenkins.hasPermission(Jenkins.ADMINISTER)) {
                    return model.includeCurrentValue(falconCredentialId);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ) && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return model.includeCurrentValue(falconCredentialId);
                }
            }
            return model.includeEmptyValue()
                    .includeAs(ACL.SYSTEM, item, FalconClientIdAndToken.class)
                    .includeCurrentValue(falconCredentialId);
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @NonNull
        @Override
        public String getDisplayName() {
            return "CrowdStrike Security Plugin";
        }

    }

}
