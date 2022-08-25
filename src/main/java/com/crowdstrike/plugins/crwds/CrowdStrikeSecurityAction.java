package com.crowdstrike.plugins.crwds;

import hudson.model.Run;
import jenkins.model.RunAction2;

public class CrowdStrikeSecurityAction implements RunAction2 {
    
    private transient Run<?, ?> run;

    private final String resultUrl;

    private final String urlSuffix;

    public CrowdStrikeSecurityAction(String artifactName, String urlSuffix) {
        this.resultUrl = "../artifact/" + artifactName;
        this.urlSuffix = urlSuffix;
    }

    @Override
    public String getIconFileName() {
        return "/plugin/crowdstrike-security-plugin/images/CICD_Icon.png";
    }

    @Override
    public String getDisplayName() {
        return "CrowdStrike Security";
    }

    @Override
    public String getUrlName() {
        return "crowdstrike-security-report-" + this.urlSuffix;
    }

    @Override
    public void onAttached(Run<?, ?> run) {
        this.run = run;
    }

    @Override
    public void onLoad(Run<?, ?> run) {
        this.run = run;
    }

    public Run<?, ?> getRun() {
        return this.run;
    }

    public String getResultUrl() {
        return this.resultUrl;
    }

}