package com.crowdstrike.plugins.crwds;

import hudson.model.Run;
import jenkins.model.RunAction2;
import jenkins.util.VirtualFile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

public class CrowdStrikeSecurityAction implements RunAction2 {

    private transient Run<?, ?> run;

    private final String artifactName;

    private final String urlSuffix;

    public CrowdStrikeSecurityAction(String artifactName, String urlSuffix, Run<?, ?> run) {
        this.artifactName = artifactName;
        this.urlSuffix = urlSuffix;
        this.run = run;
    }

    @Override
    public String getIconFileName() {
        return "/plugin/crowdstrike-security/images/CICD_Icon.png";
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

    @SuppressWarnings("unused")
    public String getArtifactContent() {
        VirtualFile artifact = getArtifact(artifactName);
        return readFile(artifact);
    }

    private String readFile(VirtualFile file) {
        try (
                InputStream is = file.open();
                InputStreamReader isr = new InputStreamReader(is, StandardCharsets.UTF_8);
                BufferedReader br = new BufferedReader(isr)
        ) {
            return br.lines().collect(Collectors.joining("\n"));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private VirtualFile getArtifact(String filename) {
        return run.getArtifacts().stream()
                .filter(a -> a.getFileName().equals(filename))
                .map(a -> run.getArtifactManager().root().child(a.relativePath))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Could not find artifact."));
    }

}