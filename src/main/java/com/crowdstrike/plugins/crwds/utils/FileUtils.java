package com.crowdstrike.plugins.crwds.utils;

import com.crowdstrike.plugins.crwds.FalconContext;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.ArtifactArchiver;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.UUID;

import static java.nio.charset.StandardCharsets.UTF_8;

public class FileUtils {

    public static String fileRead(String filepath) {
        try {
            return new String(Files.readAllBytes(Paths.get(filepath)), StandardCharsets.UTF_8);
        } catch (Exception ex) {
            return "";
        }
    }

    public static void createWorkSpaceArtifactAndArchive(FalconContext falconContext, String artifactName, String artifactData) throws IOException, InterruptedException {
        FilePath stdoutPath = falconContext.getWorkspace().child(artifactName);
        stdoutPath.write(artifactData, UTF_8.name());
        archiveReport(falconContext, stdoutPath);
    }

    private static void archiveReport(FalconContext context, FilePath report) throws IOException, InterruptedException {
        Run<?, ?> run = context.getRun();
        FilePath workspace = context.getWorkspace();
        Launcher launcher = context.getLauncher();
        EnvVars envVars = context.getEnvVars();
        TaskListener listener = context.getTaskListener();
        new ArtifactArchiver(report.getName())
                .perform(run, workspace, envVars, launcher, listener);
    }

    public static String getRandomUniqueID() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 6);
    }

}
