package com.crowdstrike.plugins.crwds;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;

import java.io.IOException;
import java.io.PrintStream;

public class FalconContext {
    private final FilePath workspace;
    private final Launcher launcher;
    private final EnvVars envVars;
    private final Run<?, ?> run;
    private final TaskListener taskListener;

    private FalconContext(
            FilePath workspace,
            Launcher launcher,
            EnvVars envVars,
            Run<?, ?> run,
            TaskListener taskListener
    ) {
        this.workspace = workspace;
        this.launcher = launcher;
        this.envVars = envVars;
        this.run = run;
        this.taskListener = taskListener;
    }

    public FilePath getWorkspace() {
        return workspace;
    }

    public Launcher getLauncher() {
        return launcher;
    }

    public EnvVars getEnvVars() {
        return envVars;
    }

    public Run<?, ?> getRun() {
        return run;
    }

    public TaskListener getTaskListener() {
        return taskListener;
    }

    public PrintStream getLogger() {
        return taskListener.getLogger();
    }

    public static FalconContext forJenkinsProject(Run<?, ?> build, FilePath workspace, Launcher launcher, TaskListener listener) {
        try {
            return new FalconContext(
                    workspace,
                    launcher,
                    build.getEnvironment(listener),
                    build,
                    listener
            );
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
