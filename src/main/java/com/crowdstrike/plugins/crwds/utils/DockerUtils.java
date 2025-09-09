package com.crowdstrike.plugins.crwds.utils;

import com.crowdstrike.plugins.crwds.FalconContext;
import hudson.*;
import hudson.Launcher.ProcStarter;
import hudson.model.TaskListener;
import hudson.util.ArgumentListBuilder;

import java.awt.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class DockerUtils {

    public enum ContainerRuntime{
        DOCKER("docker"),
        PODMAN("podman");

        private final String executable;

        ContainerRuntime(String executable) {
            this.executable = executable;
        }

        public String getExecutable() {
            return executable;
        }
    }

    private final ContainerRuntime runtime;

    public DockerUtils(){
        this(ContainerRuntime.DOCKER);
    }

    public DockerUtils(ContainerRuntime runtime){
        this.runtime = runtime;
    }

    public static boolean isRuntimeAvailable(ContainerRuntime runtime, EnvVars env, FilePath workspace, Launcher launcher, TaskListener listener) throws IOException, InterruptedException{
        try{
            ArgumentListBuilder args = new ArgumentListBuilder();
            args.add(runtime.getExecutable()).add("--version");
            int exitCode = launcher.launch().cmds(args).envs(env).stdout(listener).pwd(workspace).join();
            return exitCode == 0;
        }catch (Exception e){
            return false;
        }
    }

    public Integer containerLogin(FalconContext context, String username, String password, String csRegistryUrl) {

        context.getLogger().println("[CRWDS::DEBUG] === Container Login Debug ===");
        context.getLogger().println("[CRWDS::DEBUG] Runtime executable: " + runtime.getExecutable());

        ArgumentListBuilder args = new ArgumentListBuilder();

        args.add(runtime.getExecutable());
        args.add("login", "--username", username, "--password-stdin").add(csRegistryUrl);

        try {
            InputStream input = new ByteArrayInputStream(password.getBytes(StandardCharsets.UTF_8));
            if(launchProcess(context, args, input) != 0) {
                String errorMsg = runtime == ContainerRuntime.DOCKER ? "[ABORT] Docker Login - " + ProcessCodes.DOCKER_LOGIN_FAILURE.getDescription() : "[ABORT] Podman Login - " + ProcessCodes.PODMAN_LOGIN_FAILURE.getDescription();
                throw new AbortException(errorMsg);
            }
        } catch(IOException | InterruptedException ex) {
            context.getLogger().println("[CRWDS::DEBUG] " + runtime.getExecutable() + " Login -" + ex.getMessage());
            return runtime == ContainerRuntime.DOCKER ? ProcessCodes.DOCKER_LOGIN_FAILURE.getCode() : ProcessCodes.PODMAN_LOGIN_FAILURE.getCode();
        }

        context.getLogger().println("[CRWDS::DEBUG] " + runtime.getExecutable() + " Login -" + ProcessCodes.DOCKER_OPERATION_SUCCESS.getDescription());
        return ProcessCodes.DOCKER_OPERATION_SUCCESS.getCode();
    }

    public Integer containerPush(FalconContext context, String csRegistryUrl, String imageName, String imageTag) {

        csRegistryUrl = csRegistryUrl.replace("https://", "");

        final String imageNameTagOnRegistry = csRegistryUrl + "/" + imageName + ":" + imageTag;

        ArgumentListBuilder args = new ArgumentListBuilder();
        args.add(runtime.getExecutable()).add("push").add(imageNameTagOnRegistry);

        try {
            final Integer containerTagStatus = containerTag(context, csRegistryUrl, imageName, imageTag);
            if(containerTagStatus != ProcessCodes.DOCKER_OPERATION_SUCCESS.getCode()) {
                return containerTagStatus;
            }

            if(launchProcess(context, args, null) != 0) {
                String errorMsg = runtime == ContainerRuntime.DOCKER ? ProcessCodes.DOCKER_PUSH_FAILURE.getDescription() : ProcessCodes.PODMAN_PUSH_FAILURE.getDescription();
                throw new AbortException(errorMsg);
            }
        } catch(IOException | InterruptedException ex) {
            context.getLogger().println("[CRWDS::DEBUG] " + runtime.getExecutable() + " Push -" + ex.getMessage());
            return runtime == ContainerRuntime.DOCKER ? ProcessCodes.DOCKER_PUSH_FAILURE.getCode() : ProcessCodes.PODMAN_PUSH_FAILURE.getCode();
        }

        context.getLogger().println("[CRWDS::DEBUG] " + runtime.getExecutable() + " Push -" + ProcessCodes.DOCKER_OPERATION_SUCCESS.getDescription());
        return ProcessCodes.DOCKER_OPERATION_SUCCESS.getCode();
    }

    public Integer containerTag(FalconContext context, String csRegistryUrl, String imageName, String imageTag) {

        final String imageNameTag = imageName + ":" + imageTag;

        final String imageNameTagOnRegistry = csRegistryUrl + "/" + imageNameTag;

        ArgumentListBuilder args = new ArgumentListBuilder();
        args.add(runtime.getExecutable()).add("tag").add(imageNameTag).add(imageNameTagOnRegistry);
        try {
            if (launchProcess(context, args, null) != 0) {
                String errorMsg = runtime == ContainerRuntime.DOCKER ? "[ABORT] Docker Tag - " + ProcessCodes.DOCKER_TAG_FAILURE.getDescription() : "[ABORT] Podman Tag - " + ProcessCodes.PODMAN_TAG_FAILURE.getDescription();
                throw new AbortException(errorMsg);
            }
        } catch(IOException | InterruptedException ex) {
            context.getLogger().println("[CRWDS::DEBUG] " + runtime.getExecutable() + " Tag -" + ex.getMessage());
            return runtime == ContainerRuntime.DOCKER ? ProcessCodes.DOCKER_TAG_FAILURE.getCode() : ProcessCodes.PODMAN_TAG_FAILURE.getCode();
        }

        context.getLogger().println("[CRWDS::DEBUG] " + runtime.getExecutable() + " Tag -" + ProcessCodes.DOCKER_OPERATION_SUCCESS.getDescription());
        return ProcessCodes.DOCKER_OPERATION_SUCCESS.getCode();
    }

    // Legacy static methods: dockerLogin, dockerPush, dockerTag maintained for backward compatibility
    public static Integer dockerLogin(FalconContext context, String username, String password, String csRegistryUrl) {
        DockerUtils dockerUtils = new DockerUtils(ContainerRuntime.DOCKER);
        return dockerUtils.containerLogin(context, username, password, csRegistryUrl);
    }

    public static Integer dockerPush(FalconContext context, String csRegistryUrl, String imageName, String imageTag) {
        DockerUtils dockerUtils = new DockerUtils(ContainerRuntime.DOCKER);
        return dockerUtils.containerPush(context, csRegistryUrl, imageName, imageTag);
    }

    public static Integer dockerTag(FalconContext context, String csRegistryUrl, String imageName, String imageTag) {
        DockerUtils dockerUtils = new DockerUtils(ContainerRuntime.DOCKER);
        return dockerUtils.containerTag(context, csRegistryUrl, imageName, imageTag);
    }

    private static int launchProcess(FalconContext context, ArgumentListBuilder cmds, InputStream input) throws IOException, InterruptedException {
        ProcStarter ps = context.getLauncher().new ProcStarter();
        ps = ps.cmds(cmds).stdout(context.getTaskListener());
        ps = ps.pwd(context.getWorkspace()).envs(context.getEnvVars());
        if (input != null) {
            ps = ps.stdin(input);
        }
        Proc proc = context.getLauncher().launch(ps);
        return proc.join();
    }

    public ContainerRuntime getRuntime() {
        return runtime;
    }

    public String getRuntimeName(){
        return runtime.getExecutable();
    }

}
