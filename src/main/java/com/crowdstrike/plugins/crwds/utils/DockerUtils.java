package com.crowdstrike.plugins.crwds.utils;

import com.crowdstrike.plugins.crwds.FalconContext;
import hudson.AbortException;
import hudson.Launcher.ProcStarter;
import hudson.Proc;
import hudson.util.ArgumentListBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class DockerUtils {

    public static Integer dockerLogin(FalconContext context, String username, String password, String csRegistryUrl) {

        ArgumentListBuilder args = new ArgumentListBuilder();

        args.add("docker");
        args.add("login", "--username", username, "--password-stdin").add(csRegistryUrl);

        try {
            InputStream input = new ByteArrayInputStream(password.getBytes(StandardCharsets.UTF_8));
            if(launchProcess(context, args, input) != 0) {
                throw new AbortException("[ABORT] Docker Login - " + ProcessCodes.DOCKER_LOGIN_FAILURE.getDescription());
            }
        } catch(IOException | InterruptedException ex) {
            context.getLogger().println("[CRWDS::DEBUG] Docker Login - " + ex.getMessage());
            return ProcessCodes.DOCKER_LOGIN_FAILURE.getCode();
        }

        context.getLogger().println("[CRWDS::DEBUG] Docker Login - " + ProcessCodes.DOCKER_OPERATION_SUCCESS.getDescription());
        return ProcessCodes.DOCKER_OPERATION_SUCCESS.getCode();
    }

    public static Integer dockerPush(FalconContext context, String csRegistryUrl, String imageName, String imageTag) {

        csRegistryUrl = csRegistryUrl.replace("https://", "");

        final String imageNameTagOnRegistry = csRegistryUrl + "/" + imageName + ":" + imageTag;

        ArgumentListBuilder args = new ArgumentListBuilder();
        args.add("docker").add("push").add(imageNameTagOnRegistry);

        try {
            final Integer dockerTagStatus = dockerTag(context, csRegistryUrl, imageName, imageTag);
            if(dockerTagStatus == ProcessCodes.DOCKER_TAG_FAILURE.getCode()) {
                return ProcessCodes.DOCKER_TAG_FAILURE.getCode();
            }

            if(launchProcess(context, args, null) != 0) {
                throw new AbortException(ProcessCodes.DOCKER_PUSH_FAILURE.getDescription());
            }
        } catch(IOException | InterruptedException ex) {
            context.getLogger().println("[CRWDS::DEBUG] Docker Push - " + ex.getMessage());
            return ProcessCodes.DOCKER_PUSH_FAILURE.getCode();
        }

        context.getLogger().println("[CRWDS::DEBUG] Docker Push - " + ProcessCodes.DOCKER_OPERATION_SUCCESS.getDescription());
        return ProcessCodes.DOCKER_OPERATION_SUCCESS.getCode();
    }

    public static Integer dockerTag(FalconContext context, String csRegistryUrl, String imageName, String imageTag) {

        final String imageNameTag = imageName + ":" + imageTag;

        final String imageNameTagOnRegistry = csRegistryUrl + "/" + imageNameTag;

        ArgumentListBuilder args = new ArgumentListBuilder();
        args.add("docker").add("tag").add(imageNameTag).add(imageNameTagOnRegistry);
        try {
            if (launchProcess(context, args, null) != 0) {
                throw new AbortException("[ABORT] Docker Tag - " + ProcessCodes.DOCKER_TAG_FAILURE.getDescription());
            }
        } catch(IOException | InterruptedException ex) {
            context.getLogger().println("[CRWDS::DEBUG] Docker Tag - " + ex.getMessage());
            return ProcessCodes.DOCKER_TAG_FAILURE.getCode();
        }

        context.getLogger().println("[CRWDS::DEBUG] Docker Tag - " + ProcessCodes.DOCKER_OPERATION_SUCCESS.getDescription());
        return ProcessCodes.DOCKER_OPERATION_SUCCESS.getCode();
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

}
