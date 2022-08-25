package com.crowdstrike.plugins.crwds;

import com.crowdstrike.plugins.crwds.configuration.FalconConfiguration;
import com.crowdstrike.plugins.crwds.credentials.FalconClientIdAndToken;
import com.crowdstrike.plugins.crwds.utils.FileUtils;
import com.crowdstrike.plugins.crwds.utils.ProcessCodes;
import hudson.AbortException;

import java.io.IOException;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

public class FalconStepFlow {

    public static void perform(FalconConfiguration config, Supplier<FalconContext> contextSupplier) throws IOException, InterruptedException {
        FalconContext context = contextSupplier.get();
        FalconStepFlow.scan(context, config);
    }

    private static void scan(FalconContext context, FalconConfiguration configuration) throws IOException, InterruptedException {

        String inputImageName = configuration.getImageName();
        String inputImageTag = configuration.getImageTag();
        if(inputImageName.startsWith("$")) {
            inputImageName = context.getEnvVars().get(inputImageName.substring(1), "");
        }

        if(inputImageTag.startsWith("$")) {
            inputImageTag = context.getEnvVars().get(inputImageTag.substring(1), "");
        }

        final String imageName = inputImageName;
        final String imageTag = inputImageTag;
        final int timeout = configuration.getTimeout() == null ? 60 : configuration.getTimeout();

        final String cid = FalconClientIdAndToken.getClientID(context, configuration.getFalconCredentialId());
        final String secret = FalconClientIdAndToken.getSecret(context, configuration.getFalconCredentialId());
        final String authDomain = configuration.getFalconCloud();
        final String artifactName = "crwds_report.html";
        final boolean neverFail = configuration.getEnforce() == false;
        final String uniqueId = FileUtils.getRandomUniqueID();

        if (imageName == null || imageName.trim().equals("") || imageTag == null || imageTag.trim().equals("") || "".equals(cid) || "".equals(secret)) {
            throw new AbortException("[CRWDS::ABORT] " + ProcessCodes.INVALID_CONFIGURATION.getDescription());
        }

        context.getLogger().println("[CRWDS::DEBUG] Initiating CrowdStrike Security assessment for container image: " + imageName + ":" + imageTag + "\n\n");

        context.getLogger().println(
                "                       ..                                                                           \n" +
                "                       .!~.  :^.                                                                    \n" +
                "                        .~7!^.^!~.                                                                  \n" +
                "                        .^^^!7!^^!!~:.                                                              \n" +
                "                         .^!~^~!7!~~7??!^:..                                                        \n" +
                "                            :~!!~~!!~^!YYYJ??!~^:.                                                  \n" +
                "                               .^~!~~~^:?YYYYYYYYJ?7^.                                              \n" +
                "                                   .:^^..7YYYYYYYYYYYJ:                                             \n" +
                "                               .:::.....  ~JYYYYYYYYY?.                                             \n" +
                "                                 .^~!7J?!:.:!?JJJYYYYJ?7!^.                                         \n" +
                "                                    ..:^~~~^^77???JJJJYYYJ?~.                                       \n" +
                "                                           . :7YYYYYJJ7!~^^!~                                       \n" +
                "                                              :!JYYY7^::    .                                       \n" +
                "                                                .::7!..:                                            \n" +
                "                                                    .                                               \n" +
                "     .^7??7~.^7777!^. :~7??7~.:77: ^7~ .!7^.77777!:  ^!777~.!777777^~7777!: :77: !7^.~7!.^77777~    \n" +
                "    .?Y?~^!!.~5Y~!Y5^^YY!^~?Y?:757.J5Y:!5J.:YY!^~YY!.J5J!7~.^^75Y~^.?5?~?5Y.^YY^ ?5??Y7: ~5Y7!!:    \n" +
                "    :YY~  .. ~YY?JY7.!5Y:  ~YY: ?YJY~JJYJ: :YY^ .?5? ^!7?YJ^  ~YJ.  ?YJ?YY^ ^YY^ ?YJJY!. ~YY77~     \n" +
                "     ^?JJJJ?.~YJ.~JJ!.!JJJJJ?^  .JY~ ^JJ^  :JYJ?JJ7..?J??Y?:  ~YJ.  7Y7.?Y! ^YY: ?Y!.7Y?:~YJ???!    \n" +
                "       .::.. .:.  .::  ..::.     ..   ..   ...::..   ..::.    .:..  .:. .::..::. .:.  .:..:::::.\n\n");

        FalconScanner scanner = new FalconScanner();
        AtomicInteger scanResult = new AtomicInteger();
        try {
            /*
             * We are invoking a worker thread that returns an instance of Future using the ExecutorService
             * The future.get() method will raise a TimeoutException after the specified timeout (user entered number on per-job config view)
             */
            ExecutorService executor = Executors.newSingleThreadExecutor();
            Future<?> future = executor.submit(() -> {

                try {
                    scanResult.set(scanner.execute(context, imageName, imageTag, timeout, secret, cid, authDomain, neverFail, artifactName, uniqueId));

                    if (scanResult.get() != ProcessCodes.BUILD_SUCCESS.getCode() && scanResult.get() != ProcessCodes.PREVENT_BUILD_DUE_TO_POLICY.getCode()) {
                        htmlReportGenerationOnFailure(context, scanResult.get(), artifactName);
                    }
                } catch (ExecutionException | IOException | InterruptedException ex) {
                    context.getLogger().println("[CRWDS::DEBUG] " + ex.getMessage());
                }

            });

            try {
                future.get(timeout, TimeUnit.SECONDS);

                if(scanResult.get() == ProcessCodes.PREVENT_BUILD_DUE_TO_POLICY.getCode()) {
                    throw new AbortException(ProcessCodes.PREVENT_BUILD_DUE_TO_POLICY.getDescription());
                }

                if(scanResult.get() < 0) {
                    throw new AbortException("CrowdStrike Security Assessment Failed - " + ProcessCodes.getDescriptionByCode(scanResult.get()));
                }

            } catch (TimeoutException ex) {
                future.cancel(true);
                scanResult.set(ProcessCodes.BUILD_TIMED_OUT.getCode());
                htmlReportGenerationOnFailure(context, scanResult.get(), artifactName);
                throw new AbortException("Aborting due to timeout");
            } catch (Exception ex) {
                throw new AbortException(ex.getMessage());
            } finally {
                executor.shutdown();
            }

        } catch (Exception ex) {
            if(!neverFail) {
                throw new AbortException("[CRWDS::ABORT]" + ex.getMessage() + " Build Status : " + scanResult.get());
            } else {
                context.getLogger().println("[CRWDS::DEBUG] Errors - " + ex.getMessage() + " Build Status : " + scanResult.get());
                context.getTaskListener().getLogger().println("[CRWDS::DEBUG] " + ProcessCodes.PREVENT_BUILD_RECOMMENDATION.getDescription());
            }
        }
    }

    private static void htmlReportGenerationOnFailure(FalconContext falconContext, int scanResult, String artifactName) throws IOException, InterruptedException {

        ReportsGenerator failureReportGenerator = new ReportsGenerator(scanResult);
        String failureHtmlString = failureReportGenerator.generateFailureReport();
        if("failure".equalsIgnoreCase(failureHtmlString)) {
            failureHtmlString = "";
            falconContext.getLogger().println("[CRWDS::DEBUG] " + ProcessCodes.HTML_GENERATION_FAILURE.getDescription());
        }

        FileUtils.createWorkSpaceArtifactAndArchive(falconContext, artifactName, failureHtmlString);

    }
}
