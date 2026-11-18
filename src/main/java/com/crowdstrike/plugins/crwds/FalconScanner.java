package com.crowdstrike.plugins.crwds;

import com.crowdstrike.plugins.crwds.configuration.FalconRegion;
import com.crowdstrike.plugins.crwds.freemarker.AssessmentData;
import com.crowdstrike.plugins.crwds.freemarker.PolicyData;
import com.crowdstrike.plugins.crwds.utils.DockerUtils;
import com.crowdstrike.plugins.crwds.utils.FileUtils;
import com.crowdstrike.plugins.crwds.utils.ProcessCodes;
import com.google.gson.Gson;
import hudson.AbortException;
import hudson.model.Run;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

public class FalconScanner {

    public int execute(FalconContext falconContext, String imageName, String imageTag, Integer timeout, String clientSecret,
                       String clientId, String authDomain, Boolean neverFail, Boolean skipImageUpload, String artifactName, String uniqueId, String containerRuntime) throws IOException, InterruptedException, ExecutionException, NullPointerException {

        int BUILD_STATUS = ProcessCodes.BUILD_SUCCESS.getCode();

        // API base URLs now point to the Falcon API Gateway instead of the deprecated container-upload.* hosts.
        final String apiBaseUrl = FalconRegion.resolveApiBaseUrl(authDomain);
        if (apiBaseUrl == null) {
            falconContext.getLogger().println("[CRWDS::DEBUG] " + ProcessCodes.INVALID_CONFIGURATION.getDescription());
            return ProcessCodes.INVALID_CONFIGURATION.getCode();
        }

        final String registryUrl = apiBaseUrl;
        final String scanReportUrl = registryUrl + "/reports/v2?repository=" + imageName + "&tag=" + imageTag;

        final String accessToken = getAccessToken(falconContext, clientId, clientSecret, apiBaseUrl, timeout);
        if (accessToken.equalsIgnoreCase(ProcessCodes.AUTHENTICATION_FAILURE.getDescription())) {
            falconContext.getLogger().println("[CRWDS::DEBUG] " + ProcessCodes.AUTHENTICATION_FAILURE.getDescription());
             return ProcessCodes.AUTHENTICATION_FAILURE.getCode();
        }

        falconContext.getLogger().println("[CRWDS::DEBUG] " + ProcessCodes.AUTHENTICATION_SUCCESS.getDescription() );

        if (!skipImageUpload) {

            DockerUtils containerUtils = getContainerUtils(falconContext, containerRuntime);

            final Integer containerLoginStatus = containerUtils.containerLogin(falconContext, clientId, clientSecret, registryUrl);
            if(containerLoginStatus < 0) {
                return containerLoginStatus;
            }

            final Integer containerPushStatus = containerUtils.containerPush(falconContext, registryUrl, imageName, imageTag);
            if(containerPushStatus < 0) {
                return containerPushStatus;
            }
        }

        String falconScanReport = getFalconReport(falconContext, accessToken, scanReportUrl);
        if(falconScanReport.equalsIgnoreCase(ProcessCodes.FETCH_ASSESSMENT_REPORT_FAILURE.getDescription())) {
            return ProcessCodes.FETCH_ASSESSMENT_REPORT_FAILURE.getCode();
        }

        Gson gson = new Gson();
        AssessmentData assessmentData = gson.fromJson(falconScanReport, AssessmentData.class);

        // Policy results are embedded in the scan report, so no separate policy-checks call is needed.
        PolicyData policyData = null;
        PolicyData.Resources policyResource = assessmentData.getPolicyResponse();
        if(policyResource != null) {
            policyData = new PolicyData();
            ArrayList<PolicyData.Resources> resources = new ArrayList<>();
            resources.add(policyResource);
            policyData.setResources(resources);

            if(!neverFail && policyResource.isDeny() && "block".equalsIgnoreCase(policyResource.getAction())) {
                BUILD_STATUS = ProcessCodes.PREVENT_BUILD_DUE_TO_POLICY.getCode();
                falconContext.getLogger().println("[CRWDS::DEBUG] " + ProcessCodes.PREVENT_BUILD_DUE_TO_POLICY.getDescription());
            }
        }

        falconContext.getLogger().println("[CRWDS::DEBUG] There are " + assessmentData.getVulnerabilities().size() + " vulnerabilities in the image. " +
                "Refer to the CrowdStrike Security tab on the side panel for more details.");

        ReportsGenerator reportsGenerator = new ReportsGenerator(BUILD_STATUS);
        final String html = reportsGenerator.generateReport(falconContext, assessmentData, policyData, neverFail, uniqueId, artifactName);
        archiveArtifacts(falconContext, BUILD_STATUS, artifactName, html, falconScanReport, uniqueId);
        addSidebarLink(falconContext, artifactName, uniqueId);

        return BUILD_STATUS;

    }

    public void archiveArtifacts(FalconContext context, int buildStatus, String artifactName, String html, String falconScanReport, String uniqueId) throws AbortException {

        String scanReport = "crwds_assessment_report_" + uniqueId + ".json";
        try {
            if(buildStatus == ProcessCodes.BUILD_SUCCESS.getCode() || buildStatus == ProcessCodes.PREVENT_BUILD_RECOMMENDATION.getCode() || buildStatus == ProcessCodes.PREVENT_BUILD_DUE_TO_POLICY.getCode()) {
                FileUtils.createWorkSpaceArtifactAndArchive(context, scanReport, falconScanReport);
            }
            FileUtils.createWorkSpaceArtifactAndArchive(context, artifactName, html);
        } catch (RuntimeException ex){
            throw new AbortException("[CRWDS::ABORT] Failed to archive build artifacts" + ex.getMessage());
        } catch (Exception ex) {
            throw new AbortException("[CRWDS::ABORT] Failed to archive build artifacts - " + ex.getMessage());
        }
    }

    private void addSidebarLink(FalconContext context, String artifactName, String uniqueId) {

        Run<?, ?> run = context.getRun();
        run.addOrReplaceAction(new CrowdStrikeSecurityAction(artifactName, uniqueId, run));

    }

    public static String getAccessToken(FalconContext context, String cid, String secret, String apiBaseUrl, Integer timeout) {

        final String tokenUrl = apiBaseUrl + "/oauth2/token";

        HashMap<String, String> params = new HashMap<>();
        params.put("client_id", cid);
        params.put("client_secret", secret);
        try {
            StringBuilder postData = new StringBuilder();
            for(Map.Entry<String, String> param : params.entrySet()) {
                if(postData.length() != 0) {
                    postData.append("&");
                }
                postData.append(URLEncoder.encode(param.getKey(), StandardCharsets.UTF_8.toString()))
                        .append("=")
                        .append(URLEncoder.encode(param.getValue(), StandardCharsets.UTF_8.toString()));

            }
            byte[] postDataBytes = postData.toString().getBytes(StandardCharsets.UTF_8);

            final URL url = new URL(tokenUrl);
            final HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            connection.setRequestProperty("User-Agent", "jenkins-ia-cicd-plugin/1.0");
            connection.setConnectTimeout(timeout * 1000);

            connection.getOutputStream().write(postDataBytes);

            if(connection.getResponseCode() == 200 || connection.getResponseCode() == 201) {
                String line;
                StringBuilder content = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
                    while ((line = reader.readLine()) != null) {
                        content.append(line);
                    }
                }

                final JSONObject authResponseBodyJson = parseFromJsonString(String.valueOf(content));
                return authResponseBodyJson.get("access_token").toString();
            }
        } catch(IOException ex) {
            context.getLogger().println("[CRWDS::DEBUG] " + ex.getMessage());
        }

        return ProcessCodes.AUTHENTICATION_FAILURE.getDescription();

    }

    public static String getFalconReport(FalconContext context, String accessToken, String completeUrl) {

        int counter = 720;
        final int delayTimer = 10;
        final String service = "GET-ASSESSMENT-REPORT";

        try {
            final URL url = new URL(completeUrl);

            while(counter > 0) {
                final HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestProperty("Authorization", "Bearer " + accessToken);
                connection.setRequestProperty("User-Agent", "jenkins-ia-cicd-plugin/1.0");
                context.getLogger().println("[CRWDS::DEBUG] [" + (721 - counter) + "]" + service + " API RESPONSE - " + connection.getResponseCode());
                if(connection.getResponseCode() == 200) {
                    final BufferedReader response = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8));
                    String responseLine;
                    StringBuilder content = new StringBuilder();
                    while((responseLine = response.readLine()) != null) {
                        content.append(responseLine);
                    }
                    response.close();
                    return unwrapResources(String.valueOf(content));
                }

                counter -= 1;
                Thread.sleep(delayTimer * 1000);
            }

        } catch(IOException | InterruptedException ex) {
            context.getLogger().println("[CRWDS::DEBUG] Error in fetching the reports - " + ex.getMessage());
        }

        return ProcessCodes.FETCH_ASSESSMENT_REPORT_FAILURE.getDescription();

    }

    public static JSONObject parseFromJsonString(String jsonString) {
        return new JSONObject(jsonString);
    }

    // The /v2 report API wraps the assessment payload in a {meta, resources, errors} envelope.
    // Return the "resources" object so the rest of the flow parses a bare AssessmentData.
    static String unwrapResources(String responseBody) {
        JSONObject root = new JSONObject(responseBody);
        if (root.has("resources") && !root.isNull("resources")) {
            return root.getJSONObject("resources").toString();
        }
        return responseBody;
    }

    private DockerUtils getContainerUtils(FalconContext falconContext, String containerRuntime) throws IOException, InterruptedException {

        if ("podman".equalsIgnoreCase(containerRuntime)) {
            if (!DockerUtils.isRuntimeAvailable(DockerUtils.ContainerRuntime.PODMAN,
                    falconContext.getEnvVars(),
                    falconContext.getWorkspace(),
                    falconContext.getLauncher(),
                    falconContext.getTaskListener())) {
                throw new IOException("Podman is not available. Please ensure podman is installed and in PATH");
            }

            falconContext.getLogger().println("[CRWDS::DEBUG] Using Podman for container operations");
            return new DockerUtils(DockerUtils.ContainerRuntime.PODMAN);
        }

        if (containerRuntime != null && !containerRuntime.isEmpty() && !"docker".equalsIgnoreCase(containerRuntime)) {
            throw new IOException("Invalid container runtime: '" + containerRuntime + "'. Must be 'docker' or 'podman'.");
        }

        if (!DockerUtils.isRuntimeAvailable(DockerUtils.ContainerRuntime.DOCKER,
                falconContext.getEnvVars(),
                falconContext.getWorkspace(),
                falconContext.getLauncher(),
                falconContext.getTaskListener())) {
            throw new IOException("Docker is not available. Please ensure docker is installed and in PATH");
        }

        falconContext.getLogger().println("[CRWDS::DEBUG] Using Docker for container operations");
        return new DockerUtils(DockerUtils.ContainerRuntime.DOCKER);
    }

}
