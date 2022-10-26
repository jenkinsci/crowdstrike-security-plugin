package com.crowdstrike.plugins.crwds;

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
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

public class FalconScanner {

    public int execute(FalconContext falconContext, String imageName, String imageTag, Integer timeout, String clientSecret,
                       String clientId, String authDomain, Boolean neverFail, String artifactName, String uniqueId) throws IOException, InterruptedException, ExecutionException, NullPointerException {

        int BUILD_STATUS = ProcessCodes.BUILD_SUCCESS.getCode();

        final String registryUrl = "https://container-upload." + authDomain;
        final String scanReportUrl = registryUrl + "/reports?repository=" + imageName + "&tag=" + imageTag;
        final String policyUrl = registryUrl + "/policy-checks?policy_type=image-prevention-policy&repository=" + imageName + "&tag=" + imageTag;

        final String accessToken = getAccessToken(falconContext, clientId, clientSecret, authDomain, timeout);
        if (accessToken.equalsIgnoreCase(ProcessCodes.AUTHENTICATION_FAILURE.getDescription())) {
            falconContext.getLogger().println("[CRWDS::DEBUG] " + ProcessCodes.AUTHENTICATION_FAILURE.getDescription());
             return ProcessCodes.AUTHENTICATION_FAILURE.getCode();
        }

        falconContext.getLogger().println("[CRWDS::DEBUG] " + ProcessCodes.AUTHENTICATION_SUCCESS.getDescription() );

        final Integer dockerLoginStatus = DockerUtils.dockerLogin(falconContext, clientId, clientSecret, registryUrl);
        if(dockerLoginStatus < 0) {
            return ProcessCodes.DOCKER_LOGIN_FAILURE.getCode();
        }

        final Integer dockerPushStatus = DockerUtils.dockerPush(falconContext, registryUrl, imageName, imageTag);
        if(dockerPushStatus < 0) {
            return ProcessCodes.DOCKER_PUSH_FAILURE.getCode();
        }

        String falconScanReport = getFalconReport(falconContext, accessToken, scanReportUrl, true);
        if(falconScanReport.equalsIgnoreCase(ProcessCodes.FETCH_ASSESSMENT_REPORT_FAILURE.getDescription())) {
            return ProcessCodes.FETCH_ASSESSMENT_REPORT_FAILURE.getCode();
        }

        Gson gson = new Gson();
        String policyJson = getFalconReport(falconContext, accessToken, policyUrl, false);
        if(policyJson.equalsIgnoreCase(ProcessCodes.FETCH_POLICY_REPORT_FAILURE.getDescription())) {
            return ProcessCodes.FETCH_POLICY_REPORT_FAILURE.getCode();
        }
        PolicyData policyData = gson.fromJson(policyJson, PolicyData.class);
        boolean deny = policyData.getResources().get(0).isDeny();

        if(!neverFail && deny) {
            final String policyAction = policyData.getResources().get(0).getAction();
            if("block".equalsIgnoreCase(policyAction)) {
                BUILD_STATUS = ProcessCodes.PREVENT_BUILD_DUE_TO_POLICY.getCode();
                falconContext.getLogger().println("[CRWDS::DEBUG] " + ProcessCodes.PREVENT_BUILD_DUE_TO_POLICY.getDescription());
            }
        }

        if(!falconScanReport.equalsIgnoreCase(ProcessCodes.FETCH_ASSESSMENT_REPORT_FAILURE.getDescription())) {
            AssessmentData assessmentData = gson.fromJson(falconScanReport, AssessmentData.class);
            falconContext.getLogger().println("[CRWDS::DEBUG] There are " + assessmentData.getVulnerabilities().size() + " vulnerabilities in the image. " +
                    "Refer to the CrowdStrike Security tab on the side panel for more details.");

            ReportsGenerator reportsGenerator = new ReportsGenerator(BUILD_STATUS);
            final String html = reportsGenerator.generateReport(falconContext, assessmentData, policyData, neverFail, uniqueId, artifactName);
            archiveArtifacts(falconContext, BUILD_STATUS, artifactName, html, falconScanReport, policyJson, uniqueId);
            addSidebarLink(falconContext, artifactName, uniqueId);
        }

        return BUILD_STATUS;

    }

    public void archiveArtifacts(FalconContext context, int buildStatus, String artifactName, String html, String falconScanReport, String policyJson, String uniqueId) throws AbortException {

        String scanReport = "crwds_assessment_report_" + uniqueId + ".json";
        String policyReport = "crwds_policy_check_" + uniqueId + ".json";
        try {
            if(buildStatus == ProcessCodes.BUILD_SUCCESS.getCode() || buildStatus == ProcessCodes.PREVENT_BUILD_RECOMMENDATION.getCode() || buildStatus == ProcessCodes.PREVENT_BUILD_DUE_TO_POLICY.getCode()) {
                FileUtils.createWorkSpaceArtifactAndArchive(context, scanReport, falconScanReport);
                FileUtils.createWorkSpaceArtifactAndArchive(context, policyReport, policyJson);
            }
            FileUtils.createWorkSpaceArtifactAndArchive(context, artifactName, html);
        } catch (Exception ex) {
            throw new AbortException("[CRWDS::ABORT] Failed to archive build artifacts - " + ex.getMessage());
        }

    }

    private void addSidebarLink(FalconContext context, String artifactName, String uniqueId) {

        Run<?, ?> run = context.getRun();
        run.addOrReplaceAction(new CrowdStrikeSecurityAction(artifactName, uniqueId));

    }

    public static String getAccessToken(FalconContext context, String cid, String secret, String authDomain, Integer timeout) {

        authDomain = "https://api." + authDomain + "/oauth2/token";

        if(authDomain.contains("us-1.")) {
            authDomain = authDomain.replace("us-1.", "");
        }

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

            final URL url = new URL(authDomain);
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
                    while((line = reader.readLine()) != null) {
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

    public static String getFalconReport(FalconContext context, String accessToken, String completeUrl, boolean isScanReport) {

        int counter = 720;
        final int delayTimer = 10;
        String service = "GET-ASSESSMENT-REPORT";
        if(!isScanReport) {
            service = "GET-POLICY-REPORT";
        }

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
                    return String.valueOf(content);
                } else if (!isScanReport) {
                    break;
                }

                counter -= 1;
                Thread.sleep(delayTimer * 1000);
            }

        } catch(IOException | InterruptedException ex) {
            context.getLogger().println("[CRWDS::DEBUG] Error in fetching the reports - " + ex.getMessage());
        }

        if(isScanReport) {
            return ProcessCodes.FETCH_ASSESSMENT_REPORT_FAILURE.getDescription();
        }

        return ProcessCodes.FETCH_POLICY_REPORT_FAILURE.getDescription();

    }

    public static JSONObject parseFromJsonString(String jsonString) {
        return new JSONObject(jsonString);
    }

}
