package com.crowdstrike.plugins.crwds.utils;

public enum ProcessCodes {

    AUTHENTICATION_FAILURE(-1001, "User authentication failed. Check ClientID and Secret are valid, API Client has Falcon Container Image READ and WRITE permissions, CID exists in Cloud region, is subscribed to Cloud Workload Protection (CWP), and has the Image Assessment role. " +
            "Also ensure the report is returning before the bearer token timeout (30 minutes)."),
    AUTHENTICATION_SUCCESS(1001, "User authenticated to Falcon API. Session is valid for 30 minutes."),
    DOCKER_LOGIN_FAILURE(-1002, "Docker login has failed"),
    DOCKER_TAG_FAILURE(-1003, "Error in performing docker tag"),
    DOCKER_PUSH_FAILURE(-1004, "Error in performing docker push"),
    DOCKER_OPERATION_SUCCESS(1002, "Container runtime operation successful"),
    FETCH_ASSESSMENT_REPORT_FAILURE(-1005, "Error in fetching the CrowdStrike Security assessment report"),
    FETCH_POLICY_REPORT_FAILURE(-1006, "Error in fetching the CrowdStrike Security policy report"),
    PREVENT_BUILD_DUE_TO_POLICY(-1007, "CrowdStrike Security prevented the build due to the Falcon Policy. Please deselect `Enforce the recommendation` option in the per-build configuration if you do not want CrowdStrike Security to prevent this build."),
    PREVENT_BUILD_RECOMMENDATION(-1008, "CrowdStrike Security recommends to prevent the build as per the Falcon Policy. Please select `Enforce the recommendation` option in the per-build configuration if you want CrowdStrike Security to enforce the policy."),
    HTML_GENERATION_FAILURE(-1009, "Failed to generate HTML report"),
    BUILD_TIMED_OUT(-1010, "Build Step Timed-out. Try increasing the value in timeout field in the per-build configuration"),
    INTERNAL_ERROR(-1011, "CrowdStrike Security plugin faced an unknown internal error."),
    INVALID_CONFIGURATION(-1012, "Invalid configuration. Please use appropriate values in the per-build/global configuration for the build to succeed"),
    BUILD_SUCCESS(1000, "Build Successful"),
    // Podman error codes
    PODMAN_LOGIN_FAILURE(-1013, "Podman login has failed"),
    PODMAN_TAG_FAILURE(-1014, "Podman tag has failed"),
    PODMAN_PUSH_FAILURE(-1015, "Podman push has failed"),
    ;

    private final int code;

    private final String description;

    ProcessCodes(int code, String description) {
        this.code = code;
        this.description = description;
    }

    public int getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }

    public static String getDescriptionByCode(int code) {

        for(ProcessCodes each : ProcessCodes.values()) {
            if(each.getCode() == code) {
                return each.getDescription();
            }
        }

        return "Process description not found.";
    }

}
