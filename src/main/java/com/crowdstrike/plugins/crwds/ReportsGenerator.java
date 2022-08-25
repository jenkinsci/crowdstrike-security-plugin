package com.crowdstrike.plugins.crwds;

import com.crowdstrike.plugins.crwds.freemarker.*;
import com.crowdstrike.plugins.crwds.utils.FileUtils;
import com.crowdstrike.plugins.crwds.utils.ProcessCodes;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.io.File;

public class ReportsGenerator {

    private final Integer BUILD_STATUS;

    public ReportsGenerator(Integer buildStatus) {
        this.BUILD_STATUS = buildStatus;
    }

    @SuppressFBWarnings(value= "REC_CATCH_EXCEPTION", justification = "Other Exceptions could happen that we need to handle here.")
    public String generateReport(FalconContext falconContext, AssessmentData assessmentData, PolicyData policyData, Boolean neverFail, String uniqueId, String artifactName) {

        falconContext.getLogger().println("[CRWDS::DEBUG] Build Status = " + this.BUILD_STATUS);

        if(BUILD_STATUS != ProcessCodes.BUILD_SUCCESS.getCode() && BUILD_STATUS != ProcessCodes.PREVENT_BUILD_DUE_TO_POLICY.getCode()) {
            return generateFailureReport();
        }

        String htmlString = "";
        try {
            Reports reports = Reports.getInstance();
            reports.checkAndResetForNewRunIfNecessary(falconContext.getRun());
            CSFreeMarker csFreeMarker = CSFreeMarker.getInstance();
            htmlString = csFreeMarker.processAssessmentTemplate(assessmentData, policyData, neverFail, uniqueId);
            reports.addToUniqueReportsList(falconContext.getRun(), new Reports.ReportData(htmlString, uniqueId, neverFail));
            htmlString = csFreeMarker.processPaginatedTemplate(reports.getReport(falconContext.getRun()));
        } catch (Exception e) {
            falconContext.getLogger().println("[CRWDS::DEBUG] " + ProcessCodes.HTML_GENERATION_FAILURE.getDescription() + "\n" + e.getMessage());
        }
        return htmlString;

    }

    public String generateFailureReport() {

        String failureTemplateName = "failure.html";
        final File failureTemplateFile = new File(getClass().getResource("/reports/" + failureTemplateName).getFile());
        return FileUtils.fileRead(failureTemplateFile.getAbsolutePath());
    }

}
