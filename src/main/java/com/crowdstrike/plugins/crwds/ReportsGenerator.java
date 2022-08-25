package com.crowdstrike.plugins.crwds;

import com.crowdstrike.plugins.crwds.freemarker.AssessmentData;
import com.crowdstrike.plugins.crwds.freemarker.CSFreeMarker;
import com.crowdstrike.plugins.crwds.freemarker.PolicyData;
import com.crowdstrike.plugins.crwds.freemarker.Reports;
import com.crowdstrike.plugins.crwds.utils.FileUtils;
import com.crowdstrike.plugins.crwds.utils.ProcessCodes;
import freemarker.template.TemplateException;
import hudson.Functions;
import jenkins.model.Jenkins;
import jenkins.util.VirtualFile;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

public class ReportsGenerator {

    private final Integer BUILD_STATUS;

    public ReportsGenerator(Integer buildStatus) {
        this.BUILD_STATUS = buildStatus;
    }

    public String generateReport(FalconContext falconContext, AssessmentData assessmentData, PolicyData policyData, Boolean neverFail, String uniqueId, String artifactName) {

        falconContext.getLogger().println("[CRWDS::DEBUG] Build Status = " + this.BUILD_STATUS);

        if(BUILD_STATUS != ProcessCodes.BUILD_SUCCESS.getCode() && BUILD_STATUS != ProcessCodes.PREVENT_BUILD_DUE_TO_POLICY.getCode()) {
            return generateFailureReport();
        }

        String htmlString = "";
        try {
            Reports reports = Reports.getInstance();
            reports.checkAndResetForNewRunIfNecessary(falconContext.getRun().number);
            CSFreeMarker csFreeMarker = CSFreeMarker.getInstance();
            htmlString = csFreeMarker.processAssessmentTemplate(assessmentData, policyData, neverFail, uniqueId);
            String cssHref = Functions.getResourcePath() + "/plugin/crowdstrike-security-plugin/css/styles.css";
            htmlString = htmlString.replace("<link rel=\"stylesheet\" href= />", "<link rel=\"stylesheet\" href=\"" + Jenkins.get().getRootUrl()+cssHref + "\">");
            reports.addToUniqueReportsList(new Reports.Report(htmlString, uniqueId, neverFail));
            htmlString = csFreeMarker.processPaginatedTemplate(reports);
        } catch (TemplateException | IOException | URISyntaxException e) {
            falconContext.getLogger().println("[CRWDS::DEBUG] " + e.getMessage() + ProcessCodes.HTML_GENERATION_FAILURE.getDescription());
        }
        return htmlString;

    }

    public String generateFailureReport() {

        String failureTemplateName = "failure.html";
        final File failureTemplateFile = new File(getClass().getClassLoader().getResource("/reports/" + failureTemplateName).getFile());
        String html = FileUtils.fileRead(failureTemplateFile.getAbsolutePath());
        String cssHref = Functions.getResourcePath() + "/plugin/crowdstrike-security-plugin/css/failed.css";
        return html.replace("<style></style>", "<link rel=\"stylesheet\" href=\"" + Jenkins.get().getRootUrl()+cssHref + "\">");
    }

}
