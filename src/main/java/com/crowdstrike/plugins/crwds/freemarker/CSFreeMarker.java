package com.crowdstrike.plugins.crwds.freemarker;

import freemarker.ext.beans.BeansWrapper;
import freemarker.template.*;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URISyntaxException;
import java.util.HashMap;

public class CSFreeMarker {

    private static CSFreeMarker instance = null;
    private Configuration cfg;

    private CSFreeMarker() throws IOException, URISyntaxException {

        cfg = new Configuration(Configuration.VERSION_2_3_29);

        cfg.setClassForTemplateLoading(getClass(), "/templates/");
        cfg.setDefaultEncoding("UTF-8");
        cfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
        cfg.setLogTemplateExceptions(false);
        cfg.setWrapUncheckedExceptions(true);
        cfg.setFallbackOnNullLoopVariable(false);

        DefaultObjectWrapper owraop = new DefaultObjectWrapper(Configuration.VERSION_2_3_28);
        owraop.setIterableSupport(true);
        owraop.setExposeFields(true);
        owraop.setExposureLevel(BeansWrapper.EXPOSE_ALL);
        owraop.setMethodsShadowItems(true);
        owraop.setForceLegacyNonListCollections(true);
        owraop.setUseAdaptersForContainers(true);
        cfg.setObjectWrapper(owraop);
    }

    public static CSFreeMarker getInstance() throws IOException, URISyntaxException {

        if(instance == null)
            instance = new CSFreeMarker();

        return instance;
    }

    public String processAssessmentTemplate(AssessmentData assessmentData, PolicyData policyData, boolean neverFail, String uniqueId) throws IOException, TemplateException {
        Template template = cfg.getTemplate("index.ftl");

        HashMap<String, Object> root = new HashMap<>();
        root.put("assessmentData", assessmentData);
        root.put("policyData", policyData);
        root.put("neverFail", neverFail);
        root.put("uniqueId", uniqueId);


        StringWriter stringWriter = new StringWriter();
        template.process(root, stringWriter);
        return stringWriter.toString();
    }

    public String processPaginatedTemplate(Reports.Report report) throws IOException, TemplateException {
        Template template = cfg.getTemplate("paginated.ftl");

        HashMap<String, Object> root = new HashMap<>();
        root.put("reports", report);

        StringWriter stringWriter = new StringWriter();
        template.process(root, stringWriter);
        return stringWriter.toString();
    }
}
