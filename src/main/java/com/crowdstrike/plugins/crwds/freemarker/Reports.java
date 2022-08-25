package com.crowdstrike.plugins.crwds.freemarker;

import hudson.model.Run;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class Reports {

    private static Reports instance = null;

    private HashMap<String, Report> reportsList;

    public Reports() {
        reportsList = new HashMap<>();
    }

    public static Reports getInstance() {
        if (instance == null)
            instance = new Reports();

        return instance;
    }

    public void addToUniqueReportsList(Run<?, ?> run, ReportData reportData) {
        Report report = reportsList.get(run.getRootDir().toString());
        if (report == null)
        {
            report = new Report(run);
            reportsList.put(run.getRootDir().toString(), report);
        }

        report.uniqueReports.add(reportData);
    }

    public Report getReport(Run<?,?> run) {
        return reportsList.get(run.getRootDir().toString());
    }

    public void checkAndResetForNewRunIfNecessary(Run<?, ?> run) {
        clearOutOldReports();
        reportsList.putIfAbsent(run.getRootDir().toString(), new Report(run));
    }

    private void clearOutOldReports()
    {
        for(Iterator<Map.Entry<String, Report>> it = reportsList.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<String, Report> entry = it.next();
            if (!entry.getValue().run.isBuilding() && entry.getValue().run.getResult() != null) {
                it.remove();
            }
        }
    }

    public static class Report {
        Run<?,?> run;
        ArrayList<ReportData> uniqueReports;

        public Report(Run<?,?> run) {
            this.run = run;
            this.uniqueReports = new ArrayList<>();
        }

        public ArrayList<ReportData> getUniqueReports() {
            return uniqueReports;
        }
    }

     public static class ReportData {

        private String html;
        private String uniqueId;
        private boolean neverFail;

        public ReportData(String html, String uniqueId, boolean neverFail) {
            this.html = html;
            this.uniqueId = uniqueId;
            this.neverFail = neverFail;
        }

        public String getHtml() {
            return html;
        }

        public void setHtml(String html) {
            this.html = html;
        }

        public String getUniqueId() {
            return uniqueId;
        }

        public void setUniqueId(String uniqueId) {
            this.uniqueId = uniqueId;
        }

        public boolean isNeverFail() {
            return neverFail;
        }

        public void setNeverFail(boolean neverFail) {
            this.neverFail = neverFail;
        }
    }
}
