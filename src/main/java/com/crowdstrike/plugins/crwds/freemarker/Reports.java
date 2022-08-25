package com.crowdstrike.plugins.crwds.freemarker;

import java.util.ArrayList;

public class Reports {

    private static Reports instance = null;
    private int runNumber;
    private ArrayList<Report> uniqueReports;

    private Reports() {
        this.runNumber = 0;
        uniqueReports = new ArrayList<>();
    }

    public static Reports getInstance() {
        if (instance == null)
            instance = new Reports();

        return instance;
    }

    public ArrayList<Report> getUniqueReports() {
        return uniqueReports;
    }

    public void addToUniqueReportsList(Report report) {
        this.uniqueReports.add(report);
    }

    public void checkAndResetForNewRunIfNecessary(int runNumber) {
        if(this.runNumber != runNumber) {
            this.runNumber = runNumber;
            this.uniqueReports = new ArrayList<>();
        }
    }

    public static class Report {

        private String html;
        private String uniqueId;
        private boolean neverFail;

        public Report(String html, String uniqueId, boolean neverFail) {
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
