package com.crowdstrike.plugins.crwds.freemarker;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AssessmentData {

    private final String[] severitiesList = new String[] {"critical", "high", "medium", "low", "negligible"};

    // @SerializedName(value = "scanInfo", alternate = {"ScanInfo", "Scaninfo"})
    private ScanInfo scanInfo;
    private ImageInfo imageInfo;
    private Config config;
    private OSInfo osInfo;
    private ArrayList<Vulnerabilities> vulnerabilities;
    private ArrayList<Detections> detections;
    private ArrayList<Layers> layers;
    private ArrayList<Packages> packages;
    private ArrayList<ELFBinaries> elfBinaries;
    private InventoryEngineInfo inventoryEngineInfo;
    private DetectionEngineInfo detectionEngineInfo;

    private Manifest manifest;

    public AssessmentData.ScanInfo getScanInfo() {
        return scanInfo;
    }

    public void setScanInfo(AssessmentData.ScanInfo scanInfo) {
        this.scanInfo = scanInfo;
    }

    public AssessmentData.ImageInfo getImageInfo() {
        return imageInfo;
    }

    public void setImageInfo(AssessmentData.ImageInfo imageInfo) {
        this.imageInfo = imageInfo;
    }

    public AssessmentData.Config getConfig() {
        return config;
    }

    public void setConfig(AssessmentData.Config config) {
        this.config = config;
    }

    public AssessmentData.OSInfo getOsInfo() {
        return osInfo;
    }

    public void setOsInfo(AssessmentData.OSInfo osInfo) {
        this.osInfo = osInfo;
    }

    public ArrayList<AssessmentData.Vulnerabilities> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(ArrayList<AssessmentData.Vulnerabilities> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public ArrayList<AssessmentData.Detections> getDetections() {
        return detections;
    }

    public void setDetections(ArrayList<AssessmentData.Detections> detections) {
        this.detections = detections;
    }

    public ArrayList<AssessmentData.Layers> getLayers() {
        return layers;
    }

    public void setLayers(ArrayList<AssessmentData.Layers> layers) {
        this.layers = layers;
    }

    public ArrayList<AssessmentData.Packages> getPackages() {
        return packages;
    }

    public void setPackages(ArrayList<AssessmentData.Packages> packages) {
        this.packages = packages;
    }

    public ArrayList<AssessmentData.ELFBinaries> getElfBinaries() {
        return elfBinaries;
    }

    public void setElfBinaries(ArrayList<AssessmentData.ELFBinaries> elfBinaries) {
        this.elfBinaries = elfBinaries;
    }

    public AssessmentData.InventoryEngineInfo getInventoryEngineInfo() {
        return inventoryEngineInfo;
    }

    public void setInventoryEngineInfo(AssessmentData.InventoryEngineInfo inventoryEngineInfo) {
        this.inventoryEngineInfo = inventoryEngineInfo;
    }

    public AssessmentData.DetectionEngineInfo getDetectionEngineInfo() {
        return detectionEngineInfo;
    }

    public void setDetectionEngineInfo(AssessmentData.DetectionEngineInfo detectionEngineInfo) {
        this.detectionEngineInfo = detectionEngineInfo;
    }

    public AssessmentData.Manifest getManifest() { return manifest; }

    public void setManifest(AssessmentData.Manifest manifest) {
        this.manifest = manifest;
    }

    public int vulnerabilitiesCriticalCount() {
        int count = 0;
        if(vulnerabilities != null) {
            for (Vulnerabilities vuls : vulnerabilities) {
                Vulnerabilities.Vulnerability vul = vuls.vulnerability;
                if(vul != null && vul.details != null && vul.details.severity.equalsIgnoreCase("CRITICAL")) {
                    count++;
                }
            }
        }

        return count;
    }

    public int vulnerabilitiesRemediationsCount() {
        int count = 0;
        if(vulnerabilities != null) {
            for (Vulnerabilities vuls : vulnerabilities) {
                Vulnerabilities.Vulnerability vul = vuls.vulnerability;
                if (vul != null) {
                    count += vul.remediationsCount();
                }
            }
        }
        return count;
    }

    public HashMap<String, Integer> severitiesAndCount() {
        LinkedHashMap<String, Integer> severities = new LinkedHashMap<>();
        for (String s : severitiesList) {
            severities.put(s.toUpperCase(Locale.getDefault()), 0);
        }
        if (vulnerabilities != null) {
            for (Vulnerabilities vuls : vulnerabilities) {
                if (vuls.vulnerability != null) {
                    Vulnerabilities.Vulnerability vul = vuls.vulnerability;
                    if (vul.details != null) {
                        Integer currCount = severities.getOrDefault(vul.details.severity.toUpperCase(Locale.getDefault()), 0);
                        severities.put(vul.details.severity.toUpperCase(Locale.getDefault()), currCount + 1);
                    }
                }
            }
        }

        return severities;
    }

    public ArrayList<AssessmentData.Vulnerabilities.Vulnerability> vulnerabilityBySeverity(String severity) {
        ArrayList<AssessmentData.Vulnerabilities.Vulnerability> vulns = new ArrayList<>();
        if(vulnerabilities != null) {
            for (Vulnerabilities vuls : vulnerabilities) {
                Vulnerabilities.Vulnerability vul = vuls.vulnerability;
                if (vul != null && vul.details != null && vul.details.severity.equalsIgnoreCase(severity))
                    vulns.add(vul);
            }
        }

        return vulns;
    }

    public String vulnerabilityCVEIDByLayer(Layers layer) {
        if (vulnerabilities != null) {
            for (Vulnerabilities vul : vulnerabilities) {
                if (vul.vulnerability != null && vul.vulnerability.layerHash.equalsIgnoreCase(layer.digest))
                    return vul.vulnerability.cveid;
            }
        }

        return "";
    }

    public String severityColor(String severity) {
        switch (severity.toLowerCase(Locale.getDefault())) {
            case "critical":
                return "critical";
            case "high":
                return "high";
            case "medium":
                return "medium";
            case "low":
                return "low";
            case "negligible":
                return "negligible";
            default:
                return "nh";
        }
    }

    public String severityLabel(String severity) {
        switch (severity.toLowerCase(Locale.getDefault())) {
            case "critical":
                return "Critical";
            case "high":
                return "High";
            case "medium":
                return "Medium";
            case "low":
                return "Low";
            case "negligible":
                return "Negligible";
            default:
                return "Unknown";
        }
    }

    public String getIconByType(String type) {
        switch (type.toLowerCase(Locale.getDefault())) {
            case "success":
                return "<svg class=\"mr-1\" width=\"25\" height=\"25\" viewBox=\"0 0 25 25\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n" +
                        "    <path d=\"M12.5 1.042C6.172 1.042 1.04 6.172 1.04 12.5S6.171 23.958 12.5 23.958c6.328 0 11.458-5.13 11.458-11.458S18.828 1.042 12.5 1.042zM9.627 18.016 5.68 14.069l1.473-1.473 2.474 2.474 7.557-7.557 1.473 1.472-9.03 9.03z\" fill=\"#06E5B7\"/>\n" +
                        "</svg>";
            case "positive":
                return "<svg class=\"mr-1\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n" +
                        "    <path d=\"M2 6.804c0-.317.225-.708.5-.866l9-5.196c.275-.16.725-.16 1 0l9 5.196c.275.159.5.548.5.865v10.393c0 .317-.225.707-.5.866l-9 5.197c-.275.159-.725.159-1 0l-9-5.197c-.275-.159-.5-.549-.5-.866V6.804z\" fill=\"#11e5b6\"/>\n" +
                        "</svg>";
            case "failure":
                return "<svg class=\"mr-1\" width=\"25\" height=\"25\" viewBox=\"0 0 25 25\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n" +
                        "    <path d=\"M12.5 1.042c-6.328 0-11.458 5.13-11.458 11.458S6.172 23.958 12.5 23.958s11.458-5.13 11.458-11.458S18.828 1.042 12.5 1.042zm5.424 15.41-1.473 1.472-3.95-3.951-3.952 3.951-1.473-1.473 3.951-3.951-3.95-3.951 1.472-1.473 3.951 3.951 3.951-3.95 1.473 1.472-3.951 3.951 3.951 3.951z\" fill=\"#fa4147\"/>\n" +
                        "</svg>";
            case "critical":
                return "<svg class=\"mr-1\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n" +
                        "    <path d=\"M2 6.804c0-.317.225-.708.5-.866l9-5.196c.275-.16.725-.16 1 0l9 5.196c.275.159.5.548.5.865v10.393c0 .317-.225.707-.5.866l-9 5.197c-.275.159-.725.159-1 0l-9-5.197c-.275-.159-.5-.549-.5-.866V6.804z\" fill=\"#fa4147\"/>\n" +
                        "</svg>";
            case "high":
                return "<svg class=\"mr-1\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n" +
                        "    <path d=\"M2 6.804c0-.317.225-.708.5-.866l9-5.196c.275-.16.725-.16 1 0l9 5.196c.275.159.5.548.5.865v10.393c0 .317-.225.707-.5.866l-9 5.197c-.275.159-.725.159-1 0l-9-5.197c-.275-.159-.5-.549-.5-.866V6.804z\" fill=\"#f77d40\"/>\n" +
                        "</svg>";
            case "medium":
                return "<svg class=\"mr-1\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n" +
                        "    <path d=\"M2 6.804c0-.317.225-.708.5-.866l9-5.196c.275-.16.725-.16 1 0l9 5.196c.275.159.5.548.5.865v10.393c0 .317-.225.707-.5.866l-9 5.197c-.275.159-.725.159-1 0l-9-5.197c-.275-.159-.5-.549-.5-.866V6.804z\" fill=\"#ffcc00\"/>\n" +
                        "</svg>";
            case "info":
            case "low":
                return "<svg class=\"mr-1\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n" +
                        "    <path d=\"M2 6.804c0-.317.225-.708.5-.866l9-5.196c.275-.16.725-.16 1 0l9 5.196c.275.159.5.548.5.865v10.393c0 .317-.225.707-.5.866l-9 5.197c-.275.159-.725.159-1 0l-9-5.197c-.275-.159-.5-.549-.5-.866V6.804z\" fill=\"#9dc1fd\"/>\n" +
                        "</svg>";
            case "arrow":
                return "<svg class=\"i-arrow mr-1\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n" +
                        "    <path d=\"M12 13.586 8.352 9.94a.5.5 0 0 0-.707.707L12 15l4.354-4.354a.498.498 0 0 0 0-.708.5.5 0 0 0-.707 0L12 13.586z\" fill=\"#fafafa\"/>\n" +
                        "</svg>";
            default:
                return "<svg class=\"mr-1\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n" +
                        "    <path d=\"M2 6.804c0-.317.225-.708.5-.866l9-5.196c.275-.16.725-.16 1 0l9 5.196c.275.159.5.548.5.865v10.393c0 .317-.225.707-.5.866l-9 5.197c-.275.159-.725.159-1 0l-9-5.197c-.275-.159-.5-.549-.5-.866V6.804z\" fill=\"#63646e\"/>\n" +
                        "</svg>";
        }
    }

    public static String timeFormat(String field) {
        try {
            Instant instant = Instant.parse(field);
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMMM d yyyy',' 'at' hh:mm:ss a O");
            ZonedDateTime zdt = ZonedDateTime.ofInstant(instant, TimeZone.getDefault().toZoneId());
            return zdt.format(formatter);
        }
        catch (Exception e)
        {
            return field == null?"":field;
        }
    }

    public String toString() {
        return
                "Scan Info: " + this.scanInfo.toString() + "\n" +
                        "Image Info: " + this.imageInfo.toString() + "\n" +
                        "Config: " + this.config.toString() + "\n" +
                        "OS Info: " + this.osInfo.toString() + "\n" +
                        "Vulnerabilities: " + this.vulnerabilities.toString() + "\n" +
                        "Detections: " + this.detections.toString() + "\n" +
                        "Layers: " + this.layers.toString() + "\n" +
                        "Packages: " + this.packages.toString() + "\n" +
                        "ELF Binaries: " + this.elfBinaries.toString() + "\n" +
                        "Inventory Engine Info: " + this.inventoryEngineInfo.toString() + "\n" +
                        "Detection Engine Info: " + this.detectionEngineInfo.toString();
    }

    public static class ScanInfo {
        private String cid;
        private String username;
        private String userUUID;
        private String scanUUID;
        private String correlationUUID;
        private String requestedAt;

        public String getCid() {
            return cid;
        }

        public void setCid(String cid) {
            this.cid = cid;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getUserUUID() {
            return userUUID;
        }

        public void setUserUUID(String userUUID) {
            this.userUUID = userUUID;
        }

        public String getScanUUID() {
            return scanUUID;
        }

        public void setScanUUID(String scanUUID) {
            this.scanUUID = scanUUID;
        }

        public String getCorrelationUUID() {
            return correlationUUID;
        }

        public void setCorrelationUUID(String correlationUUID) {
            this.correlationUUID = correlationUUID;
        }

        public String getRequestedAt() {
            return requestedAt;
        }

        public void setRequestedAt(String requestedAt) {
            this.requestedAt = requestedAt;
        }

        public String getRequestedAtFormatted() {
            return timeFormat(requestedAt);
        }

        public String toString() {
            return
                    "cid : " + cid + "\n" +
                            "username : " + username + "\n" +
                            "userUUID : " + userUUID + "\n" +
                            "scanUUID : " + scanUUID + "\n" +
                            "correlationUUID : " + correlationUUID + "\n" +
                            "requestedAt : " + requestedAt;
        }
    }

    public static class ImageInfo {
        private String registry;
        private String repository;
        private String tag;
        private String id;
        private String digest;
        private String size;
        private String createdAt;
        private String architecture;
        private String scan_request_s3_key;

        public String getRegistry() {
            return registry;
        }

        public void setRegistry(String registry) {
            this.registry = registry;
        }

        public String getRepository() {
            return repository;
        }

        public void setRepository(String repository) {
            this.repository = repository;
        }

        public String getTag() {
            return tag;
        }

        public void setTag(String tag) {
            this.tag = tag;
        }

        public String getId() {
            return id;
        }

        public void setId(String ID) {
            this.id = ID;
        }

        public String getDigest() {
            return digest;
        }

        public void setDigest(String digest) {
            this.digest = digest;
        }

        public String getSize() {
            return size;
        }

        public void setSize(String size) {
            this.size = size;
        }

        public String getCreatedAt() {
            return timeFormat(createdAt);
        }

        public void setCreatedAt(String createdAt) {
            this.createdAt = createdAt;
        }

        public String getArchitecture() {
            return architecture;
        }

        public void setArchitecture(String architecture) {
            this.architecture = architecture;
        }

        public String getScan_request_s3_key() {
            return scan_request_s3_key;
        }

        public void setScan_request_s3_key(String scan_request_s3_key) {
            this.scan_request_s3_key = scan_request_s3_key;
        }

        public String toString() {
            return
                    "registry: " + registry + "\n" +
                            "repository: " + repository + "\n" +
                            "tag: " + tag + "\n" +
                            "id: " + id + "\n" +
                            "digest: " + digest + "\n" +
                            "size: " + size + "\n" +
                            "createdAt: " + createdAt + "\n" +
                            "architecture: " + architecture + "\n" +
                            "scanRequestS3Key: " + scan_request_s3_key;
        }
    }

    public static class Config {
        private String created;
        private String architecture;
        private String os;

        public String getCreated() {
            return timeFormat(created);
        }

        public void setCreated(String created) {
            this.created = created;
        }

        public String getArchitecture() {
            return architecture;
        }

        public void setArchitecture(String architecture) {
            this.architecture = architecture;
        }

        public String getOs() {
            return os;
        }

        public void setOs(String os) {
            this.os = os;
        }

        public String toString() {
            return
                    "created: " + created + "\n" +
                            "architecture: " + architecture + "\n" +
                            "os: " + os;
        }
    }

    public static class OSInfo {
        private String name;
        private String version;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getVersion() {
            return version;
        }

        public void setVersion(String version) {
            this.version = version;
        }

        public String toString() {
            return
                    "name: " + name + "\n" +
                            "version: " + version;
        }
    }

    public static class Vulnerabilities {
        private Vulnerability vulnerability;

        public AssessmentData.Vulnerabilities.Vulnerability getVulnerability() {
            return vulnerability;
        }

        public void setVulnerability(AssessmentData.Vulnerabilities.Vulnerability vulnerability) {
            this.vulnerability = vulnerability;
        }

        public static class Vulnerability {
            private String cveid;
            private String layerHash;
            private String firstSeen;
            private Product product;
            private String contentDataHash;
            private ArrayList<String> remediation;
            private Details details;
            private ExploitedDetails exploitedDetails;

            public String getCveid() {
                return cveid;
            }

            public void setCveid(String cveid) {
                this.cveid = cveid;
            }

            public String getLayerHash() {
                return layerHash;
            }

            public void setLayerHash(String layerHash) {
                this.layerHash = layerHash;
            }

            public String getFirstSeen() {
                return timeFormat(firstSeen);
            }

            public void setFirstSeen(String firstSeen) {
                this.firstSeen = firstSeen;
            }

            public AssessmentData.Vulnerabilities.Vulnerability.Product getProduct() {
                return product;
            }

            public void setProduct(AssessmentData.Vulnerabilities.Vulnerability.Product product) {
                this.product = product;
            }

            public String getContentDataHash() {
                return contentDataHash;
            }

            public void setContentDataHash(String contentDataHash) {
                this.contentDataHash = contentDataHash;
            }

            public ArrayList<String> getRemediation() {
                return remediation;
            }

            public void setRemediation(ArrayList<String> remediation) {
                this.remediation = remediation;
            }

            public AssessmentData.Vulnerabilities.Vulnerability.Details getDetails() {
                return details;
            }

            public void setDetails(AssessmentData.Vulnerabilities.Vulnerability.Details details) {
                this.details = details;
            }

            public AssessmentData.Vulnerabilities.Vulnerability.ExploitedDetails getExploitedDetails() {
                return exploitedDetails;
            }

            public void setExploitedDetails(AssessmentData.Vulnerabilities.Vulnerability.ExploitedDetails exploitedDetails) {
                this.exploitedDetails = exploitedDetails;
            }

            public int remediationsCount() {
                int count = 0;
                if (remediation != null) {
                    for (String s : remediation) {
                        if (!isHash(s)) {
                            count++;
                        }
                    }
                }
                return count;
            }

            public boolean isHash(String hash) {
                Pattern pattern = Pattern.compile("[a-f0-9]{32}", Pattern.CASE_INSENSITIVE);
                Matcher matcher = pattern.matcher(hash);
                return matcher.find();
            }

            public ArrayList<String> getRemediationsIfNotHash() {
                ArrayList<String> remediations = new ArrayList<>();
                if (remediation != null) {
                    for (String s : remediation) {
                        if (!isHash(s)) {
                            remediations.add(s);
                        }
                    }
                }

                return remediations;
            }

            public static class Product {
                private String packageSource;

                public String getPackageSource() {
                    return packageSource;
                }

                public void setPackageSource(String PackageSource) {
                    this.packageSource = PackageSource;
                }
            }

            public static class Details {
                private String id;
                private String cvss_version;
                private String source_type;
                private String source;
                private String description;
                private String vector;
                private double base_score;
                private String severity;
                private double exploitability_score;
                private double impact_score;
                private ArrayList<References> references;
                //Add more if needed

                public String getId() {
                    return id;
                }

                public void setId(String id) {
                    this.id = id;
                }

                public String getCvss_version() {
                    return cvss_version;
                }

                public void setCvss_version(String cvss_version) {
                    this.cvss_version = cvss_version;
                }

                public String getSource_type() {
                    return source_type;
                }

                public void setSource_type(String source_type) {
                    this.source_type = source_type;
                }

                public String getSource() {
                    return source;
                }

                public void setSource(String source) {
                    this.source = source;
                }

                public String getDescription() {
                    return description;
                }

                public void setDescription(String description) {
                    this.description = description;
                }

                public String getVector() {
                    return vector;
                }

                public void setVector(String vector) {
                    this.vector = vector;
                }

                public double getBase_score() {
                    return base_score;
                }

                public void setBase_score(double base_score) {
                    this.base_score = base_score;
                }

                public String getSeverity() {
                    return severity;
                }

                public void setSeverity(String severity) {
                    this.severity = severity;
                }

                public double getExploitability_score() {
                    return exploitability_score;
                }

                public void setExploitability_score(double exploitability_score) {
                    this.exploitability_score = exploitability_score;
                }

                public double getImpact_score() {
                    return impact_score;
                }

                public void setImpact_score(double impact_score) {
                    this.impact_score = impact_score;
                }

                public ArrayList<References> getReferences() {
                    return references;
                }

                public void setReferences(ArrayList<References> references) {
                    this.references = references;
                }
            }

            public static class ExploitedDetails {

            }

            public static class References {
                private String url;
                private ArrayList<String> tags;

                public String getUrl() {
                    return url;
                }

                public void setUrl(String url) {
                    this.url = url;
                }

                public ArrayList<String> getTags() {
                    return tags;
                }

                public void setTags(ArrayList<String> Tags) {
                    this.tags = Tags;
                }
            }
        }
    }

    public static class Detections {
        private Detection detection;

        public AssessmentData.Detections.Detection getDetection() {
            return detection;
        }

        public void setDetection(AssessmentData.Detections.Detection detection) {
            this.detection = detection;
        }

        public String toString() {
            return detection.toString();
        }

        public static class Detection {
            private String id;
            private String type;
            private String name;
            private String title;
            private String description;
            private String remediation;
            private String severity;

            public String getId() {
                return id;
            }

            public void setId(String ID) {
                this.id = ID;
            }

            public String getType() {
                return type;
            }

            public void setType(String type) {
                this.type = type;
            }

            public String getName() {
                return name;
            }

            public void setName(String name) {
                this.name = name;
            }

            public String getTitle() {
                return title;
            }

            public void setTitle(String title) {
                this.title = title;
            }

            public String getDescription() {
                return description;
            }

            public void setDescription(String description) {
                this.description = description;
            }

            public String getRemediation() {
                return remediation;
            }

            public void setRemediation(String remediation) {
                this.remediation = remediation;
            }

            public String getSeverity() {
                return severity;
            }

            public void setSeverity(String severity) {
                this.severity = severity;
            }

            public String toString() {
                return
                        "ID: " + id + "\n" +
                                "type: " + type + "\n" +
                                "name: " + name + "\n" +
                                "title: " + title + "\n" +
                                "description: " + description + "\n" +
                                "remediation: " + remediation + "\n" +
                                "severity: " + severity;
            }
        }
    }

    public static class Layers {
        private String digest;
        private String size;
        private String createdAt;
        private String createdBy;
        private String type;
        private String layer_inventory_s3_key;

        public String getDigest() {
            return digest;
        }

        public void setDigest(String digest) {
            this.digest = digest;
        }

        public String getSize() {
            return size;
        }

        public void setSize(String size) {
            this.size = size;
        }

        public String getCreatedAt() {
            return timeFormat(createdAt);
        }

        public void setCreatedAt(String createdAt) {
            this.createdAt = createdAt;
        }

        public String getCreatedBy() {
            return createdBy;
        }

        public void setCreatedBy(String createdBy) {
            this.createdBy = createdBy;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getLayer_inventory_s3_key() {
            return layer_inventory_s3_key;
        }

        public void setLayer_inventory_s3_key(String layer_inventory_s3_key) {
            this.layer_inventory_s3_key = layer_inventory_s3_key;
        }
    }

    public static class Packages {
        private String vendor;
        private String product;
        private String majorVersion;
        private String softwareArchitecture;
        private String packageProvider;
        private String packageSource;
        private String layerHash;
        private int layerIndex;

        public String getVendor() {
            return vendor;
        }

        public void setVendor(String vendor) {
            this.vendor = vendor;
        }

        public String getProduct() {
            return product;
        }

        public void setProduct(String product) {
            this.product = product;
        }

        public String getMajorVersion() {
            return majorVersion;
        }

        public void setMajorVersion(String majorVersion) {
            this.majorVersion = majorVersion;
        }

        public String getSoftwareArchitecture() {
            return softwareArchitecture;
        }

        public void setSoftwareArchitecture(String softwareArchitecture) {
            this.softwareArchitecture = softwareArchitecture;
        }

        public String getPackageProvider() {
            return packageProvider;
        }

        public void setPackageProvider(String packageProvider) {
            this.packageProvider = packageProvider;
        }

        public String getPackageSource() {
            return packageSource;
        }

        public void setPackageSource(String packageSource) {
            this.packageSource = packageSource;
        }

        public String getLayerHash() {
            return layerHash;
        }

        public void setLayerHash(String layerHash) {
            this.layerHash = layerHash;
        }

        public int getLayerIndex() {
            return layerIndex;
        }

        public void setLayerIndex(int layerIndex) {
            this.layerIndex = layerIndex;
        }
    }

    public static class ELFBinaries {
        private String path;
        private String hash;
        private int size;
        private String permissions;
        private String details;
        private boolean malicious;

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }

        public String getHash() {
            return hash;
        }

        public void setHash(String hash) {
            this.hash = hash;
        }

        public int getSize() {
            return size;
        }

        public void setSize(int size) {
            this.size = size;
        }

        public String getPermissions() {
            return permissions;
        }

        public void setPermissions(String permissions) {
            this.permissions = permissions;
        }

        public String getDetails() {
            return details;
        }

        public void setDetails(String details) {
            this.details = details;
        }

        public boolean isMalicious() {
            return malicious;
        }

        public void setMalicious(boolean malicious) {
            this.malicious = malicious;
        }
    }

    public static class InventoryEngineInfo {
        private String collectedAt;
        private String engineVersion;
        private String cwppScannerVersion;
        private String elfModelVersion;

        public String getCollectedAt() {
            return timeFormat(collectedAt);
        }

        public void setCollectedAt(String collectedAt) {
            this.collectedAt = collectedAt;
        }

        public String getEngineVersion() {
            return engineVersion;
        }

        public void setEngineVersion(String engineVersion) {
            this.engineVersion = engineVersion;
        }

        public String getCwppScannerVersion() {
            return cwppScannerVersion;
        }

        public void setCwppScannerVersion(String cwppScannerVersion) {
            this.cwppScannerVersion = cwppScannerVersion;
        }

        public String getElfModelVersion() {
            return elfModelVersion;
        }

        public void setElfModelVersion(String elfModelVersion) {
            this.elfModelVersion = elfModelVersion;
        }
    }

    public static class DetectionEngineInfo {
        private String performedAt;
        private String engineVersion;

        public String getPerformedAt() {
            return timeFormat(performedAt);
        }

        public void setPerformedAt(String performedAt) {
            this.performedAt = performedAt;
        }

        public String getEngineVersion() {
            return engineVersion;
        }

        public void setEngineVersion(String engineVersion) {
            this.engineVersion = engineVersion;
        }
    }

    public static class Manifest {
        private int schemaVersion;
        private String mediaType;
        private Config config;

        public int getSchemaVersion() {
            return schemaVersion;
        }

        public void setSchemaVersion(int schemaVersion) {
            this.schemaVersion = schemaVersion;
        }

        public String getMediaType() {
            return mediaType;
        }

        public void setMediaType(String mediaType) {
            this.mediaType = mediaType;
        }

        public AssessmentData.Manifest.Config getConfig() {
            return config;
        }

        public void setConfig(AssessmentData.Manifest.Config config) {
            this.config = config;
        }

        public static class Config {
            private String mediaType;
            private int size;
            private String digest;

            public String getMediaType() {
                return mediaType;
            }

            public void setMediaType(String mediaType) {
                this.mediaType = mediaType;
            }

            public int getSize() {
                return size;
            }

            public void setSize(int size) {
                this.size = size;
            }

            public String getDigest() {
                return digest;
            }

            public void setDigest(String digest) {
                this.digest = digest;
            }
        }
    }
}
