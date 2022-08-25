package com.crowdstrike.plugins.crwds.freemarker;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AssessmentData {

    private final String[] severitiesList = new String[] {"critical", "high", "medium", "low", "negligible"};

    // @SerializedName(value = "scanInfo", alternate = {"ScanInfo", "Scaninfo"})
    private ScanInfo ScanInfo;
    private ImageInfo ImageInfo;
    private Config Config;
    private OSInfo OSInfo;
    private ArrayList<Vulnerabilities> Vulnerabilities;
    private ArrayList<Detections> Detections;
    private ArrayList<Layers> Layers;
    private ArrayList<Packages> Packages;
    private ArrayList<ELFBinaries> ELFBinaries;
    private InventoryEngineInfo InventoryEngineInfo;
    private DetectionEngineInfo DetectionEngineInfo;

    private Manifest Manifest;

    public AssessmentData.ScanInfo getScanInfo() {
        return ScanInfo;
    }

    public void setScanInfo(AssessmentData.ScanInfo scanInfo) {
        ScanInfo = scanInfo;
    }

    public AssessmentData.ImageInfo getImageInfo() {
        return ImageInfo;
    }

    public void setImageInfo(AssessmentData.ImageInfo imageInfo) {
        ImageInfo = imageInfo;
    }

    public AssessmentData.Config getConfig() {
        return Config;
    }

    public void setConfig(AssessmentData.Config config) {
        Config = config;
    }

    public AssessmentData.OSInfo getOSInfo() {
        return OSInfo;
    }

    public void setOSInfo(AssessmentData.OSInfo OSInfo) {
        this.OSInfo = OSInfo;
    }

    public ArrayList<AssessmentData.Vulnerabilities> getVulnerabilities() {
        return Vulnerabilities;
    }

    public void setVulnerabilities(ArrayList<AssessmentData.Vulnerabilities> vulnerabilities) {
        Vulnerabilities = vulnerabilities;
    }

    public ArrayList<AssessmentData.Detections> getDetections() {
        return Detections;
    }

    public void setDetections(ArrayList<AssessmentData.Detections> detections) {
        Detections = detections;
    }

    public ArrayList<AssessmentData.Layers> getLayers() {
        return Layers;
    }

    public void setLayers(ArrayList<AssessmentData.Layers> layers) {
        Layers = layers;
    }

    public ArrayList<AssessmentData.Packages> getPackages() {
        return Packages;
    }

    public void setPackages(ArrayList<AssessmentData.Packages> packages) {
        Packages = packages;
    }

    public ArrayList<AssessmentData.ELFBinaries> getELFBinaries() {
        return ELFBinaries;
    }

    public void setELFBinaries(ArrayList<AssessmentData.ELFBinaries> ELFBinaries) {
        this.ELFBinaries = ELFBinaries;
    }

    public AssessmentData.InventoryEngineInfo getInventoryEngineInfo() {
        return InventoryEngineInfo;
    }

    public void setInventoryEngineInfo(AssessmentData.InventoryEngineInfo inventoryEngineInfo) {
        InventoryEngineInfo = inventoryEngineInfo;
    }

    public AssessmentData.DetectionEngineInfo getDetectionEngineInfo() {
        return DetectionEngineInfo;
    }

    public void setDetectionEngineInfo(AssessmentData.DetectionEngineInfo detectionEngineInfo) {
        DetectionEngineInfo = detectionEngineInfo;
    }

    public AssessmentData.Manifest getManifest() { return Manifest; }

    public void setManifest(AssessmentData.Manifest manifest) {
        Manifest = manifest;
    }

    public int vulnerabilitiesCriticalCount() {
        int count = 0;
        if(Vulnerabilities != null) {
            for (Vulnerabilities vuls : Vulnerabilities) {
                Vulnerabilities.Vulnerability vul = vuls.Vulnerability;
                if(vul != null && vul.Details != null && vul.Details.severity.equalsIgnoreCase("CRITICAL")) {
                    count++;
                }
            }
        }

        return count;
    }

    public int vulnerabilitiesRemediationsCount() {
        int count = 0;
        if(Vulnerabilities != null) {
            for (Vulnerabilities vuls : Vulnerabilities) {
                Vulnerabilities.Vulnerability vul = vuls.Vulnerability;
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
            severities.put(s.toUpperCase(), 0);
        }
        if (Vulnerabilities != null) {
            for (Vulnerabilities vuls : Vulnerabilities) {
                if (vuls.Vulnerability != null) {
                    Vulnerabilities.Vulnerability vul = vuls.Vulnerability;
                    if (vul.Details != null) {
                        Integer currCount = severities.getOrDefault(vul.Details.severity.toUpperCase(), 0);
                        severities.put(vul.Details.severity.toUpperCase(), currCount + 1);
                    }
                }
            }
        }

        return severities;
    }

    public ArrayList<AssessmentData.Vulnerabilities.Vulnerability> vulnerabilityBySeverity(String severity) {
        ArrayList<AssessmentData.Vulnerabilities.Vulnerability> vulns = new ArrayList<>();
        if(Vulnerabilities != null) {
            for (Vulnerabilities vuls : Vulnerabilities) {
                Vulnerabilities.Vulnerability vul = vuls.Vulnerability;
                if (vul != null && vul.Details != null && vul.Details.severity.equalsIgnoreCase(severity))
                    vulns.add(vul);
            }
        }

        return vulns;
    }

    public String vulnerabilityCVEIDByLayer(Layers layer) {
        if (Vulnerabilities != null) {
            for (Vulnerabilities vul : Vulnerabilities) {
                if (vul.Vulnerability != null && vul.Vulnerability.LayerHash.equalsIgnoreCase(layer.Digest))
                    return vul.Vulnerability.CVEID;
            }
        }

        return "";
    }

    public String severityColor(String severity) {
        switch (severity.toLowerCase()) {
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
        switch (severity.toLowerCase()) {
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
        switch (type.toLowerCase()) {
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
                "Scan Info: " + this.ScanInfo.toString() + "\n" +
                        "Image Info: " + this.ImageInfo.toString() + "\n" +
                        "Config: " + this.Config.toString() + "\n" +
                        "OS Info: " + this.OSInfo.toString() + "\n" +
                        "Vulnerabilities: " + this.Vulnerabilities.toString() + "\n" +
                        "Detections: " + this.Detections.toString() + "\n" +
                        "Layers: " + this.Layers.toString() + "\n" +
                        "Packages: " + this.Packages.toString() + "\n" +
                        "ELF Binaries: " + this.ELFBinaries.toString() + "\n" +
                        "Inventory Engine Info: " + this.InventoryEngineInfo.toString() + "\n" +
                        "Detection Engine Info: " + this.DetectionEngineInfo.toString();
    }

    public static class ScanInfo {
        private String cid;
        private String Username;
        private String UserUUID;
        private String ScanUUID;
        private String CorrelationUUID;
        private String RequestedAt;

        public String getCid() {
            return cid;
        }

        public void setCid(String cid) {
            this.cid = cid;
        }

        public String getUsername() {
            return Username;
        }

        public void setUsername(String username) {
            Username = username;
        }

        public String getUserUUID() {
            return UserUUID;
        }

        public void setUserUUID(String userUUID) {
            UserUUID = userUUID;
        }

        public String getScanUUID() {
            return ScanUUID;
        }

        public void setScanUUID(String scanUUID) {
            ScanUUID = scanUUID;
        }

        public String getCorrelationUUID() {
            return CorrelationUUID;
        }

        public void setCorrelationUUID(String correlationUUID) {
            CorrelationUUID = correlationUUID;
        }

        public String getRequestedAt() {
            return RequestedAt;
        }

        public void setRequestedAt(String requestedAt) {
            RequestedAt = requestedAt;
        }

        public String getRequestedAtFormatted() {
            return timeFormat(RequestedAt);
        }

        public String toString() {
            return
                    "cid : " + cid + "\n" +
                            "username : " + Username + "\n" +
                            "userUUID : " + UserUUID + "\n" +
                            "scanUUID : " + ScanUUID + "\n" +
                            "correlationUUID : " + CorrelationUUID + "\n" +
                            "requestedAt : " + RequestedAt;
        }
    }

    public static class ImageInfo {
        private String Registry;
        private String Repository;
        private String Tag;
        private String ID;
        private String Digest;
        private String Size;
        private String CreatedAt;
        private String Architecture;
        private String scan_request_s3_key;

        public String getRegistry() {
            return Registry;
        }

        public void setRegistry(String registry) {
            Registry = registry;
        }

        public String getRepository() {
            return Repository;
        }

        public void setRepository(String repository) {
            Repository = repository;
        }

        public String getTag() {
            return Tag;
        }

        public void setTag(String tag) {
            Tag = tag;
        }

        public String getID() {
            return ID;
        }

        public void setID(String ID) {
            this.ID = ID;
        }

        public String getDigest() {
            return Digest;
        }

        public void setDigest(String digest) {
            Digest = digest;
        }

        public String getSize() {
            return Size;
        }

        public void setSize(String size) {
            Size = size;
        }

        public String getCreatedAt() {
            return timeFormat(CreatedAt);
        }

        public void setCreatedAt(String createdAt) {
            CreatedAt = createdAt;
        }

        public String getArchitecture() {
            return Architecture;
        }

        public void setArchitecture(String architecture) {
            Architecture = architecture;
        }

        public String getScan_request_s3_key() {
            return scan_request_s3_key;
        }

        public void setScan_request_s3_key(String scan_request_s3_key) {
            this.scan_request_s3_key = scan_request_s3_key;
        }

        public String toString() {
            return
                    "registry: " + Registry + "\n" +
                            "repository: " + Repository + "\n" +
                            "tag: " + Tag + "\n" +
                            "id: " + ID + "\n" +
                            "digest: " + Digest + "\n" +
                            "size: " + Size + "\n" +
                            "createdAt: " + CreatedAt + "\n" +
                            "architecture: " + Architecture + "\n" +
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
        private String Name;
        private String Version;

        public String getName() {
            return Name;
        }

        public void setName(String name) {
            Name = name;
        }

        public String getVersion() {
            return Version;
        }

        public void setVersion(String version) {
            Version = version;
        }

        public String toString() {
            return
                    "name: " + Name + "\n" +
                            "version: " + Version;
        }
    }

    public static class Vulnerabilities {
        private Vulnerability Vulnerability;

        public AssessmentData.Vulnerabilities.Vulnerability getVulnerability() {
            return Vulnerability;
        }

        public void setVulnerability(AssessmentData.Vulnerabilities.Vulnerability vulnerability) {
            Vulnerability = vulnerability;
        }

        public static class Vulnerability {
            private String CVEID;
            private String LayerHash;
            private String FirstSeen;
            private Product Product;
            private String ContentDataHash;
            private ArrayList<String> Remediation;
            private Details Details;
            private ExploitedDetails ExploitedDetails;

            public String getCVEID() {
                return CVEID;
            }

            public void setCVEID(String CVEID) {
                this.CVEID = CVEID;
            }

            public String getLayerHash() {
                return LayerHash;
            }

            public void setLayerHash(String layerHash) {
                LayerHash = layerHash;
            }

            public String getFirstSeen() {
                return timeFormat(FirstSeen);
            }

            public void setFirstSeen(String firstSeen) {
                FirstSeen = firstSeen;
            }

            public AssessmentData.Vulnerabilities.Vulnerability.Product getProduct() {
                return Product;
            }

            public void setProduct(AssessmentData.Vulnerabilities.Vulnerability.Product product) {
                Product = product;
            }

            public String getContentDataHash() {
                return ContentDataHash;
            }

            public void setContentDataHash(String contentDataHash) {
                ContentDataHash = contentDataHash;
            }

            public ArrayList<String> getRemediation() {
                return Remediation;
            }

            public void setRemediation(ArrayList<String> remediation) {
                Remediation = remediation;
            }

            public AssessmentData.Vulnerabilities.Vulnerability.Details getDetails() {
                return Details;
            }

            public void setDetails(AssessmentData.Vulnerabilities.Vulnerability.Details details) {
                Details = details;
            }

            public AssessmentData.Vulnerabilities.Vulnerability.ExploitedDetails getExploitedDetails() {
                return ExploitedDetails;
            }

            public void setExploitedDetails(AssessmentData.Vulnerabilities.Vulnerability.ExploitedDetails exploitedDetails) {
                ExploitedDetails = exploitedDetails;
            }

            public int remediationsCount() {
                int count = 0;
                if (Remediation != null) {
                    for (String s : Remediation) {
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
                if (Remediation != null) {
                    for (String s : Remediation) {
                        if (!isHash(s)) {
                            remediations.add(s);
                        }
                    }
                }

                return remediations;
            }

            public static class Product {
                private String PackageSource;

                public String getPackageSource() {
                    return PackageSource;
                }

                public void setPackageSource(String PackageSource) {
                    this.PackageSource = PackageSource;
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
                private String URL;
                private ArrayList<String> Tags;

                public String getURL() {
                    return URL;
                }

                public void setURL(String URL) {
                    this.URL = URL;
                }

                public ArrayList<String> getTags() {
                    return Tags;
                }

                public void setTags(ArrayList<String> Tags) {
                    this.Tags = Tags;
                }
            }
        }
    }

    public static class Detections {
        private Detection Detection;

        public AssessmentData.Detections.Detection getDetection() {
            return Detection;
        }

        public void setDetection(AssessmentData.Detections.Detection detection) {
            Detection = detection;
        }

        public String toString() {
            return Detection.toString();
        }

        public static class Detection {
            private String ID;
            private String Type;
            private String Name;
            private String Title;
            private String Description;
            private String Remediation;
            private String Severity;

            public String getID() {
                return ID;
            }

            public void setID(String ID) {
                this.ID = ID;
            }

            public String getType() {
                return Type;
            }

            public void setType(String type) {
                Type = type;
            }

            public String getName() {
                return Name;
            }

            public void setName(String name) {
                Name = name;
            }

            public String getTitle() {
                return Title;
            }

            public void setTitle(String title) {
                Title = title;
            }

            public String getDescription() {
                return Description;
            }

            public void setDescription(String description) {
                Description = description;
            }

            public String getRemediation() {
                return Remediation;
            }

            public void setRemediation(String remediation) {
                Remediation = remediation;
            }

            public String getSeverity() {
                return Severity;
            }

            public void setSeverity(String severity) {
                Severity = severity;
            }

            public String toString() {
                return
                        "ID: " + ID + "\n" +
                                "type: " + Type + "\n" +
                                "name: " + Name + "\n" +
                                "title: " + Title + "\n" +
                                "description: " + Description + "\n" +
                                "remediation: " + Remediation + "\n" +
                                "severity: " + Severity;
            }
        }
    }

    public static class Layers {
        private String Digest;
        private String Size;
        private String CreatedAt;
        private String CreatedBy;
        private String type;
        private String layer_inventory_s3_key;

        public String getDigest() {
            return Digest;
        }

        public void setDigest(String digest) {
            Digest = digest;
        }

        public String getSize() {
            return Size;
        }

        public void setSize(String size) {
            Size = size;
        }

        public String getCreatedAt() {
            return timeFormat(CreatedAt);
        }

        public void setCreatedAt(String createdAt) {
            CreatedAt = createdAt;
        }

        public String getCreatedBy() {
            return CreatedBy;
        }

        public void setCreatedBy(String createdBy) {
            CreatedBy = createdBy;
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
        private String Vendor;
        private String Product;
        private String MajorVersion;
        private String SoftwareArchitecture;
        private String PackageProvider;
        private String PackageSource;
        private String LayerHash;
        private int LayerIndex;

        public String getVendor() {
            return Vendor;
        }

        public void setVendor(String vendor) {
            Vendor = vendor;
        }

        public String getProduct() {
            return Product;
        }

        public void setProduct(String product) {
            Product = product;
        }

        public String getMajorVersion() {
            return MajorVersion;
        }

        public void setMajorVersion(String majorVersion) {
            MajorVersion = majorVersion;
        }

        public String getSoftwareArchitecture() {
            return SoftwareArchitecture;
        }

        public void setSoftwareArchitecture(String softwareArchitecture) {
            SoftwareArchitecture = softwareArchitecture;
        }

        public String getPackageProvider() {
            return PackageProvider;
        }

        public void setPackageProvider(String packageProvider) {
            PackageProvider = packageProvider;
        }

        public String getPackageSource() {
            return PackageSource;
        }

        public void setPackageSource(String packageSource) {
            PackageSource = packageSource;
        }

        public String getLayerHash() {
            return LayerHash;
        }

        public void setLayerHash(String layerHash) {
            LayerHash = layerHash;
        }

        public int getLayerIndex() {
            return LayerIndex;
        }

        public void setLayerIndex(int layerIndex) {
            LayerIndex = layerIndex;
        }
    }

    public static class ELFBinaries {
        private String Path;
        private String Hash;
        private int Size;
        private String Permissions;
        private String Details;
        private boolean Malicious;

        public String getPath() {
            return Path;
        }

        public void setPath(String path) {
            Path = path;
        }

        public String getHash() {
            return Hash;
        }

        public void setHash(String hash) {
            Hash = hash;
        }

        public int getSize() {
            return Size;
        }

        public void setSize(int size) {
            Size = size;
        }

        public String getPermissions() {
            return Permissions;
        }

        public void setPermissions(String permissions) {
            Permissions = permissions;
        }

        public String getDetails() {
            return Details;
        }

        public void setDetails(String details) {
            Details = details;
        }

        public boolean isMalicious() {
            return Malicious;
        }

        public void setMalicious(boolean malicious) {
            Malicious = malicious;
        }
    }

    public static class InventoryEngineInfo {
        private String CollectedAt;
        private String EngineVersion;
        private String CWPPScannerVersion;
        private String ELFModelVersion;

        public String getCollectedAt() {
            return timeFormat(CollectedAt);
        }

        public void setCollectedAt(String collectedAt) {
            CollectedAt = collectedAt;
        }

        public String getEngineVersion() {
            return EngineVersion;
        }

        public void setEngineVersion(String engineVersion) {
            EngineVersion = engineVersion;
        }

        public String getCWPPScannerVersion() {
            return CWPPScannerVersion;
        }

        public void setCWPPScannerVersion(String CWPPScannerVersion) {
            this.CWPPScannerVersion = CWPPScannerVersion;
        }

        public String getELFModelVersion() {
            return ELFModelVersion;
        }

        public void setELFModelVersion(String ELFModelVersion) {
            this.ELFModelVersion = ELFModelVersion;
        }
    }

    public static class DetectionEngineInfo {
        private String PerformedAt;
        private String EngineVersion;

        public String getPerformedAt() {
            return timeFormat(PerformedAt);
        }

        public void setPerformedAt(String performedAt) {
            PerformedAt = performedAt;
        }

        public String getEngineVersion() {
            return EngineVersion;
        }

        public void setEngineVersion(String engineVersion) {
            EngineVersion = engineVersion;
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