package com.crowdstrike.plugins.crwds.freemarker;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.TimeZone;

public class PolicyData {

    private Meta meta;
    private ArrayList<Resources> resources;
    private ArrayList<String> errors;

    public Meta getMeta() {
        return meta;
    }

    public void setMeta(Meta meta) {
        this.meta = meta;
    }

    public ArrayList<Resources> getResources() {
        return resources;
    }

    public Resources getFirstResource() {
        return resources.get(0);
    }

    public void setResources(ArrayList<Resources> resources) {
        this.resources = resources;
    }

    public ArrayList<String> getErrors() {
        return errors;
    }

    public void setErrors(ArrayList<String> errors) {
        this.errors = errors;
    }

    public static String timeFormat(String field) {
        Instant instant = Instant.parse(field);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMMM d yyyy',' 'at' hh:mm:ss a O");
        ZonedDateTime zdt = ZonedDateTime.ofInstant(instant, TimeZone.getDefault().toZoneId());
        return zdt.format(formatter);
    }

    public static class Meta {

        private double query_time;
        private String powered_by;
        private String trace_id;

        public double getQuery_time() {
            return query_time;
        }

        public void setQuery_time(double query_time) {
            this.query_time = query_time;
        }

        public String getPowered_by() {
            return powered_by;
        }

        public void setPowered_by(String powered_by) {
            this.powered_by = powered_by;
        }

        public String getTrace_id() {
            return trace_id;
        }

        public void setTrace_id(String trace_id) {
            this.trace_id = trace_id;
        }
    }

    public static class Resources {

        private ResourcesPolicy policy;
        private PolicyGroup policy_group;
        private PolicyType policy_type;
        private PolicyImage image;
        private boolean deny;
        private String action = "";
        private EvaluationDetails evaluation_details;
        private String evaluatedAt;

        public ResourcesPolicy getPolicy() {
            return policy;
        }

        public void setPolicy(ResourcesPolicy policy) {
            this.policy = policy;
        }

        public PolicyGroup getPolicy_group() {
            return policy_group;
        }

        public void setPolicy_group(PolicyGroup policy_group) {
            this.policy_group = policy_group;
        }

        public PolicyType getPolicy_type() {
            return policy_type;
        }

        public void setPolicy_type(PolicyType policy_type) {
            this.policy_type = policy_type;
        }

        public PolicyImage getImage() {
            return image;
        }

        public void setImage(PolicyImage image) {
            this.image = image;
        }

        public boolean isDeny() {
            return deny;
        }

        public void setDeny(boolean deny) {
            this.deny = deny;
        }

        public String getAction() {
            return action;
        }

        public void setAction(String action) {
            this.action = action;
        }

        public EvaluationDetails getEvaluation_details() {
            return evaluation_details;
        }

        public void setEvaluation_details(EvaluationDetails evaluation_details) {
            this.evaluation_details = evaluation_details;
        }

        public String getEvaluatedAt() {
            return evaluatedAt;
        }

        public void setEvaluatedAt(String evaluatedAt) {
            this.evaluatedAt = evaluatedAt;
        }

        public boolean isFine() {
            return !deny;
        }

        public boolean isPrevent() {
            return deny && action.equals("block");
        }

        public boolean isWarn() {
            return deny && action.equals("alert");
        }

        public int policyMatches() {
            return evaluation_details.matched_cve_list.size();
        }

        public String actionDisplay() {
            return action.equals("block")? "Prevent" : "Alert";
        }

        public static class ResourcesPolicy {
            private String uuid;
            private String name;
            private String description;
            private boolean is_enabled;
            private boolean is_default;
            private int precedence;
            private String created_at;
            private String updated_at;

            public String getUuid() {
                return uuid;
            }

            public void setUuid(String uuid) {
                this.uuid = uuid;
            }

            public String getName() {
                return name;
            }

            public void setName(String name) {
                this.name = name;
            }

            public String getDescription() {
                return description;
            }

            public void setDescription(String description) {
                this.description = description;
            }

            public boolean isIs_enabled() {
                return is_enabled;
            }

            public void setIs_enabled(boolean is_enabled) {
                this.is_enabled = is_enabled;
            }

            public boolean isIs_default() {
                return is_default;
            }

            public void setIs_default(boolean is_default) {
                this.is_default = is_default;
            }

            public int getPrecedence() {
                return precedence;
            }

            public void setPrecedence(int precedence) {
                this.precedence = precedence;
            }

            public String getCreated_at() {
                return timeFormat(created_at);
            }

            public void setCreated_at(String created_at) {
                this.created_at = created_at;
            }

            public String getUpdated_at() {
                return timeFormat(updated_at);
            }

            public void setUpdated_at(String updated_at) {
                this.updated_at = updated_at;
            }
        }

        public static class PolicyGroup {
            private String uuid;
            private String name;
            private String description;
            private String created_at;
            private String updated_at;

            public String getUuid() {
                return uuid;
            }

            public void setUuid(String uuid) {
                this.uuid = uuid;
            }

            public String getName() {
                return name;
            }

            public void setName(String name) {
                this.name = name;
            }

            public String getDescription() {
                return description;
            }

            public void setDescription(String description) {
                this.description = description;
            }

            public String getCreated_at() {
                return timeFormat(created_at);
            }

            public void setCreated_at(String created_at) {
                this.created_at = created_at;
            }

            public String getUpdated_at() {
                return timeFormat(updated_at);
            }

            public void setUpdated_at(String updated_at) {
                this.updated_at = updated_at;
            }
        }

        public static class PolicyType {
            private String uuid;
            private String name;
            private String description;
            private String policy_type;
            private String version;

            public String getUuid() {
                return uuid;
            }

            public void setUuid(String uuid) {
                this.uuid = uuid;
            }

            public String getName() {
                return name;
            }

            public void setName(String name) {
                this.name = name;
            }

            public String getDescription() {
                return description;
            }

            public void setDescription(String description) {
                this.description = description;
            }

            public String getPolicy_type() {
                return policy_type;
            }

            public void setPolicy_type(String policy_type) {
                this.policy_type = policy_type;
            }

            public String getVersion() {
                return version;
            }

            public void setVersion(String version) {
                this.version = version;
            }
        }

        public static class PolicyImage {
            private String registry;
            private String repository;
            private String tag;
            private String image_id;
            private String image_digest;

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

            public String getImage_id() {
                return image_id;
            }

            public void setImage_id(String image_id) {
                this.image_id = image_id;
            }

            public String getImage_digest() {
                return image_digest;
            }

            public void setImage_digest(String image_digest) {
                this.image_digest = image_digest;
            }
        }

        public static class EvaluationDetails {
            private ArrayList<String> matched_cve_list;
            private ArrayList<String> excluded_cve_list;

            public ArrayList<String> getMatched_cve_list() {
                return matched_cve_list;
            }

            public void setMatched_cve_list(ArrayList<String> matched_cve_list) {
                this.matched_cve_list = matched_cve_list;
            }

            public ArrayList<String> getExcluded_cve_list() {
                return excluded_cve_list;
            }

            public void setExcluded_cve_list(ArrayList<String> excluded_cve_list) {
                this.excluded_cve_list = excluded_cve_list;
            }

            public boolean isCveIdInExcludedCveList(String cveId) {
                for (String s : excluded_cve_list) {
                    if(cveId.equalsIgnoreCase(s))
                        return true;
                }

                return false;
            }

            public boolean isCveIdInMatchedCveList(String cveId) {
                for (String s : matched_cve_list) {
                    if(cveId.equalsIgnoreCase(s))
                        return true;
                }

                return false;
            }
        }
    }
}

