<head>
    <title>Assessment | CrowdStrike Security</title>
    <link rel="stylesheet" href= />
    <body>
        <div class="content">
            <div id="header">
                <div id="top-left">
                    <div class="type-4xl c-tna mr-1">Assessment Results</div>
                </div>
                <div id="top-right">
                    <div class="d-f f-a-c f-jc-fe">
                        <#if (policyData.getFirstResource().isPrevent())!false>
                            ${(assessmentData.getIconByType("failure"))!}
                            <span class="type-xl c-critical i-text">
                                <#if neverFail??>
                                    (Ignored) Falcon Recommendation : Prevent Build
                                <#else>
                                    Falcon Prevented Build
                                </#if>
                            </span>
                        <#else>
                            ${(assessmentData.getIconByType("success"))!}
                            <span class="type-xl c-positive i-text">Falcon Allowed Build</span>
                        </#if>
                    </div>
                    <span class="type-xs c-tni">Image assessed on ${(assessmentData.getScanInfo().getRequestedAtFormatted())!}</span>
                </div>
            </div>
            <div id="header2" class="mt-3 p-3 box">
                <div class="type-xl c-tni mb-3">Container Image</div>
                <div class="form-row">
                    <div class="form-col">
                        <div class="form-field"><label class="type-md c-bal mb-1">Registry</label>
                            <span class="type-lg c-tna mr-1">
                                <span title="${(assessmentData.getImageInfo().getRegistry())!}" class="type-truncate">${(assessmentData.getImageInfo().getRegistry())!}</span>
                            </span>
                        </div>
                        <div class="form-field"><label class="type-md c-bal mb-1">Base OS</label>
                            <span class="type-lg c-tna mr-1">
                                <span title="${(assessmentData.getOSInfo().getName())!}" class="type-truncate">${(assessmentData.getOSInfo().getName())!}</span>
                            </span>
                        </div>
                    </div>
                    <div class="form-col">
                        <div class="form-field"><label class="type-md c-bal mb-1">Repository</label>
                            <span class="type-lg c-tna mr-1">
                                <span title="${(assessmentData.getImageInfo().getRepository())!}" class="type-truncate">${(assessmentData.getImageInfo().getRepository())!}</span>
                            </span>
                        </div>
                        <div class="form-field"><label class="type-md c-bal mb-1">Arch</label>
                            <span class="type-lg c-tna mr-1">
                                <span title="${(assessmentData.getConfig().getArchitecture())!}" class="type-truncate">${(assessmentData.getConfig().getArchitecture())!}</span>
                            </span>
                        </div>
                    </div>
                    <div class="form-col">
                        <div class="form-field"><label class="type-md c-bal mb-1">Image Tags</label>
                            <span class="type-lg c-tna mr-1">
                                <span title="${(assessmentData.getImageInfo().getTag())!}" class="type-truncate">${(assessmentData.getImageInfo().getTag())!}</span>
                            </span>
                        </div>
                        <div class="form-field"><label class="type-md c-bal mb-1">Image Size</label>
                            <span class="type-lg c-tna mr-1">
                                <span title="${(assessmentData.getImageInfo().getSize())!}" class="type-truncate">${(assessmentData.getImageInfo().getSize())!}</span>
                            </span>
                        </div>
                    </div>
                    <div class="form-col">
                        <div class="form-field"><label class="type-md c-bal mb-1">Image ID</label>
                            <span class="type-lg c-tna mr-1">
                                <span title="${(assessmentData.getImageInfo().getID())!}" class="type-truncate">${(assessmentData.getImageInfo().getID())!}</span>
                            </span>
                        </div>
                        <div class="form-field"><label class="type-md c-bal mb-1">Image Digest</label>
                            <span class="type-lg c-tna mr-1">
                                <span title="${(assessmentData.getImageInfo().getDigest())!}" class="type-truncate">${(assessmentData.getImageInfo().getDigest())!}</span>
                            </span>
                        </div>
                    </div>
                </div>
            </div>
            <div id="header3" class="mt-3 p-3 box">
                <#if (policyData.getFirstResource().isFine())!false>
                    <div class="type-xl c-tna mr-1 mb-2">${"No Policy Recommendations"}</div>
                <#elseif (policyData.getFirstResource().isPrevent())!false>
                    <div class="type-xl c-critical mb-2">${"Policy Recommendation \g Issue Correction"}</div>
                <#elseif (policyData.getFirstResource().isWarn())!true>
                    <div class="type-xl c-high mb-2">${"Policy Recommendation \g Caution"}</div>
                </#if>
                <div class="tabs">
                    <ul class="tab-nav">
                        <li class="tab p-2 type-usn">
                            <label for="tab1-${uniqueId}">
                                <div class="type-md tab-title mb-1">Policies</div>
                                <div class="tab-label-row">
                                    <div class="tab-label-col">
                                        <#if (policyData.getFirstResource().isWarn())!false>
                                            <label class="type-xs c-nh">Warnings</label>
                                            <span class="type-2xl c-high" title="${(policyData.getFirstResource().policyMatches())!}">${(policyData.getFirstResource().policyMatches())!}</span>
                                        <#else>
                                            <label class="type-xs c-nh">Matches</label>
                                            <#if (policyData.getFirstResource().isPrevent())!false>
                                                <span class="type-2xl c-critical" title="${(policyData.getFirstResource().policyMatches())!}">${(policyData.getFirstResource().policyMatches())!}</span>
                                            <#else>
                                                <span class="type-2xl">0</span>
                                            </#if>
                                        </#if>
                                    </div>
                                </div>
                            </label>
                        </li>
                        <div class="type-md c-tni bt-1 pt-3 pb-2">Additional Information</div>
                        <li class="tab p-2 type-usn">
                            <label for="tab2-${uniqueId}">
                                <div class="type-md tab-title mb-1">Vulnerabilities</div>
                                <div class="tab-label-row">
                                    <div class="tab-label-col">
                                        <label class="type-xs c-nh">Critical</label>
                                        <#if (assessmentData.vulnerabilitiesCriticalCount() != 0)!false>
                                            <span class="type-2xl c-critical" title="${(assessmentData.vulnerabilitiesCriticalCount())!0}">${(assessmentData.vulnerabilitiesCriticalCount())!0}
                                                <i class="i-divider"></i>
                                            </span>
                                        <#else>
                                            <span class="type-2xl" title="0">0<i class="i-divider"></i></span>
                                        </#if>
                                    </div>
                                    <div class="tab-label-col">
                                        <label class="type-xs c-nh">All</label>
                                        <span class="type-2xl" title="${(assessmentData.getVulnerabilities()?size)!0}">${(assessmentData.getVulnerabilities()?size)!0}
                                            <i class="i-divider"></i>
                                        </span>
                                    </div>
                                    <div class="tab-label-col">
                                        <label class="type-xs c-nh">Remediations</label>
                                        <span class="type-2xl" title="${(assessmentData.vulnerabilitiesRemediationsCount())!0}">${(assessmentData.vulnerabilitiesRemediationsCount())!0}</span>
                                    </div>
                                </div>
                            </label>
                        </li>
                        <li class="tab p-2 type-usn">
                            <label for="tab3-${uniqueId}">
                                <div class="type-md tab-title mb-1">Detections</div>
                                <div class="tab-label-row">
                                    <div class="tab-label-col">
                                        <span class="type-2xl" title="${(assessmentData.getDetections()?size)!0}">${(assessmentData.getDetections()?size)!0}</span>
                                    </div>
                                </div>
                            </label>
                        </li>
                        <li class="tab p-2 type-usn">
                            <label for="tab4-${uniqueId}">
                                <div class="type-md tab-title mb-1" for="tab4-${uniqueId}">Layers</div>
                                <div class="tab-label-row">
                                    <div class="tab-label-col">
                                        <span class="type-2xl" title="${(assessmentData.getLayers()?size)!0}">${(assessmentData.getLayers()?size)!0}</span>
                                    </div>
                                </div>
                            </label>
                        </li>
                    </ul>
                    <div class="tab-data">
                        <input type="radio" name="tabs" checked="checked" id="tab1-${uniqueId}"/>
                        <div id="tab-content1-${uniqueId}" class="tab-content pl-4">
                            <div class="mb-3 c-tna mr-1">Policy Matches</div>
                            <div class="type-md type-tal">
                                <table class="table mb-3 w-100">
                                    <thead>
                                    <tr class="bg-dark-1">
                                        <th class="w-50"><span>CVEs Matched</span></th>
                                        <th class="w-50"><span>Excluded from Policy</span></th>
                                    </tr>
                                    </thead>
                                    <#list (policyData.getFirstResource().getEvaluation_details().getMatched_cve_list())![] as cve_list>
                                        <tbody>
                                        <tr class="bg-dark-2">
                                            <td>
                                                <span>${cve_list}</span>
                                            </td>
                                            <td>
                                                <#if (policyData.getFirstResource().getEvaluation_details().isCveIdInExcludedCveList(cve_list))!false>
                                                    <span>
                                                        ${(assessmentData.getIconByType("positive"))!}
                                                    </span>
                                                </#if>
                                            </td>
                                        </tr>
                                        </tbody>
                                    </#list>
                                </table>
                                <div class="form-row">
                                    <div class="form-col">
                                        <div class="form-field">
                                            <label class="type-md c-bal mb-1">Policy Name</label>
                                            <span class="type-lg c-tna mr-1">
                                                <span title="${(policyData.getFirstResource().getPolicy().getName())!}" class="type-truncate">${(policyData.getFirstResource().getPolicy().getName())!}</span>
                                            </span>
                                        </div>
                                        <div class="form-field">
                                            <label class="type-md c-bal mb-1">Policy Description</label>
                                            <span class="type-lg c-tna mr-1">
                                                <span title="${(policyData.getFirstResource().getPolicy().getDescription())!}" class="type-truncate">${(policyData.getFirstResource().getPolicy().getDescription())!}</span>
                                            </span>
                                        </div>
                                        <div class="form-field">
                                            <label class="type-md c-bal mb-1">Policy Created At</label>
                                            <span class="type-lg c-tna mr-1">
                                                <span title="${(policyData.getFirstResource().getPolicy().getCreated_at())!}" class="type-truncate">${(policyData.getFirstResource().getPolicy().getCreated_at())!}</span>
                                            </span>
                                        </div>
                                        <div class="form-field">
                                            <label class="type-md c-bal mb-1">Policy Updated At</label>
                                            <span class="type-lg c-tna mr-1">
                                                <span title="${(policyData.getFirstResource().getPolicy().getUpdated_at())!}" class="type-truncate">${(policyData.getFirstResource().getPolicy().getUpdated_at())!}</span>
                                            </span>
                                        </div>
                                        <div class="form-field">
                                            <label class="type-md c-bal mb-1">Policy Precedence</label>
                                            <span class="type-lg c-tna mr-1">
                                                <span title="${(policyData.getFirstResource().getPolicy().getPrecedence())!}" class="type-truncate">${(policyData.getFirstResource().getPolicy().getPrecedence())!}</span>
                                            </span>
                                        </div>
                                    </div>
                                    <div class="form-col">
                                        <div class="form-field">
                                            <label class="type-md c-bal mb-1">Policy Type Name</label>
                                            <span class="type-lg c-tna mr-1">
                                                <span title="${(policyData.getFirstResource().getPolicy_type().getName())!}" class="type-truncate">${(policyData.getFirstResource().getPolicy_type().getName())!}</span>
                                            </span>
                                        </div>
                                        <div class="form-field">
                                            <label class="type-md c-bal mb-1">Policy Type Description</label>
                                            <span class="type-lg c-tna mr-1">
                                                <span title="${(policyData.getFirstResource().getPolicy_type().getDescription())!}" class="type-truncate">${(policyData.getFirstResource().getPolicy_type().getDescription())!}</span>
                                            </span>
                                        </div>
                                        <div class="form-field">
                                            <label class="type-md c-bal mb-1">Policy Action</label>
                                            <span class="type-lg c-tna mr-1">
                                                <span title="${(policyData.getFirstResource().actionDisplay())!}" class="type-truncate">${(policyData.getFirstResource().actionDisplay())!}</span>
                                            </span>
                                        </div>
                                    </div>
                                    <div class="form-col">
                                        <div class="form-field">
                                            <label class="type-md c-bal mb-1">Policy Group Name</label>
                                            <span class="type-lg c-tna mr-1">
                                                <span title="${(policyData.getFirstResource().getPolicy_group().getName())!}" class="type-truncate">${(policyData.getFirstResource().getPolicy_group().getName())!}</span>
                                            </span>
                                        </div>
                                        <div class="form-field">
                                            <label class="type-md c-bal mb-1">Policy Group Description</label>
                                            <span class="type-lg c-tna mr-1">
                                                <span title="${(policyData.getFirstResource().getPolicy_group().getDescription())!}" class="type-truncate">${(policyData.getFirstResource().getPolicy_group().getDescription())!}</span>
                                            </span>
                                        </div>
                                        <div class="form-field">
                                            <label class="type-md c-bal mb-1">Policy Group Created At</label>
                                            <span class="type-lg c-tna mr-1">
                                                <span title="${(policyData.getFirstResource().getPolicy_group().getCreated_at())!}" class="type-truncate">${(policyData.getFirstResource().getPolicy_group().getCreated_at())!}</span>
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <input type="radio" name="tabs" id="tab2-${uniqueId}"/>
                        <div id="tab-content2-${uniqueId}" class="tab-content pl-4">
                            <div class="folds">
                                <#assign severityMap = (assessmentData.severitiesAndCount())!/>
                                <#list (severityMap?keys)![] as key>
                                    <div class="fold">
                                        <input type="checkbox" id="check${key?index}-${uniqueId}"/>
                                        <label class="fold-label p-2" for="check${key?index}-${uniqueId}">
                                            ${(assessmentData.getIconByType(key))!}
                                            <span class="type-lg c-tna mr-1">${(assessmentData.severityLabel(key))!} (${(severityMap[key])!})</span>
                                            ${(assessmentData.getIconByType("arrow"))!}
                                        </label>
                                        <div class="fold-content bg-dark-1 type-md">
                                            <div class="folds-header-row row p-2">
                                                <span class="cell1">Vulnerability</span>
                                                <span class="cell2">Package Name & Version</span>
                                                <span class="cell3">Severity</span>
                                                <span class="cell4">CVSS Version</span>
                                                <span class="cell5">Remediation</span>
                                                <span class="cell6">Policy Matched</span>
                                            </div>
                                            <div class="vulns">
                                                <div class="folds-row">
                                                    <#assign vulnerabilityBySeverity = (assessmentData.vulnerabilityBySeverity(key))!/>
                                                    <#list (vulnerabilityBySeverity)![] as vul>
                                                        <div class="vuln">
                                                            <input type="checkbox" id="vul-check${key}${vul?index}-${uniqueId}"/>
                                                            <label class="vul-label p-2" for="vul-check${key}${vul?index}-${uniqueId}">
                                                                <span class="cell1" title="${(vul.getCVEID())!}">${(vul.getCVEID())!}</span>
                                                                <span class="cell2" title="${(vul.getProduct().getPackageSource())!}">${(vul.getProduct().getPackageSource())!}</span>
                                                                <span class="cell3">
                                                                    <span class="c-${(assessmentData.severityColor(key))!}" title="${(assessmentData.severityLabel(key))!}">${(assessmentData.severityLabel(key))!}</span>
                                                                </span>
                                                                <span class="cell4" title="${(vul.getDetails().getBase_score())!}">${(vul.getDetails().getBase_score())!}</span>
                                                                <span class="cell5">
                                                                    <span class="type-truncate" title="${(vul.getRemediationsIfNotHash()[0])!}">${(vul.getRemediationsIfNotHash()[0])!}</span>
                                                                </span>
                                                                <span class="cell6">
                                                                    <#if (policyData.getFirstResource().getEvaluation_details().isCveIdInMatchedCveList(vul.getCVEID()))!false>
                                                                        <span>${(assessmentData.getIconByType("success"))!}</span>
                                                                    </#if>
                                                                </span>
                                                                ${(assessmentData.getIconByType("arrow"))!}
                                                            </label>
                                                            <div class="vul-content">
                                                                <div class="p-3">
                                                                    <div class="type-xxs c-bal mb-2" title="First seen at ${(vul.getFirstSeen())!}">${(vul.getFirstSeen())!}</div>
                                                                    <div class="c-tna mr-1 lh-1">${(vul.getDetails().getDescription())!"No description provided"}</div>
                                                                    <div class="refs">
                                                                        <#list (vul.getDetails().getReferences())![] as reference>
                                                                            <div class="ref">
                                                                                <div class="tags">
                                                                                    <#list (reference.getTags())![] as tag>
                                                                                        <span class="tag">${tag}</span>
                                                                                    </#list>
                                                                                </div>
                                                                                <a
                                                                                    href=${reference.getURL()} target="_blank"
                                                                                    class="url">${reference.getURL()}
                                                                                </a>
                                                                            </div>
                                                                        </#list>
                                                                    </div>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    </#list>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </#list>
                            </div>
                        </div>
                        <input type="radio" name="tabs" id="tab3-${uniqueId}"/>
                        <div id="tab-content3-${uniqueId}" class="tab-content pl-4">
                            <div class="c-tna mr-1 mb-3">Detections</div>
                            <div class="type-md type-tal">
                                <table class="table striped w-100">
                                    <thead>
                                        <tr class="bg-dark-1 p-3">
                                            <th><span>Name</span></th>
                                            <th><span>Severity</span></th>
                                            <th><span>Type</span></th>
                                            <th><span>Description</span></th>
                                            <th><span>Details</span></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <#list (assessmentData.getDetections())![] as detections>
                                            <tr>
                                                <td>
                                                    <span title="${detections.getDetection().getName()}">${detections.getDetection().getName()}</span>
                                                </td>
                                                <td>
                                                    <span class="c-${(assessmentData.severityColor(detections.getDetection().getSeverity()))!}" title="${(detections.getDetection().getName())!}">${(detections.getDetection().getName())!}</span>
                                                </td>
                                                <td>
                                                    <span title="${(detections.getDetection().getType())!}">${(detections.getDetection().getType())!}</span>
                                                </td>
                                                <td>
                                                    <span>
                                                        <span class="type-truncate" title="${(detections.getDetection().getDescription())!}">${(detections.getDetection().getDescription())!}</span>
                                                    </span>
                                                </td>
                                                <td>
                                                    <span class="type-xxs">
                                                        <span class="type-truncate" title="${(detections.getDetection().getDetails().Match)!}">${(detections.getDetection().getDetails().Match)!}</span>
                                                    </span>
                                                </td>
                                            </tr>
                                        </#list>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                        <input type="radio" name="tabs" id="tab4-${uniqueId}"/>
                        <div id="tab-content4-${uniqueId}" class="tab-content pl-4">
                            <div class="c-tna mr-1 mb-3">Layers</div>
                            <div class="type-md type-tal">
                                <table class="table striped rounded w-100">
                                    <thead>
                                        <tr class="bg-dark-1 p-3">
                                            <th><span>Command</span></th>
                                            <th><span>Digest</span></th>
                                            <th><span>Index</span></th>
                                            <th><span>Vulnerabilities</span></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <#list (assessmentData.getLayers())![] as layer>
                                            <tr>
                                                <td>
                                                    <span>
                                                        <code>${(layer.getCreatedBy())!}</code>
                                                    </span>
                                                </td>
                                                <td>
                                                    <span>
                                                        <span class="type-truncate" title="${(layer.getDigest())!}">${(layer.getDigest())!}</span>
                                                    </span>
                                                </td>
                                                <td>
                                                    <span>${(layer?index)!}</span>
                                                </td>
                                                <td>
                                                    <span>
                                                        <div class="layer-vulns">
                                                              <span class="type-truncate" title="${(assessmentData.vulnerabilityByLayer(layer))!}">${(assessmentData.vulnerabilityByLayer(layer))!}</span>
                                                        </div>
                                                    </span>
                                                </td>
                                            </tr>
                                        </#list>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div id="header4" class="mt-3 p-3 box">
                <div class="folds">
                    <div class="fold">
                        <input type="checkbox" id="checkDiagnostics-${uniqueId}">
                        <label class="fold-label d-f type-xl c-tni p-2" for="checkDiagnostics-${uniqueId}">Assessment Diagnostics${(assessmentData.getIconByType("arrow"))!}</label>
                        <div class="fold-content">
                            <div class="form-row p-2">
                                <div class="form-col">
                                    <div class="form-field"><label class="type-md c-bal mb-1">Packages</label>
                                        <span class="type-lg c-tna mr-1">
                                            <span title="${(assessmentData.getPackages()?size)!0}" class="type-truncate">${(assessmentData.getPackages()?size)!0}</span>
                                        </span>
                                    </div>
                                    <div class="form-field"><label class="type-md c-bal mb-1">ELF Binaries</label>
                                        <span class="type-lg c-tna mr-1">
                                            <span title="${(assessmentData.getELFBinaries()?size)!0}" class="type-truncate">${(assessmentData.getELFBinaries()?size)!0}</span>
                                        </span>
                                    </div>
                                    <div class="form-field"><label class="type-md c-bal mb-1">Manifest</label>
                                        <span class="type-lg c-tna mr-1">
                                            <span class="type-truncate" title="${(assessmentData.getManifest().getMediaType())!}">${(assessmentData.getManifest().getMediaType())!}</span>
                                        </span>
                                    </div>
                                </div>
                                <div class="form-col">
                                    <div class="form-field"><label class="type-md c-bal mb-1">Inventory Engine</label>
                                        <span class="type-lg c-tna mr-1">
                                            <span class="type-truncate" title="ver ${(assessmentData.getInventoryEngineInfo().getEngineVersion())!} | ${(assessmentData.getInventoryEngineInfo().getCWPPScannerVersion())!} | ${(assessmentData.getInventoryEngineInfo().getELFModelVersion())!}">ver ${(assessmentData.getInventoryEngineInfo().getEngineVersion())!} | ${(assessmentData.getInventoryEngineInfo().getCWPPScannerVersion())!} | ${(assessmentData.getInventoryEngineInfo().getELFModelVersion())!}</span>
                                        </span>
                                    </div>
                                    <div class="form-field"><label class="type-md c-bal mb-1">Detection Engine</label>
                                        <span class="type-lg c-tna mr-1">
                                            <span class="type-truncate" title="ver ${(assessmentData.getDetectionEngineInfo().getEngineVersion())!"Unknown"}">ver ${(assessmentData.getDetectionEngineInfo().getEngineVersion())!"Unknown"}</span>
                                        </span>
                                    </div>
                                    <div class="form-field">
                                        <label class="type-md c-bal mb-1">Policy Type Version</label>
                                        <span class="type-lg c-tna mr-1" title="${(policyData.getFirstResource().getPolicy_type().getVersion())!}">${(policyData.getFirstResource().getPolicy_type().getVersion())!}</span>
                                    </div>
                                </div>
                                <div class="form-col">
                                    <div class="form-field"><label class="type-md c-bal mb-1">Policy UUID</label>
                                        <span class="type-lg c-tna mr-1 type-truncate" title="${(policyData.getFirstResource().getPolicy().getUuid())!}">${(policyData.getFirstResource().getPolicy().getUuid())!}</span>
                                    </div>
                                    <div class="form-field"><label class="type-md c-bal mb-1">Policy Type UUID</label>
                                        <span class="type-lg c-tna mr-1 type-truncate" title="${(policyData.getFirstResource().getPolicy_type().getUuid())!}">${(policyData.getFirstResource().getPolicy_type().getUuid())!}</span>
                                    </div>
                                    <div class="form-field"><label class="type-md c-bal mb-1">Policy Group UUID</label>
                                        <span class="type-lg c-tna mr-1 type-truncate" title="${(policyData.getFirstResource().getPolicy_type().getUuid())!}">${(policyData.getFirstResource().getPolicy_type().getUuid())!}</span>
                                    </div>
                                </div>
                                <div class="form-col">
                                    <div class="form-field"><label class="type-md c-bal mb-1">Trace ID</label>
                                        <span class="type-lg c-tna mr-1 type-truncate" title="${(policyData.getMeta().getTrace_id())!}">${(policyData.getMeta().getTrace_id())!}</span>
                                    </div>
                                    <div class="form-field"><label class="type-md c-bal mb-1">Correlation UUID</label>
                                        <span class="type-lg c-tna mr-1 type-truncate" title="${(assessmentData.getScanInfo().getCorrelationUUID())!}">${(assessmentData.getScanInfo().getCorrelationUUID())!}</span>
                                    </div>
                                    <div class="form-field"><label class="type-md c-bal mb-1">CrowdStrike User CID</label>
                                        <span class="type-lg c-tna mr-1 type-truncate" title="${(assessmentData.getScanInfo().getCid())!}">${(assessmentData.getScanInfo().getCid())!}</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
</head>