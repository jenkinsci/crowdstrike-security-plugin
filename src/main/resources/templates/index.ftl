<head>
    <h1 class="display-info">Please open from sidebar or save and open in browser to view with stylesheet</h1>
    <title>Assessment | CrowdStrike Security</title>
    <style>
        /**
         * CrowdStrike Security for Jenkins
         */

        /* css reset */
        * {
            margin:0;
            padding:0;
            line-height:1em;
            cursor:inherit;
        }
        html {
            font: normal 16px/1em Arial, Helvetica, sans-serif;
        }
        body {
            background: #27262c; /* ground-floor */
            color: #a6acb0; /* body-and-labels */
            padding: 1em;
        }
        a {
            color:#9dc1fd; /* info */
            cursor:pointer;
        }

        /* typography */
        h1, .type-4xl { font-size:48px; font-weight:bold; }
        h2, .type-2xl { font-size:32px; font-weight:bold; }
        h3, .type-xl { font-size:24px; font-weight:bold; }
        body, .type-lg { font-size:20px; font-weight:normal; }
        h3, .type-lg { font-size:20px; font-weight:normal; }
        h4, .type-lg-tight-medium { font-size:20px; font-weight:bold; }
        .type-md { font-size:16px; font-weight:normal; }
        h5, .type-xs { font-size:12px; font-weight:normal; }
        .type-xxs { font-size:9px; font-weight:normal; }
        .type-truncate {
            max-width: 250px;
            display: inline-block;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .type-usn {
            user-select: none;
        }
        .type-tal {
            text-align:left;
        }
        .type-tac {
            text-align:center;
        }

        /* colors */
        .c-critical { color:#fa4147; }
        .c-high { color:#f77d40; }
        .c-medium { color:#ffcc00; }
        .c-info { color:#9dc1fd; }
        .c-positive { color:#11e5b6; }
        .c-positive-darker { color:#0f99a1; }
        .c-tna { color:#e2e2e4; }
        .c-ground-floor { color:#27262c; }
        .c-tni { color:#fafafa; }
        .c-bal { color:#a6acb0; }
        .c-ld { color:#09090c; } /* lines-dark */
        .c-nh { color:#63646e; } /* normal-hover */

        .bg-dark-1 { background:#111014; }
        .bg-dark-2 { background:#1d1c21; }

        /* icons */
        i.i {
            line-height:0;
            display:inline-block; width:25px; height:25px;
            background-repeat:no-repeat;
            background-position:50% 50%;
        }
        .i-arrow {
            transform: rotate(-90deg);
            margin-left:auto;
            overflow:visible;
        }
        .i-text {
            line-height:32px;
        }
        .i-divider::before {
            content:"|";
        }
        .i-divider {
            padding:0 5px;
            font-style:normal;
            font-weight:normal;
            font-family:monospace;
            color:#09090c;
            font-size:.7em;
        }

        /* spacing */
        .m-1 { margin:.25rem; }
        .mr-1 { margin-right:.25rem; }
        .mt-1 { margin-top:.25rem; }
        .mb-1 { margin-bottom:.25rem; }
        .m-2 { margin:.5rem; }
        .mt-2 { margin-top:.5rem; }
        .mb-2 { margin-bottom:.5rem; }
        .mr-2 { margin-right:.5rem; }
        .m-3 { margin:1rem; }
        .mt-3 { margin-top:1rem; }
        .mb-3 { margin-bottom:1rem; }
        .mr-3 { margin-right:1rem; }
        .m-4 { margin:1.5rem; }
        .mt-4 { margin-top:1.5rem; }
        .mb-4 { margin-bottom:1.5rem; }
        .m-5 { margin:3rem; }
        .mt-5 { margin-top:3rem; }
        .mb-5 { margin-bottom:3rem; }

        .mr-3 { margin-right:1rem; }

        .p-1 { padding:.25rem; }
        .pt-1 { padding-top:.25rem; }
        .pb-1 { padding-bottom:.25rem; }
        .pl-1 { padding-left:.25rem; }
        .p-2 { padding:.5rem; }
        .pt-2 { padding-top:.5rem; }
        .pb-2 { padding-bottom:.5rem; }
        .pl-2 { padding-left:.5rem; }
        .pr-2 { padding-right:.5rem; }
        .p-3 { padding:1rem; }
        .pt-3 { padding-top:1rem; }
        .pb-3 { padding-bottom:1rem; }
        .pl-3 { padding-left:1rem; }
        .pr-3 { padding-right:1rem; }
        .p-4 { padding:1.5rem; }
        .pl-4 { padding-left:1.5rem; }
        .p-5 { padding:3rem; }
        .pl-5 { padding-left:3rem; }

        .pl-8 { padding-left:15rem; }

        .bt-1 { border-top: 1px solid #000; }
        .bb-1 { border-bottom: 1px solid #000;}
        .lh-1 { line-height: 1.3em; }
        .w-50 { width:50%; }
        .w-100 { width:100%; }
        .clickable { cursor:pointer; }
        .cur-help { cursor:help; }

        /* flexbox */
        .d-n { display:none; }
        .d-f { display:flex; }
        .f-d-r { flex-direction:row; }
        .f-d-c { flex-direction:column; }
        .f-a-c { align-items:center; }
        .f-jc-fe { justify-content:flex-end; }

        /* content */
        #content {
            width:100%;
            display:flex;
            flex-direction:column;
        }
        #header {
            display:flex;
            flex-direction:row;
            justify-content:space-between;
            white-space:nowrap;
            overflow-x: auto;
            overflow-y: hidden;
        }
        #header > #top-right {
            display:flex;
            flex-direction:column;
            text-align:right;
        }

        /* components */
        .display-info {
            display:none;
        }

        .form-field {
            display:flex;
            flex-direction:column;
        }

        .form-row {
            display:flex;
            flex-direction:row;
            justify-content:space-between;
            white-space:nowrap;
            overflow-x:auto;
            overflow-y:hidden;
        }

        .form-col {
            display:flex;
            flex-direction:column;
            flex: 1 0 250px;
        }
        .form-col > .form-field:not(:last-child) {
            margin-bottom:1.5rem;
        }

        .box {
            box-shadow: -6px 8px 28px 0 rgba(0, 0, 0, 0.15);
            border: solid 1px #09090c;
            border-radius: 4px;
            background-color: #27262c;
        }

        .content input[type=radio] {
            display:none;
        }

        .content input[type="checkbox"] {
            display:none;
        }

        .content .tab-content {
            display:none;
        }

        .folds-content {
            max-height: 0;
            padding: 0 1em;
        }

        .content input[type="radio"]:checked + .tab-content {
            display:block;
        }

        .content input[type="radio"]:checked + label {
            background-color:#fafafa; /* tni */
            color:#09090c; /* lines-dark */
        }

        .tab-data {
            display:flex;
            flex-direction: column;
            flex: 1 1 auto;
            overflow: auto;
        }

        .tabs .tab-nav li {
            list-style-type:none;
            display:block;
        }

        .tabs .tab-nav li {
            list-style-type:none;
            display:block;
        }

        .tabs .tab-nav li label {
            display:block;
        }

        .tabs .tab-nav li:hover {
            background: #525252;
        }

        .tabs {
            display:flex;
            flex-direction:row;
        }
        .tabs > .tab-nav {
            display:flex;
            flex-direction:column;
            flex: 0 0 auto;
        }
        .tabs > .tab-nav > .tab {
            cursor:pointer;
            border-radius: 2.9px;
            box-shadow: 0 1.5px 5.8px 0 rgba(0, 0, 0, 0.15);
            border: solid 0.7px #09090c;
            background-color: #343338;
            margin: 0 0 1rem 0;
        }
        .tabs > .tab-nav >  .tab .tab-title {
            color:#fafafa; /* tna */
        }
        .tabs > .tab-nav > .tab-active {
            background-color:#fafafa; /* tni */
            color:#09090c; /* lines-dark */
        }
        .tabs > .tab-nav > .tab-active .tab-title {
            color:#09090c; /* lines-dark */
        }
        .tabs > .tab-nav > .tab .tab-label-row {
            display:flex;
            flex-direction:row;
            justify-content:space-between;
            align-items:flex-end;
        }
        .tabs > .tab-nav > .tab .tab-label-row > .tab-label-col {
            display:flex;
            flex-direction:column;
        }
        .tabs > .tab-content {
            width:100%;
        }

        .folds {
            display:flex;
            flex-direction:column;
        }
        .folds > .fold {
            display:flex;
            flex-direction:column;
            color: white;
            overflow: hidden;
        }
        .folds > .fold > .fold-label:hover {
            background: #525252;
        }
        label {
            display:flex;
            align-items:center;
        }
        .fold-label {
            display:flex;
            align-items:center;
            background-color: #38373b;
            cursor:pointer;
            box-shadow: 0 4px 6px 0 rgb(0 0 0 / 10%), 0 2px 4px 0 rgb(0 0 0 / 33%)
        }
        .fold-content .folds-row label > span,
        .folds-header-row > span {
            flex: 1 0 200px;
        }
        .folds-header-row > span {
            white-space:nowrap;
        }
        .fold-content {
            max-height: 0;
            margin-bottom: 5px;
            overflow-x: auto;
            overflow-y: hidden;
        }
        input[type="checkbox"]:checked + .fold-label {
            background: #525252;
        }
        input[type="checkbox"]:checked + .fold-label > .i-arrow {
            transform: rotate(0deg)!important;
        }
        input[type="checkbox"]:checked ~ .fold-content {
            display:block;
            max-height: 100%;
        }

        .vulns {
            display:flex;
            flex-direction:column;
        }
        .vulns .vuln {
            display:flex;
            flex-direction:column;
            color: white;
            overflow: hidden;
            width: fit-content;
        }
        .vul-label:hover {
            background: #525252;
        }
        .vul-label {
            display: flex;
            background-color: #38373b;
            cursor:pointer;
        }
        .vul-content {
            max-height: 0;
        }
        input[id^="vul-check"]:checked + .vul-label {
            background: #525252;
        }
        input[id^="vul-check"]:checked + .vul-label > .i-arrow {
            transform: rotate(0deg)!important;
        }
        input[id^="vul-check"]:checked ~ .vul-content {
            display:block;
            max-height: 100%;
        }

        .row {
            display: flex;
        }


        .cell1 {
            width:200px;
        }

        .cell2 {
            width: 300px;
        }

        .cell3 {
            width: 100px;
        }

        .cell4 {
            width: 100px;
        }

        .cell5 {
            width: 300px;
        }

        .cell6 {
            width: 100px;
        }

        .cell {
            display: table-cell;

            padding: 6px;
            text-align: center;
        }

        .primary {
            text-align: left;
        }


        .table {
            border-collapse:collapse;
        }
        .table td {
            vertical-align:top;
        }
        .table > thead > tr > th {
            color:#fafafa;
            text-align:left;
            padding:.75rem;
        }
        .table > thead > tr > th > span {
            padding-left:1rem;
            border-left: 1px solid #e2e2e4;
            height: 1em;
            display: block;
            text-overflow: ellipsis;
            overflow: hidden;
        }
        .table > thead > tr > th:first-child > span {
            margin-left:0;
            padding-left:0;
            border-left:0;
        }
        .table > tbody > tr.toggle > th > .i-arrow-s {
            cursor:pointer;
        }
        .table > tbody > tr.toggle + tr {
            display:none;
        }
        .table > tbody > tr.toggle.active + tr {
            display:table-row;
        }
        .table > tbody > tr.toggle.active > th > .i-arrow-s {
            transform: rotate(-180deg);
        }
        .table > tbody > tr > th,
        .table > tbody > tr > td {
            text-align:left;
            font-weight:normal;
        }
        .table > tbody > tr > th > span,
        .table > tbody > tr > td > span {
            padding:.5rem 0 .5rem 2rem;
            display:block;
        }
        .table > tbody > tr > th:first-child > span,
        .table > tbody > tr > td:first-child > span {
            padding:.5rem 0 .5rem .75rem;
            display:block;
        }
        .table.striped > tbody > tr:nth-child(even) > td {
            background:#27262c;
        }
        .table.striped > tbody > tr:nth-child(odd) > td {
            background:#222126;
        }
        .table.solid > tbody > tr > td {
            background:#222126;
        }
        table.rounded > thead > tr:last-child > th:first-child {
            border-top-left-radius:10px;
        }
        table.rounded > thead > tr:last-child > th:last-child {
            border-top-right-radius:10px;
        }
        table.rounded > tbody > tr:last-child > td:first-child {
            border-bottom-left-radius:10px;
        }
        table.rounded > tbody > tr:last-child > td:last-child {
            border-bottom-right-radius:10px;
        }

        .refs {
            font-size:14px;
            margin-top:.5rem;
        }
        .refs > .ref > .url {
            text-overflow:ellipsis;
            overflow:hidden;
            white-space:nowrap;
            margin:0 0 .5rem 0;
            display:block;
        }
        .tag {
            background: #fff2;
            padding:.1rem .5rem;
            border-radius: 10px;
            margin:0 .5rem .25rem 0;
            display:inline-block;
            color:#ddd;
        }

        code {
            font-size:12px;
            line-height:1.3em;
            padding:.5rem;
            border-radius:4px;
            font-weight:normal;
            background:#1d1c21;
            color:#9dc1fd;
            display:block;
            overflow:hidden;
            width:150px;
            max-height:100px;
            text-overflow:ellipsis;
        }

        .layer-vulns {
            display:flex;
            flex-direction:column;
        }
        .layer-vulns > .layer-vuln {
            display:flex;
            flex-direction:row;
            justify-content:space-between;
            margin-bottom:.5rem;
        }
        .align-content-center {
            align-content:center;
        }

        .pagination > .p-tabs > li > label {
            display: flex;
            align-content: center;
            padding: .25rem .5rem;
            margin: 0 .25rem;
            cursor: pointer;
            background: #343338;
            border: solid #222;
            border-width: 1px 1px 0 1px;
            border-radius: 5px 5px 0 0;
            color: #eee;
        }
        .pagination > .scrollbox > .scrollable-data > .data-content {
            display:none;
        }

        .pagination > .scrollbox > .scrollable-data > input[type="radio"]:checked + .data-content {
            display:block;
        }

        .pagination > .scrollbox  > .scrollable-data > input[type="radio"]:checked + .label {
            background: #525252;
        }

        .pagination > .scrollbox  > .scrollable-data > input[type=radio] {
            display:none;
        }

        .pagination > .p-tabs {
            display: flex;
            white-space:nowrap;
            list-style: none;
            max-width: fit-content;
            overflow-x: auto;
            overflow-y: hidden;
            padding: 0 0 1em;
        }

        .pagination > .scrollbox {
            overflow-x: auto;
            overflow-y: hidden;
        }

        .p-tabs > li.active > label,
        .p-tabs > li > label:hover {
            background: #525252;
        }
    </style>
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
                                <span title="${(assessmentData.getOsInfo().getName())!}" class="type-truncate">${(assessmentData.getOsInfo().getName())!}</span>
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
                                <span title="${(assessmentData.getImageInfo().getId())!}" class="type-truncate">${(assessmentData.getImageInfo().getId())!}</span>
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
                                                                <span class="cell1" title="${(vul.getCveId())!}">${(vul.getCveId())!}</span>
                                                                <span class="cell2" title="${(vul.getProduct().getPackageSource())!}">${(vul.getProduct().getPackageSource())!}</span>
                                                                <span class="cell3">
                                                                    <span class="c-${(assessmentData.severityColor(key))!}" title="${(assessmentData.severityLabel(key))!}">${(assessmentData.severityLabel(key))!}</span>
                                                                </span>
                                                                <span class="cell4" title="${(vul.getDetails().getBase_score())!}">${(vul.getDetails().getBase_score())!}</span>
                                                                <span class="cell5">
                                                                    <span class="type-truncate" title="${(vul.getRemediationsIfNotHash()[0])!}">${(vul.getRemediationsIfNotHash()[0])!}</span>
                                                                </span>
                                                                <span class="cell6">
                                                                    <#if (policyData.getFirstResource().getEvaluation_details().isCveIdInMatchedCveList(vul.getCveId()))!false>
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
                                                                                    href=${reference.getUrl()} target="_blank"
                                                                                    class="url">${reference.getUrl()}
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
                                            <span title="${(assessmentData.getElfBinaries()?size)!0}" class="type-truncate">${(assessmentData.getElfBinaries()?size)!0}</span>
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
                                            <span class="type-truncate" title="ver ${(assessmentData.getInventoryEngineInfo().getEngineVersion())!} | ${(assessmentData.getInventoryEngineInfo().getCwppScannerVersion())!} | ${(assessmentData.getInventoryEngineInfo().getElfModelVersion())!}">ver ${(assessmentData.getInventoryEngineInfo().getEngineVersion())!} | ${(assessmentData.getInventoryEngineInfo().getCwppScannerVersion())!} | ${(assessmentData.getInventoryEngineInfo().getElfModelVersion())!}</span>
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