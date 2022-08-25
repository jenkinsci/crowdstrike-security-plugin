<head>
    <body>
        <#if (reports.getUniqueReports()?size>1)!>
            <div class="pagination">
                <ul class="p-tabs">
                    <label>Reports:</label>
                    <#list (reports.getUniqueReports())![] as report>
                    <li>
                        <label for="report${report?index}">${report?index+1}</label>
                     </li>
                     </#list>
                </ul>
                <div class="scrollbox">
                    <div class="scrollable-data">
                        <#list (reports.getUniqueReports())![] as reportData>
                            <#if reportData?is_first>
                                <input type="radio" checked="checked" name="reports" id="report${reportData?index}"/>
                            <#else>
                                <input type="radio" name="reports" id="report${reportData?index}"/>
                            </#if>
                            <div id="report-content${reportData?index}" class="data-content">${reportData.getHtml()}</div>
                        </#list>
                    </div>
                </div>
            </div>
        <#else>
            ${reports.getUniqueReports()[0].getHtml()}
        </#if>
    </body>
</head>