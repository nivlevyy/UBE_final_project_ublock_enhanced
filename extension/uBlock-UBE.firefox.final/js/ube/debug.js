import {ubolog} from '../console.js';
import {UBECore} from './core.js';

export const UBEDebug = {
    getStatus() {
        return {
            enabled: UBECore.enabled,
            queueLength: UBECore.countQueue,
            activeProcessing: UBECore.countProcessing,
            activeResults: UBECore.countResults,
            allResultsCount: UBECore.countAllResults
        };
    },

    exportCSV() {
        const headers = [
            "URL",
            "URL Length",
            "Subdomains",
            "Hostname Length",
            "IP",
            "Shortener",
            "Hyphens",
            "At Signs",
            "Query Parameters",
            "Resources",
            //"Has Protocol",
            //"Is Email",
            "Suspicious Chars",
            //"Has Double Slash",
            "SSL Exists",
            "SSL Valid",
            "SSL Issuer",
            "Domain Age",
            "Domain Expiry",
            "Domain Registrar",
            "VT Reputation",
            "VT Malicious",
            "VT Suspicious",
            "VT Undetected",
            "VT Harmless",
            "favicon Present",
            "favicon Different Domains",
            "favicon Invalid Type",
            "Anchor Tags",
            "Anchor Empty Hrefs",
            "Anchor Different Domains",
            "Anchor Different Domains Ratio",
            "External Metas",
            "External Metas Suspicious Words",
            "External Metas Ratio",
            "External Scripts",
            "External Scripts Suspicious Words",
            "External Scripts Ratio",
            "Total Links",
            "External Links",
            "External Links Ratio",
            "External Total",
            "Resources Total",
            "Resources External",
            "Resources External Ratio",
            "SFH Total",
            "SFH Blank Actions",
            "SFH Different Domains",
            "SFH Passwords",
            "SFH Suspicious Words",
            "IFrame src",
            "IFrame src Hidden",
            "IFrame src Size",
            "IFrame src Different Domains",
            "IFrame src No Sandbox",
            "IFrame External src Ratio",
            "IFrame srcdoc",
            "IFrame srcdoc Hidden",
            "IFrame srcdoc Scripts",
            "IFrame srcdoc Suspicious Words",
            "IFrame Total",
            "JS Inline",
            "JS High Risk Patterns",
            "JS Medium Risk Patterns",
            "JS Low Risk Patterns",
            "JS Different Domains",
            "JS Behave Ratio",
            "JS Risk Patterns Ratio",
            "NLP",
            "JS Total",
            "JS External",
            "AR Meta Refresh",
            "AR JS",
            "AR Cross Domain",
            "Hidden Login Forms",
            "JS OnMouseOver Scripts",
            "JS OnMouseOver Tags",
            "Right Click Scripts",
            "Right Click Menu Tags",
            //"Different Domains",
            //"validity"
        ];

        try {
            const csvRows = [
                headers.join(','),
                ...UBECore.allResults.map(row =>
                    headers.map(h => JSON.stringify(row[h] ?? "N/A")).join(',')
                )
            ];

            const blob = new Blob([csvRows.join('\n')], {type: 'text/csv'});
            const blobUrl = URL.createObjectURL(blob);

            browser.downloads.download({
                url: blobUrl,
                filename: `ube_collected_results_${new Date().toISOString().slice(0, 10)}.csv`,
                saveAs: true
            }).then((downloadId) => {
                    if (browser.runtime.lastError) {
                        ubolog(`${UBECore.LOG_ICONS.ERROR} UBE Debug: Download failed: ${browser.runtime.lastError.message}`);
                    } else {
                        ubolog(`${UBECore.LOG_ICONS.SUCCESS} UBE Debug: Download started, ID: ${downloadId}`);
                    }
                });

            ubolog(`${UBECore.LOG_ICONS.SUCCESS} UBE Debug: CSV export initiated using browser.download`);

            setTimeout(() => {
                URL.revokeObjectURL(blobUrl);
            }, 10000);
        } catch (error) {
            ubolog(`${UBECore.LOG_ICONS.ERROR} UBE Debug: CSV export failed: ${error.message}`);
        }
    }
};