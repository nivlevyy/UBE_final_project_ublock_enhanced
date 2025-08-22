import {ubolog} from '../console.js';
import {processURL} from '../bundleST1and2.js';
import {UBEContentScript} from './content-script.js';
import {UBECore} from './core.js';

export const UBEAnalysis = {
    async getFirstAndSecondStagesResults(tabId, url) {
        try {
            ubolog(`${UBECore.LOG_ICONS.WAIT} UBE: (Stage 1) Processing Tab ${tabId}`);

            const urlResult = await processURL(url);

            ubolog(`${UBECore.LOG_ICONS.SUCCESS} UBE: (Stage 1) Successfully finished for Tab ${tabId}`);

            if (Object.keys(urlResult).length === 0) {
                ubolog(`${UBECore.LOG_ICONS.WARNING} UBE: (Stage 1) Empty result received for Tab ${tabId}`);
            }

            return urlResult;
        } catch (error) {
            ubolog(`${UBECore.LOG_ICONS.ERROR} UBE: (Stage 1) Failed to process Tab ${tabId}: ${error}`);
            throw error;
        }
    },

    async getThirdStageResults(tabId, url) {
        // set up listener and return promise immediately
        const readyPromise = UBEContentScript.waitForContentScriptReady(tabId);

        // for timeout / race condition / other exceptions
        readyPromise.catch(() => {
            ubolog(`${UBECore.LOG_ICONS.ERROR} UBE: Ready Promise failed for Tab ${tabId}`);
        });

        try {
            ubolog(`${UBECore.LOG_ICONS.ACTION} UBE: (Stage 3) Injecting content script to Tab ${tabId}`);

            await UBEContentScript.injectContentScript(tabId);

            ubolog(`${UBECore.LOG_ICONS.WAIT} UBE: (Stage 3) Waiting for 'content script ready' message for Tab ${tabId}`);

            readyPromise.startTimeout(3000);

            await readyPromise;

            ubolog(`${UBECore.LOG_ICONS.ADVANCED} UBE: (Stage 3) Content script ready for Tab ${tabId}`);

            const response = await UBEContentScript.triggerContentScriptCheck(tabId, {
                source: 'ubeBackgroundScript',
                what: 'checkHTML',
                tabId: tabId,
                url: url
            });

            ubolog(`${UBECore.LOG_ICONS.SUCCESS} UBE: (Stage 3) Successfully finished for Tab ${tabId}`);

            if (!response.result || Object.keys(response.result).length === 0) {
                ubolog(`${UBECore.LOG_ICONS.WARNING} UBE: (Stage 3) Empty result received for Tab ${tabId}`);
                return {};
            }

            return response.result;
        } catch (error) {
            ubolog(`${UBECore.LOG_ICONS.ERROR} UBE: (Stage 3) Failed to process Tab ${tabId}: ${error}`);
            throw error;
        } finally {
            readyPromise?.cancel?.();
        }
    },

    async processAllStages(tabId, url) {
        const [firstAndSecondStagesResult, thirdStageResult] = await Promise.all([
            this.getFirstAndSecondStagesResults(tabId, url),
            this.getThirdStageResults(tabId, url)
        ]);

        return {
            ...firstAndSecondStagesResult,
            ...thirdStageResult
        };
    }
};