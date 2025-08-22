import {ubolog} from '../console.js';
import {UBECore} from './core.js';
import {UBEAnalysis} from './analysis.js';


export const UBEProcessing = {
    handleProcessingSuccess(tabId, url, combinedResults) {
        if (!UBECore.enabled) {
            ubolog(`${UBECore.LOG_ICONS.INFO} UBE: Ignoring results for Tab ${tabId} (Disabled)`);
            return;
        }

        if (!combinedResults || Object.keys(combinedResults).length === 0) {
            ubolog(`${UBECore.LOG_ICONS.INFO} UBE: No results received for Tab ${tabId}`);
            return;
        }

        ////
        //combinedResults['Prediction'] = this.testModel(combinedResults);
        ////

        ubolog(`${UBECore.LOG_ICONS.SUCCESS} UBE: Successfully received results for Tab ${tabId}`);

        const activeProcessingData = UBECore.getActiveProcessing(tabId);

        if (activeProcessingData) {
            const resultData = {
                url: url,
                result: combinedResults,
                timestamps: {
                    begin: activeProcessingData?.timestamp,
                    end: Date.now()
                },
                executionTimes: {
                    begin: activeProcessingData?.timestampPerf,
                    end: performance.now()
                }
            };

            UBECore.addResult(tabId, resultData);
            UBECore.addToAllResults({URL: url, ...combinedResults});
            UBECore.sendAnalysisStatusMessage({
                source: 'ubeBackgroundScript',
                what: UBECore.MESSAGE_TYPES.ANALYSIS_COMPLETE,
                tabId: tabId,
                result: UBECore.getResult(tabId)
            });

            ubolog(`${UBECore.LOG_ICONS.SAVE} UBE: Saved results for Tab ${tabId} - ${url}`);
        }
    },

    handleProcessingError(tabId, url, error) {
        if (error.message?.includes('No tab with id')) {
            ubolog(`${UBECore.LOG_ICONS.ERROR} UBE: Tab ${tabId} was closed before processing`);
        } else {
            ubolog(`${UBECore.LOG_ICONS.ERROR} UBE: Processing failed for Tab ${tabId} - ${url}: ${error.message}`);
        }
    },

    getNextTabInQueue() {
        if (UBECore.countQueue === 0) {
            ubolog(`${UBECore.LOG_ICONS.INFO} UBE: Processing queue is empty`);
            return null;
        }

        if (UBECore.countProcessing >= UBECore.MAX_CONCURRENT) {
            ubolog(`${UBECore.LOG_ICONS.ALERT} UBE: At max capacity [${UBECore.countProcessing}/${UBECore.MAX_CONCURRENT}]. Waiting...`);
            return null;
        }

        return UBECore.getNextInQueue();
    },

    async processNext() {
        const nextTab = this.getNextTabInQueue();

        if (!nextTab) {
            return;
        }

        const {tabId, url} = nextTab;

        UBECore.setActiveProcessing(tabId, {url: url, timestamp: Date.now(), timestampPerf: performance.now()});
        ubolog(`${UBECore.LOG_ICONS.START} UBE: Started processing Tab ${tabId} [Queue: ${UBECore.countQueue}, Active: ${UBECore.countProcessing}]`);
        UBECore.sendAnalysisStatusMessage({
            source: 'ubeBackgroundScript',
            what: UBECore.MESSAGE_TYPES.ANALYSIS_STARTED,
            tabId: tabId,
        });

        try {
            const combinedResults = await UBEAnalysis.processAllStages(tabId, url);
            this.handleProcessingSuccess(tabId, url, combinedResults);
        } catch (error) {
            this.handleProcessingError(tabId, url, error);
        } finally {
            UBECore.removeActiveProcessing(tabId);
            ubolog(`${UBECore.LOG_ICONS.FINISH} UBE: Finished Tab ${tabId} - ${url}`);
            ubolog(`${UBECore.LOG_ICONS.INFO} UBE: [Queue: ${UBECore.countQueue}, Active: ${UBECore.countProcessing}]`);

            setTimeout(() => {
                this.processNext();
            }, 10);
        }
    }
};