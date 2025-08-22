import {ubolog} from '../console.js';
import {UBEContentScript} from './content-script.js';
import {UBECore} from './core.js';
import {processURL} from './Bundled_UBE_Stage1.js';

const modelWorker = {
    instance: null,
    ready: null,
    pending: new Map(),
    
};
const TIMEOUT = 3000;
const _sendToWorker = (tabId, data) => {
    const id = crypto.randomUUID();
    // resolves through worker's onmessage via the appropriate id
    return new Promise((resolve, reject) => {
        modelWorker.pending.set(id, {resolve, reject});
        modelWorker.instance.postMessage({what: 'predict', tabId: tabId, id: id, input: data})

        setTimeout(() => {
            if (modelWorker.pending.has(id)) {
                modelWorker.pending.delete(id);
                reject(new Error('Worker timeout'));
            }
        }, TIMEOUT);
    });
};

const _getStageResults = async (tabId, url, fn, stage) => {
    try {
        if (stage === 1) { // stage 3 is handled by message listener
            ubolog(`${UBECore.LOG_ICONS.WAIT} UBE: (Stage ${stage}) Started for Tab ${tabId}`);
        }

        const result = await fn(tabId, url);

        ubolog(`${UBECore.LOG_ICONS.ADVANCED} UBE: (Stage ${stage}) Finished for Tab ${tabId}`);

        return result ?? {};
    }
    catch (error) {
        throw new Error(`(Stage ${stage}) Failed to process Tab ${tabId}: ${error}`);
    }
};

export const UBEAnalysis = {
    async initWorker() {
            if (modelWorker.instance) {
                return;
            }

            return new Promise((resolve, reject) => {

            let workerUrl;
                
            if (UBECore.modelBlobUrl ) {
                workerUrl = UBECore.modelBlobUrl;
                ubolog(`✅ UBE: Using dynamic worker Blob URL: ${workerUrl}`);
            } else {
                workerUrl = vAPI.getURL('/js/ube/phishing_model_worker.js');
                ubolog(`✅ UBE: Using static worker script: ${workerUrl}`);
            }

            modelWorker.instance = new Worker(workerUrl, { type: 'module' });
            modelWorker.instance.onmessage = (msg) => {
                const data = msg.data;

                if (!data) {
                    reject(new Error('No data in worker message'));
                    return;
                }

                if (data.what === 'workerReady') {
                    modelWorker.ready = true;
                    resolve();
                    ubolog(`${UBECore.LOG_ICONS.ADVANCED} UBE: Worker initialized`);
                    return;
                }

                const {id, tabId, result, error} = msg.data;
                const pending = modelWorker.pending.get(id);

                if (pending) {
                    modelWorker.pending.delete(id);

                    if (data.what === 'predictionResult') {
                        pending.resolve(result);
                        ubolog(`${UBECore.LOG_ICONS.ADVANCED} UBE: Received prediction result for Tab ${tabId}`);
                    } else if (data.what === 'error') {
                        pending.reject(new Error(error || "Unknown error in worker"));
                    } else {
                        pending.reject(new Error("Invalid message 'what' from worker"));
                    }
                }
            }

            modelWorker.instance.onerror = (error) => {
                ubolog(`${UBECore.LOG_ICONS.ERROR} UBE: Worker onerror: ${error}`);
                reject(error);
            };
        });
    },

    terminateWorker() {
        if (modelWorker.instance) {
            modelWorker.ready = false;
            modelWorker.instance.terminate();
            modelWorker.instance = null;
        }

        modelWorker.pending.clear();
        ubolog(`${UBECore.LOG_ICONS.SUCCESS} UBE: Terminated worker`);
    },

    async getFirstAndSecondStagesResults(tabId, url) {
        const fn = (_tabId, _url) => processURL(_url);

        return _getStageResults(tabId, url, fn, 1);
    },

    async getThirdStageResults(tabId, url) {
        await UBEContentScript.injectContentScript(tabId);

        const fn = (_tabId, _url) => UBEContentScript.triggerContentScriptCheck(_tabId, _url);

        return _getStageResults(tabId, url, fn, 3);
    },

    async predict(tabId, combinedResults) {
        try {
            const prediction = await _sendToWorker(tabId, combinedResults);
            const validation = prediction.validation;

            if (!validation.isValid) {
                ubolog(`${UBECore.LOG_ICONS.WARNING} UBE: Received [${validation.present.length}/${validation.required}] features`);
                ubolog(`${UBECore.LOG_ICONS.WARNING} UBE: Missing required features: ${validation.missing}`);
                return 'N/A';
            }

            ubolog(`${UBECore.LOG_ICONS.INFO} UBE: Model result data output: `, {
                label: prediction.label,
                probabilities: prediction.probabilities,
                isPhishing: prediction.isPhishing,
                presentFeatures: prediction.validation.features
            });

            return prediction.label;
        } catch (error) {
            ubolog(`${UBECore.LOG_ICONS.ERROR} UBE: Model error: ${error}`);
            return 'N/A';
        }
    },

    async processAllStages(tabId, url) {
        const [firstAndSecondStagesResult, thirdStageResult] = await Promise.all([
            this.getFirstAndSecondStagesResults(tabId, url),
            this.getThirdStageResults(tabId, url)
        ]);

        if (Object.keys(firstAndSecondStagesResult).length === 0) {
            ubolog(`${UBECore.LOG_ICONS.WARNING} UBE: (Stage 1) Empty result received for Tab ${tabId}`);
            return {};
        }

        if (Object.keys(thirdStageResult).length === 0) {
            ubolog(`${UBECore.LOG_ICONS.WARNING} UBE: (Stage 3) Empty result received for Tab ${tabId}`);
            return {};
        }

        const finalResults = {...firstAndSecondStagesResult, ...thirdStageResult};

        finalResults['Prediction'] = await this.predict(tabId, finalResults);

        return finalResults;
    }
};