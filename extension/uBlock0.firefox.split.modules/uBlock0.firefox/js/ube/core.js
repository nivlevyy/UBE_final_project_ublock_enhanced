import {ubolog} from '../console.js';
import {UBEDebug} from './debug.js';

const _state = {
    enabled: false,
    tabResults: new Map(),
    activeProcessing: new Map(),
    processingQueue: [],
    allResults: []
};

const _constants = {
    MAX_CONCURRENT: 10,
    MAX_STORED_RESULTS: 30,
    MESSAGE_TYPES: {
        ANALYSIS_COMPLETE: 'analysisComplete',
        CHECK_HTML: 'checkHTML',
        CHECK_RESULT: 'getCheckResult',
        ANALYSIS_STARTED: 'analysisStarted',
        EXPORT_CSV: 'exportCSV'
    },
    LOG_ICONS: {
        START: '🚀',
        SUCCESS: '✅',
        ADVANCED: '☑️',
        WARNING: '⚠️',
        ERROR: '❌',
        MESSAGE: '✉️',
        SAVE: '💾',
        FINISH: '🔄',
        INFO: 'ℹ️',
        WAIT: '⏳',
        ACTION: '🛠️',
        ALERT: '🚨',
        REMOVE: '🗑️',
        CLEAN: '🧹',
        NEW: '📥'
    }
};

export const UBECore = {
    get enabled() { return _state.enabled; },

    get countResults() { return _state.tabResults.size; },
    get countProcessing() { return _state.activeProcessing.size; },
    get countQueue() { return _state.processingQueue.length; },
    get countAllResults() { return _state.allResults.length; },

    get allResults() { return { ..._state.allResults }; },

    get MAX_CONCURRENT() { return _constants.MAX_CONCURRENT; },
    get MESSAGE_TYPES() { return _constants.MESSAGE_TYPES; },
    get LOG_ICONS() { return _constants.LOG_ICONS; },

    setEnabled(value) {
        if (typeof value !== 'boolean') {
            throw new Error('UBE enabled must be boolean');
        }
        _state.enabled = value;
    },

    validateCapacity(tabId) {
        if (_state.tabResults.size >= _constants.MAX_STORED_RESULTS) {
            const oldestEntry = Array.from(_state.tabResults.entries())
                .sort((a, b) => a[1].timestamps.end - b[1].timestamps.end)[0];

            _state.tabResults.delete(oldestEntry[0]);
            ubolog(`${_constants.LOG_ICONS.REMOVE} UBE: Removed oldest result (Tab ${oldestEntry[0]}) for new results for Tab ${tabId}`);
        }
    },

    clearQueue() {
        ubolog(`${_constants.LOG_ICONS.INFO} UBE Disabled: Clearing any pending requests in processing queue...`);

        if (_state.processingQueue.length > 0) {
            _state.processingQueue.length = 0;
        }
    },

    addToQueue(item) {
        if (!item || typeof item !== 'object') {
            throw new Error('Queue item must be an object');
        }
        if (item?.tabId < 0) {
            throw new Error('Queue item must have valid tabId');
        }
        if (typeof item?.url !== 'string') {
            throw new Error('Queue item must have valid URL');
        }

        _state.processingQueue.push({
            tabId: item.tabId,
            url: item.url,
            timestamp: item.timestamp || Date.now()
        });
    },

    removeFromQueue(index) {
        if (0 <= index && index < _state.processingQueue.length) {
            _state.processingQueue.splice(index, 1);
        }
    },

    getNextInQueue() {
        return _state.processingQueue.shift();
    },

    findInQueue(tabId) {
        return _state.processingQueue.findIndex(item => item.tabId === tabId);
    },

    setActiveProcessing(tabId, data) {
        _state.activeProcessing.set(tabId, data);
    },

    removeActiveProcessing(tabId) {
        _state.activeProcessing.delete(tabId);
    },

    inActiveProcessing(tabId) {
        return _state.activeProcessing.has(tabId);
    },

    getActiveProcessing(tabId) {
        return _state.activeProcessing.get(tabId);
    },

    addResult(tabId, resultData) {
        this.validateCapacity(tabId);
        _state.tabResults.set(tabId, resultData);
    },

    removeResult(tabId) {
        if (typeof tabId !== 'number') {
            throw new Error('TabId must be a number');
        }
        return _state.tabResults.delete(tabId);
    },

    hasResult(tabId) {
        return _state.tabResults.has(tabId);
    },

    getResult(tabId) {
        return _state.tabResults.get(tabId);
    },

    addToAllResults(result) {
        if (!result || typeof result !== 'object') {
            throw new Error('Result must be an object');
        }
        _state.allResults.push(result);
    },

    cleanupTab(tabId) {
        const queueIndex = _state.processingQueue.findIndex(item => item.tabId === tabId);

        if (queueIndex !== -1) {
            _state.processingQueue.splice(queueIndex, 1);
            ubolog(`${_constants.LOG_ICONS.REMOVE} Removed closed Tab ${tabId} from queue`);
        }

        if (_state.tabResults.has(tabId)) {
            _state.tabResults.delete(tabId);
            ubolog(`${_constants.LOG_ICONS.REMOVE} Cleaned up results for closed Tab ${tabId}`);
        }

        if (_state.activeProcessing.has(tabId)) {
            _state.activeProcessing.delete(tabId);
        }
    },

    sendAnalysisStatusMessage(details) {
        if (browser.runtime?.sendMessage) {
            browser.runtime.sendMessage(details,
                () => {
                    if (browser.runtime.lastError) {
                        ubolog(`${_constants.LOG_ICONS.ERROR} Error sending message: ${browser.runtime.lastError.message}`);
                    }
                });
        }
    },

    debug: {
        getStatus() {
            return UBEDebug.getStatus();
        },

        exportCSV() {
            return UBEDebug.exportCSV();
        }
    }
};