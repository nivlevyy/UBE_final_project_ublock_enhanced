import {ubolog} from '../console.js';
import {UBECore} from './core.js';
import {UBEProcessing} from './processing.js';
import {UBEDebug} from './debug.js';
// import { onMessage } from '../messaging.js';

const _browserListeners = {
    navigationOnCommitted: null,
    runtimeMessage: null,
    tabRemoved: null
};

export const UBEEvents = {
    ///// added async because
    ///// trying out local storage
    /*async*/ onNavigationCommitted(details) {
        if (!UBECore.enabled) {
            return;
        }

        if (details?.frameId !== 0) {
            return;
        }
        if (details?.tabId < 0 || !details?.url) {
            ubolog(`${UBECore.LOG_ICONS.ERROR} UBE: Invalid tabId or URL`);
            return;
        }

        // safety check
        if (!details.url.startsWith('http://') && !details.url.startsWith('https://')) {
            ubolog(`${UBECore.LOG_ICONS.ALERT} UBE: Skipping non-HTTP(S) URL: ${details.url}`);
            return;
        }

        // const {hostname} = new URL(details.url);
        // const keyHostname = 'ube_visited::' + hostname;
        //
        // const result = await browser.storage.local.get(keyHostname);
        //
        // if (result[keyHostname]) {
        //     ubolog(`${UBECore.LOG_ICONS.ALERT} UBE: Skipping already visited hostname: ${hostname}`);
        //     return;
        // }

        // function to collect them all
        // const all = await browser.storage.get(null);
        // const keysUBE = Object.entries(all)
        //     .filter(([key]) => key.startsWith('ube_visited::'))
        //     .map(([key, timestamp]) => ( {
        //         hostname: key.slice(13), //key prefix length
        //         visited: timestamp
        //     }));
        // => POST to API

        const {tabId, url} = details;

        if (UBECore.inActiveProcessing(tabId)) { // edge case
            return;
        }

        ubolog(`${UBECore.LOG_ICONS.NEW} UBE: New page loading at Tab ${tabId} - ${url}`);

        const queueIndex = UBECore.findInQueue(tabId);

        if (queueIndex >= 0) {
            ubolog(`${UBECore.LOG_ICONS.INFO} UBE: Replacing Tab ${tabId} in processing queue due to page navigation`);
            UBECore.removeFromQueue(queueIndex);
        }

        UBECore.addToQueue({
            tabId: tabId,
            url: url,
            timestamp: Date.now()
        });


        //await browser.storage.local.set({[keyHostname]: Date.now()});

        UBEProcessing.processNext();
    },

    handleRuntimeMessage(request, sender, sendResponse) {
        const {source, what, tabId} = request;

        if (source === 'ubePopup') {
            switch (what) {
                case 'getCheckResult': {
                    if (!tabId) {
                        sendResponse({
                            source: 'ubeBackgroundScript',
                            error: 'No tabId provided'
                        });
                    } else {
                        const result = UBECore.getResult(tabId);

                        if (result) {
                            sendResponse({
                                source: 'ubeBackgroundScript',
                                tabId: tabId,
                                result: result
                            });
                        } else if (UBECore.inActiveProcessing(tabId)) {
                            sendResponse({
                                source: 'ubeBackgroundScript',
                                tabId: tabId,
                                processing: true
                            });
                        } else {
                            sendResponse({
                                source: 'ubeBackgroundScript',
                                tabId: tabId,
                                error: 'No analysis results available for this tab\nTry refreshing the page'
                            });
                        }
                    }
                    break;
                }
                case 'exportCSV': {
                    UBEDebug.exportCSV();
                    break;
                }
            }
        } else if (source === 'ubeContentScript') {
            switch (what) {
                case 'startedProcessing': {
                    ubolog(`${UBECore.LOG_ICONS.WAIT} UBE: (Stage 3) Started for Tab ${tabId}`);
                    break;
                }
            }
        } else if (source === 'popup-fenix') {
            const hasResult = UBECore.hasResult(tabId);
            const isProcessing = hasResult ? false : UBECore.inActiveProcessing(tabId);

            switch (what) {
                case 'getStatus':
                    sendResponse({
                        processing: isProcessing,
                        hasResult: hasResult,
                        ...(hasResult && {result: UBECore.getResultPrediction(request.tabId)})
                    });
                    break;
                case 'toggle':
                    UBECore.toggle();
                    sendResponse();
                    break;
            }
        }
    },

    registerOnCommittedListener() {
        if (browser.webNavigation && !_browserListeners.navigationOnCommitted) {
            _browserListeners.navigationOnCommitted = this.onNavigationCommitted.bind(this);

            browser.webNavigation.onCommitted.addListener(
                _browserListeners.navigationOnCommitted,
                {url: [{schemes: ["http", "https"]}]}
            );

            return true;
        } else {
            return false;
        }
    },

    registerCoreListeners() {
        if (browser.runtime && !_browserListeners.runtimeMessage) {
            _browserListeners.runtimeMessage = this.handleRuntimeMessage.bind(this);

            browser.runtime.onMessage.addListener(_browserListeners.runtimeMessage);
        }
        else {
            return false;
        }

        if (browser.tabs && !_browserListeners.tabRemoved) {
            _browserListeners.tabRemoved = (tabId) => {
                UBECore.cleanupTab(tabId);
            };

            browser.tabs.onRemoved.addListener(_browserListeners.tabRemoved);

            return true;
        }
        else {
            return false;
        }
    },

    removeOnCommittedListener() {
        if (_browserListeners.navigationOnCommitted) {
            browser.webNavigation.onCommitted.removeListener(_browserListeners.navigationOnCommitted);
            _browserListeners.navigationOnCommitted = null;
        }
    }
,
// registerUbeEventHandlers() {
//     onMessage.addHandlers({
//         'assets.json-updated': () => {
//             ubolog('🟢 UBE: assets.json-updated RECEIVED!');
//             UBECore.takeAssetsFromRegistry();
//         }
//     })
// }
    async registerUbeEventHandlers() {
    browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.what === 'assets.json-updated') {
            ubolog('🟢 UBE: assets.json-updated RECEIVED!');
            UBECore.takeAssetsFromRegistry();
            sendResponse({ success: true });
            return true;
        }
    });
}


};

