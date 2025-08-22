import { ubolog } from '../console.js';
import { UBECore } from './core.js';
import { UBEProcessing } from './processing.js';
import { UBEDebug } from './debug.js';

export const UBEEvents = {
    browserListeners: {
        navigationOnCommitted: null,
        runtimeMessage: null,
        tabRemoved: null
    },

    onNavigationCommitted(details) {
        if (!UBECore.enabled) {
            return;
        }

        if (details?.frameId !== 0) {
            ubolog(`${UBECore.LOG_ICONS.ALERT} UBE: Skipping non-main frame ${details.frameId}`);
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

        const {tabId, url} = details;

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

        UBEProcessing.processNext();
    },

    handleRuntimeMessage(request, sender, sendResponse) {
        try {
            const { source, what, tabId } = request;

            if (source === 'ubePopup') {
                switch (what) {
                    case UBECore.MESSAGE_TYPES.CHECK_RESULT: {
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
                        return;
                    }

                    case UBECore.MESSAGE_TYPES.EXPORT_CSV: {
                        UBEDebug.exportCSV();
                        return;
                    }

                    default: {
                        sendResponse({
                            source: 'ubeBackgroundScript',
                            tabId: tabId,
                            error: 'Error: Unknown what'
                        });
                        return;
                    }
                }
            }
            else if (source === 'ubeContentScript') {
                switch (what) {
                    case UBECore.MESSAGE_TYPES.ANALYSIS_STARTED: {
                        ubolog(`${UBECore.LOG_ICONS.WAIT} UBE: (Stage 3) Processing Tab ${tabId}`);
                        return;
                    }

                    default: {
                        sendResponse({
                            source: 'ubeBackgroundScript',
                            tabId: tabId,
                            error: 'Error: Unknown what'
                        });
                        return;
                    }
                }

            } else {
                sendResponse({
                    source: 'ubeBackgroundScript',
                    error: 'Error: Unknown message source'
                });
            }
        } catch (error) {
            ubolog(`${UBECore.LOG_ICONS.ERROR} UBE: Error in browser message handler: ${error.message}`);
            sendResponse({
                source: 'ubeBackgroundScript',
                error: 'Internal error'
            });
        }
    },

    registerOnCommittedListener() {
        if (browser.webNavigation && !this.browserListeners.navigationOnCommitted) {
            this.browserListeners.navigationOnCommitted = this.onNavigationCommitted.bind(this);

            browser.webNavigation.onCommitted.addListener(
                this.browserListeners.navigationOnCommitted,
                {url: [{schemes: ["http", "https"]}]}
            );

            ubolog(`${UBECore.LOG_ICONS.SUCCESS} UBE: browser WebNavigation listener registered`);
        } else {
            ubolog(`${UBECore.LOG_ICONS.ERROR} UBE: browser WebNavigation API not available`);
        }
    },

    registerCoreListeners() {
        if (browser.runtime && !this.browserListeners.runtimeMessage) {
            this.browserListeners.runtimeMessage = this.handleRuntimeMessage.bind(this);

            browser.runtime.onMessage.addListener(this.browserListeners.runtimeMessage);
            ubolog(`${UBECore.LOG_ICONS.SUCCESS} UBE: browser runtime onMessage listener registered`);
        }

        if (browser.tabs && !this.browserListeners.tabRemoved) {
            this.browserListeners.tabRemoved = (tabId) => {
                UBECore.cleanupTab(tabId);
            };

            browser.tabs.onRemoved.addListener(this.browserListeners.tabRemoved);
            ubolog(`${UBECore.LOG_ICONS.SUCCESS} UBE: browser tabs onRemoved listener registered`);
        }
    },

    removeOnCommittedListener() {
        if (this.browserListeners.navigationOnCommitted) {
            browser.webNavigation.onCommitted.removeListener(this.browserListeners.navigationOnCommitted);
            this.browserListeners.navigationOnCommitted = null;
            ubolog(`${UBECore.LOG_ICONS.SUCCESS} UBE: browser WebNavigation listener removed`);
        }
    }
};