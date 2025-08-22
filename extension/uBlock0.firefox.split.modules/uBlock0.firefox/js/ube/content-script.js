import {ubolog} from '../console.js';
import {UBECore} from './core.js';

export const UBEContentScript = {
    async injectContentScript(tabId) {
        let injectionRes;

        try {
            injectionRes = await vAPI.tabs.executeScript(tabId, {
                file: '/js/bundleST3_uBO_EDITION.js',
                allFrames: false,
                runAt: "document_end"
            });
        } catch (error) {
            ubolog(`${UBECore.LOG_ICONS.ERROR} UBE: Content script injection failed for Tab ${tabId}: ${error}`);
            throw error;
        }

        if (injectionRes.length === 0) {
            throw new Error('Script injection returned empty result');
        }

        ubolog(`${UBECore.LOG_ICONS.ADVANCED} UBE: Content script injected to Tab ${tabId}`);
    },

    waitForContentScriptReady(tabId) {
        ubolog(`${UBECore.LOG_ICONS.ACTION} UBE: (Stage 3) Setting up listener for 'content script ready' message for Tab ${tabId}`);

        let readyListener = null;
        let timeoutHandle = null;
        let promiseReject;

        const cleanup = () => {
            if (timeoutHandle) {
                clearTimeout(timeoutHandle);
                timeoutHandle = null;
            }

            if (readyListener && browser.runtime?.onMessage) {
                browser.runtime.onMessage.removeListener(readyListener);
                readyListener = null;
            }
        };

        const promise = new Promise((resolve, reject) => {
            promiseReject = reject;

            readyListener = (message, sender) => {
                if (sender.tab?.id === tabId &&
                    message.source === 'ubeContentScript' &&
                    message.what === 'contentScriptReady') {
                    cleanup();
                    resolve();
                }
            };

            if (browser.runtime?.onMessage) {
                browser.runtime.onMessage.addListener(readyListener);
            }
        });

        // add as function so we can start timeout manually later
        promise.startTimeout = (timeoutMs = 5000) => {
            if (timeoutHandle) {
                return;
            }

            timeoutHandle = setTimeout(() => {
                cleanup();
                promiseReject(new Error(`'Content script ready' timeout for Tab ${tabId}`));
            }, timeoutMs);
        };

        promise.cancel = () => {
            cleanup();
            promiseReject(new Error('Ready Promise Cancelled'));
        };

        return promise;
    },

    async triggerContentScriptCheck(tabId, message, timeoutMs = 10000) {
        ubolog(`${UBECore.LOG_ICONS.MESSAGE} UBE: Sending message to Tab ${tabId} to start processing`);

        if (!browser.tabs) {
            throw new Error('browser.tabs not available');
        }

        let timeoutId;
        const timeoutPromise = new Promise((_, reject) => {
            timeoutId = setTimeout(() => {
                reject(new Error(`Message timeout ${tabId}`));
            }, timeoutMs);
        });

        try {
            const response = await Promise.race([
                browser.tabs.sendMessage(tabId, message),
                timeoutPromise
            ]);

            clearTimeout(timeoutId);

            if (response?.source === 'ubeContentScript' && response?.success) {
                return response;
            } else {
                throw new Error(response?.error || 'Unknown error from content script');
            }
        } catch (error) {
            clearTimeout(timeoutId);
            throw new Error(`Failed to trigger content script check for Tab ${tabId}: ${error.message}`);
        }
    }
};