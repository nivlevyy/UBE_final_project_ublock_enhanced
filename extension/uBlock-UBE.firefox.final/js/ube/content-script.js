import {ubolog} from '../console.js';
import {UBECore} from './core.js';

const TIMEOUT = 3000;
const _executeScript = async (tabId) => {
    let injectionRes;

    try {
        injectionRes = await vAPI.tabs.executeScript(tabId, {
            file: '/js/ube/Bundled_UBE_Stage3.js',
            allFrames: false,
            runAt: "document_end"
        });
    } catch (error) {
        throw new Error(`executeScript failed: ${error.message}`);
    }

    if (injectionRes?.length === 0) {
        throw new Error('executeScript returned an empty array');
    }
};
const _createTimeout = (msg, timeoutMs = TIMEOUT) => {
    let timeoutId;
    const timeoutPromise = new Promise((_, reject) => {
        timeoutId = setTimeout(() => {
            reject(new Error(msg));
        }, timeoutMs);
    });

    return {
        promise: timeoutPromise,
        clear: () => clearTimeout(timeoutId)
    };
};

export const UBEContentScript = {
    async injectContentScript(tabId) {
        let onReadyListener;
        const onReadyPromise = new Promise((resolve) => {
            onReadyListener = (message, sender) => {
                if (sender.tab?.id === tabId &&
                    message.source === 'ubeContentScript' &&
                    message.what === 'contentScriptReady') {
                    browser.runtime.onMessage.removeListener(onReadyListener);
                    resolve();
                }
            };
            browser.runtime.onMessage.addListener(onReadyListener);
        });

        ubolog(`${UBECore.LOG_ICONS.ACTION} UBE: (Stage 3) Injecting content script to Tab ${tabId}`);

        await _executeScript(tabId);

        const timeoutObj = _createTimeout('Content script ready timeout');

        try {
            await Promise.race([onReadyPromise, timeoutObj.promise]);
            ubolog(`${UBECore.LOG_ICONS.INFO} UBE: (Stage 3) Content script ready for Tab ${tabId}`);
        } catch (error) {
            throw new Error(`Failed to trigger content script ready check: ${error.message}`)
        } finally {
            timeoutObj?.clear();

            if (onReadyListener) {
                browser.runtime.onMessage.removeListener(onReadyListener);
            }
        }
    },

    async triggerContentScriptCheck(tabId, url) {
        if (!browser.tabs) {
            throw new Error('browser.tabs not available');
        }

        let response;
        const timeoutObj = _createTimeout('Content script response timeout');
        const messagePromise = browser.tabs.sendMessage(tabId, {
            source: 'ubeBackgroundScript',
            what: 'checkHTML',
            tabId: tabId,
            url: url
        });

        try {
            response = await Promise.race([
                messagePromise,
                timeoutObj.promise
            ]);
        } catch (error) {
            const errorMsg = error?.message || 'Unknown error';
            throw new Error(`Failed to trigger content script start check: ${errorMsg}`);
        } finally {
            timeoutObj?.clear();
        }

        if (response?.source === 'ubeContentScript' && response?.success) {
            return response.result;
        } else {
            throw new Error(response?.error || 'Unknown error from content script');
        }
    }
};