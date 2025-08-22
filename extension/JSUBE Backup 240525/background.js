import { processURL } from './dist/bundle.js';

let lastCheckResult = null;

chrome.webRequest.onBeforeRequest.addListener(
    async (details) => {
        lastCheckResult = await processURL(details.url);
        return {};
    },
    {
        urls: ['http://*/*', 'https://*/*'],
        types: ['main_frame']
    },
    ['blocking']
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'getCheckResult') {
        sendResponse({ result: lastCheckResult });
    }
});