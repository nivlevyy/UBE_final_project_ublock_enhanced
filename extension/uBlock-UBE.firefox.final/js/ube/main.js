import {UBECore} from './core.js';
import {UBEPopup} from './popup.js';

// unites all modules (facade-like)
// and exposes an interface
// for simpler implementation and usage
export const UBE = {
    get enabled() {
        return UBECore.enabled;
    },

    hasResult(tabId) {
        return UBECore.hasResult(tabId);
    },

    getResultPrediction(tabId) {
        return UBECore.getResultPrediction(tabId);
    },

    isActiveProcessing(tabId) {
        return UBECore.inActiveProcessing(tabId);
    },

    async openPopupWindow(tabId, hostname) {
        return UBEPopup.openPopupWindow(tabId, hostname);
    },

    debug: {
        getStatus() {
            return UBECore.debug.getStatus();
        },
        exportCSV() {
            return UBECore.debug.exportCSV();
        }
    },

    enable() {
        UBECore.enable();
    },

    disable() {
        UBECore.disable();
    },

    toggle() {
        UBECore.toggle();
    },

    async initialize() {
        await UBECore.loadAssetsFromRegistry();
        UBECore.initialize();
    }
};