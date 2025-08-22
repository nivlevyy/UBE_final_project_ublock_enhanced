import {ubolog} from '../console.js';
import {UBECore} from './core.js';
import {UBEPopup} from './popup.js';
import {UBEEvents} from './events.js';

// unites all modules (facade-like)
// and exposes an interface
// for simpler implementation and usage
export const UBE = {
    get enabled() {
        return UBECore.enabled;
    },

    get LOG_ICONS() {
        return UBECore.LOG_ICONS;
    },

    hasResult(tabId) {
        return UBECore.hasResult(tabId);
    },

    isActiveProcessing(tabId) {
        return UBECore.inActiveProcessing(tabId);
    },

    async openPopupWindow(tabId, hostname) {
        return UBEPopup.openPopupWindow(tabId, hostname);
    },

    get popupWindow() {
        return {
            instance: UBEPopup.instance ? {
                id: UBEPopup.instance.id,
                tabId: UBEPopup.instance.tabId,
                hostname: UBEPopup.instance.hostname
            } : null
        };
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
        if (UBECore.enabled) {
            return;
        }

        UBECore.setEnabled(true);
        UBEEvents.registerOnCommittedListener();
        ubolog('🟢 UBE: Enabled');
    },

    disable() {
        if (!UBECore.enabled) {
            return;
        }

        UBECore.setEnabled(false);
        UBEEvents.removeOnCommittedListener();
        // don't remove the other listeners
        // since we might need it in the future
        // even when disabled

        // enable to automatically close
        // results when UBE is toggled off
        // if (this.popupWindow.instance) {
        //     this.closePopupWindow();
        // }

        UBECore.clearQueue();

        ubolog(`🔴 UBE: Disabled`);
    },

    initialize() {
        UBEEvents.registerCoreListeners();

        if (this.enabled) {
            UBEEvents.registerOnCommittedListener();
        }

        ubolog(`${UBECore.LOG_ICONS.SUCCESS} UBE ready ${Date.now() - vAPI.T0} ms after launch`);
    }
};