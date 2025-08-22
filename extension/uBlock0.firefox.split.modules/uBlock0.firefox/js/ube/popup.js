import {ubolog} from '../console.js';
import {UBECore} from './core.js';

export const UBEPopup = {
    instance: null,
    _boundOnPopupWindowClosed: null,
    _boundOnTabChanged: null,
    _boundOnTabUpdated: null,

    async openPopupWindow(tabId, hostname) {
        try {
            if (this.instance) {
                await this.closePopupWindow();
            }

            if (!vAPI.windows && !browser.windows) {
                ubolog(`${UBECore.LOG_ICONS.ERROR} UBE: Windows API not available`);
                return;
            }

            const currentWindow = await vAPI.windows.get(browser.windows.WINDOW_ID_CURRENT);
            const popupWidth = 365;
            const popupHeight = 500;
            const toolbarHeight = 80;
            const rightMargin = 5;

            let left, top;

            if (currentWindow) {
                left = currentWindow.left + currentWindow.width - popupWidth - rightMargin;
                top = currentWindow.top + toolbarHeight;
            }

            const createOptions = {
                url: vAPI.getURL(`popupmoogzam.html?tabId=${tabId}&hostname=${encodeURIComponent(hostname)}`),
                type: 'popup',
                width: popupWidth,
                height: popupHeight,
                focused: true,
            };

            if (left !== undefined && top !== undefined) {
                createOptions.left = left;
                createOptions.top = top;
            }

            if (vAPI.windows.create) {
                const popupWindow = await vAPI.windows.create(createOptions);

                if (!popupWindow) {
                    ubolog(`${UBECore.LOG_ICONS.ERROR} UBE: Failed to create window: popupWindow is null`);
                    return;
                }

                this.instance = {
                    id: popupWindow.id,
                    tabId: tabId,
                    hostname: hostname
                };

                ubolog(`${UBECore.LOG_ICONS.INFO} UBE: Popup window opened for tab ${tabId}`);

                this.setupPopupWindowListeners();
            }
        } catch (error) {
            ubolog(`${UBECore.LOG_ICONS.ERROR} UBE: Failed to create popup window: ${error.message}`);
        }
    },

    async closePopupWindow() {
        if (!this.instance) {
            return;
        }

        const {id, tabId} = this.instance;
        this.instance = null;

        try {
            if (vAPI.windows && vAPI.windows.update) {
                try {
                    await vAPI.windows.update(id, {state: 'minimized'});
                    await new Promise(resolve => setTimeout(resolve, 100));
                } catch (error) {
                    ubolog(`${UBECore.LOG_ICONS.WARNING} UBE: Could not minimize window: ${error.message}`);
                }
            }

            await browser.windows.remove(id);

            ubolog(`${UBECore.LOG_ICONS.INFO} UBE: Popup window closed for tab ${tabId}`);
        } catch (error) {
            ubolog(`${UBECore.LOG_ICONS.ERROR} UBE: Error closing popup window: ${error.message}`);
        }

        this.removePopupWindowListeners();
    },

    onPopupWindowClosed(windowId) {
        if (this.instance?.id === windowId) {
            ubolog(`${UBECore.LOG_ICONS.INFO} UBE: Popup window for Tab ${this.instance.tabId} was closed by user`);

            this.instance = null;
            this.removePopupWindowListeners();
        }
    },

    onTabChanged(activeInfo) {
        if (this.instance?.tabId !== activeInfo.tabId) {
            const currentTabId = this.instance?.tabId;

            if (currentTabId) {
                ubolog(`${UBECore.LOG_ICONS.INFO} UBE: Closing popup due to tab change from ${currentTabId} to ${activeInfo.tabId}`);

                this.closePopupWindow();
            }
        }
    },

    onTabUpdated(tabId, changeInfo, tabInfo) {
        if (this.instance?.tabId === tabId && changeInfo.url) {
            ubolog(`${UBECore.LOG_ICONS.INFO} UBE: Closing popup due to navigation in tab ${tabId} to ${changeInfo.url}`);

            this.closePopupWindow();
        }
    },

    setupPopupWindowListeners() {
        if (!this._boundOnPopupWindowClosed) {
            this._boundOnPopupWindowClosed = this.onPopupWindowClosed.bind(this);
            this._boundOnTabChanged = this.onTabChanged.bind(this);
            this._boundOnTabUpdated = this.onTabUpdated.bind(this);
        }

        if (!browser.windows.onRemoved.hasListener(this._boundOnPopupWindowClosed)) {
            browser.windows.onRemoved.addListener(this._boundOnPopupWindowClosed);
        }

        if (!browser.tabs.onActivated.hasListener(this._boundOnTabChanged)) {
            browser.tabs.onActivated.addListener(this._boundOnTabChanged);
        }

        if (!browser.tabs.onUpdated.hasListener(this._boundOnTabUpdated)) {
            browser.tabs.onUpdated.addListener(this._boundOnTabUpdated);
        }
    },

    removePopupWindowListeners() {
        if (this._boundOnPopupWindowClosed) {
            browser.windows.onRemoved.removeListener(this._boundOnPopupWindowClosed);
            browser.tabs.onActivated.removeListener(this._boundOnTabChanged);
            browser.tabs.onUpdated.removeListener(this._boundOnTabUpdated);

            this._boundOnPopupWindowClosed = null;
            this._boundOnTabChanged = null;
            this._boundOnTabUpdated = null;
        }
    }
};