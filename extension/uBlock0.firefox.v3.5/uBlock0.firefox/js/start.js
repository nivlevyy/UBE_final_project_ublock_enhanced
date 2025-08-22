/*******************************************************************************

 uBlock Origin - a comprehensive, efficient content blocker
 Copyright (C) 2014-present Raymond Hill

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see {http://www.gnu.org/licenses/}.

 Home: https://github.com/gorhill/uBlock
 */

import './vapi-common.js';
import './vapi-background.js';
import './vapi-background-ext.js';


import {processURL} from './bundleST1and2.js';
//import {PhishingModel} from './phishing_model.js';

/******************************************************************************/

// The following modules are loaded here until their content is better organized
import './commands.js';
import './messaging.js';
import './storage.js';
import './tab.js';
import './ublock.js';
import './utils.js';

import {
    permanentFirewall,
    permanentSwitches,
    permanentURLFiltering,
    sessionFirewall,
    sessionSwitches,
    sessionURLFiltering,
} from './filtering-engines.js';

import cacheStorage from './cachestorage.js';
import contextMenu from './contextmenu.js';
import {filteringBehaviorChanged} from './broadcast.js';
import io from './assets.js';
import {redirectEngine} from './redirect-engine.js';
import staticExtFilteringEngine from './static-ext-filtering.js';
import {staticFilteringReverseLookup} from './reverselookup.js';
import staticNetFilteringEngine from './static-net-filtering.js';
import {ubolog} from './console.js';
import webRequest from './traffic.js';
import µb from './background.js';

/******************************************************************************/

let lastVersionInt = 0;
let thisVersionInt = 0;

/******************************************************************************/

vAPI.app.onShutdown = () => {
    staticFilteringReverseLookup.shutdown();
    io.updateStop();
    staticNetFilteringEngine.reset();
    staticExtFilteringEngine.reset();
    sessionFirewall.reset();
    permanentFirewall.reset();
    sessionURLFiltering.reset();
    permanentURLFiltering.reset();
    sessionSwitches.reset();
    permanentSwitches.reset();
};

vAPI.alarms.onAlarm.addListener(alarm => {
    µb.alarmQueue.push(alarm.name);
});

/******************************************************************************/

// This is called only once, when everything has been loaded in memory after
// the extension was launched. It can be used to inject content scripts
// in already opened web pages, to remove whatever nuisance could make it to
// the web pages before uBlock was ready.
//
// https://bugzilla.mozilla.org/show_bug.cgi?id=1652925#c19
//   Mind discarded tabs.

const initializeTabs = async () => {
    const manifest = browser.runtime.getManifest();
    if (manifest instanceof Object === false) {
        return;
    }

    const toCheck = [];
    const tabIds = [];
    {
        const checker = {file: 'js/scriptlets/should-inject-contentscript.js'};
        const tabs = await vAPI.tabs.query({url: '<all_urls>'});
        for (const tab of tabs) {
            if (tab.discarded === true) {
                continue;
            }
            if (tab.status === 'unloaded') {
                continue;
            }
            const {id, url} = tab;
            µb.tabContextManager.commit(id, url);
            µb.bindTabToPageStore(id, 'tabCommitted', tab);
            // https://github.com/chrisaljoudi/uBlock/issues/129
            //   Find out whether content scripts need to be injected
            //   programmatically. This may be necessary for web pages which
            //   were loaded before uBO launched.
            toCheck.push(
                /^https?:\/\//.test(url)
                    ? vAPI.tabs.executeScript(id, checker)
                    : false
            );
            tabIds.push(id);
        }
    }
    // We do not want to block on content scripts injection
    Promise.all(toCheck).then(results => {
        for (let i = 0; i < results.length; i++) {
            const result = results[i];
            if (result.length === 0 || result[0] !== true) {
                continue;
            }
            // Inject declarative content scripts programmatically.
            for (const contentScript of manifest.content_scripts) {
                for (const file of contentScript.js) {
                    vAPI.tabs.executeScript(tabIds[i], {
                        file: file,
                        allFrames: contentScript.all_frames,
                        runAt: contentScript.run_at
                    });
                }
            }
        }
    });
};

/******************************************************************************/

// To bring older versions up to date
//
// https://www.reddit.com/r/uBlockOrigin/comments/s7c9go/
//   Abort suspending network requests when uBO is merely being installed.

const onVersionReady = async lastVersion => {
    lastVersionInt = vAPI.app.intFromVersion(lastVersion);
    thisVersionInt = vAPI.app.intFromVersion(vAPI.app.version);
    if (thisVersionInt === lastVersionInt) {
        return;
    }

    vAPI.storage.set({
        version: vAPI.app.version,
        versionUpdateTime: Date.now(),
    });

    // Special case: first installation
    if (lastVersionInt === 0) {
        vAPI.net.unsuspend({all: true, discard: true});
        return;
    }

    // Remove cache items with obsolete names
    if (lastVersionInt < vAPI.app.intFromVersion('1.56.1b5')) {
        io.remove(`compiled/${µb.pslAssetKey}`);
        io.remove('compiled/redirectEngine/resources');
        io.remove('selfie/main');
    }

    // Since built-in resources may have changed since last version, we
    // force a reload of all resources.
    redirectEngine.invalidateResourcesSelfie(io);
};

/******************************************************************************/

// https://github.com/uBlockOrigin/uBlock-issues/issues/1433
//   Allow admins to add their own trusted-site directives.

const onNetWhitelistReady = (netWhitelistRaw, adminExtra) => {
    if (typeof netWhitelistRaw === 'string') {
        netWhitelistRaw = netWhitelistRaw.split('\n');
    }

    // Remove now obsolete built-in trusted directives
    if (lastVersionInt !== thisVersionInt) {
        if (lastVersionInt < vAPI.app.intFromVersion('1.56.1b12')) {
            const obsolete = [
                'about-scheme',
                'chrome-scheme',
                'edge-scheme',
                'opera-scheme',
                'vivaldi-scheme',
                'wyciwyg-scheme',
            ];
            for (const directive of obsolete) {
                const i = netWhitelistRaw.findIndex(s =>
                    s === directive || s === `# ${directive}`
                );
                if (i === -1) {
                    continue;
                }
                netWhitelistRaw.splice(i, 1);
            }
        }
    }

    // Append admin-controlled trusted-site directives
    if (adminExtra instanceof Object) {
        if (Array.isArray(adminExtra.trustedSiteDirectives)) {
            for (const directive of adminExtra.trustedSiteDirectives) {
                µb.netWhitelistDefault.push(directive);
                netWhitelistRaw.push(directive);
            }
        }
    }

    µb.netWhitelist = µb.whitelistFromArray(netWhitelistRaw);
    µb.netWhitelistModifyTime = Date.now();
};

/******************************************************************************/

// User settings are in memory

const onUserSettingsReady = fetched => {
    // Terminate suspended state?
    const tnow = Date.now() - vAPI.T0;
    if (
        vAPI.Net.canSuspend() &&
        fetched.suspendUntilListsAreLoaded === false
    ) {
        vAPI.net.unsuspend({all: true, discard: true});
        ubolog(`Unsuspend network activity listener at ${tnow} ms`);
        µb.supportStats.unsuspendAfter = `${tnow} ms`;
    } else if (
        vAPI.Net.canSuspend() === false &&
        fetched.suspendUntilListsAreLoaded
    ) {
        vAPI.net.suspend();
        ubolog(`Suspend network activity listener at ${tnow} ms`);
    }

    // `externalLists` will be deprecated in some future, it is kept around
    // for forward compatibility purpose, and should reflect the content of
    // `importedLists`.
    if (Array.isArray(fetched.externalLists)) {
        fetched.externalLists = fetched.externalLists.join('\n');
        vAPI.storage.set({externalLists: fetched.externalLists});
    }
    if (
        fetched.importedLists.length === 0 &&
        fetched.externalLists !== ''
    ) {
        fetched.importedLists = fetched.externalLists.trim().split(/[\n\r]+/);
    }

    fromFetch(µb.userSettings, fetched);

    if (µb.privacySettingsSupported) {
        vAPI.browserSettings.set({
            'hyperlinkAuditing': !µb.userSettings.hyperlinkAuditingDisabled,
            'prefetching': !µb.userSettings.prefetchingDisabled,
            'webrtcIPAddress': !µb.userSettings.webrtcIPAddressHidden
        });
    }

    // https://github.com/uBlockOrigin/uBlock-issues/issues/1513
    if (
        vAPI.net.canUncloakCnames &&
        µb.userSettings.cnameUncloakEnabled === false
    ) {
        vAPI.net.setOptions({cnameUncloakEnabled: false});
    }
};

/******************************************************************************/

// https://bugzilla.mozilla.org/show_bug.cgi?id=1588916
//   Save magic format numbers into the cache storage itself.
// https://github.com/uBlockOrigin/uBlock-issues/issues/1365
//   Wait for removal of invalid cached data to be completed.

const onCacheSettingsReady = async (fetched = {}) => {
    let selfieIsInvalid = false;
    if (fetched.compiledMagic !== µb.systemSettings.compiledMagic) {
        µb.compiledFormatChanged = true;
        selfieIsInvalid = true;
        ubolog(`Serialized format of static filter lists changed`);
    }
    if (fetched.selfieMagic !== µb.systemSettings.selfieMagic) {
        selfieIsInvalid = true;
        ubolog(`Serialized format of selfie changed`);
    }
    if (selfieIsInvalid === false) {
        return;
    }
    µb.selfieManager.destroy({janitor: true});
    cacheStorage.set(µb.systemSettings);
};

/******************************************************************************/

const onHiddenSettingsReady = async () => {
    // Maybe customize webext flavor
    if (µb.hiddenSettings.modifyWebextFlavor !== 'unset') {
        const tokens = µb.hiddenSettings.modifyWebextFlavor.split(/\s+/);
        for (const token of tokens) {
            switch (token[0]) {
                case '+':
                    vAPI.webextFlavor.soup.add(token.slice(1));
                    break;
                case '-':
                    vAPI.webextFlavor.soup.delete(token.slice(1));
                    break;
                default:
                    vAPI.webextFlavor.soup.add(token);
                    break;
            }
        }
        ubolog(`Override default webext flavor with ${tokens}`);
    }

    // Maybe disable WebAssembly
    if (vAPI.canWASM && µb.hiddenSettings.disableWebAssembly !== true) {
        const wasmModuleFetcher = function (path) {
            return fetch(`${path}.wasm`, {mode: 'same-origin'}).then(
                WebAssembly.compileStreaming
            ).catch(reason => {
                ubolog(reason);
            });
        };
        staticNetFilteringEngine.enableWASM(wasmModuleFetcher, './js/wasm/').then(result => {
            if (result !== true) {
                return;
            }
            ubolog(`WASM modules ready ${Date.now() - vAPI.T0} ms after launch`);
        });
    }
};

/******************************************************************************/

const onFirstFetchReady = (fetched, adminExtra) => {
    // https://github.com/uBlockOrigin/uBlock-issues/issues/507
    //   Firefox-specific: somehow `fetched` is undefined under certain
    //   circumstances even though we asked to load with default values.
    if (fetched instanceof Object === false) {
        fetched = createDefaultProps();
    }

    // Order is important -- do not change:
    fromFetch(µb.restoreBackupSettings, fetched);

    permanentFirewall.fromString(fetched.dynamicFilteringString);
    sessionFirewall.assign(permanentFirewall);
    permanentURLFiltering.fromString(fetched.urlFilteringString);
    sessionURLFiltering.assign(permanentURLFiltering);
    permanentSwitches.fromString(fetched.hostnameSwitchesString);
    sessionSwitches.assign(permanentSwitches);

    onNetWhitelistReady(fetched.netWhitelist, adminExtra);
};

/******************************************************************************/

const toFetch = (from, fetched) => {
    for (const k in from) {
        if (Object.hasOwn(from, k) === false) {
            continue;
        }
        fetched[k] = from[k];
    }
};

const fromFetch = (to, fetched) => {
    for (const k in to) {
        if (Object.hasOwn(to, k) === false) {
            continue;
        }
        if (Object.hasOwn(fetched, k) === false) {
            continue;
        }
        to[k] = fetched[k];
    }
};

const createDefaultProps = () => {
    const fetchableProps = {
        'dynamicFilteringString': µb.dynamicFilteringDefault.join('\n'),
        'urlFilteringString': '',
        'hostnameSwitchesString': µb.hostnameSwitchesDefault.join('\n'),
        'netWhitelist': µb.netWhitelistDefault,
        'version': '0.0.0.0'
    };
    toFetch(µb.restoreBackupSettings, fetchableProps);
    return fetchableProps;
};

/******************************************************************************/

(async () => {
// >>>>> start of async/await scope

    try {
        ubolog(`Start sequence of loading storage-based data ${Date.now() - vAPI.T0} ms after launch`);

        // https://github.com/gorhill/uBlock/issues/531
        await µb.restoreAdminSettings();
        ubolog(`Admin settings ready ${Date.now() - vAPI.T0} ms after launch`);

        await µb.loadHiddenSettings();
        await onHiddenSettingsReady();
        ubolog(`Hidden settings ready ${Date.now() - vAPI.T0} ms after launch`);

        const adminExtra = await vAPI.adminStorage.get('toAdd');
        ubolog(`Extra admin settings ready ${Date.now() - vAPI.T0} ms after launch`);

        // Maybe override default cache storage
        µb.supportStats.cacheBackend = await cacheStorage.select(
            µb.hiddenSettings.cacheStorageAPI
        );
        ubolog(`Backend storage for cache will be ${µb.supportStats.cacheBackend}`);

        await vAPI.storage.get(createDefaultProps()).then(async fetched => {
            ubolog(`Version ready ${Date.now() - vAPI.T0} ms after launch`);
            await onVersionReady(fetched.version);
            return fetched;
        }).then(fetched => {
            ubolog(`First fetch ready ${Date.now() - vAPI.T0} ms after launch`);
            onFirstFetchReady(fetched, adminExtra);
        });

        await Promise.all([
            µb.loadSelectedFilterLists().then(() => {
                ubolog(`List selection ready ${Date.now() - vAPI.T0} ms after launch`);
            }),
            µb.loadUserSettings().then(fetched => {
                ubolog(`User settings ready ${Date.now() - vAPI.T0} ms after launch`);
                onUserSettingsReady(fetched);
            }),
            µb.loadPublicSuffixList().then(() => {
                ubolog(`PSL ready ${Date.now() - vAPI.T0} ms after launch`);
            }),
            cacheStorage.get({compiledMagic: 0, selfieMagic: 0}).then(bin => {
                ubolog(`Cache magic numbers ready ${Date.now() - vAPI.T0} ms after launch`);
                onCacheSettingsReady(bin);
            }),
            µb.loadLocalSettings(),
        ]);

        // https://github.com/uBlockOrigin/uBlock-issues/issues/1547
        if (lastVersionInt === 0 && vAPI.webextFlavor.soup.has('chromium')) {
            vAPI.app.restart();
            return;
        }
    } catch (ex) {
        console.trace(ex);
    }

// Prime the filtering engines before first use.
    staticNetFilteringEngine.prime();

// https://github.com/uBlockOrigin/uBlock-issues/issues/817#issuecomment-565730122
//   Still try to load filter lists regardless of whether a serious error
//   occurred in the previous initialization steps.
    let selfieIsValid = false;
    try {
        selfieIsValid = await µb.selfieManager.load();
        if (selfieIsValid === true) {
            ubolog(`Loaded filtering engine from selfie ${Date.now() - vAPI.T0} ms after launch`);
        }
    } catch (ex) {
        console.trace(ex);
    }
    if (selfieIsValid !== true) {
        try {
            await µb.loadFilterLists();
            ubolog(`Filter lists ready ${Date.now() - vAPI.T0} ms after launch`);
        } catch (ex) {
            console.trace(ex);
        }
    }

// Flush memory cache -- unsure whether the browser does this internally
// when loading a new extension.
    filteringBehaviorChanged();

// Final initialization steps after all needed assets are in memory.

// https://github.com/uBlockOrigin/uBlock-issues/issues/974
//   This can be used to defer filtering decision-making.
    µb.readyToFilter = true;

// Initialize internal state with maybe already existing tabs.
    await initializeTabs();

// Start network observers.
    webRequest.start();

// Force an update of the context menu according to the currently
// active tab.
    contextMenu.update();

// https://github.com/uBlockOrigin/uBlock-issues/issues/717
//   Prevent the extension from being restarted mid-session.
    browser.runtime.onUpdateAvailable.addListener(details => {
        const toInt = vAPI.app.intFromVersion;
        if (
            µb.hiddenSettings.extensionUpdateForceReload === true ||
            toInt(details.version) <= toInt(vAPI.app.version)
        ) {
            vAPI.app.restart();
        }
    });

    µb.supportStats.allReadyAfter = `${Date.now() - vAPI.T0} ms`;
    if (selfieIsValid) {
        µb.supportStats.allReadyAfter += ' (selfie)';
    }
    ubolog(`All ready ${µb.supportStats.allReadyAfter} after launch`);

    µb.isReadyResolve();


// https://github.com/chrisaljoudi/uBlock/issues/184
//   Check for updates not too far in the future.
    io.addObserver(µb.assetObserver.bind(µb));
    if (µb.userSettings.autoUpdate) {
        let needEmergencyUpdate = false;
        const entries = await io.getUpdateAges({
            filters: µb.selectedFilterLists,
            internal: ['*'],
        });
        for (const entry of entries) {
            if (entry.ageNormalized < 2) {
                continue;
            }
            needEmergencyUpdate = true;
            break;
        }
        const updateDelay = needEmergencyUpdate
            ? 2000
            : µb.hiddenSettings.autoUpdateDelayAfterLaunch * 1000;
        µb.scheduleAssetUpdater({
            auto: true,
            updateDelay,
            fetchDelay: needEmergencyUpdate ? 1000 : undefined
        });
    }

// Process alarm queue
    while (µb.alarmQueue.length !== 0) {
        const what = µb.alarmQueue.shift();
        ubolog(`Processing alarm event from suspended state: '${what}'`);
        switch (what) {
            case 'assetUpdater':
                µb.scheduleAssetUpdater({auto: true, updateDelay: 2000, fetchDelay: 1000});
                break;
            case 'createSelfie':
                µb.selfieManager.create();
                break;
            case 'saveLocalSettings':
                µb.saveLocalSettings();
                break;
        }
    }

// <<<<< end of async/await scope
})();


(async () => {
    await µb.isReadyPromise;

    // class StandardScaler {
    //     constructor() {
    //         this.mean = null;
    //         this.std = null;
    //     }
    //
    //     fit(values) {
    //         this.mean = values.reduce((sum, val) => sum + val, 0) / values.length;
    //         const variance = values.reduce((sum, val) => sum + Math.pow(val - this.mean, 2), 0) / values.length;
    //         this.std = Math.sqrt(variance);
    //         return this;
    //     }
    //
    //     transform(values) {
    //         if (this.mean === null || this.std === null) {
    //             throw new Error('Scaler must be fitted before transforming');
    //         }
    //         return values.map(val => (val - this.mean) / this.std);
    //     }
    //
    //     fitTransform(values) {
    //         return this.fit(values).transform(values);
    //     }
    // }

    µb.UBE = {
        enabled: false,

        tabResults: new Map(),
        activeProcessing: new Map(),
        processingQueue: [],
        allResults: [],

        MAX_CONCURRENT: 10,
        MAX_STORED_RESULTS: 30,

        MESSAGE_TYPES: {
            ANALYSIS_COMPLETE: 'analysisComplete',
            CHECK_HTML: 'checkHTML',
            CHECK_RESULT: 'getCheckResult',
            STARTED_PROCESSING: 'startedProcessing'
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
        },

        browserListeners: {
            navigationOnCommitted: null,
            runtimeMessage: null,
            tabRemoved: null
        },

        popupWindow: {
            instance: null,
            _boundOnPopupWindowClosed: null,
            _boundOnTabChanged: null,
            _boundOnTabUpdated: null,
        },

        // scaler: new StandardScaler(),
        //
        // scaleData: function(numberList) {
        //     return this.scaler.fitTransform(numberList);
        // },

//         testModel(results) {
//             const parts = [
//                 // results["URL Length"],
//                 results["Subdomains"],
//                 results["Hostname Length"],
//                 // results["IP"],
//                 results["Shortener"],
//                 results["Hyphens"],
//                 results["At Signs"],
//                 results["Query Parameters"],
//                 // results["Resources"],
//                 // 1,
//                 // 0,
// //             results["Has Protocol"],
// //             results["Is Email"],
//                 results["Suspicious Chars"],
// //        0,
// //             results["Has Double Slash"],
//                 //results["Final Domain"],
//                 results["SSL Exists"],
//                 results["SSL Valid"],
//                 //       results["SSL Issuer"],
//                 results["Domain Age"],
//                 results["Domain Expiry"],
//                 //       results["Domain Registrar"],
//                 results["VT Reputation"],
//                 results["VT Malicious"],
//                 results["VT Suspicious"],
//                 //results["VT Undetected"],
//                 results["VT Harmless"],
//                 results["favicon Present"],
//                 results["favicon Different Domains"],
//                 results["favicon Invalid Type"],
//                 results["Anchor Tags"],
//                 results["Anchor Empty Hrefs"],
//                 results["Anchor Different Domains"],
//                 results["Anchor Different Domains Ratio"],
//                 results["External Metas"],
//                 results["External Metas Suspicious Words"],
//                 results["External Metas Ratio"],
//                 results["External Scripts"],
//                 results["External Scripts Suspicious Words"],
//                 results["External Scripts Ratio"],
//                 // results["Total Links"],
//                 results["External Links"],
//                 results["External Links Ratio"],
//                 // results["External Total"],
//                 // results["Resources Total"],
//                 results["Resources External"],
//                 results["Resources External Ratio"],
//                 // results["SFH Total"],
//                 results["SFH Blank Actions"],
//                 results["SFH Different Domains"],
//                 results["SFH Passwords"],
//                 results["SFH Suspicious Words"],
//                 results["IFrame src"],
//                 results["IFrame src Hidden"],
//                 results["IFrame src Size"],
//                 results["IFrame src Different Domains"],
//                 results["IFrame src No Sandbox"],
//                 results["IFrame External src Ratio"],
//                 results["IFrame srcdoc"],
//                 results["IFrame srcdoc Hidden"],
//                 results["IFrame srcdoc Scripts"],
//                 results["IFrame srcdoc Suspicious Words"],
//                 //results["IFrame Total"],
//                 results["JS Inline"],
//                 //results["JS High Risk Patterns"],
//                 //results["JS Medium Risk Patterns"],
//                 // results["JS Low Risk Patterns"],
//                 // results["JS Different Domains"],
//                 // results["JS Behave Ratio"],
//                 // results["JS Risk Patterns Ratio"],
//                 results["NLP"],
//                 // results["JS Total"],
//                 // results["JS External"],
//                 // results["AR Meta Refresh"],
//                 // results["AR JS"],
//                 // results["AR Cross Domain"],
//                 // results["Hidden Login Forms"],
//                 results["JS OnMouseOver Scripts"],
//                 results["JS OnMouseOver Tags"],
//                 results["Right Click Scripts"],
//                 results["Right Click Menu Tags"],
//                 0
//             ];
//
//             const scaledValues = this.scaleData(parts);
//             const prediction = PhishingModel().predict(scaledValues);
//
//             return prediction ? 'phishing aware!' : 'safe, be calm dude ';
//         },


        async openPopupWindow(tabId, hostname) {
            try {
                if (this.popupWindow.instance) {
                    await this.closePopupWindow();
                }

                if (!vAPI.windows && !browser.windows) {
                    ubolog(`${this.LOG_ICONS.ERROR} UBE: Windows API not available`);
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
                        throw new Error('popupWindow is null');
                    }

                    this.popupWindow.instance = {
                        id: popupWindow.id,
                        tabId: tabId,
                        hostname: hostname
                    };

                    ubolog(`${this.LOG_ICONS.INFO} UBE: Popup window opened for tab ${tabId}`);

                    this.setupPopupWindowListeners();
                }
            } catch (error) {
                ubolog(`${this.LOG_ICONS.ERROR} UBE: Failed to create popup window: ${error.message}`);
            }
        },

        async closePopupWindow() {
            if (!this.popupWindow.instance) {
                return;
            }

            const {id, tabId} = this.popupWindow.instance;
            this.popupWindow.instance = null;

            try {
                if (vAPI.windows && vAPI.windows.update) {
                    try {
                        await vAPI.windows.update(id, {state: 'minimized'});
                        await new Promise(resolve => setTimeout(resolve, 100));
                    } catch (error) {
                        ubolog(`${this.LOG_ICONS.WARNING} UBE: Could not minimize window: ${error.message}`);
                    }
                }

                await browser.windows.remove(id);

                ubolog(`${this.LOG_ICONS.INFO} UBE: Popup window closed for tab ${tabId}`);
            } catch (error) {
                ubolog(`${this.LOG_ICONS.ERROR} UBE: Error closing popup window: ${error.message}`);
            }

            this.removePopupWindowListeners();
        },

        onPopupWindowClosed(windowId) {
            if (this.popupWindow.instance?.id === windowId) {
                ubolog(`${this.LOG_ICONS.INFO} UBE: Popup window for Tab ${this.popupWindow.instance.tabId} was closed by user`);

                this.popupWindow.instance = null;
                this.removePopupWindowListeners();
            }
        },

        onTabChanged(activeInfo) {
            if (this.popupWindow.instance?.tabId !== activeInfo.tabId) {
                const currentTabId = this.popupWindow.instance?.tabId;

                if (currentTabId) {
                    ubolog(`${this.LOG_ICONS.INFO} UBE: Closing popup due to tab change from ${currentTabId} to ${activeInfo.tabId}`);

                    this.closePopupWindow();
                }
            }
        },

        onTabUpdated(tabId, changeInfo, tabInfo) {
            if (this.popupWindow.instance?.tabId === tabId && changeInfo.url) {
                ubolog(`${this.LOG_ICONS.INFO} UBE: Closing popup due to navigation in tab ${tabId} to ${changeInfo.url}`);

                this.closePopupWindow();
            }
        },

        async getFirstAndSecondStagesResults(tabId, url) {
            try {
                ubolog(`${this.LOG_ICONS.WAIT} UBE: (Stage 1) Processing Tab ${tabId}`);

                const urlResult = await processURL(url);

                ubolog(`${this.LOG_ICONS.SUCCESS} UBE: (Stage 1) Successfully finished for Tab ${tabId}`);

                if (Object.keys(urlResult).length === 0) {
                    ubolog(`${this.LOG_ICONS.WARNING} UBE: (Stage 1) Empty result received for Tab ${tabId}`);
                    return {};
                }

                return urlResult;
            } catch (error) {
                ubolog(`${this.LOG_ICONS.ERROR} UBE: (Stage 1) Failed to process Tab ${tabId}: ${error}`);
                throw error;
            }
        },

        async getThirdStageResults(tabId, url) {
            // set up listener and return promise immediately
            const readyPromise = this.waitForContentScriptReady(tabId);

            // for timeout / race condition / other exceptions
            readyPromise.catch(() => {
                ubolog(`${this.LOG_ICONS.ERROR} UBE: Ready Promise failed for Tab ${tabId}`);
            });

            try {
                ubolog(`${this.LOG_ICONS.ACTION} UBE: (Stage 3) Injecting content script to Tab ${tabId}`);

                await this.injectContentScript(tabId);

                ubolog(`${this.LOG_ICONS.WAIT} UBE: (Stage 3) Waiting for 'content script ready' message for Tab ${tabId}`);

                readyPromise.startTimeout(3000);

                await readyPromise;

                ubolog(`${this.LOG_ICONS.ADVANCED} UBE: (Stage 3) Content script ready for Tab ${tabId}`);

                const response = await this.triggerContentScriptCheck(tabId, {
                    source: 'ubeBackgroundScript',
                    what: 'checkHTML',
                    tabId: tabId,
                    url: url
                });

                ubolog(`${this.LOG_ICONS.SUCCESS} UBE: (Stage 3) Successfully finished for Tab ${tabId}`);

                if (!response.result || Object.keys(response.result).length === 0) {
                    ubolog(`${this.LOG_ICONS.WARNING} UBE: (Stage 3) Empty result received for Tab ${tabId}`);
                    return {};
                }

                return response.result;
            } catch (error) {
                ubolog(`${this.LOG_ICONS.ERROR} UBE: (Stage 3) Failed to process Tab ${tabId}: ${error}`);
                throw error;
            } finally {
                readyPromise?.cancel?.();
            }
        },

        async processAllStages(tabId, url) {
            const [firstAndSecondStagesResult, thirdStageResult] = await Promise.all([
                this.getFirstAndSecondStagesResults(tabId, url),
                this.getThirdStageResults(tabId, url)
            ]);

            return {
                ...firstAndSecondStagesResult,
                ...thirdStageResult
            };
        },

        async injectContentScript(tabId) {
            try {
                await vAPI.tabs.executeScript(tabId, {
                    file: '/js/bundleST3_uBO_EDITION.js',
                    allFrames: false,
                    runAt: "document_end"
                });

                ubolog(`${this.LOG_ICONS.ADVANCED} UBE: Content script injected to Tab ${tabId}`);
            } catch (error) {
                ubolog(`${this.LOG_ICONS.ERROR} UBE: Content script injection failed for Tab ${tabId}: ${error}`);
                throw error;
            }
        },

        waitForContentScriptReady(tabId) {
            ubolog(`${this.LOG_ICONS.ACTION} UBE: (Stage 3) Setting up listener for 'content script ready' message for Tab ${tabId}`);

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
            ubolog(`${this.LOG_ICONS.MESSAGE} UBE: Sending message to Tab ${tabId} to start processing`);

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
        },

        validateCapacity(tabId) {
            if (this.tabResults.size >= this.MAX_STORED_RESULTS) {
                const oldestEntry = Array.from(this.tabResults.entries())
                    .sort((a, b) => a[1].timestamps.end - b[1].timestamps.end)[0];

                this.tabResults.delete(oldestEntry[0]);
                ubolog(`${this.LOG_ICONS.REMOVE} UBE: Removed oldest result (Tab ${oldestEntry[0]}) for new results for Tab ${tabId}`);
            }
        },

        sendCompleteMessageToPopup(details) {
            if (browser.runtime?.sendMessage) {
                browser.runtime.sendMessage(details,
                    () => {
                        if (browser.runtime.lastError) {
                            ubolog(`${this.LOG_ICONS.ERROR} Error sending message: ${browser.runtime.lastError.message}`);
                        }
                    });
            }
        },

        handleProcessingSuccess(tabId, url, combinedResults) {
            if (!this.enabled) {
                ubolog(`${this.LOG_ICONS.INFO} UBE: Ignoring results for Tab ${tabId} (Disabled)`);
                return;
            }

            if (Object.keys(combinedResults).length === 0) {
                ubolog(`${this.LOG_ICONS.INFO} UBE: No results received for Tab ${tabId}`);
                return;
            }

            ubolog(`${this.LOG_ICONS.SUCCESS} UBE: Successfully received results for Tab ${tabId}`);
            this.validateCapacity(tabId);

            ////
            //combinedResults['Prediction'] = this.testModel(combinedResults);
            ////

            this.allResults.push({URL: url, ...combinedResults});

            const resultData = {
                url: url,
                result: combinedResults,
                timestamps: {
                    begin: this.activeProcessing.get(tabId)?.timestamp,
                    end: Date.now()
                },
                executionTimes: {
                    begin: this.activeProcessing.get(tabId)?.timestampPerf,
                    end: performance.now()
                }
            };

            this.tabResults.set(tabId, resultData);

            this.sendCompleteMessageToPopup({
                source: 'ubeBackgroundScript',
                what: this.MESSAGE_TYPES.ANALYSIS_COMPLETE,
                tabId: tabId,
                result: this.tabResults.get(tabId)
            });

            ubolog(`${this.LOG_ICONS.SAVE} UBE: Saved results for Tab ${tabId} - ${url}`);
        },

        handleProcessingError(tabId, url, error) {
            if (error.message?.includes('No tab with id')) {
                ubolog(`${this.LOG_ICONS.ERROR} UBE: Tab ${tabId} was closed before processing`);
            } else {
                ubolog(`${this.LOG_ICONS.ERROR} UBE: Processing failed for Tab ${tabId} - ${url}: ${error.message}`);
            }
        },

        getNextTabInQueue() {
            if (this.processingQueue.length === 0) {
                ubolog(`${this.LOG_ICONS.INFO} UBE: Processing queue is empty`);
                return null;
            }

            if (this.activeProcessing.size >= this.MAX_CONCURRENT) {
                ubolog(`${this.LOG_ICONS.ALERT} UBE: At max capacity [${this.activeProcessing.size}/${this.MAX_CONCURRENT}]. Tab ${this.processingQueue[0].tabId} waiting...`);
                return null;
            }

            return this.processingQueue.shift();
        },

        async processNext() {
            const nextTab = this.getNextTabInQueue();

            if (!nextTab) {
                return;
            }

            const {tabId, url} = nextTab;
            this.activeProcessing.set(tabId, {timestamp: Date.now(), timestampPerf: performance.now()});
            ubolog(`${this.LOG_ICONS.START} UBE: Started processing Tab ${tabId} [Queue: ${this.processingQueue.length}, Active: ${this.activeProcessing.size}]`);

            try {
                const combinedResults = await this.processAllStages(tabId, url);
                this.handleProcessingSuccess(tabId, url, combinedResults);
            } catch (error) {
                this.handleProcessingError(tabId, url, error);
            } finally {
                this.activeProcessing.delete(tabId);
                ubolog(`${this.LOG_ICONS.FINISH} UBE: Finished Tab ${tabId} - ${url}`);
                ubolog(`${this.LOG_ICONS.INFO} UBE: [Queue: ${this.processingQueue.length}, Active: ${this.activeProcessing.size}]`);

                setTimeout(() => {
                    this.processNext();
                }, 10);
            }
        },

        debug: {
            getStatus() {
                return {
                    enabled: this.enabled,
                    queueLength: this.processingQueue.length,
                    activeProcessing: this.activeProcessing.size,
                    totalResults: this.tabResults.size,
                    allResultsCount: this.allResults.length
                };
            },

            exportCSV() {
                const headers = [
                    "URL",
                    "URL Length",
                    "Subdomains",
                    "Hostname Length",
                    "IP",
                    "Shortener",
                    "Hyphens",
                    "At Signs",
                    "Query Parameters",
                    "Resources",
                    //"Has Protocol",
                    //"Is Email",
                    "Suspicious Chars",
                    //"Has Double Slash",
                    "SSL Exists",
                    "SSL Valid",
                    "SSL Issuer",
                    "Domain Age",
                    "Domain Expiry",
                    "Domain Registrar",
                    "VT Reputation",
                    "VT Malicious",
                    "VT Suspicious",
                    "VT Undetected",
                    "VT Harmless",
                    "favicon Present",
                    "favicon Different Domains",
                    "favicon Invalid Type",
                    "Anchor Tags",
                    "Anchor Empty Hrefs",
                    "Anchor Different Domains",
                    "Anchor Different Domains Ratio",
                    "External Metas",
                    "External Metas Suspicious Words",
                    "External Metas Ratio",
                    "External Scripts",
                    "External Scripts Suspicious Words",
                    "External Scripts Ratio",
                    "Total Links",
                    "External Links",
                    "External Links Ratio",
                    "External Total",
                    "Resources Total",
                    "Resources External",
                    "Resources External Ratio",
                    "SFH Total",
                    "SFH Blank Actions",
                    "SFH Different Domains",
                    "SFH Passwords",
                    "SFH Suspicious Words",
                    "IFrame src",
                    "IFrame src Hidden",
                    "IFrame src Size",
                    "IFrame src Different Domains",
                    "IFrame src No Sandbox",
                    "IFrame External src Ratio",
                    "IFrame srcdoc",
                    "IFrame srcdoc Hidden",
                    "IFrame srcdoc Scripts",
                    "IFrame srcdoc Suspicious Words",
                    "IFrame Total",
                    "JS Inline",
                    "JS High Risk Patterns",
                    "JS Medium Risk Patterns",
                    "JS Low Risk Patterns",
                    "JS Different Domains",
                    "JS Behave Ratio",
                    "JS Risk Patterns Ratio",
                    "NLP",
                    "JS Total",
                    "JS External",
                    "AR Meta Refresh",
                    "AR JS",
                    "AR Cross Domain",
                    "Hidden Login Forms",
                    "JS OnMouseOver Scripts",
                    "JS OnMouseOver Tags",
                    "Right Click Scripts",
                    "Right Click Menu Tags",
                    //"Different Domains",
                    //"validity"
                ];

                try {
                    const csvRows = [
                        headers.join(','),
                        ...µb.UBE.allResults.map(row =>
                            headers.map(h => JSON.stringify(row[h] ?? "N/A")).join(',')
                        )
                    ];

                    const blob = new Blob([csvRows.join('\n')], {type: 'text/csv'});
                    const blobUrl = URL.createObjectURL(blob);

                    browser.downloads.download({
                        url: blobUrl,
                        filename: `ube_collected_results_${new Date().toISOString().slice(0, 10)}.csv`,
                        saveAs: true
                    }, (downloadId) => {
                        if (browser.runtime.lastError) {
                            ubolog(`${µb.UBE.LOG_ICONS.ERROR} Download failed: ${browser.runtime.lastError.message}`);
                        } else {
                            ubolog(`${µb.UBE.LOG_ICONS.SUCCESS} Download started, ID: ${downloadId}`);
                        }
                    });

                    ubolog(`${µb.UBE.LOG_ICONS.SUCCESS} UBE: CSV export initiated using browser.download`);

                    setTimeout(() => {
                        URL.revokeObjectURL(blobUrl);
                    }, 10000);
                } catch (error) {
                    ubolog(`${µb.UBE.LOG_ICONS.ERROR} UBE: CSV export failed: ${error.message}`);
                }
            }
        },

        // async startForTab(tabId, hostname) {
        //     if (!this.enabled) return;
        //
        //     ubolog(`${this.LOG_ICONS.INFO} UBE: Enabled for tab ${tabId} (${hostname})`);
        // },

        clearQueue() {
            ubolog(`${this.LOG_ICONS.INFO} UBE Disabled: Clearing any pending requests in processing queue...`);

            if (this.processingQueue.length > 0) {
                this.processingQueue.length = 0;
            }
        },

        cleanupTab(tabId) {
            const queueIndex = this.processingQueue.findIndex(item => item.tabId === tabId);

            if (queueIndex !== -1) {
                this.processingQueue.splice(queueIndex, 1);
                ubolog(`${this.LOG_ICONS.REMOVE} Removed closed Tab ${tabId} from queue`);
            }

            if (this.tabResults.has(tabId)) {
                this.tabResults.delete(tabId);
                ubolog(`${this.LOG_ICONS.REMOVE} Cleaned up results for closed Tab ${tabId}`);
            }

            if (this.popupWindow.instance?.tabId === tabId) {
                ubolog(`${this.LOG_ICONS.REMOVE} Closing popup for removed Tab ${tabId}`);
                this.closePopupWindow();
            }
        },

        onNavigationCommitted(details) {
            if (!this.enabled) {
                return;
            }

            if (details?.frameId !== 0) {
                ubolog(`${this.LOG_ICONS.ALERT} UBE: Skipping non-main frame ${details.frameId}`);
                return;
            }
            if (details?.tabId < 0 || !details?.url) {
                ubolog(`${this.LOG_ICONS.ERROR} UBE: Invalid tabId or URL`);
                return;
            }

            // safety check
            if (!details.url.startsWith('http://') && !details.url.startsWith('https://')) {
                ubolog(`${this.LOG_ICONS.ALERT} UBE: Skipping non-HTTP(S) URL: ${details.url}`);
                return;
            }

            const {tabId, url} = details;

            ubolog(`${this.LOG_ICONS.NEW} UBE: New page loading at Tab ${tabId} - ${url}`);

            const queueIndex = this.processingQueue.findIndex(item => item.tabId === tabId);

            if (queueIndex !== -1) {
                ubolog(`${this.LOG_ICONS.INFO} UBE: Replacing Tab ${tabId} in processing queue due to page navigation`);
                this.processingQueue.splice(queueIndex, 1);
            }

            this.processingQueue.push({
                tabId: tabId,
                url: url,
                timestamp: Date.now()
            });

            this.processNext();
        },

        handleRuntimeMessage(request, sender, sendResponse) {
            try {
                const { source, what, tabId } = request;

                if (source === 'ubePopup') {
                    switch (what) {
                        case 'getCheckResult': {
                            if (!tabId) {
                                sendResponse({
                                    source: 'ubeBackgroundScript',
                                    error: 'No tabId provided'
                                });
                            } else {
                                const result = this.tabResults.get(tabId);

                                if (result) {
                                    sendResponse({
                                        source: 'ubeBackgroundScript',
                                        tabId: tabId,
                                        result: result
                                    });
                                } else if (this.activeProcessing.has(tabId)) {
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

                        case 'exportCSV': {
                            if (this.debug?.exportCSV) {
                                this.debug.exportCSV();
                            }
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
                        case 'startedProcessing': {
                            ubolog(`${this.LOG_ICONS.WAIT} UBE: (Stage 3) Processing Tab ${tabId}`);
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
                ubolog(`${this.LOG_ICONS.ERROR} UBE: Error in browser message handler: ${error.message}`);
                sendResponse({
                    source: 'ubeBackgroundScript',
                    error: 'Internal error'
                });
            }
        },

        setupPopupWindowListeners() {
            if (!this.popupWindow._boundOnPopupWindowClosed) {
                this.popupWindow._boundOnPopupWindowClosed = this.onPopupWindowClosed.bind(this);
                this.popupWindow._boundOnTabChanged = this.onTabChanged.bind(this);
                this.popupWindow._boundOnTabUpdated = this.onTabUpdated.bind(this);
            }

            if (!browser.windows.onRemoved.hasListener(this.popupWindow._boundOnPopupWindowClosed)) {
                browser.windows.onRemoved.addListener(this.popupWindow._boundOnPopupWindowClosed);
            }

            if (!browser.tabs.onActivated.hasListener(this.popupWindow._boundOnTabChanged)) {
                browser.tabs.onActivated.addListener(this.popupWindow._boundOnTabChanged);
            }

            if (!browser.tabs.onUpdated.hasListener(this.popupWindow._boundOnTabUpdated)) {
                browser.tabs.onUpdated.addListener(this.popupWindow._boundOnTabUpdated);
            }
        },

        removePopupWindowListeners() {
            if (this.popupWindow._boundOnPopupWindowClosed) {
                browser.windows.onRemoved.removeListener(this.popupWindow._boundOnPopupWindowClosed);
                browser.tabs.onActivated.removeListener(this.popupWindow._boundOnTabChanged);
                browser.tabs.onUpdated.removeListener(this.popupWindow._boundOnTabUpdated);
                this.popupWindow._boundOnPopupWindowClosed = null;
                this.popupWindow._boundOnTabChanged = null;
                this.popupWindow._boundOnTabUpdated = null;
            }
        },

        registerOnCommittedListener() {
            if (browser.webNavigation && !this.browserListeners.navigationOnCommitted) {
                this.browserListeners.navigationOnCommitted = this.onNavigationCommitted.bind(this);

                browser.webNavigation.onCommitted.addListener(
                    this.browserListeners.navigationOnCommitted,
                    {url: [{schemes: ["http", "https"]}]}
                );

                ubolog(`${this.LOG_ICONS.SUCCESS} UBE: browser WebNavigation listener registered`);
            } else {
                ubolog(`${this.LOG_ICONS.ERROR} UBE: browser WebNavigation API not available`);
            }
        },

        registerCoreListeners() {
            if (browser.runtime && !this.browserListeners.runtimeMessage) {
                this.browserListeners.runtimeMessage = this.handleRuntimeMessage.bind(this);

                browser.runtime.onMessage.addListener(this.browserListeners.runtimeMessage);
                ubolog(`${this.LOG_ICONS.SUCCESS} UBE: browser runtime onMessage listener registered`);
            }

            if (browser.tabs && !this.browserListeners.tabRemoved) {
                this.browserListeners.tabRemoved = this.cleanupTab.bind(this);

                browser.tabs.onRemoved.addListener(this.browserListeners.tabRemoved);
                ubolog(`${this.LOG_ICONS.SUCCESS} UBE: browser tabs onRemoved listener registered`);
            }
        },

        // removeCoreListeners() {
        //     if (this.browserListeners.runtimeMessage) {
        //         browser.runtime.onMessage.removeListener(this.browserListeners.runtimeMessage);
        //         this.browserListeners.runtimeMessage = null;
        //         ubolog(`${this.LOG_ICONS.SUCCESS} UBE: browser runtime onMessage listener removed`);
        //     }
        //
        //     if (this.browserListeners.tabRemoved) {
        //         browser.tabs.onRemoved.removeListener(this.browserListeners.tabRemoved);
        //         this.browserListeners.tabRemoved = null;
        //         ubolog(`${this.LOG_ICONS.SUCCESS} UBE: browser tabs onRemoved listener removed`);
        //     }
        // },

        removeOnCommittedListener() {
            if (this.browserListeners.navigationOnCommitted) {
                browser.webNavigation.onCommitted.removeListener(this.browserListeners.navigationOnCommitted);
                this.browserListeners.navigationOnCommitted = null;
                ubolog(`${this.LOG_ICONS.SUCCESS} UBE: browser WebNavigation listener removed`);
            }
        },

        enable() {
            if (this.enabled) {
                return;
            }

            this.enabled = true;
            this.registerOnCommittedListener();

            ubolog('🟢 UBE: Enabled');
        },

        disable() {
            if (!this.enabled) {
                return;
            }

            this.enabled = false;
            this.removeOnCommittedListener();

            // enable to automatically close
            // results when UBE is toggled off
            // if (this.popupWindow.instance) {
            //     this.closePopupWindow();
            // }

            this.clearQueue();

            ubolog(`🔴 UBE: Disabled`);
        }
    };

    µb.UBE.registerCoreListeners();

    if (µb.UBE.enabled) {
        µb.UBE.registerOnCommittedListener();
    }

    ubolog(`${µb.UBE.LOG_ICONS.SUCCESS} UBE ready ${Date.now() - vAPI.T0} ms after launch`);
})();