import https from 'node:https';
import {URL} from 'node:url';

var API_KEY = "5382bc9e97064da411e167ca79369353e3616978d6f8bbfddfab94be354db043";
var API_URL = "https://www.virustotal.com/api/v3/domains/";
var TIMEOUT_API = 2000;

export async function fetchJson(finalDomain) {
    const headers = {
        'accept': 'application/json',
        'x-apikey': API_KEY
    };

    return new Promise((resolve, reject) => {
        const urlObj = new URL(API_URL + finalDomain);

        const requestOptions = {
            hostname: urlObj.hostname,
            path: urlObj.pathname, // + urlObj.search,
            method: 'GET',
            headers,
        };

        const req = https.get(requestOptions, (res) => {
            let data = '';

            res.on('data', (chunk) => (data += chunk));
            res.on('end', () => {
                if (res.statusCode >= 400) {
                    return reject(new Error(`Request failed with status ${res.statusCode}`));
                }

                try {
                    const json = JSON.parse(data);
                    resolve(json);
                } catch (e) {
                    reject(new Error('Invalid JSON response'));
                }
            });
        });

        req.on('error', reject);

        // Optional timeout to abort hanging connections
        req.setTimeout(TIMEOUT_API, () => {
            req.destroy();
            reject(new Error('Request timed out'));
        });
    });
}
