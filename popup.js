// popup.js – UI onglets + sélection + actions + thème (Hashes regroupés)
/***** --- Helpers existants réutilisés --- *****/

function showToast(msg) {
    const c = document.getElementById("toastContainer");
    const t = document.createElement("div");
    t.textContent = msg;
    t.style.background = "rgba(40,40,40,0.95)";
    t.style.color = "#fff";
    t.style.padding = "8px 14px";
    t.style.marginTop = "8px";
    t.style.borderRadius = "6px";
    t.style.fontSize = "13px";
    t.style.boxShadow = "0 4px 12px rgba(0,0,0,0.4)";
    t.style.opacity = "0";
    t.style.transition = "opacity 0.3s ease";
    c.appendChild(t);
    requestAnimationFrame(() => { t.style.opacity = "1"; });
    setTimeout(() => {
        t.style.opacity = "0";
        setTimeout(() => c.removeChild(t), 300);
    }, 2000);
}


// VT
function vtUrlFor(type, value) {
    return "https://www.virustotal.com/gui/search/" + encodeURIComponent(value);
}
function vtDirectUrl(type, value) {
    switch (type.toLowerCase()) {
        case "ips": return "https://www.virustotal.com/gui/ip-address/" + value;
        case "domaines": return "https://www.virustotal.com/gui/domain/" + value;
        case "hashes": return "https://www.virustotal.com/gui/file/" + value;
        default: return vtUrlFor(type, value);
    }
}
function hashType(v) {
    if (/^[0-9a-f]{32}$/i.test(v)) return "MD5";
    if (/^[0-9a-f]{40}$/i.test(v)) return "SHA1";
    if (/^[0-9a-f]{64}$/i.test(v)) return "SHA256";
    return "HASH";
}
// URL validator (HTTP(S)/FTP + TCP/UDP)
function isValidHostname(host) {
    const ipv4 = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
    if (ipv4.test(host)) return true;
    const domain = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
    return domain.test(host);
}
function isValidHttpLikeUrl(u) {
    try {
        const url = new URL(u);
        const okScheme = /^(https?|ftp)$/i.test(url.protocol.replace(':', ''));
        if (!okScheme) return false;
        if (!isValidHostname(url.hostname)) return false;
        if (url.port) {
            const p = Number(url.port);
            if (!(p >= 1 && p <= 65535)) return false;
        }
        return true;
    } catch { return false; }
}
function isValidTcpUdpUrl(u) {
    const m = /^(tcp|udp):\/\/([^/:]+)(?::(\d{1,5}))?(?:\/.*)?$/i.exec(u);
    if (!m) return false;
    const host = m[2];
    const port = m[3] ? Number(m[3]) : null;
    if (!isValidHostname(host)) return false;
    if (port !== null && !(port >= 1 && port <= 65535)) return false;
    return true;
}
function validateUrls(urls) {
    return urls.filter(u => (/^(tcp|udp):\/\//i.test(u) ? isValidTcpUdpUrl(u) : isValidHttpLikeUrl(u)));
}

// Whitelist
const DEFAULT_WHITELIST = {
    ips: ["127.0.0.1", "0.0.0.0", "255.255.255.255", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "198.18.0.0/15", "224.0.0.0/4"],
    domaines: ["localhost", "*.local", "example.com", "example.org", "example.net"],
    urls: [], emails: [], fichiers: [], hashes: []
};
function loadWhitelist() {
    return new Promise(resolve => {
        chrome.storage.local.get({ whitelist: DEFAULT_WHITELIST }, data => {
            resolve(data.whitelist || DEFAULT_WHITELIST);
        });
    });
}
// IP/CIDR utils
function ipToInt(ip) { return ip.split('.').reduce((a, p) => (a << 8) + Number(p), 0) >>> 0; }
function cidrMatch(ip, cidr) { const [n, b] = cidr.split('/'); const bits = Number(b); const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0; return (ipToInt(ip) & mask) === (ipToInt(n) & mask); }
function ipWhitelisted(ip, list) { for (const r of list) { if (r.includes('/')) { if (cidrMatch(ip, r)) return true; } else if (ip === r) return true; } return false; }
function domainWhitelisted(domain, list) { const d = domain.toLowerCase(); for (const r0 of list) { const r = r0.toLowerCase(); if (r.startsWith("*.")) { const s = r.slice(1); if (d.endsWith(s)) return true; } else if (d === r) return true; } return false; }
function urlWhitelisted(u, list, domainWL) { try { const url = new URL(u); if (domainWhitelisted(url.hostname, domainWL)) return true; } catch { } return list.includes(u); }
function applyWhitelist(categories, wl) {
    return {
        IPs: categories.IPs.filter(ip => !ipWhitelisted(ip, wl.ips)),
        Domaines: categories.Domaines.filter(d => !domainWhitelisted(d, wl.domaines)),
        URLs: validateUrls(categories.URLs).filter(u => !urlWhitelisted(u, wl.urls, wl.domaines)),
        Emails: categories.Emails.filter(e => !wl.emails.includes(e)),
        Fichiers: categories.Fichiers.filter(f => !wl.fichiers.includes(f)),
        Hashes: categories.Hashes.filter(h => !wl.hashes.includes(h))
    };
}

// KQL builders (inchangés)
function kqlQuote(s) { return `'${String(s).replace(/'/g, "''")}'`; }
function buildKqlIPs(ips) {
    if (!ips.length) return '';
    const list = ips.map(kqlQuote).join(', ');
    return [
        '// IPs → DeviceNetworkEvents (RemoteIP match)',
        'DeviceNetworkEvents',
        `| where RemoteIP in (${list})`,
        '| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessSHA256, ReportId',
        '| order by Timestamp desc'
    ].join('\n');
}
function buildKqlDomains(domains) {
    if (!domains.length) return '';
    return [
        '// Domaines → DnsEvents (Name match)',
        'DnsEvents',
        `| where Name in~ (${domains.map(kqlQuote).join(', ')})`,
        '| project Timestamp, DeviceName, Name, ReportId',
        '| order by Timestamp desc',
        '',
        '// (Option) URLs HTTP(S) contenant ces domaines',
        'DeviceNetworkEvents',
        `| where RemoteUrl has_any (pack_array(${domains.map(kqlQuote).join(', ')}))`,
        '| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessSHA256, ReportId',
        '| order by Timestamp desc'
    ].join('\n');
}
function buildKqlURLs(urls) {
    if (!urls.length) return '';
    const list = urls.map(kqlQuote).join(', ');
    return [
        '// URLs → DeviceNetworkEvents (RemoteUrl exact)',
        'DeviceNetworkEvents',
        `| where RemoteUrl in~ (${list})`,
        '| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessSHA256, ReportId',
        '| order by Timestamp desc'
    ].join('\n');
}
function splitHashes(hashes) {
    const md5 = [], sha1 = [], sha256 = [];
    for (const h of hashes) {
        if (/^[0-9a-f]{32}$/i.test(h)) md5.push(h);
        else if (/^[0-9a-f]{40}$/i.test(h)) sha1.push(h);
        else if (/^[0-9a-f]{64}$/i.test(h)) sha256.push(h);
    }
    return { md5, sha1, sha256 };
}
function buildKqlHashes(hashes) {
    if (!hashes.length) return '';
    const { md5, sha1, sha256 } = splitHashes(hashes);
    const conds = [];
    if (md5.length) conds.push(`MD5 in (${md5.map(kqlQuote).join(', ')})`);
    if (sha1.length) conds.push(`SHA1 in (${sha1.map(kqlQuote).join(', ')})`);
    if (sha256.length) conds.push(`SHA256 in (${sha256.map(kqlQuote).join(', ')})`);
    const where = conds.length ? conds.join(' or ') : 'false';
    return [
        '// Hashes → DeviceFileEvents + DeviceProcessEvents',
        '(DeviceFileEvents',
        `| where ${where}`,
        '| project Timestamp, DeviceName, ActionType, FileName, FolderPath, MD5, SHA1, SHA256, InitiatingProcessFileName, InitiatingProcessSHA256, ReportId',
        ')',
        'union',
        '(DeviceProcessEvents',
        `| where ${where}`,
        '| project Timestamp, DeviceName, FileName, FolderPath, MD5, SHA1, SHA256, InitiatingProcessFileName, InitiatingProcessSHA256, ReportId',
        ')',
        '| order by Timestamp desc'
    ].join('\n');
}
function buildKqlFiles(files) {
    if (!files.length) return '';
    const list = files.map(kqlQuote).join(', ');
    return [
        '// Fichiers → DeviceFileEvents (FileName / InitiatingProcessFileName)',
        'DeviceFileEvents',
        `| where FileName in~ (${list}) or InitiatingProcessFileName in~ (${list})`,
        '| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessSHA256, ReportId',
        '| order by Timestamp desc',
        '',
        '// (Option) Processus ayant ces noms',
        'DeviceProcessEvents',
        `| where FileName in~ (${list})`,
        '| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ReportId',
        '| order by Timestamp desc'
    ].join('\n');
}
function buildKqlEmails(emails) {
    if (!emails.length) return '';
    const list = emails.map(kqlQuote).join(', ');
    return [
        '// Emails → Si Microsoft Defender pour Office 365 connecté',
        'EmailEvents',
        `| where SenderFromAddress in~ (${list}) or RecipientEmailAddress in~ (${list})`,
        '| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, ReportId',
        '| order by Timestamp desc'
    ].join('\n');
}
function buildKqlBundle(categories) {
    const parts = [];
    const add = (label, kql) => { if (kql) parts.push(`// ==== ${label} ====\n${kql}`); };
    add('IPs', buildKqlIPs(categories.IPs));
    add('Domaines', buildKqlDomains(categories.Domaines));
    add('URLs', buildKqlURLs(categories.URLs));
    add('Hashes', buildKqlHashes(categories.Hashes));
    add('Fichiers', buildKqlFiles(categories.Fichiers));
    add('Emails', buildKqlEmails(categories.Emails));
    return parts.join('\n\n');
}

/***** --- Thème --- *****/
async function loadTheme() {
    return new Promise(res => chrome.storage.local.get({ theme: 'dark' }, d => res(d.theme || 'dark')));
}
async function saveTheme(theme) {
    return new Promise(res => chrome.storage.local.set({ theme }, res));
}
function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    const btn = document.getElementById('themeToggle');
    btn.textContent = theme === 'dark' ? '🌙 Mode sombre' : '☀️ Mode clair';
}

/***** --- UI State --- *****/
// Hashes regroupés dans un seul onglet
const Tabs = [
    { key: 'ALL', label: 'ALL' },
    { key: 'Hashes', label: 'Hashes' },
    { key: 'IPs', label: 'IP' },
    { key: 'Domaines', label: 'Domain' },
    { key: 'URLs', label: 'URL' },
    { key: 'Emails', label: 'Email' },
    { key: 'Fichiers', label: 'Files' },
];

let CURRENT_TAB = 'ALL';
const selection = new Map();
function getSelSet(key) { if (!selection.has(key)) selection.set(key, new Set()); return selection.get(key); }
function clearSel(key) { getSelSet(key).clear(); updateSelCount(); }
function selectAll(key, items) { const s = getSelSet(key); s.clear(); items.forEach(x => s.add(x)); updateSelCount(); }
function toggleItem(key, val, checked) { const s = getSelSet(key); if (checked) s.add(val); else s.delete(val); updateSelCount(); }
function currentSelected(items) { const s = getSelSet(CURRENT_TAB); return items.filter(v => s.has(v)); }
function updateSelCount() {
    const n = getSelSet(CURRENT_TAB).size;
    document.getElementById('selCount').textContent = `${n} sélection(s)`;
}

/***** --- RENDER --- *****/
function renderTabs(counts) {
    const tabs = document.getElementById('tabs');
    tabs.innerHTML = '';
    Tabs.forEach(t => {
        const b = document.createElement('button');
        b.className = 'tab' + (CURRENT_TAB === t.key ? ' active' : '');
        const c = counts[t.key] ?? '';
        b.textContent = c ? `${t.label} (${c})` : t.label;
        b.onclick = () => { CURRENT_TAB = t.key; updateSelCount(); renderList(); renderSummary(); renderTabs(counts); };
        tabs.appendChild(b);
    });
}
function renderSummary() {
    const s = document.getElementById('summary');
    const total = TOTAL_COUNT;
    s.textContent = `Total : ${total} IOCs (après filtre URL & liste blanche)`;
    document.getElementById('totalChip').textContent = `${total}`;
}
function makeRow(type, value) {
    const row = document.createElement('div'); row.className = 'row';

    const cb = document.createElement('input'); cb.type = 'checkbox';
    cb.checked = getSelSet(CURRENT_TAB).has(value);
    cb.onchange = (e) => toggleItem(CURRENT_TAB, value, e.target.checked);

    const tag = document.createElement('span'); tag.className = 'tag';
    tag.textContent = (type === 'Hashes') ? hashType(value) : type.slice(0, -1).toUpperCase();

    const txt = document.createElement('div'); txt.className = 'ioc'; txt.textContent = value;

    const vt = document.createElement('a'); vt.href = vtDirectUrl(type, value); vt.target = '_blank'; vt.rel = 'noopener noreferrer'; vt.className = 'vt'; vt.textContent = 'VirusTotal';

    row.appendChild(cb);
    row.appendChild(tag);
    row.appendChild(txt);
    row.appendChild(vt);

    if (type.toLowerCase() === "domaines") {
        const whois = document.createElement("a");
        whois.href = "https://whois.domaintools.com/" + encodeURIComponent(value);
        whois.target = "_blank";
        whois.rel = "noopener noreferrer";
        whois.className = "vt";
        whois.textContent = "WHOIS";
        row.appendChild(whois);
    }

    return row;
}

function listForTab() {
    if (CURRENT_TAB === 'ALL') {
        const out = [];
        for (const [type, arr] of Object.entries(CATEGORIES)) {
            for (const v of arr) { out.push({ type, value: v }); }
        }
        return out;
    }
    if (CURRENT_TAB === 'Hashes') {
        return CATEGORIES.Hashes.map(v => ({ type: 'Hashes', value: v }));
    }
    if (CATEGORIES[CURRENT_TAB]) return CATEGORIES[CURRENT_TAB].map(v => ({ type: CURRENT_TAB, value: v }));
    return [];
}

function renderList() {
    const list = document.getElementById('list');
    list.innerHTML = '';
    const items = listForTab();
    if (!items.length) {
        const row = document.createElement('div'); row.className = 'row';
        const txt = document.createElement('div'); txt.className = 'ioc'; txt.textContent = 'Aucun IOC dans cet onglet.';
        row.appendChild(txt); list.appendChild(row); return;
    }
    for (const it of items) { list.appendChild(makeRow(it.type, it.value)); }
}

/***** --- Actions bas de page --- *****/
function downloadFile(content, filename, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename; a.click(); URL.revokeObjectURL(url);
}
function exportCSV(type, items) {
    let csv = "Type,Value\n";
    items.forEach(ioc => { csv += `${type},${ioc}\n`; });
    downloadFile(csv, `${type}_iocs.csv`, "text/csv");
}
function exportJSON(type, items) {
    const json = JSON.stringify({ [type]: items }, null, 2);
    downloadFile(json, `${type}_iocs.json`, "application/json");
}
function openOnVT(type, items) {
    for (const v of items) { chrome.tabs.create({ url: vtDirectUrl(type, v), active: false }); }
}

function itemsForCurrentTab() {
    if (CURRENT_TAB === 'ALL') {
        const all = [].concat(...Object.values(CATEGORIES));
        return { label: 'ALL', typeKey: 'Mixed', items: getSelSet('ALL').size ? currentSelected(all) : all };
    }
    const arr = (CURRENT_TAB === 'Hashes') ? CATEGORIES.Hashes : (CATEGORIES[CURRENT_TAB] || []);
    const sel = getSelSet(CURRENT_TAB).size ? currentSelected(arr) : arr;
    return { label: CURRENT_TAB, typeKey: CURRENT_TAB.toLowerCase(), items: sel };
}

function bindBottomActions() {
    document.getElementById('copyBtn').onclick = () => {
        const { items } = itemsForCurrentTab();
        navigator.clipboard.writeText(items.join("\n")).then(() => {
            showToast("✅ Copié !");
        });
    };
    document.getElementById('csvBtn').onclick = () => {
        const { label, items } = itemsForCurrentTab();
        exportCSV(label, items);
        showToast("💾 Export CSV !");
    };
    document.getElementById('jsonBtn').onclick = () => {
        const { label, items } = itemsForCurrentTab();
        exportJSON(label, items);
        showToast("📄 Export JSON !");
    };
    document.getElementById('vtBtn').onclick = () => {
        const { typeKey, items } = itemsForCurrentTab();
        const t = (typeKey === 'mixed') ? 'hashes' : typeKey;
        if (!items.length) return;
        openOnVT(t, items);
    };
    document.getElementById('kqlBtn').onclick = () => {
        const { label, items } = itemsForCurrentTab();
        let kql = '';
        if (label === 'IPs') kql = buildKqlIPs(items);
        else if (label === 'Domaines' || label === 'Domain') kql = buildKqlDomains(items);
        else if (label === 'URLs' || label === 'URL') kql = buildKqlURLs(items);
        else if (label === 'Hashes') kql = buildKqlHashes(items);
        else if (label === 'Fichiers' || label === 'Files') kql = buildKqlFiles(items);
        else if (label === 'Emails' || label === 'Email') kql = buildKqlEmails(items);
        if (kql) {
            navigator.clipboard.writeText(kql).then(() => {
                showToast("⚙️ KQL copié !");
            });
        }

    };
    document.getElementById('huntBtn').onclick = () => {
        // alias KQL
        const { label } = itemsForCurrentTab();
        let kql = '';
        if (label === 'IPs') kql = buildKqlIPs(CATEGORIES.IPs);
        else if (label.startsWith('Domain')) kql = buildKqlDomains(CATEGORIES.Domaines);
        else if (label.startsWith('URL')) kql = buildKqlURLs(CATEGORIES.URLs);
        else if (label === 'Hashes') kql = buildKqlHashes(CATEGORIES.Hashes);
        else if (label.startsWith('File')) kql = buildKqlFiles(CATEGORIES.Fichiers);
        else if (label.startsWith('Email')) kql = buildKqlEmails(CATEGORIES.Emails);
        if (kql) navigator.clipboard.writeText(kql);
    };

    document.getElementById('selectAll').onclick = () => {
        const list = listForTab().map(x => x.value);
        selectAll(CURRENT_TAB, list);
        renderList();
    };
    document.getElementById('clearSel').onclick = () => {
        clearSel(CURRENT_TAB);
        renderList();
    };
}

/***** --- INIT --- *****/
let CATEGORIES = {};
let TOTAL_COUNT = 0;

document.addEventListener("DOMContentLoaded", async () => {
    // Thème
    const theme = await loadTheme();
    applyTheme(theme);
    document.getElementById('themeToggle').onclick = async () => {
        const cur = document.documentElement.getAttribute('data-theme') || 'dark';
        const next = (cur === 'dark') ? 'light' : 'dark';
        applyTheme(next); await saveTheme(next);
    };

    document.getElementById("openWhitelist").onclick = () => {
        chrome.tabs.create({ url: chrome.runtime.getURL("whitelist.html") });
    };

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        chrome.tabs.sendMessage(tabs[0].id, { action: "getIOCs" }, async (data) => {
            const summary = document.getElementById("summary");
            if (!data) { summary.textContent = "⚠️ Aucun IOC trouvé."; return; }

            const categoriesRaw = {
                IPs: data.ips,
                Domaines: data.domains,
                URLs: data.urls,
                Emails: data.emails,
                Fichiers: (data.files || []),
                Hashes: data.hashes
            };

            const wl = await loadWhitelist();
            CATEGORIES = applyWhitelist(categoriesRaw, wl);

            TOTAL_COUNT = Object.values(CATEGORIES).reduce((acc, arr) => acc + arr.length, 0);

            const counts = {
                ALL: TOTAL_COUNT,
                Hashes: CATEGORIES.Hashes.length,
                IPs: CATEGORIES.IPs.length,
                Domaines: CATEGORIES.Domaines.length,
                URLs: CATEGORIES.URLs.length,
                Emails: CATEGORIES.Emails.length,
                Fichiers: CATEGORIES.Fichiers.length
            };

            renderTabs(counts);
            renderSummary();
            renderList();
            bindBottomActions();
            updateSelCount();
        });
    });
});
