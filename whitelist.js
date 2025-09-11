const DEFAULT_WHITELIST = {
    ips: [
        "127.0.0.1", "0.0.0.0", "255.255.255.255", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "100.64.0.0/10", "198.18.0.0/15", "224.0.0.0/4"
    ],
    domaines: ["localhost", "*.local", "example.com", "example.org", "example.net"],
    urls: [], emails: [], fichiers: [], hashes: []
};

function loadWhitelist() {
    return new Promise(resolve => {
        chrome.storage.local.get({ whitelist: DEFAULT_WHITELIST }, data => resolve(data.whitelist || DEFAULT_WHITELIST));
    });
}
function saveWhitelist(wl) { return new Promise(resolve => chrome.storage.local.set({ whitelist: wl }, resolve)); }
function elt(id) { return document.getElementById(id); }
function toLines(v) { return (v || []).join("\n"); }
function fromLines(s) { return s.split("\n").map(x => x.trim()).filter(Boolean); }

// Theme
function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    const btn = document.getElementById('themeToggle');
    btn.textContent = theme === 'dark' ? '🌙 Mode sombre' : '☀️ Mode clair';
}
async function loadTheme() {
    return new Promise(res => chrome.storage.local.get({ theme: 'dark' }, d => res(d.theme || 'dark')));
}
async function saveTheme(theme) {
    return new Promise(res => chrome.storage.local.set({ theme }, res));
}

async function refresh() {
    const wl = await loadWhitelist();
    elt("wl_ips").value = toLines(wl.ips);
    elt("wl_domains").value = toLines(wl.domaines);
    elt("wl_urls").value = toLines(wl.urls);
    elt("wl_emails").value = toLines(wl.emails);
    elt("wl_files").value = toLines(wl.fichiers);
    elt("wl_hashes").value = toLines(wl.hashes);
}

document.addEventListener("DOMContentLoaded", async () => {
    // theme
    const theme = await loadTheme(); applyTheme(theme);
    document.getElementById('themeToggle').onclick = async () => {
        const cur = document.documentElement.getAttribute('data-theme') || 'dark';
        const next = (cur === 'dark') ? 'light' : 'dark';
        applyTheme(next); await saveTheme(next);
    };

    await refresh();

    elt("save").onclick = async () => {
        const wl = {
            ips: fromLines(elt("wl_ips").value),
            domaines: fromLines(elt("wl_domains").value),
            urls: fromLines(elt("wl_urls").value),
            emails: fromLines(elt("wl_emails").value),
            fichiers: fromLines(elt("wl_files").value),
            hashes: fromLines(elt("wl_hashes").value)
        };
        await saveWhitelist(wl);
        alert("✅ Liste blanche enregistrée.");
    };

    elt("reset").onclick = async () => {
        if (!confirm("Réinitialiser la liste blanche aux valeurs par défaut ?")) return;
        await saveWhitelist(DEFAULT_WHITELIST);
        await refresh();
        alert("✅ Liste blanche réinitialisée.");
    };
});
