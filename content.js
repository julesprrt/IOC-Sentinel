// content.js – Extrait les IOCs d'une page web
(() => {
    // 1. Définition des regex pour chaque type d'IOC
    const regexIPv4 = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.|\[\.\]|\(\.\))){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?::\d{1,5})?\b/g;
    const regexDomain = /\b(?:(?:[A-Za-z0-9][A-Za-z0-9-]{0,62})(?:\.|\[\.\]|\(\.\)))+(?:[A-Za-z]{2,})(?::\d{1,5})?\b/gi;
    const regexURL = /(?:(?:https?|hxxps?|ftp|tcp|udp):\/\/)[^\s"<>()]+/gi;
    const regexEmail = /\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b/gi;
    const regexMD5 = /\b[0-9A-Fa-f]{32}\b/g;
    const regexSHA1 = /\b[0-9A-Fa-f]{40}\b/g;
    const regexSHA256 = /\b[0-9A-Fa-f]{64}\b/g;

    // Regex fichiers suspects
    const regexFiles = /\b[\w.-]+\.(exe|dll|bat|cmd|ps1|js|vbs|scr)\b/gi;

    // 2. Fonction de déobfuscation du texte (remplace les tokens [.] , hxxp, etc.)
    function refang(text) {
        text = text.replace(/hxxps?:\/\//gi, (m) => m.toLowerCase().startsWith("hxxps") ? "https://" : "http://");
        text = text.replace(/\[:\]/g, ":");
        text = text.replace(/\[\.\]|\(\.\)|\[dot\]|\(dot\)/gi, ".");
        text = text.replace(/\[\@\]|\(\@\)|\[at\]|\(at\)/gi, "@");
        text = text.replace(/(?<=\w)[ \t]*\.[ \t]*(?=\w)/g, ".");
        text = text.replace(/(?<=\w)[ \t]*\@[ \t]*(?=\w)/g, "@");
        return text;
    }

    // 3. Vérification de domaines valides
    function isValidDomain(domain) {
        const parts = domain.toLowerCase().split(".");
        if (parts.length < 2) return false;

        const tld = parts[parts.length - 1];
        const stoplist = ["the", "once", "use", "check", "block", "read", "earlier", "services", "standards", "organization", "education"];
        if (stoplist.includes(tld)) return false;

        if (/[A-Z]/.test(domain)) return false; // éviter .The etc.
        if (!/^[a-z]{2,24}$/.test(tld)) return false;

        return true;
    }

    // 4. Récupérer et refanger le texte
    let pageText = document.body.innerText || "";
    if (!pageText) return;
    pageText = refang(pageText);

    // 5. Extraction brute
    let ips = pageText.match(regexIPv4) || [];
    let domains = pageText.match(regexDomain) || [];
    let urls = pageText.match(regexURL) || [];
    let emails = pageText.match(regexEmail) || [];
    let files = pageText.match(regexFiles) || [];
    let md5s = pageText.match(regexMD5) || [];
    let sha1s = pageText.match(regexSHA1) || [];
    let sha256s = pageText.match(regexSHA256) || [];
    let hashes = [...md5s, ...sha1s, ...sha256s];

    // 6. Déduplication
    const dedup = arr => [...new Set(arr)];
    ips = dedup(ips);
    domains = dedup(domains);
    urls = dedup(urls);
    emails = dedup(emails);
    files = dedup(files);
    hashes = dedup(hashes);

    // 7. Nettoyage & filtrage
    const trimTrailing = arr => arr.map(x => x.replace(/[,\.\)\]\}]+$/g, ""));
    ips = trimTrailing(ips);
    domains = trimTrailing(domains).filter(isValidDomain);
    urls = trimTrailing(urls);
    emails = trimTrailing(emails);
    files = trimTrailing(files);
    hashes = trimTrailing(hashes);

    // 8. Préparer les résultats
    const results = {
        total: ips.length + domains.length + urls.length + emails.length + files.length + hashes.length,
        ips, domains, urls, emails, files, hashes
    };

    // 9. Observer les changements dynamiques
    const observer = new MutationObserver((mutations) => {
        for (const mut of mutations) {
            if (mut.type === "childList") {
                mut.addedNodes.forEach(node => {
                    let newText = "";
                    if (node.nodeType === Node.TEXT_NODE) {
                        newText = node.nodeValue;
                    } else if (node.nodeType === Node.ELEMENT_NODE) {
                        newText = node.innerText || "";
                    }
                    if (newText) {
                        newText = refang(newText);
                        (newText.match(regexIPv4) || []).forEach(ip => { if (!results.ips.includes(ip)) results.ips.push(ip); });
                        (newText.match(regexDomain) || []).forEach(dom => { dom = dom.replace(/[,\.\)\]\}]+$/g, ""); if (isValidDomain(dom) && !results.domains.includes(dom)) results.domains.push(dom); });
                        (newText.match(regexURL) || []).forEach(url => { url = url.replace(/[,\.\)\]\}]+$/g, ""); if (!results.urls.includes(url)) results.urls.push(url); });
                        (newText.match(regexEmail) || []).forEach(mail => { mail = mail.replace(/[,\.\)\]\}]+$/g, ""); if (!results.emails.includes(mail)) results.emails.push(mail); });
                        (newText.match(regexFiles) || []).forEach(f => { f = f.replace(/[,\.\)\]\}]+$/g, ""); if (!results.files.includes(f)) results.files.push(f); });
                        (newText.match(regexMD5) || []).concat(newText.match(regexSHA1) || [], newText.match(regexSHA256) || [])
                            .forEach(hash => { if (!results.hashes.includes(hash)) results.hashes.push(hash); });
                        results.total = results.ips.length + results.domains.length + results.urls.length + results.emails.length + results.files.length + results.hashes.length;
                    }
                });
            }
        }
    });
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });

    // 10. Répondre au popup
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === "getIOCs") {
            sendResponse(results);
        }
    });
})();
