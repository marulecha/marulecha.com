/* marulecha.com — passive domain scanner
   Everything runs in the visitor's browser. The target is never contacted:
   queries go to public DNS-over-HTTPS resolvers, RDAP registries,
   certificate-transparency logs, IP intelligence and the Internet Archive.
   Plain JS, no dependencies. */
(function () {
  'use strict';

  /* ------------------------------------------------------------------ */
  /* Utilities                                                           */
  /* ------------------------------------------------------------------ */
  function $(sel, root) { return (root || document).querySelector(sel); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function uniq(arr) { return arr.filter(function (v, i, a) { return v != null && a.indexOf(v) === i; }); }
  function norm(name) { return String(name || '').replace(/\.$/, '').toLowerCase(); }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function daysUntil(iso) { return Math.round((new Date(iso).getTime() - Date.now()) / 86400000); }
  function fmtDate(iso) { if (!iso) return '—'; var d = new Date(iso); return isNaN(d) ? String(iso) : d.toISOString().slice(0, 10); }
  function plural(n, s, pl) { return n + ' ' + (n === 1 ? s : (pl || (/(s|x|ch|sh)$/.test(s) ? s + 'es' : s + 's'))); }
  function endsWithDomain(host, apex) { return host === apex || host.slice(-(apex.length + 1)) === '.' + apex; }

  /* concurrency-limited map */
  function pool(items, limit, fn) {
    var i = 0, results = new Array(items.length);
    function worker() {
      if (i >= items.length) return Promise.resolve();
      var idx = i++;
      return Promise.resolve().then(function () { return fn(items[idx], idx); })
        .then(function (r) { results[idx] = r; }, function (e) { results[idx] = { error: String(e && e.message || e) }; })
        .then(worker);
    }
    var workers = [];
    for (var k = 0; k < Math.min(limit, items.length); k++) workers.push(worker());
    return Promise.all(workers).then(function () { return results; });
  }

  function fetchWithTimeout(url, opts, ms) {
    var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var t = ctrl ? setTimeout(function () { ctrl.abort(); }, ms || 20000) : null;
    var o = Object.assign({}, opts || {}, ctrl ? { signal: ctrl.signal } : {});
    STATS.queries++; UI.stat();
    STATS.inflight[url] = Date.now();
    return fetch(url, o).finally(function () { if (t) clearTimeout(t); delete STATS.inflight[url]; });
  }
  function getJSON(url, headers, ms) {
    return fetchWithTimeout(url, { headers: headers || {} }, ms).then(function (r) {
      if (!r.ok) { var e = new Error('HTTP ' + r.status); e.status = r.status; e.url = r.url; throw e; }
      return r.json().then(function (j) { j.__url = r.url; return j; });
    });
  }
  function getText(url, ms) {
    return fetchWithTimeout(url, {}, ms).then(function (r) {
      if (!r.ok) { var e = new Error('HTTP ' + r.status); e.status = r.status; throw e; }
      return r.text();
    });
  }

  var STATS = { queries: 0, inflight: {} };

  /* ------------------------------------------------------------------ */
  /* Optional relay (Netlify/Cloudflare). Empty = disabled; the page then */
  /* behaves exactly as the pure client-side build. Set to your deployed  */
  /* relay, e.g. 'https://proxy.marulecha.com/relay'. See netlify-proxy/.  */
  /* ------------------------------------------------------------------ */
  var PROXY = '';
  function proxyOn() { return !!PROXY; }
  function relayData(url) { return getJSON(PROXY + '?url=' + encodeURIComponent(url), {}, 15000); }
  function relaySite(host, path) { return getJSON(PROXY + '?site=' + encodeURIComponent(host) + '&path=' + encodeURIComponent(path || '/'), {}, 15000); }

  /* ------------------------------------------------------------------ */
  /* DNS over HTTPS                                                       */
  /* ------------------------------------------------------------------ */
  var T = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, DS: 43, RRSIG: 46, DNSKEY: 48, CAA: 257 };
  var TN = {}; Object.keys(T).forEach(function (k) { TN[T[k]] = k; });
  var dnsCache = Object.create(null);

  function txtValue(data) {
    var s = String(data);
    var m = s.match(/"((?:[^"\\]|\\.)*)"/g);
    if (!m) return s;
    return m.map(function (p) { return p.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\'); }).join('');
  }

  function normalizeDoh(j) {
    var ans = (j.Answer || []).map(function (a) {
      return { name: norm(a.name), type: a.type, typeName: TN[a.type] || String(a.type), ttl: a.TTL, data: a.type === T.TXT ? txtValue(a.data) : String(a.data).replace(/\.$/, '') };
    });
    return { status: j.Status, ad: !!j.AD, answers: ans, authority: j.Authority || [] };
  }

  function doh(name, type, timeoutMs) {
    var key = name + '/' + type;
    if (dnsCache[key]) return dnsCache[key];
    var tnum = T[type] || type, ms = timeoutMs || 12000;
    var cf = 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(name) + '&type=' + type + '&do=true';
    var gg = 'https://dns.google/resolve?name=' + encodeURIComponent(name) + '&type=' + tnum + '&do=1';
    var p = getJSON(cf, { 'Accept': 'application/dns-json' }, ms)
      .catch(function () { return getJSON(gg, {}, ms); })
      .then(normalizeDoh)
      .catch(function (e) { return { status: -1, ad: false, answers: [], error: String(e.message || e) }; });
    dnsCache[key] = p;
    return p;
  }
  /* records of exactly `type` for name (follows CNAME chains as the resolver returns them) */
  function rr(name, type) {
    return doh(name, type).then(function (r) { return r.answers.filter(function (a) { return a.type === T[type]; }).map(function (a) { return a.data; }); });
  }

  /* ------------------------------------------------------------------ */
  /* Findings                                                             */
  /* ------------------------------------------------------------------ */
  var SEV = { critical: 25, high: 15, medium: 8, low: 3, info: 0, ok: 0 };
  var SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'ok'];
  function F(severity, title, detail, fix) { return { severity: severity, title: title, detail: detail || '', fix: fix || '' }; }

  /* ------------------------------------------------------------------ */
  /* Registrable domain (compact public-suffix heuristic)                 */
  /* ------------------------------------------------------------------ */
  var SLD = ['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk', 'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'net.nz', 'org.nz', 'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'co.za', 'org.za', 'web.za', 'com.br', 'net.br', 'org.br', 'gov.br', 'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'com.mx', 'org.mx', 'com.ar', 'com.co', 'co.in', 'net.in', 'org.in', 'firm.in', 'gen.in', 'ind.in', 'co.kr', 'or.kr', 'com.cn', 'net.cn', 'org.cn', 'com.sg', 'com.hk', 'com.tw', 'co.il', 'org.il', 'com.pl', 'net.pl', 'org.pl', 'com.ua', 'com.eg', 'com.sa', 'com.ng', 'com.ph', 'com.my', 'com.vn', 'com.pk', 'gov.gr', 'edu.gr', 'com.gr', 'net.gr', 'org.gr', 'co.th', 'com.pe', 'com.ve', 'com.ec', 'com.uy', 'com.py', 'com.bo', 'com.do', 'com.gt', 'com.cy', 'org.cy', 'ac.cy', 'gov.cy', 'com.mt', 'org.mt', 'com.ro', 'co.ro', 'com.ru', 'org.ru', 'net.ru', 'co.id', 'or.id', 'ac.id', 'com.kw', 'com.qa', 'com.bh', 'com.om', 'com.lb', 'com.jo', 'ac.be', 'gov.it', 'edu.it', 'co.at', 'or.at', 'ac.at', 'gv.at', 'github.io', 'gitlab.io', 'herokuapp.com', 'azurewebsites.net', 'cloudfront.net', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com', 'appspot.com', 'blogspot.com', 'wordpress.com', 'myshopify.com', 'amazonaws.com'];
  function apexOf(host) {
    var parts = host.split('.');
    if (parts.length <= 2) return host;
    var last2 = parts.slice(-2).join('.');
    if (SLD.indexOf(last2) !== -1 && parts.length >= 3) return parts.slice(-3).join('.');
    return last2;
  }
  function parseDomain(input) {
    var s = String(input || '').trim();
    if (!s) return null;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'http://' + s;
    var host;
    try { host = new URL(s).hostname; } catch (e) { return null; }
    host = norm(host).replace(/^\[|\]$/g, '');
    if (!/^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$/.test(host)) return null;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return null;
    return host;
  }

  /* ------------------------------------------------------------------ */
  /* Fingerprint tables                                                   */
  /* ------------------------------------------------------------------ */
  var MX_PROVIDERS = [
    [/google(mail)?\.com$/, 'Google Workspace'], [/protection\.outlook\.com$|outlook\.com$|hotmail\.com$/, 'Microsoft 365'],
    [/pphosted\.com$|proofpoint\.com$/, 'Proofpoint'], [/mimecast/, 'Mimecast'], [/barracudanetworks\.com$/, 'Barracuda'],
    [/messagelabs\.com$/, 'Broadcom (Symantec)'], [/iphmx\.com$|cisco\.com$/, 'Cisco Secure Email'], [/hornetsecurity|antispameurope/, 'Hornetsecurity'],
    [/zoho(mail)?\.(com|eu|in)$/, 'Zoho Mail'], [/protonmail\.ch$|proton\.me$/, 'Proton Mail'], [/secureserver\.net$/, 'GoDaddy'],
    [/emailsrvr\.com$/, 'Rackspace'], [/fastmail\.com$|messagingengine\.com$/, 'Fastmail'], [/mailgun\.org$|mxrecord\.io$/, 'Mailgun'],
    [/amazonaws\.com$|awsapps\.com$/, 'Amazon (SES/WorkMail)'], [/ovh\.net$/, 'OVH'], [/yandex\.(net|ru)$/, 'Yandex'], [/icloud\.com$|apple\.com$/, 'Apple iCloud'],
    [/mx\.cloudflare\.net$/, 'Cloudflare Email Routing'], [/ionos\.(com|de)$|1and1\.(com|de)$|kundenserver\.de$/, 'IONOS'], [/mailroute\.net$/, 'MailRoute'],
    [/trendmicro\.(com|eu)$/, 'Trend Micro'], [/sophos\.com$|reflexion\.net$/, 'Sophos'], [/forcepoint\.net$|mailcontrol\.com$/, 'Forcepoint'],
    [/hostinger|titan\.email$/, 'Hostinger / Titan'], [/mailchannels\.net$/, 'MailChannels'], [/sendgrid\.net$/, 'SendGrid'], [/spamexperts|antispamcloud\.com$/, 'SpamExperts'],
    [/eu\.mailgun|mailjet\.com$/, 'Mailjet'], [/mx\.mail-tester|migadu\.com$/, 'Migadu'], [/hover\.com$|tucows/, 'Hover / Tucows'], [/registrar-servers\.com$|privateemail\.com$/, 'Namecheap Private Email'],
    [/mail\.eo\.outlook\.com$/, 'Microsoft 365'], [/qq\.com$/, 'Tencent QQ Mail'], [/aliyun\.com$/, 'Alibaba Cloud Mail'], [/mailbox\.org$/, 'mailbox.org'], [/posteo\.de$/, 'Posteo'], [/kolabnow|kolab/, 'Kolab Now']
  ];
  var NS_PROVIDERS = [
    [/\.ns\.cloudflare\.com$/, 'Cloudflare'], [/awsdns-/, 'Amazon Route 53'], [/azure-dns\./, 'Azure DNS'], [/googledomains\.com$|google\.com$|googleapis/, 'Google Cloud DNS'],
    [/nsone\.net$|ns1\.com$/, 'NS1 (IBM)'], [/dnsimple\.com$/, 'DNSimple'], [/ultradns\.(com|net|org|biz|info)$/, 'Vercara UltraDNS'], [/akam\.net$|akamai/, 'Akamai'],
    [/domaincontrol\.com$/, 'GoDaddy'], [/registrar-servers\.com$/, 'Namecheap'], [/digitalocean\.com$/, 'DigitalOcean'], [/linode\.com$/, 'Linode (Akamai)'],
    [/hetzner\.(com|de)$/, 'Hetzner'], [/ovh\.net$|anycast\.me$/, 'OVH'], [/gandi\.net$/, 'Gandi'], [/dnsmadeeasy\.com$/, 'DNS Made Easy'], [/he\.net$/, 'Hurricane Electric'],
    [/name-services\.com$/, 'Enom'], [/worldnic\.com$/, 'Network Solutions'], [/wixdns\.net$/, 'Wix'], [/squarespacedns\.com$/, 'Squarespace'], [/hostgator\.com$/, 'HostGator'],
    [/bluehost\.com$/, 'Bluehost'], [/ui-dns\.(com|de|org|biz)$/, 'IONOS'], [/papaki\.gr$|papaki\.com$/, 'Papaki (GR)'], [/top\.host$|tophost\.gr$/, 'TopHost (GR)'],
    [/dreamhost\.com$/, 'DreamHost'], [/vercel-dns\.com$/, 'Vercel'], [/netlify/, 'Netlify'], [/nsone|nsimple/, 'NS1'], [/dyn\.com$|dynect\.net$/, 'Oracle Dyn'],
    [/constellix\.com$/, 'Constellix'], [/cloudns\.net$/, 'ClouDNS'], [/hostinger\.com$|dns-parking\.com$/, 'Hostinger'], [/siteground\.net$/, 'SiteGround'],
    [/wpengine\.com$/, 'WP Engine'], [/kinsta/, 'Kinsta'], [/inmotionhosting\.com$/, 'InMotion'], [/a2hosting\.com$/, 'A2 Hosting'], [/name\.com$/, 'Name.com'],
    [/porkbun\.com$/, 'Porkbun'], [/ionos/, 'IONOS'], [/mailgun/, 'Mailgun'], [/nic\.gr$|forthnet\.gr$/, 'Greek registry / ISP'], [/rackspace\.com$|stabletransit\.com$/, 'Rackspace'],
    [/fastly/, 'Fastly'], [/ns\.ovh/, 'OVH'], [/edgecastdns|verizondigitalmedia/, 'Edgio'], [/dnsowl\.com$/, 'NameSilo'], [/csof\.net$|cscdns\.net$/, 'CSC Corporate Domains'], [/markmonitor\.com$/, 'MarkMonitor']
  ];
  var TXT_TOKENS = [
    [/^google-site-verification=/, 'Google (Workspace / Search Console)'], [/^MS=ms\d+/i, 'Microsoft 365'], [/^v=msv1/, 'Microsoft 365'], [/^facebook-domain-verification=/, 'Meta Business'],
    [/^apple-domain-verification=/, 'Apple Business'], [/^atlassian-domain-verification=/, 'Atlassian'], [/^docusign=/, 'DocuSign'], [/^adobe-idp-site-verification=|^adobe-sign-verification=/, 'Adobe'],
    [/^ZOOM_verify_|^zoom-domain-verification=/i, 'Zoom'], [/^stripe-verification=/, 'Stripe'], [/^hubspot-developer-verification=/, 'HubSpot'], [/^_globalsign-domain-verification=/, 'GlobalSign'],
    [/^dropbox-domain-verification=/, 'Dropbox Business'], [/^miro-verification=/, 'Miro'], [/^canva-site-verification=/, 'Canva'], [/^pardot/, 'Salesforce Pardot'], [/^mailru-verification/, 'Mail.ru'],
    [/^yandex-verification/, 'Yandex'], [/^slack-domain-verification=/, 'Slack'], [/^cisco-ci-domain-verification=/, 'Cisco (Duo / Webex)'], [/^webexdomainverification/, 'Cisco Webex'],
    [/^knowbe4-site-verification=/, 'KnowBe4'], [/^have-i-been-pwned-verification=/, 'Have I Been Pwned'], [/^onetrust-domain-verification=/, 'OneTrust'], [/^brevo-code:|^Sendinblue-code:/, 'Brevo (Sendinblue)'],
    [/^mongodb-site-verification=/, 'MongoDB Atlas'], [/^openai-domain-verification=/, 'OpenAI'], [/^anthropic-domain-verification=/, 'Anthropic'], [/^notion-domain-verification=/, 'Notion'],
    [/^loom-site-verification=/, 'Loom'], [/^postman-domain-verification=/, 'Postman'], [/^wiz-domain-verification=/, 'Wiz'], [/^1password-site-verification=/, '1Password'],
    [/^logmein-verification-code=/, 'LogMeIn'], [/^citrix-verification-code=/, 'Citrix'], [/^smartsheet-site-validation=/, 'Smartsheet'], [/^amazonses:/, 'Amazon SES'],
    [/^status-page-domain-verification=/, 'Atlassian Statuspage'], [/^workplace-domain-verification=/, 'Meta Workplace'], [/^twilio-domain-verification=/, 'Twilio'], [/^shopify-verification=/, 'Shopify'],
    [/^tiktok-domain-verification=/, 'TikTok for Business'], [/^pinterest-site-verification=/, 'Pinterest'], [/^ahrefs-site-verification/, 'Ahrefs'], [/^segment-site-verification=/, 'Twilio Segment'],
    [/^airtable-verification=/, 'Airtable'], [/^asv=/, 'Amazon (asv)'], [/^intacct-esk=/, 'Sage Intacct'], [/^d365mktkey/, 'Dynamics 365 Marketing'], [/^teamviewer-sso-verification=/, 'TeamViewer'],
    [/^linkedin-domain-verification=/, 'LinkedIn'], [/^godaddy-verification=|^godaddyverification/i, 'GoDaddy'], [/^wrike-verification=/, 'Wrike'], [/^box-domain-verification=/, 'Box'],
    [/^autodesk-domain-verification=/, 'Autodesk'], [/^dynatrace-site-verification=/, 'Dynatrace'], [/^sophos-domain-verification=/, 'Sophos'], [/^cloudflare-verify=/, 'Cloudflare'],
    [/^hosted-email-verification=/, 'Hosted email'], [/^mscid=/, 'Microsoft (mscid)'], [/^protonmail-verification=/, 'Proton Mail'], [/^zoho-verification=/, 'Zoho'],
    [/^bugcrowd-verification=/, 'Bugcrowd'], [/^hackerone-verification=|^h1-domain-verification=/, 'HackerOne'], [/^intercom-domain-verification=/, 'Intercom'], [/^firebase=/, 'Firebase'],
    [/^keybase-site-verification=/, 'Keybase'], [/^ms-domain-verification=/, 'Microsoft'], [/^sendgrid-verification=/, 'SendGrid'], [/^_github-challenge|^github-verification=|^gh-verification=/, 'GitHub'],
    [/^vercel=|^vc-domain-verify=/, 'Vercel'], [/^netlify-verification=/, 'Netlify'], [/^ca3-/, 'Cloudflare (ca3)'], [/^webflow=|^webflow-verification=/, 'Webflow'], [/^wix-verification=|^_wix/, 'Wix'],
    [/^mixpanel-domain-verify=/, 'Mixpanel'], [/^calendly-site-verification=/, 'Calendly'], [/^lastpass-verification-code=/, 'LastPass'], [/^okta-verification=|^okta-domain-verification=/i, 'Okta'],
    [/^onelogin-domain-verification=/, 'OneLogin'], [/^jamf-verification=/, 'Jamf'], [/^ping-identity-verification=/, 'Ping Identity'], [/^docker-verification=/, 'Docker'],
    [/^_dnsauth|^_acme-challenge/, 'ACME challenge (leftover)'], [/^globalsign-smime-dv=/, 'GlobalSign S/MIME'], [/^sectigo/, 'Sectigo'], [/^digicert/, 'DigiCert']
  ];
  var TAKEOVER_CNAMES = [
    [/\.github\.io$/, 'GitHub Pages'], [/\.herokuapp\.com$|\.herokudns\.com$/, 'Heroku'], [/\.azurewebsites\.net$|\.cloudapp\.(net|azure\.com)$|\.azure-api\.net$|\.trafficmanager\.net$|\.blob\.core\.windows\.net$|\.azurefd\.net$|\.azureedge\.net$|\.azurecontainer\.io$/, 'Microsoft Azure'],
    [/\.cloudfront\.net$/, 'AWS CloudFront'], [/\.s3[.-][a-z0-9-]*\.amazonaws\.com$|\.s3\.amazonaws\.com$|s3-website/, 'AWS S3'], [/\.elasticbeanstalk\.com$/, 'AWS Elastic Beanstalk'], [/\.elb\.amazonaws\.com$/, 'AWS ELB'],
    [/\.netlify\.(app|com)$/, 'Netlify'], [/\.ghost\.io$/, 'Ghost'], [/\.readme\.io$|\.readmessl\.com$/, 'ReadMe'], [/\.helpjuice\.com$/, 'Helpjuice'], [/\.helpscoutdocs\.com$/, 'Help Scout'],
    [/\.zendesk\.com$/, 'Zendesk'], [/\.myshopify\.com$/, 'Shopify'], [/\.surge\.sh$/, 'Surge'], [/\.bitbucket\.io$/, 'Bitbucket'], [/\.wordpress\.com$/, 'WordPress.com'],
    [/\.pantheonsite\.io$/, 'Pantheon'], [/\.wpengine\.com$/, 'WP Engine'], [/\.unbounce\.com$/, 'Unbounce'], [/\.uservoice\.com$/, 'UserVoice'], [/\.tumblr\.com$/, 'Tumblr'],
    [/\.statuspage\.io$/, 'Statuspage'], [/\.freshdesk\.com$/, 'Freshdesk'], [/\.hubspot\.net$|\.hs-sites\.com$/, 'HubSpot'], [/\.cargocollective\.com$/, 'Cargo'], [/\.feedpress\.me$/, 'FeedPress'],
    [/\.smugmug\.com$/, 'SmugMug'], [/\.strikinglydns\.com$/, 'Strikingly'], [/\.webflow\.io$|proxy-ssl\.webflow\.com$/, 'Webflow'], [/\.teamwork\.com$/, 'Teamwork'], [/\.intercom\.help$/, 'Intercom'],
    [/\.ngrok\.io$|\.ngrok-free\.app$/, 'ngrok'], [/\.wixdns\.net$/, 'Wix'], [/\.vercel\.app$|\.vercel-dns\.com$|\.now\.sh$/, 'Vercel'], [/\.fly\.dev$/, 'Fly.io'], [/\.onrender\.com$/, 'Render'],
    [/\.pages\.dev$/, 'Cloudflare Pages'], [/\.web\.app$|\.firebaseapp\.com$/, 'Firebase Hosting'], [/\.appspot\.com$/, 'Google App Engine'], [/\.ghost\.org$/, 'Ghost'], [/\.launchrock\.com$/, 'LaunchRock'],
    [/\.desk\.com$/, 'Desk.com'], [/\.kinsta\.cloud$/, 'Kinsta'], [/\.gitlab\.io$/, 'GitLab Pages'], [/\.mailchimp\.com$|\.list-manage\.com$/, 'Mailchimp'], [/\.landingi\.com$/, 'Landingi'],
    [/\.instapage\.com$|pageserve\.co$/, 'Instapage'], [/\.tictail\.com$/, 'Tictail'], [/\.bigcartel\.com$/, 'Big Cartel'], [/\.brightcovegallery\.com$/, 'Brightcove'], [/\.acquia-sites\.com$/, 'Acquia'],
    [/\.simplebooklet\.com$/, 'Simplebooklet'], [/\.getresponse\.com$/, 'GetResponse'], [/\.aftership\.com$/, 'AfterShip'], [/\.canny\.io$/, 'Canny'], [/\.fastly\.net$/, 'Fastly'],
    [/\.hatenablog\.com$/, 'Hatena'], [/\.thinkific\.com$/, 'Thinkific'], [/\.tave\.com$/, 'Tave'], [/\.wishpond\.com$/, 'Wishpond'], [/\.agilecrm\.com$/, 'Agile CRM'], [/\.anima\.io$/, 'Anima'],
    [/\.gr-site\.com$|\.apps\.ionos/, 'IONOS'], [/\.squarespace\.com$/, 'Squarespace'], [/\.sites\.hubspot\.net$/, 'HubSpot'], [/\.webhostingpad|\.hostgator/, 'shared hosting'], [/\.kajabi\.com$|\.mykajabi\.com$/, 'Kajabi']
  ];
  var INTERESTING = /^(dev|develop|development|staging|stage|stg|test|testing|uat|qa|preprod|pre-prod|sandbox|demo|beta|alpha|old|legacy|backup|bak|tmp|temp|internal|intranet|corp|admin|administrator|manage|manager|console|panel|cpanel|whm|plesk|portal|vpn|remote|rdp|citrix|gateway|gw|sso|auth|login|id|idp|adfs|okta|owa|autodiscover|exchange|mail|webmail|smtp|imap|pop|mx|ftp|sftp|ssh|git|gitlab|github|bitbucket|jenkins|ci|cd|build|jira|confluence|wiki|kb|grafana|kibana|prometheus|zabbix|nagios|splunk|elk|elastic|sentry|api|api-dev|graphql|rest|swagger|docs|db|database|mysql|postgres|mongo|redis|phpmyadmin|pma|s3|minio|storage|files|share|nas|docker|k8s|kube|argo|argocd|rancher|vault|consul|nexus|artifactory|sonar|sonarqube|teamcity|bamboo|jumphost|bastion|dmz|nat|fw|firewall|router|switch|cam|camera|nvr|printer|voip|pbx|sip|helpdesk|support|ticket|hr|payroll|erp|crm|sap|oracle|bi|report|reporting|analytics|metrics|status|monitor|monitoring|health|debug|trace|shell|webshell|cmd|exec|upload|uploads|media|cdn|static|assets|img|images|dl|download|downloads|backup1|backup2|new|next|v2|v3|canary|preview|edge|origin|origin-www|direct|ip|host|server|srv|node|node1|web1|web2|app|app1|app2|apps|service|services|svc|micro|lambda|fn|function|functions)(-|\d|$)/i;
  var DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2', 's3', 'dkim', 'mail', 'email', 'smtp', 'mx', 'mandrill', 'mailchimp', 'mailjet', 'mailgun', 'mg', 'sendgrid', 'sg', 'sg1', 'sg2', 'zendesk1', 'zendesk2', 'zoho', 'zmail', 'protonmail', 'protonmail2', 'protonmail3', 'pm', 'amazonses', 'ses', 'hs1', 'hs2', 'hubspot', 'cm', 'dk', 'key1', 'key2', 'mxvault', 'fd', 'fd2', 'fdm', 'klaviyo', 'kl', 'kl2', 'sparkpost', 'spop', 'mimecast20180101', 'mimecast', 'turbo-smtp', 'pic', 'salesforce', 'sf', 'sf1', 'marketo', 'm1', 'brevo', 'sib', 'postmark', 'pm1', 'pm2', 'everlytickey1', 'everlytickey2', 'x', 'dkim1', 'dkim2', 'ms', 'mailo', 'ovh', 'ionos', 'hostinger', 'titan', 'yandex', 'mail1', 'mail2', 'ed25519', 'rsa', 'v1', 's1024', 's2048', 'api', 'shopify', 'sendinblue', 'ml', 'mailerlite', 'constantcontact', 'cc', 'campaignmonitor', 'exacttarget', 'et', 'eloqua', 'sailthru', 'iterable', 'customerio', 'cio', 'braze', 'onesignal', 'intercom', 'front', 'helpscout', 'freshdesk', 'zd', 'zendesk', 'atlassian', 'jira', 'gitlab', 'github', 'slack', 'notion', 'figma', 'linear', 'cal', 'calendly', 'docusign', 'adobe', 'dropbox', 'box', 'okta', 'duo', 'auth0', 'stripe', 'paypal', 'square', 'gusto', 'rippling', 'workday', 'bamboohr', 'greenhouse', 'lever'];
  var CDN_ORGS = /cloudflare|fastly|akamai|cloudfront|amazon.*(cloudfront|edge)|imperva|incapsula|sucuri|stackpath|edgecast|edgio|limelight|cdn77|bunny|keycdn|azure front door|microsoft.*front|google.*cloud armor|gcore|g-core|quic\.cloud|ddos-guard|qrator|myra/i;
  var CLOUD_ORGS = /amazon|aws|google|microsoft|azure|digitalocean|hetzner|ovh|linode|akamai connected cloud|vultr|scaleway|oracle|alibaba|tencent|ibm cloud|softlayer|upcloud|contabo|ionos|leaseweb|rackspace|godaddy|hostinger|siteground|namecheap|wix|squarespace|shopify|github|fastly|netlify|vercel|heroku|salesforce/i;

  /* ------------------------------------------------------------------ */
  /* Module: DNS                                                          */
  /* ------------------------------------------------------------------ */
  function modDns(ctx) {
    var d = ctx.domain, log = ctx.log, out = ctx.data.dns = { records: {}, ips: [], www: {} };
    log('Resolving A, AAAA, NS, SOA, MX, TXT, CAA, CNAME, DNSKEY for ' + d);
    var types = ['A', 'AAAA', 'NS', 'SOA', 'MX', 'TXT', 'CAA', 'CNAME', 'DNSKEY'];
    return Promise.all(types.map(function (t) { return doh(d, t); })).then(function (rs) {
      var ad = false, anyErr = null;
      rs.forEach(function (r, i) {
        var t = types[i];
        if (r.error && !anyErr) anyErr = r.error;
        out.records[t] = r.answers.filter(function (a) { return a.type === T[t]; });
        if (r.ad) ad = true;
        if (t === 'A' && r.status === 3) out.nxdomain = true;
      });
      if (anyErr && rs.every(function (r) { return r.error; })) throw new Error('DNS resolvers unreachable: ' + anyErr);
      if (out.nxdomain) {
        ctx.findings.push(F('critical', 'Domain does not resolve (NXDOMAIN)', 'The resolver reports that ' + d + ' does not exist in DNS. Either the domain is unregistered, expired, or its delegation is broken.', 'Check registration status in the RDAP module. An expired domain can be registered by anyone and used to receive its email.'));
      }
      var A = out.records.A.map(function (a) { return a.data; }), AAAA = out.records.AAAA.map(function (a) { return a.data; });
      var NS = out.records.NS.map(function (a) { return norm(a.data); }), MX = out.records.MX, TXT = out.records.TXT.map(function (a) { return a.data; });
      var CAA = out.records.CAA, CN = out.records.CNAME, DK = out.records.DNSKEY;
      out.ips = uniq(A.concat(AAAA));
      out.dnssec = !!(ad && DK.length) || (ad && DK.length === 0 && false);
      out.dnssecAd = ad; out.dnskey = DK.length;

      /* address records */
      if (!A.length && !AAAA.length && !CN.length && !out.nxdomain) ctx.findings.push(F('info', 'No address records at the apex', 'The bare domain has no A or AAAA record; it may be mail-only or served solely from www.', ''));
      if (A.length && !AAAA.length) ctx.findings.push(F('info', 'No IPv6 (AAAA) records', 'The site is IPv4-only. Not a vulnerability, but IPv6-only clients reach it through translation.', 'Publish AAAA records if the hosting supports IPv6.'));
      if (CN.length) ctx.findings.push(F('low', 'CNAME at the zone apex', 'The apex points to ' + CN[0].data + '. RFC 1034 forbids a CNAME alongside other records at the same name; many providers emulate this with ALIAS/ANAME flattening, but it can break MX and TXT lookups on strict resolvers.', 'Use provider-side ALIAS/ANAME or plain A/AAAA records at the apex.'));
      var lowTtl = out.records.A.filter(function (a) { return a.ttl <= 60; });
      if (out.records.A.length && lowTtl.length === out.records.A.length) ctx.findings.push(F('info', 'Very low TTL on A records', 'TTL is ' + out.records.A[0].ttl + 's. Common behind CDNs and load balancers; also seen on fast-flux infrastructure.', ''));

      /* name servers */
      if (!NS.length && !out.nxdomain) ctx.findings.push(F('high', 'No NS records returned', 'The resolver returned no authoritative name servers for the domain.', 'Verify delegation at the registrar.'));
      else if (NS.length === 1) ctx.findings.push(F('medium', 'Single authoritative name server', 'Only one NS record (' + NS[0] + '). A single point of failure for the whole domain, including mail.', 'Publish at least two name servers, ideally on separate networks.'));
      var nsProv = uniq(NS.map(function (n) { return fingerprint(n, NS_PROVIDERS); }).filter(Boolean));
      out.dnsProvider = nsProv.join(', ') || (NS.length ? 'Self-hosted / unknown (' + NS[0] + ')' : '—');
      if (NS.length) ctx.findings.push(F('ok', 'Name servers: ' + (nsProv.join(', ') || 'custom'), NS.join(', '), ''));

      /* SOA */
      if (out.records.SOA.length) {
        var soa = out.records.SOA[0].data.split(/\s+/);
        out.soa = { primary: norm(soa[0]), hostmaster: soa[1] ? soa[1].replace(/\.$/, '').replace(/^([^.]+)\./, '$1@') : '', serial: soa[2], refresh: soa[3], retry: soa[4], expire: soa[5], minimum: soa[6] };
        if (out.soa.hostmaster && !/^hostmaster@|^dns@|^noc@|^admin@|^dns-admin|^awsdns-hostmaster|^cloudflare|^dns\./i.test(out.soa.hostmaster)) ctx.findings.push(F('info', 'SOA exposes a contact mailbox', 'RNAME is ' + out.soa.hostmaster + '. A useful address for social-engineering pretexts.', 'Use a role mailbox such as hostmaster@ for the SOA contact.'));
      }

      /* CAA */
      if (!CAA.length) ctx.findings.push(F('low', 'No CAA record', 'Any public CA can issue certificates for this domain. CAA lets you restrict issuance to the CAs you actually use and receive violation reports.', 'Publish CAA records, e.g. 0 issue "letsencrypt.org" and 0 iodef "mailto:security@' + ctx.apex + '".'));
      else {
        var issuers = CAA.map(function (c) { return c.data; });
        ctx.findings.push(F('ok', 'CAA restricts certificate issuance', issuers.join(' · '), ''));
        if (!issuers.some(function (i) { return /iodef/.test(i); })) ctx.findings.push(F('info', 'CAA has no iodef reporting address', 'You will not be notified when a CA refuses an issuance request because of CAA.', 'Add 0 iodef "mailto:security@' + ctx.apex + '".'));
      }

      /* DNSSEC */
      if (out.dnssec) ctx.findings.push(F('ok', 'DNSSEC validated', 'The resolver returned the AD (authenticated data) flag and ' + plural(DK.length, 'DNSKEY record') + '.', ''));
      else if (DK.length) ctx.findings.push(F('medium', 'DNSKEY published but responses not validated', 'The zone has DNSKEY records but the validating resolver did not set AD. The DS record at the parent may be missing or mismatched, which can make the domain unreachable for validating clients.', 'Check the DS record at the registrar matches the current KSK.'));
      else ctx.findings.push(F('low', 'DNSSEC not enabled', 'Responses for this zone are not signed. Cache-poisoning and spoofing of DNS answers is not cryptographically prevented.', 'Enable DNSSEC at the DNS provider and publish the DS record at the registrar.'));

      /* TXT: third-party inventory */
      var saas = [], other = [];
      TXT.forEach(function (t) {
        if (/^v=spf1/i.test(t)) return;
        var hit = null;
        for (var i = 0; i < TXT_TOKENS.length; i++) if (TXT_TOKENS[i][0].test(t)) { hit = TXT_TOKENS[i][1]; break; }
        if (hit) saas.push(hit); else other.push(t);
      });
      out.saas = uniq(saas);
      if (out.saas.length) ctx.findings.push(F('info', 'Third-party services verified through TXT records', out.saas.join(', ') + '. Each token names a SaaS platform the organisation uses: useful for phishing pretexts and for scoping SSO or OAuth attack surface.', 'Remove verification tokens once onboarding is complete; most providers only check them once.'));
      if (other.length) ctx.findings.push(F('info', 'Unrecognised TXT records', other.map(function (t) { return t.length > 90 ? t.slice(0, 90) + '…' : t; }).join(' · '), ''));
      if (TXT.length > 12) ctx.findings.push(F('info', 'Large TXT record set at the apex', plural(TXT.length, 'record') + '. Oversized answers fall back to TCP and increase the chance of truncation.', 'Prune stale verification tokens.'));

      /* www + wildcard */
      var probe = 'zq9x-wildcard-probe-' + Math.random().toString(36).slice(2, 8) + '.' + d;
      return Promise.all([doh('www.' + d, 'A'), doh('www.' + d, 'AAAA'), doh(probe, 'A')]).then(function (w) {
        out.www = { A: w[0].answers.filter(function (a) { return a.type === T.A; }).map(function (a) { return a.data; }), CNAME: w[0].answers.filter(function (a) { return a.type === T.CNAME; }).map(function (a) { return a.data; }), AAAA: w[1].answers.filter(function (a) { return a.type === T.AAAA; }).map(function (a) { return a.data; }), status: w[0].status };
        out.ips = uniq(out.ips.concat(out.www.A, out.www.AAAA));
        out.wildcard = w[2].status === 0 && w[2].answers.length > 0;
        if (out.wildcard) ctx.findings.push(F('info', 'Wildcard DNS detected', 'A random label under ' + d + ' resolves, so every hostname "exists". Subdomain enumeration by resolution produces false positives here; results below rely on certificate logs instead.', ''));
        if (!out.www.A.length && !out.www.CNAME.length && !out.www.AAAA.length && !out.wildcard && A.length) ctx.findings.push(F('info', 'No www record', 'www.' + d + ' does not resolve. Users typing it will get an error.', 'Add a www CNAME or A record redirecting to the canonical host.'));
        if (out.www.CNAME.length) { var tk = fingerprint(norm(out.www.CNAME[out.www.CNAME.length - 1]), TAKEOVER_CNAMES); if (tk) out.wwwService = tk; }
        log('DNS: ' + plural(out.ips.length, 'address') + ', ' + NS.length + ' NS, ' + MX.length + ' MX, ' + TXT.length + ' TXT' + (out.dnssec ? ', DNSSEC ✓' : ''));
      });
    });
  }

  function fingerprint(name, table) {
    for (var i = 0; i < table.length; i++) if (table[i][0].test(name)) return table[i][1];
    return null;
  }

  /* ------------------------------------------------------------------ */
  /* Module: Email security                                               */
  /* ------------------------------------------------------------------ */
  function spfLookups(domain, depth, seen, acc) {
    acc = acc || { count: 0, chain: [], voids: 0, includes: [] };
    if (depth > 10 || seen[domain]) return Promise.resolve(acc);
    seen[domain] = true;
    return rr(domain, 'TXT').then(function (txts) {
      var spf = txts.filter(function (t) { return /^v=spf1(\s|$)/i.test(t); });
      if (!spf.length) { if (depth > 0) acc.voids++; return acc; }
      var terms = spf[0].split(/\s+/).slice(1);
      var subs = [];
      terms.forEach(function (t) {
        var m = t.match(/^([+\-~?])?(include|a|mx|ptr|exists|redirect|ip4|ip6|all)(?:[:=](.*))?$/i);
        if (!m) return;
        var mech = m[2].toLowerCase(), arg = m[3];
        if (mech === 'include' || mech === 'redirect') { acc.count++; acc.includes.push(arg); subs.push(arg); }
        else if (mech === 'a' || mech === 'mx' || mech === 'ptr' || mech === 'exists') acc.count++;
      });
      acc.chain.push(domain + ' (' + terms.length + ' terms)');
      return pool(subs, 4, function (s) { return spfLookups(norm(s), depth + 1, seen, acc); }).then(function () { return acc; });
    });
  }

  function modEmail(ctx) {
    var d = ctx.apex, log = ctx.log, out = ctx.data.email = {};
    var dns = ctx.data.dns || { records: {} };
    var MX = (dns.records.MX || []).map(function (a) { var p = a.data.split(/\s+/); return { pref: +p[0], host: norm(p[1] || '') }; }).sort(function (a, b) { return a.pref - b.pref; });
    out.mx = MX;
    log('Checking SPF, DMARC, DKIM (' + DKIM_SELECTORS.length + ' selectors), MTA-STS, TLS-RPT, BIMI');

    var nullMx = MX.length === 1 && MX[0].host === '' && MX[0].pref === 0;
    var prov = uniq(MX.map(function (m) { return fingerprint(m.host, MX_PROVIDERS); }).filter(Boolean));
    out.mailProvider = nullMx ? 'None (null MX)' : (prov.join(', ') || (MX.length ? 'Self-hosted / unknown (' + MX[0].host + ')' : '—'));
    if (nullMx) ctx.findings.push(F('ok', 'Null MX: domain explicitly receives no mail', 'RFC 7505 null MX record present.', ''));
    else if (!MX.length) ctx.findings.push(F('info', 'No MX records', 'The domain does not accept email. It can still be spoofed as a sender unless SPF and DMARC say otherwise (checked below).', ''));
    else ctx.findings.push(F('ok', 'Mail handled by ' + out.mailProvider, MX.map(function (m) { return m.pref + ' ' + m.host; }).join(' · '), ''));

    var tasks = [
      rr(d, 'TXT'), rr('_dmarc.' + d, 'TXT'), rr('_mta-sts.' + d, 'TXT'), rr('_smtp._tls.' + d, 'TXT'), rr('default._bimi.' + d, 'TXT'),
      pool(MX.filter(function (m) { return m.host; }), 4, function (m) { return doh(m.host, 'A').then(function (r) { return { host: m.host, ok: r.answers.some(function (a) { return a.type === T.A || a.type === T.CNAME; }), status: r.status }; }); }),
      pool(DKIM_SELECTORS, 8, function (s) {
        var n = s + '._domainkey.' + d;
        return doh(n, 'TXT').then(function (r) {
          var txt = r.answers.filter(function (a) { return a.type === T.TXT; }).map(function (a) { return a.data; }).join('');
          var cname = r.answers.filter(function (a) { return a.type === T.CNAME; }).map(function (a) { return a.data; });
          if (!txt && !cname.length) return null;
          var p = (txt.match(/(?:^|;)\s*p=([^;]*)/) || [])[1];
          var k = (txt.match(/(?:^|;)\s*k=([^;]*)/) || [])[1] || 'rsa';
          var bits = null;
          if (p && k === 'rsa') { var bytes = Math.floor(p.replace(/\s/g, '').length * 3 / 4) - 38; bits = Math.round(bytes * 8 / 512) * 512; }
          return { selector: s, txt: txt, cname: cname[0] || null, revoked: p === '' && !!txt, bits: bits, k: k };
        });
      })
    ];
    return Promise.all(tasks).then(function (r) {
      var spfAll = r[0].filter(function (t) { return /^v=spf1(\s|$)/i.test(t); });
      var dmarcAll = r[1].filter(function (t) { return /^v=DMARC1(\s|;|$)/i.test(t); });
      out.spf = spfAll; out.dmarc = dmarcAll; out.mtaSts = r[2].filter(function (t) { return /^v=STSv1/i.test(t); }); out.tlsRpt = r[3].filter(function (t) { return /^v=TLSRPTv1/i.test(t); }); out.bimi = r[4].filter(function (t) { return /^v=BIMI1/i.test(t); });
      out.mxResolve = r[5]; out.dkim = r[6].filter(Boolean);

      /* SPF */
      var spfP = Promise.resolve();
      if (!spfAll.length) {
        ctx.findings.push(F(MX.length && !nullMx ? 'high' : 'medium', 'No SPF record', 'Receivers cannot tell which servers may send mail as @' + d + '. Combined with a missing or weak DMARC policy, the domain can be spoofed freely.', 'Publish a TXT record such as v=spf1 include:<provider> -all, or v=spf1 -all for a domain that never sends mail.'));
      } else if (spfAll.length > 1) {
        ctx.findings.push(F('high', 'Multiple SPF records (permerror)', 'RFC 7208 requires exactly one SPF record. Receivers treat this as a permanent error and ignore SPF entirely.', 'Merge the records into a single v=spf1 string.'));
      } else {
        var spf = spfAll[0], terms = spf.split(/\s+/).slice(1);
        out.spfTerms = terms;
        var all = terms.filter(function (t) { return /^[+\-~?]?all$/i.test(t); }).pop() || '';
        var q = all ? (all[0] === 'a' ? '+' : all[0]) : null;
        if (q === '+') ctx.findings.push(F('critical', 'SPF ends with +all', 'Every host on the internet is authorised to send mail as @' + d + '. SPF provides no protection.', 'Change the terminal mechanism to -all.'));
        else if (q === '?') ctx.findings.push(F('high', 'SPF ends with ?all (neutral)', 'Unauthorised senders receive a neutral result, which most receivers treat as no policy.', 'Use -all, or ~all together with an enforcing DMARC policy.'));
        else if (q === '~') ctx.findings.push(F('info', 'SPF uses ~all (softfail)', 'Unauthorised mail is marked but not rejected by SPF alone. This is acceptable when DMARC is set to quarantine or reject, because DMARC enforces the result.', 'Move to -all once you are confident all legitimate senders are listed.'));
        else if (q === '-') ctx.findings.push(F('ok', 'SPF ends with -all (hard fail)', spf.length > 140 ? spf.slice(0, 140) + '…' : spf, ''));
        else ctx.findings.push(F('medium', 'SPF has no all mechanism', 'Without a terminal all mechanism, senders not matched by any rule get a neutral result.', 'Append -all.'));
        if (terms.some(function (t) { return /^[+\-~?]?ptr/i.test(t); })) ctx.findings.push(F('low', 'SPF uses the deprecated ptr mechanism', 'ptr is slow, unreliable and discouraged by RFC 7208; some receivers ignore it.', 'Replace ptr with ip4/ip6 or include mechanisms.'));
        terms.forEach(function (t) {
          var m = t.match(/^[+\-~?]?ip4:(\d+\.\d+\.\d+\.\d+)\/(\d+)$/i);
          if (m && +m[2] < 16) ctx.findings.push(F('medium', 'Overly broad SPF range ' + m[1] + '/' + m[2], 'A /' + m[2] + ' authorises ' + Math.pow(2, 32 - m[2]).toLocaleString() + ' addresses, most of which are not the organisation\'s mail servers.', 'Narrow the range to the actual sending hosts.'));
        });
        var spfProv = uniq(terms.map(function (t) { var m = t.match(/^[+\-~?]?(?:include|redirect)[:=](.+)$/i); return m ? (fingerprint(norm(m[1]), MX_PROVIDERS) || fingerprint(norm(m[1]), [[/sendgrid/, 'SendGrid'], [/mailchimp|servers\.mcsv/, 'Mailchimp'], [/mandrill/, 'Mandrill'], [/mailgun/, 'Mailgun'], [/mailjet/, 'Mailjet'], [/sendinblue|brevo/, 'Brevo'], [/salesforce|exacttarget|pardot/, 'Salesforce'], [/hubspot/, 'HubSpot'], [/zendesk/, 'Zendesk'], [/freshdesk/, 'Freshdesk'], [/atlassian/, 'Atlassian'], [/klaviyo/, 'Klaviyo'], [/postmark|mtasv/, 'Postmark'], [/sparkpost/, 'SparkPost'], [/amazonses/, 'Amazon SES'], [/constantcontact/, 'Constant Contact'], [/mailerlite/, 'MailerLite'], [/intercom/, 'Intercom'], [/marketo/, 'Marketo'], [/customer\.io|customeriomail/, 'Customer.io'], [/protection\.outlook/, 'Microsoft 365'], [/_spf\.google/, 'Google Workspace'], [/zoho/, 'Zoho'], [/mimecast/, 'Mimecast'], [/pphosted|proofpoint/, 'Proofpoint'], [/docusign/, 'DocuSign'], [/shopify/, 'Shopify'], [/stripe/, 'Stripe'], [/qualtrics/, 'Qualtrics'], [/surveymonkey/, 'SurveyMonkey'], [/workday/, 'Workday'], [/servicenow/, 'ServiceNow'], [/smartsheet/, 'Smartsheet'], [/gusto/, 'Gusto'], [/bamboohr/, 'BambooHR'], [/greenhouse/, 'Greenhouse'], [/lever/, 'Lever'], [/slack/, 'Slack'], [/notion/, 'Notion'], [/figma/, 'Figma'], [/github/, 'GitHub'], [/gitlab/, 'GitLab'], [/twilio/, 'Twilio'], [/okta/, 'Okta'], [/duo/, 'Duo']]) || norm(m[1])) : null; }).filter(Boolean));
        out.spfSenders = spfProv;
        if (spfProv.length) ctx.findings.push(F('info', 'Authorised third-party senders', spfProv.join(', ') + '. Each is a platform that can send mail as the organisation; account compromise at any of them enables convincing phishing.', ''));
        spfP = spfLookups(d, 0, {}, null).then(function (acc) {
          out.spfLookups = acc.count; out.spfVoids = acc.voids;
          if (acc.count > 10) ctx.findings.push(F('high', 'SPF exceeds the 10 DNS-lookup limit (' + acc.count + ')', 'Receivers must return permerror once the limit is passed, so SPF fails for every message.', 'Flatten includes, remove unused senders, or use a flattening service.'));
          else if (acc.count >= 8) ctx.findings.push(F('low', 'SPF is close to the 10-lookup limit (' + acc.count + ')', 'One more include from a provider can push the record into permerror.', 'Consolidate includes.'));
          if (acc.voids > 2) ctx.findings.push(F('low', 'SPF references domains without SPF (' + acc.voids + ' void lookups)', 'RFC 7208 allows at most two void lookups before permerror.', 'Remove includes that no longer publish SPF.'));
        });
      }

      /* DMARC */
      if (!dmarcAll.length) {
        ctx.findings.push(F('high', 'No DMARC record', 'Without DMARC, SPF and DKIM results are advisory: receivers do not reject spoofed mail from @' + d + ' and the domain owner receives no reports.', 'Publish _dmarc.' + d + ' TXT "v=DMARC1; p=none; rua=mailto:dmarc@' + d + '" to start, then move to quarantine and reject.'));
      } else if (dmarcAll.length > 1) {
        ctx.findings.push(F('high', 'Multiple DMARC records', 'Receivers treat more than one DMARC record as no policy.', 'Keep a single record.'));
      } else {
        var tags = {};
        dmarcAll[0].split(';').forEach(function (kv) { var m = kv.trim().match(/^(\w+)\s*=\s*(.*)$/); if (m) tags[m[1].toLowerCase()] = m[2].trim(); });
        out.dmarcTags = tags;
        var p = (tags.p || '').toLowerCase();
        if (p === 'none') ctx.findings.push(F('medium', 'DMARC policy is p=none (monitoring only)', 'Spoofed messages are still delivered; DMARC only produces reports.', 'Progress to p=quarantine and then p=reject once reports show legitimate mail is aligned.'));
        else if (p === 'quarantine') ctx.findings.push(F('low', 'DMARC policy is p=quarantine', 'Spoofed mail goes to spam rather than being rejected.', 'Move to p=reject when ready.'));
        else if (p === 'reject') ctx.findings.push(F('ok', 'DMARC policy is p=reject', dmarcAll[0], ''));
        else ctx.findings.push(F('high', 'DMARC record is malformed (no valid p= tag)', dmarcAll[0], 'Fix the syntax; an invalid record is ignored.'));
        if (tags.pct && +tags.pct < 100) ctx.findings.push(F('low', 'DMARC applies to only ' + tags.pct + '% of mail', 'pct=' + tags.pct + ' leaves the remainder unenforced.', 'Set pct=100 (or remove the tag).'));
        if (!tags.rua) ctx.findings.push(F('low', 'No DMARC aggregate reporting (rua)', 'Without rua the owner has no visibility of who is sending as the domain.', 'Add rua=mailto:dmarc@' + d + ' or a reporting service address.'));
        if (tags.sp && ['none', 'quarantine'].indexOf(tags.sp.toLowerCase()) !== -1 && p === 'reject') ctx.findings.push(F('low', 'Subdomain policy weaker than the domain policy', 'sp=' + tags.sp + ' lets attackers spoof any subdomain (e.g. hr.' + d + ') even though the apex is protected.', 'Set sp=reject or remove sp so p applies.'));
        if (p === 'reject' && !tags.sp) ctx.findings.push(F('ok', 'Subdomains inherit p=reject', 'No sp tag, so the apex policy covers all subdomains.', ''));
        if ((tags.adkim || 'r') === 'r' && (tags.aspf || 'r') === 'r') ctx.findings.push(F('info', 'Relaxed DMARC alignment', 'adkim and aspf default to relaxed: any subdomain of ' + d + ' aligns. Strict alignment (s) is tighter but often breaks third-party senders.', ''));
        if (tags.rua && !tags.rua.split(',').some(function (u) { return norm(u).indexOf('@' + d) !== -1 || /@(dmarcian|valimail|agari|postmarkapp|dmarc|ondmarc|easydmarc|proofpoint|mimecast|microsoft|google|uriports|dmarcanalyzer|mxtoolbox|fraudmarc|sendmarc|powerdmarc|redsift|kitterman|dmarcly|dmarcreport)/i.test(u); })) ctx.findings.push(F('info', 'DMARC reports go to an external domain', tags.rua + '. Legitimate when a monitoring vendor is used; verify it is expected.', ''));
      }
      /* non-sending domain without protection */
      if (!MX.length && !nullMx && (!spfAll.length || !dmarcAll.length)) ctx.findings.push(F('medium', 'Non-mail domain is spoofable', 'The domain has no MX but also lacks a complete SPF + DMARC pair, so attackers can send as @' + d + ' with no consequences.', 'Publish v=spf1 -all, a DMARC p=reject record and, ideally, a null MX (0 .).'));

      /* DKIM */
      if (out.dkim.length) {
        ctx.findings.push(F('ok', 'DKIM selectors found: ' + out.dkim.map(function (k) { return k.selector; }).join(', '), out.dkim.map(function (k) { return k.selector + (k.cname ? ' → ' + k.cname : k.bits ? ' (' + k.k + ' ' + k.bits + '-bit)' : ''); }).join(' · '), ''));
        out.dkim.forEach(function (k) {
          if (k.bits && k.bits <= 1024) ctx.findings.push(F('low', 'Weak ' + k.bits + '-bit DKIM key on selector ' + k.selector, 'RSA keys of 1024 bits or less are considered factorable by well-resourced attackers; RFC 8301 requires at least 1024 and recommends 2048.', 'Rotate to a 2048-bit key.'));
          if (k.revoked) ctx.findings.push(F('info', 'Revoked DKIM key on selector ' + k.selector, 'An empty p= tag means the key is retired; mail signed with it will fail.', ''));
        });
      } else ctx.findings.push(F('info', 'No DKIM key found on ' + DKIM_SELECTORS.length + ' common selectors', 'Selectors are provider-specific and can be anything; absence here is not proof that DKIM is unused. Inspect a real message header (DKIM-Signature s= tag) to find the selector.', ''));

      /* MTA-STS / TLS-RPT / BIMI */
      if (out.mtaSts.length) ctx.findings.push(F('ok', 'MTA-STS policy advertised', out.mtaSts[0] + '. The policy file itself lives at https://mta-sts.' + d + '/.well-known/mta-sts.txt and cannot be fetched from a browser.', ''));
      else if (MX.length && !nullMx) ctx.findings.push(F('low', 'No MTA-STS', 'Inbound SMTP TLS can be downgraded by an on-path attacker because senders have no way to know the domain requires TLS.', 'Publish _mta-sts.' + d + ' TXT "v=STSv1; id=<date>" and host the policy at https://mta-sts.' + d + '/.well-known/mta-sts.txt with mode: enforce.'));
      if (out.tlsRpt.length) ctx.findings.push(F('ok', 'TLS-RPT reporting enabled', out.tlsRpt[0], ''));
      else if (MX.length && !nullMx) ctx.findings.push(F('info', 'No TLS-RPT record', 'You will not receive reports of TLS failures from sending servers.', 'Publish _smtp._tls.' + d + ' TXT "v=TLSRPTv1; rua=mailto:tlsrpt@' + d + '".'));
      if (out.bimi.length) ctx.findings.push(F('info', 'BIMI record present', out.bimi[0], ''));

      /* MX resolution */
      (out.mxResolve || []).forEach(function (m) { if (m && m.host && !m.ok) ctx.findings.push(F('medium', 'MX host does not resolve: ' + m.host, 'Mail to the domain will bounce or fall to a lower-priority host. A dangling MX that points at an expired domain lets an attacker receive the organisation\'s mail.', 'Remove or fix the record.')); });
      return spfP;
    }).then(function () { log('Email: SPF ' + (out.spf.length ? '✓' : '✗') + ', DMARC ' + (out.dmarcTags ? 'p=' + (out.dmarcTags.p || '?') : '✗') + ', DKIM ' + out.dkim.length + ' selector(s)'); });
  }

  /* ------------------------------------------------------------------ */
  /* Module: Registration (RDAP)                                          */
  /* ------------------------------------------------------------------ */
  function vcardFn(entity) {
    try { var v = entity.vcardArray[1]; for (var i = 0; i < v.length; i++) if (v[i][0] === 'fn' && v[i][3]) return v[i][3]; } catch (e) { /* noop */ }
    return null;
  }
  function modRdap(ctx) {
    var d = ctx.apex, log = ctx.log, out = ctx.data.rdap = {};
    log('Querying RDAP (registry data) for ' + d);
    return getJSON('https://rdap.org/domain/' + encodeURIComponent(d), { 'Accept': 'application/rdap+json, application/json' }, 20000).then(function (j) {
      out.source = j.__url;
      var ev = {}; (j.events || []).forEach(function (e) { ev[e.eventAction] = e.eventDate; });
      out.registered = ev.registration || null; out.expires = ev.expiration || null; out.changed = ev['last changed'] || null;
      out.status = j.status || [];
      var ents = j.entities || [];
      var reg = ents.filter(function (e) { return (e.roles || []).indexOf('registrar') !== -1; })[0];
      out.registrar = reg ? (vcardFn(reg) || reg.handle) : null;
      out.registrarId = reg && reg.publicIds && reg.publicIds[0] ? reg.publicIds[0].identifier : null;
      var rnt = ents.filter(function (e) { return (e.roles || []).indexOf('registrant') !== -1; })[0];
      out.registrant = rnt ? (vcardFn(rnt) || 'redacted') : null;
      var abuse = null;
      ents.forEach(function (e) { (e.entities || []).forEach(function (s) { if ((s.roles || []).indexOf('abuse') !== -1) { try { s.vcardArray[1].forEach(function (v) { if (v[0] === 'email' && v[3]) abuse = v[3]; }); } catch (x) { /* noop */ } } }); });
      out.abuse = abuse;
      out.nameservers = (j.nameservers || []).map(function (n) { return norm(n.ldhName || n.unicodeName); }).filter(Boolean);
      out.dsSigned = !!(j.secureDNS && j.secureDNS.delegationSigned);
      out.handle = j.handle;

      if (out.expires) {
        var days = daysUntil(out.expires);
        if (days < 0) ctx.findings.push(F('critical', 'Registration expired ' + (-days) + ' days ago', 'The registry lists ' + fmtDate(out.expires) + ' as the expiry date. Expired domains enter a grace period and can then be bought by anyone, who inherits the mail and the web traffic.', 'Renew immediately.'));
        else if (days < 30) ctx.findings.push(F('high', 'Registration expires in ' + days + ' days', 'Expiry ' + fmtDate(out.expires) + '. A lapse takes down web, mail and every certificate that depends on DNS.', 'Renew now and enable auto-renew.'));
        else if (days < 90) ctx.findings.push(F('medium', 'Registration expires in ' + days + ' days', 'Expiry ' + fmtDate(out.expires) + '.', 'Renew and enable auto-renew.'));
        else ctx.findings.push(F('ok', 'Registered until ' + fmtDate(out.expires), (out.registrar ? 'Registrar: ' + out.registrar + '. ' : '') + (out.registered ? 'First registered ' + fmtDate(out.registered) + '.' : ''), ''));
      }
      if (out.registered && (Date.now() - new Date(out.registered)) < 90 * 86400000) ctx.findings.push(F('info', 'Recently registered domain', 'Created ' + fmtDate(out.registered) + '. Young domains score poorly with mail and web reputation systems.', ''));
      var st = out.status.map(function (s) { return s.toLowerCase(); });
      if (st.some(function (s) { return /pending delete|redemption/.test(s); })) ctx.findings.push(F('critical', 'Domain is pending deletion', out.status.join(', '), 'Restore it through the registrar before it drops.'));
      if (st.some(function (s) { return /hold/.test(s); })) ctx.findings.push(F('high', 'Domain is on hold', out.status.join(', ') + '. A hold status removes the domain from the zone; it will not resolve.', 'Contact the registrar: holds usually follow unverified contact details or abuse complaints.'));
      if (st.some(function (s) { return /transfer prohibited/.test(s); })) ctx.findings.push(F('ok', 'Registrar transfer lock enabled', out.status.join(', '), ''));
      else if (out.status.length) ctx.findings.push(F('low', 'No transfer lock', 'Without clientTransferProhibited a compromised registrar account can move the domain away in hours.', 'Enable the transfer lock (and registry lock for high-value domains).'));
      if (!st.some(function (s) { return /update prohibited/.test(s); }) && out.status.length) ctx.findings.push(F('info', 'No update lock', 'clientUpdateProhibited prevents silent nameserver changes from a compromised registrar account.', 'Consider enabling it; some registrars bundle it with the transfer lock.'));

      var live = ((ctx.data.dns || {}).records || {}).NS;
      if (live && live.length && out.nameservers.length) {
        var a = uniq(live.map(function (x) { return norm(x.data); })).sort(), b = uniq(out.nameservers).sort();
        if (a.join() !== b.join()) ctx.findings.push(F('medium', 'Registry name servers differ from the live NS set', 'Registry: ' + b.join(', ') + ' · Zone: ' + a.join(', ') + '. A mismatch means the delegation and the zone disagree; some resolvers will use one set, some the other, and a stale registry NS can be a hijack vector.', 'Make both sets identical.'));
        else ctx.findings.push(F('ok', 'Registry delegation matches the zone', b.join(', '), ''));
      }
      var dns = ctx.data.dns || {};
      if (out.dsSigned && dns.records && !dns.dnskey) ctx.findings.push(F('high', 'DS record at the registry but no DNSKEY in the zone', 'Validating resolvers will treat every answer as bogus and the domain becomes unreachable for them.', 'Either remove the DS at the registrar or re-sign the zone with the matching key.'));
      if (!out.dsSigned && dns.dnssec) ctx.findings.push(F('info', 'Zone is signed but registry has no DS', 'DNSSEC is not actually active: without the DS at the parent, resolvers cannot build a chain of trust.', 'Publish the DS record at the registrar.'));
      log('RDAP: ' + (out.registrar || 'registrar unknown') + (out.expires ? ', expires ' + fmtDate(out.expires) : ''));
    }).catch(function (e) {
      if (e.status === 404) {
        out.unavailable = true;
        var tld = d.split('.').pop();
        ctx.findings.push(F('info', 'No RDAP service for .' + tld, 'Many country-code registries do not publish RDAP yet, so registration data cannot be read from a browser. Use the WHOIS link in the Pivot module.', ''));
        log('RDAP: not available for .' + tld);
      } else if (e.status === 429) {
        out.unavailable = true;
        ctx.findings.push(F('info', 'RDAP rate-limited this browser', 'Try again in a minute.', ''));
      } else throw e;
    });
  }

  /* ------------------------------------------------------------------ */
  /* Module: Subdomains (passive)                                         */
  /* ------------------------------------------------------------------ */
  function fetchCT(ctx) {
    var d = ctx.apex;
    if (ctx.shared.ct) return ctx.shared.ct;
    ctx.shared.ct = Promise.all([
      getJSON('https://crt.sh/?q=' + encodeURIComponent('%.' + d) + '&output=json', {}, 35000).then(function (rows) { return { ok: true, rows: Array.isArray(rows) ? rows : [] }; }).catch(function (e) { return { ok: false, error: e.message }; }),
      getJSON('https://api.certspotter.com/v1/issuances?domain=' + encodeURIComponent(d) + '&include_subdomains=true&expand=dns_names&expand=issuer', {}, 35000).then(function (rows) { return { ok: true, rows: Array.isArray(rows) ? rows : [] }; }).catch(function (e) { return { ok: false, error: e.message }; })
    ]).then(function (r) { return { crt: r[0], certspotter: r[1] }; });
    return ctx.shared.ct;
  }

  function modSubdomains(ctx) {
    var d = ctx.apex, log = ctx.log, out = ctx.data.subdomains = { names: Object.create(null), resolved: [], errors: [], hints: Object.create(null) };
    log('Querying certificate-transparency logs (crt.sh, Certspotter) and HackerTarget');
    function add(n, src) {
      n = norm(n).trim(); var wild = false;
      if (n.slice(0, 2) === '*.') { wild = true; n = n.slice(2); }
      if (!n || !endsWithDomain(n, d) || /[^a-z0-9._-]/.test(n)) return;
      if (!out.names[n]) out.names[n] = { sources: [], wildcard: false };
      if (out.names[n].sources.indexOf(src) === -1) out.names[n].sources.push(src);
      if (wild) out.names[n].wildcard = true;
    }
    var ht = getText('https://api.hackertarget.com/hostsearch/?q=' + encodeURIComponent(d), 20000).then(function (txt) {
      if (!/,/.test(txt)) { if (/error|exceeded|invalid|no records/i.test(txt)) throw new Error(txt.trim().slice(0, 70)); return 'HackerTarget: 0 hosts'; }
      var n = 0;
      txt.trim().split('\n').forEach(function (l) { var p = l.split(','); if (p[0]) { add(p[0], 'hackertarget'); n++; if (p[1]) out.hints[norm(p[0])] = p[1].trim(); } });
      return 'HackerTarget: ' + n + ' hosts';
    }).catch(function (e) { out.errors.push('HackerTarget: ' + e.message); return 'HackerTarget failed (' + e.message + ')'; });

    return Promise.all([fetchCT(ctx), ht]).then(function (r) {
      var ct = r[0];
      if (ct.crt.ok) { ct.crt.rows.forEach(function (row) { String(row.name_value || '').split('\n').concat([row.common_name || '']).forEach(function (n) { add(n, 'crt.sh'); }); }); log('crt.sh: ' + plural(ct.crt.rows.length, 'certificate')); }
      else { out.errors.push('crt.sh: ' + ct.crt.error); log('crt.sh failed (' + ct.crt.error + ')'); }
      if (ct.certspotter.ok) { ct.certspotter.rows.forEach(function (row) { (row.dns_names || []).forEach(function (n) { add(n, 'certspotter'); }); }); log('Certspotter: ' + plural(ct.certspotter.rows.length, 'certificate')); }
      else { out.errors.push('Certspotter: ' + ct.certspotter.error); log('Certspotter failed (' + ct.certspotter.error + ')'); }
      log(r[1]);

      var list = Object.keys(out.names).filter(function (n) { return n !== d; }).sort();
      out.total = list.length;
      if (!list.length) {
        ctx.findings.push(F('info', out.errors.length === 3 ? 'All passive subdomain sources failed' : 'No subdomains found in passive sources', out.errors.length ? out.errors.join(' · ') : 'No certificate has been logged for any hostname under ' + d + '.', ''));
        return;
      }
      function interesting(n) { return n.slice(0, -(d.length + 1)).split('.').some(function (l) { return INTERESTING.test(l); }); }
      var ordered = list.filter(interesting).concat(list.filter(function (n) { return !interesting(n); }));
      var toResolve = ordered.slice(0, 150);
      out.capped = list.length - toResolve.length;
      log('Resolving ' + toResolve.length + (out.capped ? ' of ' + list.length : '') + ' hostnames through DNS-over-HTTPS');
      return pool(toResolve, 16, function (n) {
        return doh(n, 'A', 7000).then(function (r) {
          var cn = r.answers.filter(function (a) { return a.type === T.CNAME; }).map(function (a) { return norm(a.data); });
          var ips = r.answers.filter(function (a) { return a.type === T.A; }).map(function (a) { return a.data; });
          var last = cn.length ? cn[cn.length - 1] : null;
          return { name: n, cname: cn, target: last, ips: ips, status: r.status, service: last ? fingerprint(last, TAKEOVER_CNAMES) : null, sources: out.names[n].sources, wildcard: out.names[n].wildcard, interesting: interesting(n) };
        });
      }).then(function (res) {
        res = res.filter(function (x) { return x && x.name; });
        out.resolved = res.sort(function (a, b) { return (b.ips.length ? 1 : 0) - (a.ips.length ? 1 : 0) || a.name.localeCompare(b.name); });
        var live = res.filter(function (x) { return x.ips.length; }), dead = res.filter(function (x) { return !x.ips.length; });
        out.live = live.length; out.dead = dead.length;
        out.ips = uniq([].concat.apply([], live.map(function (x) { return x.ips; })));
        ctx.findings.push(F('info', plural(list.length, 'hostname') + ' discovered without touching the target', live.length + ' resolve to an address, ' + dead.length + ' no longer resolve' + (out.capped ? ', ' + out.capped + ' not resolved (cap)' : '') + '. Stale names in certificate logs are a map of past infrastructure.', ''));
        res.forEach(function (x) {
          if (x.target && !x.ips.length) {
            if (x.service) ctx.findings.push(F('high', 'Possible dangling CNAME: ' + x.name + ' → ' + x.target, 'The record points at ' + x.service + ' but the target does not resolve (' + (x.status === 3 ? 'NXDOMAIN' : 'no address') + '). If the provider lets anyone claim that name, the subdomain can be taken over and used to serve content or read cookies under ' + d + '.', 'Verify with SubdomainTKO (https://tko.marulecha.com/) and remove the record or reclaim the resource.'));
            else ctx.findings.push(F('medium', 'Dangling CNAME: ' + x.name + ' → ' + x.target, 'The CNAME target does not resolve. Stale aliases like this are the usual precondition for subdomain takeover.', 'Remove the record, or re-point it at a resource you control.'));
          } else if (x.service) ctx.findings.push(F('info', x.name + ' is hosted on ' + x.service, 'CNAME → ' + x.target + '. Resolves, so it is not currently dangling; confirm the resource is still owned by the organisation.', ''));
        });
        var intr = res.filter(function (x) { return x.interesting; });
        if (intr.length) ctx.findings.push(F('info', plural(intr.length, 'sensitive-sounding hostname'), intr.slice(0, 15).map(function (x) { return x.name + (x.ips.length ? '' : ' (stale)'); }).join(', ') + (intr.length > 15 ? ' …' : '') + '. Names suggesting non-production, administrative or infrastructure systems.', 'Make sure these are meant to be reachable from the internet and are covered by the same controls as production.'));
        var wild = list.filter(function (n) { return out.names[n].wildcard; }).concat(out.names[d] && out.names[d].wildcard ? [d] : []);
        if (wild.length) ctx.findings.push(F('info', 'Wildcard certificates issued for ' + uniq(wild).slice(0, 5).map(function (n) { return '*.' + n; }).join(', '), 'One key covers every host under the name; a compromise on any of them exposes all.', 'Prefer per-host certificates where practical.'));
        if (list.length > 300) ctx.findings.push(F('info', 'Very large hostname footprint', plural(list.length, 'name') + ' under one apex. Large surfaces accumulate forgotten hosts.', 'Run a periodic inventory and decommission stale names.'));
        log('Subdomains: ' + live.length + ' live, ' + dead.length + ' stale');
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /* Module: Certificates                                                 */
  /* ------------------------------------------------------------------ */
  function modCerts(ctx) {
    var d = ctx.apex, out = ctx.data.certs = { certs: [] };
    ctx.log('Building certificate timeline from CT data');
    return fetchCT(ctx).then(function (ct) {
      var certs = [];
      if (ct.certspotter.ok && ct.certspotter.rows.length) certs = ct.certspotter.rows.map(function (c) { return { names: (c.dns_names || []).map(norm), issuer: (c.issuer && (c.issuer.friendly_name || c.issuer.name)) || '—', notBefore: c.not_before, notAfter: c.not_after, revoked: !!c.revoked, src: 'Certspotter', link: null }; });
      else if (ct.crt.ok) certs = ct.crt.rows.map(function (c) { return { names: uniq(String(c.name_value || '').split('\n').map(norm)), issuer: (String(c.issuer_name || '').match(/O=([^,]+)/) || [])[1] || c.issuer_name, notBefore: c.not_before, notAfter: c.not_after, revoked: false, src: 'crt.sh', link: 'https://crt.sh/?id=' + c.id }; });
      var seen = {};
      certs = certs.filter(function (c) { var k = c.names.slice().sort().join(',') + '|' + String(c.notAfter).slice(0, 10); if (seen[k]) return false; seen[k] = true; return true; });
      certs.sort(function (a, b) { return new Date(b.notBefore) - new Date(a.notBefore); });
      out.certs = certs; out.total = certs.length;
      if (!certs.length) { ctx.findings.push(F('info', 'No certificates found in CT logs', ct.crt.ok || ct.certspotter.ok ? 'No public CA has logged a certificate for ' + d + '; the domain may not serve HTTPS.' : 'Both CT sources were unreachable: ' + ct.crt.error + ' / ' + ct.certspotter.error, '')); return; }
      var now = Date.now();
      var active = certs.filter(function (c) { return new Date(c.notAfter) > now && !c.revoked; });
      out.active = active.length;
      var byIssuer = Object.create(null); (active.length ? active : certs).forEach(function (c) { byIssuer[c.issuer] = (byIssuer[c.issuer] || 0) + 1; });
      var issuers = Object.keys(byIssuer).sort(function (a, b) { return byIssuer[b] - byIssuer[a]; });
      out.issuers = issuers.map(function (i) { return i + ' (' + byIssuer[i] + ')'; });
      ctx.findings.push(F('info', plural(certs.length, 'certificate') + ' logged, ' + active.length + ' currently valid', 'Issuers: ' + out.issuers.slice(0, 6).join(', ') + '. Source: ' + certs[0].src + '.', ''));
      [d, 'www.' + d].forEach(function (name) {
        var parent = name.split('.').slice(1).join('.');
        var covering = certs.filter(function (c) { return c.names.indexOf(name) !== -1 || c.names.indexOf('*.' + parent) !== -1; });
        if (!covering.length) { ctx.findings.push(F('info', 'No certificate covers ' + name, 'Either the host does not serve HTTPS or its certificate was never logged.', '')); return; }
        var latest = covering.reduce(function (m, c) { return new Date(c.notAfter) > new Date(m.notAfter) ? c : m; });
        var days = daysUntil(latest.notAfter);
        if (days < 0) ctx.findings.push(F('medium', 'Latest certificate for ' + name + ' expired ' + (-days) + ' days ago', 'Issued by ' + latest.issuer + ', no newer certificate appears in the logs. Either HTTPS is broken on that host or the renewal was not logged.', 'Renew and confirm the new certificate appears in CT.'));
        else if (days < 14) ctx.findings.push(F('medium', 'Certificate for ' + name + ' expires in ' + days + ' days', 'Issued by ' + latest.issuer + ', expires ' + fmtDate(latest.notAfter) + '. No replacement is logged yet.', 'Check that automated renewal is working.'));
        else ctx.findings.push(F('ok', name + ' has a valid certificate for ' + days + ' more days', 'Issued by ' + latest.issuer + ', valid ' + fmtDate(latest.notBefore) + ' → ' + fmtDate(latest.notAfter) + '.', ''));
      });
      var wild = active.filter(function (c) { return c.names.some(function (n) { return n[0] === '*'; }); });
      if (wild.length) ctx.findings.push(F('info', plural(wild.length, 'active wildcard certificate'), uniq([].concat.apply([], wild.map(function (c) { return c.names.filter(function (n) { return n[0] === '*'; }); }))).join(', '), 'A wildcard private key must be protected as carefully as every host it covers.'));
      var recent = certs.filter(function (c) { return now - new Date(c.notBefore) < 90 * 86400000; });
      if (recent.length) ctx.findings.push(F('info', plural(recent.length, 'certificate') + ' issued in the last 90 days', 'Issuance velocity reflects automated renewal (ACME) and new hosts appearing.', ''));
      var rev = certs.filter(function (c) { return c.revoked; });
      if (rev.length) ctx.findings.push(F('info', plural(rev.length, 'revoked certificate') + ' in the log', 'Revocations can indicate a key compromise or a decommissioned host.', ''));
      if (issuers.length > 3) ctx.findings.push(F('info', 'Certificates from ' + issuers.length + ' different CAs', 'Several teams or platforms are issuing independently; a CAA record can constrain this.', ''));
      var sans = active.map(function (c) { return c.names.length; }).sort(function (a, b) { return b - a; })[0] || 0;
      if (sans > 40) ctx.findings.push(F('info', 'A certificate lists ' + sans + ' hostnames', 'Large SAN lists leak the full set of hosts behind one edge (often a CDN or shared hosting).', ''));
      /* timeline: when each hostname first appeared in CT, and hosts that never renewed */
      var firstSeen = Object.create(null), lastSeen = Object.create(null);
      certs.forEach(function (c) { c.names.forEach(function (n) { var t = new Date(c.notBefore).getTime(); if (!firstSeen[n] || t < firstSeen[n]) firstSeen[n] = t; if (!lastSeen[n] || t > lastSeen[n]) lastSeen[n] = t; }); });
      out.timeline = Object.keys(firstSeen).map(function (n) { return { name: n, first: firstSeen[n], last: lastSeen[n] }; }).sort(function (a, b) { return a.first - b.first; });
      var newHosts = out.timeline.filter(function (t) { return now - t.first < 30 * 86400000 && t.name.indexOf('*') !== 0; });
      if (newHosts.length) ctx.findings.push(F('info', plural(newHosts.length, 'hostname') + ' first appeared in CT in the last 30 days', newHosts.slice(0, 12).map(function (t) { return t.name; }).join(', ') + (newHosts.length > 12 ? ' …' : '') + '. Newly issued names often mark a launch, migration or a freshly stood-up service worth a look.', ''));
      var abandoned = out.timeline.filter(function (t) { return t.name.indexOf('*') !== 0 && (now - t.last) > 400 * 86400000; });
      if (abandoned.length) ctx.findings.push(F('info', plural(abandoned.length, 'hostname') + ' with no certificate in over a year', abandoned.slice(0, 12).map(function (t) { return t.name; }).join(', ') + (abandoned.length > 12 ? ' …' : '') + '. Names that stopped renewing are often decommissioned projects; if any still has a live DNS record it is worth checking for takeover.', ''));
      var span = out.timeline.length ? Math.round((now - out.timeline[0].first) / (365.25 * 86400000) * 10) / 10 : 0;
      if (span >= 1) ctx.findings.push(F('info', 'Certificate history spans about ' + span + ' years', 'Earliest logged issuance ' + fmtDate(out.timeline[0].first) + '. CT history is a rough age signal for the web presence.', ''));
      ctx.log('Certificates: ' + active.length + ' valid of ' + certs.length + ' logged');
    });
  }

  /* ------------------------------------------------------------------ */
  /* Module: Hosting & network                                            */
  /* ------------------------------------------------------------------ */
  function ptr(ip) {
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return Promise.resolve(null);
    return rr(ip.split('.').reverse().join('.') + '.in-addr.arpa', 'PTR').then(function (r) { return r[0] ? norm(r[0]) : null; });
  }
  function cdnName(i) { var m = ((i.org || '') + ' ' + (i.isp || '')).match(CDN_ORGS); return m ? m[0].replace(/^\w/, function (c) { return c.toUpperCase(); }) : null; }
  function modHosting(ctx) {
    var dns = ctx.data.dns || {}, sub = ctx.data.subdomains || {}, out = ctx.data.hosting = { ips: [] };
    var primary = uniq(dns.ips || []);
    var others = uniq((sub.ips || []).filter(function (ip) { return primary.indexOf(ip) === -1; }));
    var all = primary.concat(others);
    out.total = all.length;
    if (!all.length) { ctx.findings.push(F('info', 'No addresses to enrich', 'Neither the apex nor any discovered hostname resolved to an IP address.', '')); return Promise.resolve(); }
    var targets = all.slice(0, 40);
    ctx.log('Enriching ' + targets.length + (all.length > targets.length ? ' of ' + all.length : '') + ' addresses (ASN, geolocation, reverse DNS)');
    function hostsUsing(ip) {
      var h = [];
      if ((dns.records && dns.records.A || []).concat(dns.records && dns.records.AAAA || []).some(function (a) { return a.data === ip; })) h.push(ctx.domain);
      if (dns.www && (dns.www.A || []).concat(dns.www.AAAA || []).indexOf(ip) !== -1) h.push('www.' + ctx.domain);
      (sub.resolved || []).forEach(function (r) { if (r.ips.indexOf(ip) !== -1) h.push(r.name); });
      return uniq(h);
    }
    function enrich(ip) {
      var e = encodeURIComponent(ip);
      return getJSON('https://get.geojs.io/v1/ip/geo/' + e + '.json', {}, 7000)
        .then(function (j) { if (!j || !j.ip) throw new Error('empty'); return { ip: ip, asn: j.asn ? +j.asn : null, org: j.organization_name || String(j.organization || '').replace(/^AS\d+\s+/, ''), isp: '', country: j.country, cc: j.country_code, city: j.city, eu: null, src: 'geojs.io' }; })
        .catch(function () { return getJSON('https://api.ipapi.is/?q=' + e, {}, 7000).then(function (j) { var m = String(j.asn || '').match(/^AS(\d+)\s+(.*)$/); return { ip: ip, asn: m ? +m[1] : null, org: m ? m[2] : (j.company || ''), isp: j.company || '', country: j.country, cc: j.country_code, city: j.city, eu: null, src: 'ipapi.is' }; }); })
        .catch(function () { return getJSON('https://ipinfo.io/' + e + '/json', {}, 7000).then(function (j) { var m = String(j.org || '').match(/^AS(\d+)\s+(.*)$/); return { ip: ip, asn: m ? +m[1] : null, org: m ? m[2] : j.org, isp: '', country: j.country, cc: j.country, city: j.city, eu: null, anycast: !!j.anycast, src: 'ipinfo.io' }; }); })
        .catch(function () { return getJSON('https://ipwho.is/' + e, {}, 7000).then(function (j) { if (j.success === false) throw new Error(j.message || 'lookup failed'); return { ip: ip, asn: j.connection && j.connection.asn, org: j.connection && j.connection.org, isp: j.connection && j.connection.isp, country: j.country, cc: j.country_code, city: j.city, eu: !!j.is_eu, src: 'ipwho.is' }; }); })
        .catch(function (e2) { return { ip: ip, error: e2.message }; });
    }
    return pool(targets, 4, function (ip) {
      return Promise.all([enrich(ip), ptr(ip)]).then(function (r) { var info = r[0]; info.ptr = r[1]; info.hosts = hostsUsing(ip); info.primary = primary.indexOf(ip) !== -1; return info; });
    }).then(function (infos) {
      out.ips = infos;
      var ok = infos.filter(function (i) { return !i.error; });
      if (!ok.length) { ctx.findings.push(F('info', 'IP intelligence providers unreachable', infos.map(function (i) { return i.ip + ': ' + i.error; }).join(' · '), '')); return; }
      var prim = ok.filter(function (i) { return i.primary; });
      var isCdn = function (i) { return CDN_ORGS.test((i.org || '') + ' ' + (i.isp || '')); };
      var cdn = prim.filter(isCdn);
      out.cdn = cdn.length ? uniq(cdn.map(cdnName)).join(', ') : null;
      var p0 = prim[0] || ok[0];
      out.summary = (p0.org || p0.isp || 'unknown') + (p0.asn ? ' · AS' + p0.asn : '') + (p0.country ? ' · ' + p0.country : '');
      if (cdn.length) ctx.findings.push(F('ok', 'Apex fronted by ' + out.cdn, 'The public addresses belong to a CDN/WAF, which hides the origin server and absorbs volumetric attacks.', ''));
      else if (prim.length) ctx.findings.push(F('info', 'Apex hosted directly at ' + (p0.org || p0.isp) + (p0.asn ? ' (AS' + p0.asn + ', ' + p0.country + ')' : ''), 'No CDN or WAF in front: the origin server is directly exposed to the internet.', 'Consider a CDN/WAF for business-critical sites, and rate-limit at the edge.'));
      if (cdn.length) {
        var leaks = ok.filter(function (i) { return !i.primary && !isCdn(i); });
        if (leaks.length) ctx.findings.push(F('medium', 'Hostnames resolve outside the CDN (possible origin exposure)', leaks.map(function (i) { return i.hosts.slice(0, 3).join(', ') + ' → ' + i.ip + ' (' + (i.org || i.isp) + ')'; }).join(' · ') + '. If any of these is the origin behind the CDN, the WAF can be bypassed by connecting to it directly.', 'Restrict origin ingress to the CDN\'s address ranges; move direct-access hosts behind the CDN or a VPN.'));
      }
      var asns = uniq(ok.map(function (i) { return i.asn; }).filter(Boolean)), countries = uniq(ok.map(function (i) { return i.country; }).filter(Boolean));
      var orgs = uniq(ok.map(function (i) { return i.org || i.isp; }).filter(Boolean));
      ctx.findings.push(F('info', 'Footprint: ' + plural(all.length, 'address') + ' across ' + plural(asns.length, 'network') + ' in ' + plural(countries.length, 'country'), orgs.slice(0, 8).join(', ') + (orgs.length > 8 ? ' …' : '') + (all.length > targets.length ? '. Only the first ' + targets.length + ' addresses were enriched.' : ''), ''));
      var cloud = uniq(ok.map(function (i) { var m = ((i.org || '') + ' ' + (i.isp || '')).match(CLOUD_ORGS); return m ? m[0] : null; }).filter(Boolean));
      if (cloud.length) ctx.findings.push(F('info', 'Cloud and hosting providers in use', cloud.join(', '), ''));
      var euKnown = ok.filter(function (i) { return i.eu !== null && i.eu !== undefined; });
      if (euKnown.length) { var eu = euKnown.filter(function (i) { return i.eu; }).length; ctx.findings.push(F('info', (eu === euKnown.length ? 'All' : eu + ' of ' + euKnown.length) + ' geolocated addresses are in the EU', 'Relevant to data-residency questions. Anycast (CDN) addresses report one country regardless of where the edge actually serving a user is.', '')); }
      var noPtr = prim.filter(function (i) { return /^\d+\.\d+\.\d+\.\d+$/.test(i.ip) && !i.ptr && !isCdn(i); });
      if (noPtr.length) ctx.findings.push(F('info', 'No reverse DNS for ' + noPtr.map(function (i) { return i.ip; }).join(', '), 'Missing PTR records hurt mail deliverability if these hosts send email.', 'Ask the hosting provider to set PTR records.'));
      ctx.log('Hosting: ' + out.summary);
    });
  }

  /* ------------------------------------------------------------------ */
  /* Module: Lookalike domains                                            */
  /* ------------------------------------------------------------------ */
  var HOMOGLYPHS = { o: ['0'], '0': ['o'], l: ['1', 'i'], i: ['1', 'l'], '1': ['l', 'i'], e: ['3'], a: ['4'], s: ['5', 'z'], z: ['s'], g: ['q', '9'], q: ['g'], b: ['d'], d: ['b', 'cl'], m: ['rn', 'nn'], n: ['m'], w: ['vv'], u: ['v'], v: ['u'], t: ['f'], f: ['t'], c: ['e'], k: ['lc'], h: ['b'], r: ['n'], y: ['v'] };
  var KEYBOARD = { q: 'wa', w: 'qeas', e: 'wrds', r: 'etf', t: 'ryg', y: 'tuh', u: 'yij', i: 'uok', o: 'ipl', p: 'o', a: 'qwsz', s: 'awedxz', d: 'serfcx', f: 'drtgvc', g: 'ftyhbv', h: 'gyujnb', j: 'huikmn', k: 'jiolm', l: 'kop', z: 'asx', x: 'zsdc', c: 'xdfv', v: 'cfgb', b: 'vghn', n: 'bhjm', m: 'njk' };
  var TLDS = ['com', 'net', 'org', 'co', 'io', 'info', 'biz', 'us', 'eu', 'gr', 'de', 'co.uk', 'app', 'dev', 'xyz', 'online', 'site', 'shop', 'tech', 'me', 'cc', 'cloud', 'ai', 'support', 'login', 'email', 'store', 'live', 'help', 'services'];
  var AFFIX = ['s', '-login', '-secure', '-support', '-mail', '-portal', '-app', '-online', '-official', '-hr', '-vpn', '-sso', '-pay', '-invoice', '-help', '-account', '-verify', '-update'];
  var PREFIX = ['my', 'secure-', 'login-', 'mail-', 'www', 'vpn-', 'portal-', 'account-', 'support-', 'hr-'];
  var KIND_ORDER = ['tld', 'homoglyph', 'idn-homograph', 'omission', 'transposition', 'addition', 'prefix', 'hyphenation', 'repetition', 'keyboard', 'vowel'];
  var CONFUSABLES = { a: ['\u0430', '\u03b1'], c: ['\u0441', '\u03f2'], e: ['\u0435'], o: ['\u043e', '\u03bf', '\u0585'], p: ['\u0440', '\u03c1'], x: ['\u0445', '\u03c7'], y: ['\u0443', '\u04af'], i: ['\u0456', '\u0131'], j: ['\u0458'], s: ['\u0455'], d: ['\u0501'], h: ['\u04bb'], n: ['\u0578'], b: ['\u0432'], g: ['\u0261'], l: ['\u04c0', '\u1e37'], m: ['\u043c'], t: ['\u0442'], k: ['\u043a'] };

  function permutations(apex) {
    var parts = apex.split('.');
    var tldLen = (SLD.indexOf(parts.slice(-2).join('.')) !== -1 && parts.length >= 3) ? 2 : 1;
    var tld = parts.slice(-tldLen).join('.'), label = parts.slice(0, -tldLen).join('.');
    var set = {}, unicodeOf = {}, i;
    function add(l, t, kind) { var name = l + '.' + t; if (name === apex || !/^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(l) || l[0] === '-' || l.slice(-1) === '-' || l.length < 2) return; if (!set[name]) set[name] = kind; }
    TLDS.forEach(function (t) { if (t !== tld) add(label, t, 'tld'); });
    for (i = 0; i < label.length; i++) (HOMOGLYPHS[label[i]] || []).forEach(function (r) { add(label.slice(0, i) + r + label.slice(i + 1), tld, 'homoglyph'); });
    if (/rn/.test(label)) add(label.replace('rn', 'm'), tld, 'homoglyph');
    if (/vv/.test(label)) add(label.replace('vv', 'w'), tld, 'homoglyph');
    if (/cl/.test(label)) add(label.replace('cl', 'd'), tld, 'homoglyph');
    for (i = 0; i < label.length; i++) add(label.slice(0, i) + label.slice(i + 1), tld, 'omission');
    for (i = 0; i < label.length - 1; i++) if (label[i] !== label[i + 1]) add(label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2), tld, 'transposition');
    AFFIX.forEach(function (s) { add(label + s, tld, 'addition'); });
    PREFIX.forEach(function (p) { add(p + label, tld, 'prefix'); });
    for (i = 1; i < label.length; i++) if (label[i] !== '-' && label[i - 1] !== '-' && label[i] !== '.' && label[i - 1] !== '.') add(label.slice(0, i) + '-' + label.slice(i), tld, 'hyphenation');
    if (/-/.test(label)) add(label.replace(/-/g, ''), tld, 'hyphenation');
    for (i = 0; i < label.length; i++) if (/[a-z]/.test(label[i])) add(label.slice(0, i) + label[i] + label.slice(i), tld, 'repetition');
    for (i = 0; i < label.length; i++) (KEYBOARD[label[i]] || '').split('').forEach(function (r) { if (r) add(label.slice(0, i) + r + label.slice(i + 1), tld, 'keyboard'); });
    for (i = 0; i < label.length; i++) if (/[aeiou]/.test(label[i])) 'aeiou'.split('').forEach(function (v) { if (v !== label[i]) add(label.slice(0, i) + v + label.slice(i + 1), tld, 'vowel'); });
    /* IDN homographs: swap one Latin letter for a confusable, punycode via the browser URL parser */
    Object.keys(CONFUSABLES).forEach(function (ch) {
      var at = label.indexOf(ch);
      if (at === -1) return;
      CONFUSABLES[ch].forEach(function (uni) {
        var uLabel = label.slice(0, at) + uni + label.slice(at + 1);
        var puny;
        try { puny = new URL('http://' + uLabel + '.' + tld + '/').hostname; } catch (e) { return; }
        if (puny && /^xn--/.test(puny.split('.')[0]) && puny !== apex) { if (!set[puny]) { set[puny] = 'idn-homograph'; unicodeOf[puny] = uLabel + '.' + tld; } }
      });
    });
    return Object.keys(set).map(function (k) { return { domain: k, kind: set[k], unicode: unicodeOf[k] || null }; })
      .sort(function (a, b) { return KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind) || a.domain.localeCompare(b.domain); });
  }

  function modTyposquat(ctx) {
    var d = ctx.apex, out = ctx.data.typosquat = { tested: [], registered: [] };
    var all = permutations(d);
    var cands = all.slice(0, 140);
    out.generated = all.length; out.tested = cands;
    ctx.log('Generated ' + all.length + ' lookalike permutations, checking ' + cands.length + ' for registration (NS lookups)');
    return pool(cands, 12, function (c) {
      return doh(c.domain, 'NS', 7000).then(function (r) {
        c.status = r.status;
        c.registered = r.status === 0 && r.answers.some(function (a) { return a.type === T.NS; });
        if (!c.registered && r.status === 0 && r.authority && r.authority.some(function (a) { return a.type === T.SOA && norm(a.name) === c.domain; })) c.registered = true;
        if (!c.registered) return c;
        return Promise.all([rr(c.domain, 'A'), rr(c.domain, 'MX')]).then(function (x) { c.ips = x[0]; c.mx = x[1].length > 0 && !(x[1].length === 1 && /^0 \.?$/.test(x[1][0])); return c; });
      });
    }).then(function () {
      var reg = cands.filter(function (c) { return c.registered; });
      out.registered = reg;
      var live = reg.filter(function (c) { return c.ips && c.ips.length; }), mail = reg.filter(function (c) { return c.mx; });
      if (!reg.length) ctx.findings.push(F('ok', 'No registered lookalikes among ' + cands.length + ' permutations', 'TLD swaps, homoglyphs, omissions, transpositions, affixes and keyboard-adjacent typos were tested.', ''));
      else {
        if (live.length) ctx.findings.push(F('medium', plural(live.length, 'lookalike domain') + ' registered and resolving', live.slice(0, 12).map(function (c) { return (c.unicode ? c.unicode + ' [' + c.domain + ']' : c.domain) + ' (' + c.kind + (c.mx ? ', has MX' : '') + ')'; }).join(', ') + (live.length > 12 ? ' …' : '') + '. Some will be defensive registrations by the organisation itself and some are parking pages; the rest are candidates for phishing or typo-traffic capture. Entries with MX can also receive mail.', 'Verify ownership of each (RDAP links below). For hostile ones: brand-monitoring, registrar abuse reports, or UDRP.'));
        var parked = reg.filter(function (c) { return !c.ips || !c.ips.length; });
        if (parked.length) ctx.findings.push(F('low', plural(parked.length, 'lookalike domain') + ' registered but not serving a site', parked.slice(0, 12).map(function (c) { return c.domain + (c.mx ? ' (has MX)' : ''); }).join(', ') + (parked.length > 12 ? ' …' : ''), 'Check whether these are yours; a registered-but-idle lookalike can be activated at any time.'));
        if (mail.length) ctx.findings.push(F('info', plural(mail.length, 'lookalike') + ' can receive email', mail.map(function (c) { return c.domain; }).join(', ') + '. MX records on a lookalike enable reply-capture and mis-addressed mail harvesting.', ''));
      }
      ctx.findings.push(F('info', 'Coverage note', cands.length + ' of ' + all.length + ' permutations were tested (TLD swaps, ASCII typos and IDN homographs). Dedicated brand-monitoring tests thousands more.', ''));
      ctx.log('Lookalikes: ' + reg.length + ' registered, ' + live.length + ' live');
    });
  }

  /* ------------------------------------------------------------------ */
  /* Module: Web archive                                                  */
  /* ------------------------------------------------------------------ */
  function fmtTs(ts) { ts = String(ts || ''); return ts.length >= 8 ? ts.slice(0, 4) + '-' + ts.slice(4, 6) + '-' + ts.slice(6, 8) : ts; }
  function modArchive(ctx) {
    var d = ctx.apex, out = ctx.data.archive = {};
    ctx.log('Asking the Internet Archive for the first and latest captures');
    var base = 'https://archive.org/wayback/available?url=' + encodeURIComponent(d);
    return Promise.all([
      getJSON(base + '&timestamp=19960101', {}, 15000).catch(function (e) { return { error: e }; }),
      getJSON(base, {}, 15000).catch(function (e) { return { error: e }; })
    ]).then(function (r) {
      if (r[0].error && r[1].error) {
        var st = r[0].error.status || r[1].error.status;
        out.error = st || 'unreachable';
        ctx.findings.push(F('info', st === 429 ? 'Internet Archive rate-limited this browser' : 'Internet Archive unreachable or rate-limited', 'The availability API throttles aggressively. Retry in a minute, or browse the archive manually via the Pivot module.', ''));
        return;
      }
      var first = r[0].archived_snapshots && r[0].archived_snapshots.closest, last = r[1].archived_snapshots && r[1].archived_snapshots.closest;
      out.first = first || null; out.last = last || null;
      if (!first && !last) { ctx.findings.push(F('info', 'No captures in the Wayback Machine', 'The domain has never been archived, which is unusual for an established site and typical for a young or private one.', '')); return; }
      var f = first || last, l = last || first;
      ctx.findings.push(F('info', 'Archived since ' + fmtTs(f.timestamp).slice(0, 4) + ', latest capture ' + fmtTs(l.timestamp), 'Historic snapshots preserve old endpoints, staff names, technology banners and files that were later removed. Both captures are linked in the raw data below.', ''));
      ctx.findings.push(F('info', 'Full URL history needs a manual step', 'The archive\'s CDX index does not allow cross-origin requests, so it cannot be listed here. The Pivot module links to the list of every archived URL under ' + d + '.', ''));
      ctx.log('Archive: ' + fmtTs(f.timestamp) + ' → ' + fmtTs(l.timestamp));
    });
  }

  /* ------------------------------------------------------------------ */
  /* Module: Pivot links (opens in the visitor's own browser, nothing fetched) */
  /* ------------------------------------------------------------------ */
  function modPivot(ctx) {
    var d = ctx.apex, e = encodeURIComponent(d);
    ctx.data.pivot = [
      { group: 'Infrastructure', links: [
        ['Shodan', 'https://www.shodan.io/domain/' + e], ['Censys hosts', 'https://search.censys.io/search?resource=hosts&q=' + e], ['urlscan.io', 'https://urlscan.io/domain/' + e],
        ['VirusTotal', 'https://www.virustotal.com/gui/domain/' + e], ['BuiltWith', 'https://builtwith.com/' + e], ['DNSDumpster', 'https://dnsdumpster.com/'] ] },
      { group: 'Web & TLS (active, third-party run)', links: [
        ['Security Headers', 'https://securityheaders.com/?q=' + e + '&followRedirects=on'], ['SSL Labs', 'https://www.ssllabs.com/ssltest/analyze.html?d=' + e], ['Hardenize', 'https://www.hardenize.com/report/' + e],
        ['Mozilla Observatory', 'https://developer.mozilla.org/en-US/observatory/analyze?host=' + e], ['security.txt', 'https://' + d + '/.well-known/security.txt'], ['robots.txt', 'https://' + d + '/robots.txt'] ] },
      { group: 'Email', links: [
        ['MXToolbox SuperTool', 'https://mxtoolbox.com/SuperTool.aspx?action=mx%3a' + e + '&run=toolpage'], ['DMARC inspector', 'https://dmarcian.com/dmarc-inspector/?domain=' + e], ['MTA-STS policy', 'https://mta-sts.' + d + '/.well-known/mta-sts.txt'], ['Learn DMARC', 'https://www.learndmarc.com/'] ] },
      { group: 'Registration & history', links: [
        ['RDAP (raw)', 'https://rdap.org/domain/' + e], ['WHOIS', 'https://who.is/whois/' + e], ['Wayback: all archived URLs', 'https://web.archive.org/web/*/' + d + '/*'], ['Wayback: latest', 'https://web.archive.org/web/2/https://' + d + '/'],
        ['crt.sh', 'https://crt.sh/?q=' + encodeURIComponent('%.' + d)], ['DNS history (SecurityTrails)', 'https://securitytrails.com/domain/' + e + '/history/a'] ] },
      { group: 'Brand & presence', links: [
        ['GitHub (code & orgs)', 'https://github.com/search?q=' + encodeURIComponent(d.split('.')[0]) + '&type=users'], ['LinkedIn companies', 'https://www.linkedin.com/search/results/companies/?keywords=' + encodeURIComponent(d.split('.')[0])],
        ['Crunchbase', 'https://www.crunchbase.com/textsearch?q=' + encodeURIComponent(d.split('.')[0])], ['X / Twitter', 'https://x.com/search?q=' + e + '&f=live'], ['YouTube', 'https://www.youtube.com/results?search_query=' + e], ['Reddit mentions', 'https://www.reddit.com/search/?q=' + e] ] },
      { group: 'Search dorks', links: [
        ['site:' + d, 'https://www.google.com/search?q=' + encodeURIComponent('site:' + d)], ['Documents (pdf, docx, xlsx)', 'https://www.google.com/search?q=' + encodeURIComponent('site:' + d + ' (ext:pdf OR ext:docx OR ext:xlsx OR ext:pptx)')],
        ['Login pages', 'https://www.google.com/search?q=' + encodeURIComponent('site:' + d + ' (inurl:login OR inurl:signin OR intitle:login)')], ['Directory listings', 'https://www.google.com/search?q=' + encodeURIComponent('site:' + d + ' intitle:"index of"')],
        ['Config & backup files', 'https://www.google.com/search?q=' + encodeURIComponent('site:' + d + ' (ext:env OR ext:bak OR ext:sql OR ext:log OR ext:config OR ext:ini)')], ['GitHub code mentions', 'https://github.com/search?q=' + encodeURIComponent('"' + d + '"') + '&type=code'],
        ['Pastes & leaks (Google)', 'https://www.google.com/search?q=' + encodeURIComponent('"' + d + '" (site:pastebin.com OR site:ghostbin.com OR site:paste.ee)')], ['Google Safe Browsing', 'https://transparencyreport.google.com/safe-browsing/search?url=' + e] ] }
    ];
    var cand = (ctx.data.storage || {}).candidates || [];
    if (cand.length) ctx.data.pivot.splice(1, 0, { group: 'Cloud storage candidates (open to check)', links: [].concat.apply([], cand.slice(0, 8).map(function (c) { return [['S3 ' + c.label, c.s3], ['GCS ' + c.label, c.gcs]]; })) });
    ctx.log('Pivot links ready (nothing fetched)');
    return Promise.resolve();
  }


  /* ------------------------------------------------------------------ */
  /* Module: DNS probe of well-known hostnames (resolver only)            */
  /* ------------------------------------------------------------------ */
  var PROBE_NAMES = ['www', 'mail', 'webmail', 'smtp', 'imap', 'pop', 'mx', 'mx1', 'mx2', 'autodiscover', 'autoconfig', 'owa', 'exchange', 'remote', 'vpn', 'sslvpn', 'gateway', 'portal', 'intranet', 'extranet', 'sso', 'login', 'auth', 'id', 'idp', 'adfs', 'okta', 'api', 'api2', 'app', 'apps', 'mobile', 'm', 'dev', 'test', 'staging', 'stage', 'uat', 'qa', 'demo', 'beta', 'sandbox', 'preprod', 'admin', 'cpanel', 'whm', 'plesk', 'panel', 'ftp', 'sftp', 'files', 'share', 'cloud', 'drive', 'docs', 'wiki', 'kb', 'help', 'support', 'helpdesk', 'status', 'blog', 'news', 'shop', 'store', 'careers', 'jobs', 'hr', 'crm', 'erp', 'git', 'gitlab', 'jenkins', 'ci', 'jira', 'confluence', 'grafana', 'kibana', 'monitor', 'nagios', 'zabbix', 'cdn', 'static', 'assets', 'img', 'images', 'media', 'video', 'stream', 'ns', 'ns1', 'ns2', 'dns', 'dns1', 'db', 'mysql', 'sql', 'backup', 'old', 'new', 'legacy', 'secure', 'pay', 'payments', 'billing', 'invoice', 'edge', 'lb', 'proxy', 'relay', 'vpn2', 'ras', 'citrix', 'rdp', 'ts', 'voip', 'sip', 'pbx', 'meet', 'video1', 'teams', 'zoom', 'lyncdiscover', 'enterpriseregistration', 'enterpriseenrollment', 'msoid', 'selector1._domainkey', 'selector2._domainkey', '_dmarc', 'mta-sts', 'openvpn', 'wireguard', 'fw', 'firewall', 'router', 'cam', 'nvr', 'iot', 's3', 'minio', 'storage', 'registry', 'docker', 'k8s', 'argocd', 'vault', 'sonar', 'nexus', 'artifactory', 'sentry', 'elastic', 'redis', 'kafka', 'rabbit', 'mq'];
  function modProbe(ctx) {
    var d = ctx.apex, out = ctx.data.probe = { hits: [], tested: 0, skipped: false };
    var dns = ctx.data.dns || {};
    var known = {}; Object.keys((ctx.data.subdomains || {}).names || {}).forEach(function (n) { known[n] = true; });
    var names = uniq(PROBE_NAMES).map(function (l) { return l + '.' + d; }).filter(function (n) { return !known[n]; });
    if (dns.wildcard) { out.skipped = true; ctx.log('Hostname probe skipped: wildcard DNS makes every name resolve'); return Promise.resolve(); }
    out.tested = names.length;
    ctx.log('Probing ' + names.length + ' well-known hostnames through the resolver (not the target)');
    return pool(names, 16, function (n) {
      return doh(n, 'A', 6000).then(function (r) {
        var cn = r.answers.filter(function (a) { return a.type === T.CNAME; }).map(function (a) { return norm(a.data); });
        var ips = r.answers.filter(function (a) { return a.type === T.A; }).map(function (a) { return a.data; });
        if (!cn.length && !ips.length) return null;
        var last = cn.length ? cn[cn.length - 1] : null;
        return { name: n, cname: cn, target: last, ips: ips, status: r.status, service: last ? fingerprint(last, TAKEOVER_CNAMES) : null, sources: ['dns-probe'] };
      });
    }).then(function (res) {
      out.hits = res.filter(function (x) { return x && x.name; });
      if (out.hits.length) ctx.findings.push(F('info', plural(out.hits.length, 'well-known hostname') + ' exist that no certificate log mentions', out.hits.slice(0, 15).map(function (h) { return h.name.replace('.' + d, ''); }).join(', ') + (out.hits.length > 15 ? ' …' : '') + '. Hosts without a public certificate are often internal-facing services exposed by DNS.', ''));
      ctx.log('Probe: ' + out.hits.length + ' of ' + names.length + ' names exist');
    });
  }

  /* ------------------------------------------------------------------ */
  /* Module: Service records (SRV / well-known names → products in use)   */
  /* ------------------------------------------------------------------ */
  var SERVICE_RECORDS = [
    ['_sipfederationtls._tcp', 'SRV', [[/lync\.com|office\.com|teams\.microsoft/, 'Microsoft Teams / Skype for Business (federation)'], [/./, 'SIP federation']]],
    ['_sip._tls', 'SRV', [[/lync\.com|office\.com/, 'Microsoft Teams / Skype for Business'], [/./, 'SIP over TLS']]],
    ['_sip._tcp', 'SRV', [[/./, 'SIP (VoIP)']]],
    ['_sips._tcp', 'SRV', [[/./, 'SIP over TLS (VoIP)']]],
    ['_autodiscover._tcp', 'SRV', [[/outlook|office365/, 'Exchange Online (Autodiscover SRV)'], [/./, 'Exchange Autodiscover (SRV)']]],
    ['_xmpp-client._tcp', 'SRV', [[/google/, 'Google Talk (legacy XMPP)'], [/./, 'XMPP chat']]],
    ['_xmpp-server._tcp', 'SRV', [[/./, 'XMPP federation']]],
    ['_caldavs._tcp', 'SRV', [[/google/, 'Google Calendar (CalDAV)'], [/icloud|apple/, 'iCloud (CalDAV)'], [/./, 'CalDAV']]],
    ['_carddavs._tcp', 'SRV', [[/./, 'CardDAV']]],
    ['_ldap._tcp', 'SRV', [[/./, 'Active Directory / LDAP (public SRV record)']]],
    ['_kerberos._tcp', 'SRV', [[/./, 'Kerberos (public SRV record)']]],
    ['_imaps._tcp', 'SRV', [[/./, 'Mail autoconfig (IMAPS, RFC 6186)']]],
    ['_submission._tcp', 'SRV', [[/./, 'Mail autoconfig (submission, RFC 6186)']]],
    ['_matrix._tcp', 'SRV', [[/./, 'Matrix homeserver']]],
    ['_minecraft._tcp', 'SRV', [[/./, 'Minecraft server']]],
    ['_collab-edge._tls', 'SRV', [[/./, 'Cisco Expressway / Webex Edge']]],
    ['_cisco-uds._tcp', 'SRV', [[/./, 'Cisco Unified Communications']]],
    ['_turn._udp', 'SRV', [[/./, 'TURN (WebRTC relay)']]],
    ['_stun._udp', 'SRV', [[/./, 'STUN']]],
    ['_h323cs._tcp', 'SRV', [[/./, 'H.323 video conferencing']]],
    ['lyncdiscover', 'CNAME', [[/lync\.com|office\.com/, 'Microsoft Teams / Skype for Business'], [/./, 'Lync discovery']]],
    ['enterpriseregistration', 'CNAME', [[/windows\.net|microsoft/, 'Microsoft Entra ID (device registration)'], [/./, 'Enterprise device registration']]],
    ['enterpriseenrollment', 'CNAME', [[/manage\.microsoft\.com|microsoft/, 'Microsoft Intune (MDM enrollment)'], [/./, 'MDM enrollment']]],
    ['autodiscover', 'CNAME', [[/outlook\.com|office365/, 'Exchange Online (Autodiscover)'], [/mail\.protection|mimecast|proofpoint/, 'Hosted Exchange autodiscover'], [/./, 'Exchange Autodiscover']]],
    ['msoid', 'CNAME', [[/./, 'Microsoft Online (legacy federation)']]],
    ['autoconfig', 'CNAME', [[/./, 'Thunderbird autoconfig']]],
    ['_domainconnect', 'TXT', [[/./, 'Domain Connect (DNS templates)']]],
    ['_acme-challenge', 'TXT', [[/./, 'ACME / Let\'s Encrypt automation (leftover challenge)']]],
    ['_atproto', 'TXT', [[/./, 'Bluesky handle verification']]],
    ['_amazonses', 'TXT', [[/./, 'Amazon SES domain verification']]],
    ['_github-pages-challenge', 'TXT', [[/./, 'GitHub Pages domain verification']]],
    ['_dnsauth', 'TXT', [[/./, 'DNS-based CA validation']]],
    ['_asvdns', 'TXT', [[/./, 'Amazon domain verification']]],
    ['_mailchimp', 'TXT', [[/./, 'Mailchimp domain verification']]],
    ['_netlify', 'TXT', [[/./, 'Netlify domain verification']]],
    ['_vercel', 'TXT', [[/./, 'Vercel domain verification']]],
    ['_psl', 'TXT', [[/./, 'Public Suffix List entry request']]],
    ['_report._dmarc', 'TXT', [[/./, 'Receives DMARC reports for other domains']]],
    ['_adsp._domainkey', 'TXT', [[/./, 'DKIM ADSP (obsolete)']]]
  ];
  function modServices(ctx) {
    var d = ctx.apex, out = ctx.data.services = { records: [], found: [] };
    ctx.log('Checking ' + SERVICE_RECORDS.length + ' service and well-known records (SRV, CNAME, TXT)');
    return pool(SERVICE_RECORDS, 12, function (def) {
      var name = def[0] + '.' + d;
      return doh(name, def[1], 6000).then(function (r) {
        var ans = r.answers.filter(function (a) { return a.type === T[def[1]] || (def[1] === 'CNAME' && a.type === T.A); });
        if (!ans.length && def[1] === 'TXT') ans = r.answers.filter(function (a) { return a.type === T.TXT; });
        if (!ans.length) return null;
        var data = ans.map(function (a) { return a.data; }).join(' | ');
        var target = data;
        if (def[1] === 'SRV') { var p = ans[0].data.split(/\s+/); target = norm(p[3] || ''); }
        var label = null;
        for (var i = 0; i < def[2].length; i++) if (def[2][i][0].test(target)) { label = def[2][i][1]; break; }
        return { name: name, type: def[1], data: data, target: target, service: label };
      });
    }).then(function (res) {
      out.records = res.filter(Boolean);
      out.found = uniq(out.records.map(function (r) { return r.service; }).filter(Boolean));
      if (out.records.some(function (r) { return /_ldap\._tcp|_kerberos\._tcp/.test(r.name); })) ctx.findings.push(F('low', 'Active Directory SRV records are published in public DNS', out.records.filter(function (r) { return /_ldap|_kerberos/.test(r.name); }).map(function (r) { return r.name + ' → ' + r.target; }).join(' · ') + '. Internal domain-controller names are visible to anyone.', 'Serve AD records only from internal resolvers (split-horizon DNS).'));
      if (out.found.length) ctx.findings.push(F('info', 'Products identified from service records', out.found.join(', '), ''));
      ctx.log('Service records: ' + out.records.length + ' present, ' + out.found.length + ' products identified');
    });
  }

  /* ------------------------------------------------------------------ */
  /* Module: Related domains (co-hosted, shared NS, shared certificates)  */
  /* ------------------------------------------------------------------ */
  function modRelated(ctx) {
    var d = ctx.apex, out = ctx.data.related = { reverseIp: {}, sharedNs: {}, skipped: [] };
    var hosting = ctx.data.hosting || {}, dns = ctx.data.dns || {};
    var tasks = [];
    var apexV4 = (hosting.ips || []).filter(function (i) { return i.primary && /^\d+\.\d+\.\d+\.\d+$/.test(i.ip) && !i.error; });
    var shared = function (i) { return CDN_ORGS.test((i.org || '') + ' ' + (i.isp || '')) || CLOUD_ORGS.test((i.org || '') + ' ' + (i.isp || '')); };
    var dedicated = apexV4.filter(function (i) { return !shared(i); }).slice(0, 2);
    if (!apexV4.length) out.skipped.push('reverse IP: no enriched IPv4 for the apex');
    else if (!dedicated.length) out.skipped.push('reverse IP: apex addresses belong to a CDN or cloud provider, where co-hosted domains are unrelated');
    dedicated.forEach(function (i) {
      tasks.push(getText('https://api.hackertarget.com/reverseiplookup/?q=' + encodeURIComponent(i.ip), 20000).then(function (txt) {
        if (/error|exceeded|no records/i.test(txt) && txt.split('\n').length < 3) throw new Error(txt.trim().slice(0, 60));
        out.reverseIp[i.ip] = txt.trim().split('\n').map(norm).filter(function (x) { return x && x !== d && !endsWithDomain(x, d); }).slice(0, 60);
        return 'Reverse IP ' + i.ip + ': ' + out.reverseIp[i.ip].length + ' other domains';
      }).catch(function (e) { out.skipped.push('reverse IP ' + i.ip + ': ' + e.message); return 'Reverse IP ' + i.ip + ' failed (' + e.message + ')'; }));
    });
    var NS = ((dns.records || {}).NS || []).map(function (a) { return norm(a.data); });
    var vanity = NS.filter(function (n) { return !fingerprint(n, NS_PROVIDERS); });
    if (NS.length && !vanity.length) out.skipped.push('shared NS: name servers belong to a public DNS provider, where sharing is meaningless');
    if (vanity.length) {
      var ns = vanity[0];
      tasks.push(getText('https://api.hackertarget.com/findshareddns/?q=' + encodeURIComponent(ns), 20000).then(function (txt) {
        if (/error|exceeded|no records/i.test(txt) && txt.split('\n').length < 3) throw new Error(txt.trim().slice(0, 60));
        out.sharedNs[ns] = txt.trim().split('\n').map(norm).filter(function (x) { return x && x !== d; }).slice(0, 60);
        return 'Shared NS ' + ns + ': ' + out.sharedNs[ns].length + ' other domains';
      }).catch(function (e) { out.skipped.push('shared NS: ' + e.message); return 'Shared NS lookup failed (' + e.message + ')'; }));
    }
    if (!tasks.length) ctx.log('Related domains: ' + out.skipped.join('; '));
    return Promise.all(tasks).then(function (msgs) {
      msgs.forEach(ctx.log);
      var inv = buildInventory();
      var rel = inv.related;
      if (rel.length) ctx.findings.push(F('info', plural(rel.length, 'related domain') + ' discovered', rel.slice(0, 12).map(function (r) { return r.domain + ' (' + r.relations[0] + ')'; }).join(', ') + (rel.length > 12 ? ' …' : ''), ''));
    });
  }

  /* ------------------------------------------------------------------ */
  /* Inventory: everything discovered, grouped by what it is             */
  /* ------------------------------------------------------------------ */
  var DKIM_PROVIDERS = [[/^google$/, 'Google Workspace'], [/^selector[12]$/, 'Microsoft 365'], [/^k[123]$/, 'Mailchimp'], [/^mandrill$/, 'Mandrill'], [/^mailjet$/, 'Mailjet'], [/^(mg|mailgun)$/, 'Mailgun'], [/^(sendgrid|sg\d?|s[12])$/, 'SendGrid'], [/^zendesk[12]$/, 'Zendesk'], [/^(zoho|zmail)$/, 'Zoho'], [/^protonmail\d?$|^pm$/, 'Proton Mail'], [/^(amazonses|ses)$/, 'Amazon SES'], [/^(hs[12]|hubspot)$/, 'HubSpot'], [/^cm$/, 'Campaign Monitor'], [/^fd\d?m?$/, 'Freshdesk'], [/^(klaviyo|kl\d?)$/, 'Klaviyo'], [/^(sparkpost|spop)$/, 'SparkPost'], [/^mimecast/, 'Mimecast'], [/^(salesforce|sf\d?)$/, 'Salesforce'], [/^(marketo|m1)$/, 'Marketo'], [/^(brevo|sib|sendinblue)$/, 'Brevo'], [/^(postmark|pm[12])$/, 'Postmark'], [/^everlytickey/, 'Everlytic'], [/^(mailerlite|ml)$/, 'MailerLite'], [/^(constantcontact|cc)$/, 'Constant Contact'], [/^(exacttarget|et)$/, 'Salesforce Marketing Cloud'], [/^eloqua$/, 'Oracle Eloqua'], [/^iterable$/, 'Iterable'], [/^(customerio|cio)$/, 'Customer.io'], [/^braze$/, 'Braze'], [/^intercom$/, 'Intercom'], [/^front$/, 'Front'], [/^helpscout$/, 'Help Scout'], [/^atlassian$/, 'Atlassian'], [/^shopify$/, 'Shopify'], [/^docusign$/, 'DocuSign'], [/^stripe$/, 'Stripe'], [/^okta$/, 'Okta'], [/^calendly$/, 'Calendly']];
  var DKIM_CNAME = [[/onmicrosoft\.com$/, 'Microsoft 365'], [/sendgrid\.net$/, 'SendGrid'], [/amazonses\.com$/, 'Amazon SES'], [/mailgun\.org$/, 'Mailgun'], [/mailchimp|mcsv\.net$/, 'Mailchimp'], [/mandrillapp/, 'Mandrill'], [/hubspot/, 'HubSpot'], [/zendesk/, 'Zendesk'], [/klaviyo/, 'Klaviyo'], [/sparkpost/, 'SparkPost'], [/mailjet/, 'Mailjet'], [/brevo|sendinblue/, 'Brevo'], [/postmarkapp|mtasv/, 'Postmark'], [/freshdesk|freshemail/, 'Freshdesk'], [/salesforce|exacttarget/, 'Salesforce'], [/marketo/, 'Marketo'], [/zoho/, 'Zoho'], [/mimecast/, 'Mimecast'], [/proofpoint|pphosted/, 'Proofpoint'], [/google/, 'Google Workspace'], [/mailerlite/, 'MailerLite'], [/customeriomail/, 'Customer.io'], [/intercom/, 'Intercom'], [/atlassian/, 'Atlassian']];
  var DMARC_VENDORS = [[/dmarcian/, 'dmarcian'], [/valimail/, 'Valimail'], [/agari/, 'Agari'], [/ondmarc|redsift/, 'Red Sift OnDMARC'], [/easydmarc/, 'EasyDMARC'], [/dmarcanalyzer|mimecast/, 'Mimecast DMARC Analyzer'], [/proofpoint/, 'Proofpoint'], [/uriports/, 'URIports'], [/mxtoolbox/, 'MXToolbox'], [/powerdmarc/, 'PowerDMARC'], [/sendmarc/, 'Sendmarc'], [/dmarcly/, 'DMARCLY'], [/fraudmarc/, 'Fraudmarc'], [/postmarkapp/, 'Postmark DMARC'], [/microsoft|office365/, 'Microsoft'], [/google/, 'Google'], [/kitterman/, 'Kitterman'], [/dmarcreport/, 'DMARC Report'], [/cloudflare/, 'Cloudflare DMARC Management']];

  function buildInventory() {
    var d = state.apex, data = state.data, dns = data.dns || {}, em = data.email || {}, rd = data.rdap || {}, sd = data.subdomains || {}, ce = data.certs || {}, ho = data.hosting || {}, ty = data.typosquat || {}, pr = data.probe || {}, sv = data.services || {}, re = data.related || {}, st = data.storage || {}, tk = data.takeover || {}, mx = data.mailx || {}, ex = data.expand || {};
    var hosts = Object.create(null), ips = Object.create(null), related = Object.create(null), services = Object.create(null), contacts = Object.create(null);
    function host(name, props, src) {
      name = norm(name); if (!name || !endsWithDomain(name, d)) return;
      var h = hosts[name] || (hosts[name] = { name: name, ips: [], cname: null, service: null, sources: [], status: null });
      if (props.ips) h.ips = uniq(h.ips.concat(props.ips));
      if (props.cname) h.cname = props.cname;
      if (props.service) h.service = props.service;
      if (props.status != null) h.status = props.status;
      if (src && h.sources.indexOf(src) === -1) h.sources.push(src);
    }
    function ip(addr, props, hostName) {
      var i = ips[addr] || (ips[addr] = { ip: addr, hosts: [] });
      Object.keys(props || {}).forEach(function (k) { if (props[k] != null && props[k] !== '' && i[k] == null) i[k] = props[k]; });
      if (hostName && i.hosts.indexOf(hostName) === -1) i.hosts.push(hostName);
    }
    function rel(domain, relation, evidence) {
      domain = norm(domain); if (!domain || domain === d || endsWithDomain(domain, d) || !/\./.test(domain)) return;
      var r = related[domain] || (related[domain] = { domain: domain, relations: [], evidence: [] });
      if (r.relations.indexOf(relation) === -1) r.relations.push(relation);
      if (evidence && r.evidence.indexOf(evidence) === -1 && r.evidence.length < 4) r.evidence.push(evidence);
    }
    function svc(name, category, evidence) {
      if (!name) return;
      var s = services[name] || (services[name] = { name: name, category: category, evidence: [] });
      if (evidence && s.evidence.indexOf(evidence) === -1 && s.evidence.length < 5) s.evidence.push(evidence);
    }
    function contact(addr, source) {
      addr = String(addr || '').replace(/^mailto:/i, '').trim().toLowerCase(); if (!addr || !/@/.test(addr)) return;
      var dom = addr.split('@')[1];
      var party = endsWithDomain(dom, d) ? 'domain owner' : (fingerprint(dom, [[/cloudflare/, 'Cloudflare (DNS provider)'], [/godaddy|secureserver/, 'GoDaddy (registrar)'], [/namecheap/, 'Namecheap (registrar)'], [/awsdns|amazon/, 'Amazon (DNS provider)'], [/google/, 'Google'], [/microsoft|outlook/, 'Microsoft'], [/gandi/, 'Gandi (registrar)'], [/ionos|1and1/, 'IONOS'], [/ovh/, 'OVH'], [/tucows|hover/, 'Tucows (registrar)'], [/markmonitor/, 'MarkMonitor (registrar)'], [/csc/, 'CSC (registrar)']]) || fingerprint(dom, DMARC_VENDORS) || fingerprint(dom, NS_PROVIDERS) || fingerprint(dom, MX_PROVIDERS) || (rd.registrar && new RegExp(rd.registrar.split(/[\s,.]/)[0], 'i').test(dom) ? rd.registrar : null) || 'third party');
      var c = contacts[addr] || (contacts[addr] = { address: addr, sources: [], party: party });
      if (c.sources.indexOf(source) === -1) c.sources.push(source);
    }

    /* hosts */
    if (dns.records) {
      host(state.domain, { ips: (dns.records.A || []).concat(dns.records.AAAA || []).map(function (a) { return a.data; }), cname: dns.records.CNAME && dns.records.CNAME[0] ? norm(dns.records.CNAME[0].data) : null, status: dns.nxdomain ? 3 : 0 }, 'dns');
      if (dns.www) host('www.' + state.domain, { ips: (dns.www.A || []).concat(dns.www.AAAA || []), cname: dns.www.CNAME && dns.www.CNAME.length ? norm(dns.www.CNAME[dns.www.CNAME.length - 1]) : null, service: dns.wwwService, status: dns.www.status }, 'dns');
      (dns.records.MX || []).forEach(function (a) { var h = norm(a.data.split(/\s+/)[1] || ''); if (h) host(h, {}, 'mx'); });
      (dns.records.NS || []).forEach(function (a) { host(norm(a.data), {}, 'ns'); });
    }
    (sd.resolved || []).forEach(function (x) { host(x.name, { ips: x.ips, cname: x.target, service: x.service, status: x.status }, null); x.sources.forEach(function (s) { host(x.name, {}, s); }); });
    Object.keys(sd.names || {}).forEach(function (n) { if (!hosts[n] && n !== d) { host(n, { status: null }, null); sd.names[n].sources.forEach(function (s) { host(n, {}, s); }); } });
    (pr.hits || []).forEach(function (x) { host(x.name, { ips: x.ips, cname: x.target, service: x.service, status: x.status }, 'dns-probe'); });
    (sv.records || []).forEach(function (r) { host(r.name, { status: 0 }, 'service-record'); if (r.target && endsWithDomain(r.target, d)) host(r.target, {}, 'srv-target'); });
    (em.dkim || []).forEach(function (k) { host(k.selector + '._domainkey.' + d, { cname: k.cname, status: 0 }, 'dkim'); });

    /* ips */
    (ho.ips || []).forEach(function (i) { if (!i.error) ip(i.ip, { ptr: i.ptr, asn: i.asn, org: i.org || i.isp, country: i.country, city: i.city, primary: i.primary }); else ip(i.ip, { error: i.error }); });
    Object.keys(hosts).forEach(function (n) { hosts[n].ips.forEach(function (a) { ip(a, {}, n); }); });

    /* networks */
    var nets = Object.create(null);
    Object.keys(ips).forEach(function (a) { var i = ips[a]; var key = i.asn ? 'AS' + i.asn : (i.org || 'unknown network'); var n = nets[key] || (nets[key] = { asn: key, org: i.org || '—', countries: [], ips: 0, hosts: [] }); n.ips++; if (i.country && n.countries.indexOf(i.country) === -1) n.countries.push(i.country); i.hosts.forEach(function (h) { if (n.hosts.indexOf(h) === -1) n.hosts.push(h); }); });

    /* related domains */
    (ce.certs || []).forEach(function (c) {
      var apexes = uniq(c.names.map(function (n) { return apexOf(n.replace(/^\*\./, '')); }));
      if (apexes.length < 2 || apexes.length > 6) return; /* single-domain cert, or a multi-tenant cert from shared hosting: no relationship implied */
      var mine = c.names.filter(function (n) { return endsWithDomain(n.replace(/^\*\./, ''), d); })[0];
      apexes.forEach(function (a) { if (a !== d) rel(a, 'shares a certificate', (mine || d) + ' · ' + c.issuer + ' · ' + fmtDate(c.notBefore)); });
    });
    (em.mx || []).forEach(function (m) { if (m.host && !endsWithDomain(m.host, d) && !fingerprint(m.host, MX_PROVIDERS)) rel(apexOf(m.host), 'mail exchanger', m.host); });
    ((dns.records || {}).NS || []).forEach(function (a) { var n = norm(a.data); if (!endsWithDomain(n, d) && !fingerprint(n, NS_PROVIDERS)) rel(apexOf(n), 'name server', n); });
    (em.spfTerms || []).forEach(function (t) { var m = t.match(/^[+\-~?]?(?:include|redirect)[:=](.+)$/i); if (m) { var n = norm(m[1]); if (!endsWithDomain(n, d) && !fingerprint(n, MX_PROVIDERS) && !/(_spf\.google|outlook|sendgrid|mailgun|mailchimp|mcsv|mandrill|amazonses|zoho|protonmail|hubspot|zendesk|salesforce|pphosted|mimecast|mailjet|brevo|sendinblue|klaviyo|postmark|sparkpost|freshdesk|atlassian|shopify|stripe|docusign|constantcontact|mailerlite|marketo|customer\.io|intercom|qualtrics|surveymonkey|workday|servicenow|smartsheet|gusto|bamboohr|greenhouse|lever|slack|notion|figma|github|gitlab|twilio|okta|duo)/i.test(n)) rel(apexOf(n), 'SPF include', t); } });
    if (em.dmarcTags) ['rua', 'ruf'].forEach(function (k) { (em.dmarcTags[k] || '').split(',').forEach(function (u) { var m = u.match(/@([a-z0-9.-]+)/i); if (m) { var dom = norm(m[1]); if (!endsWithDomain(dom, d) && !fingerprint(dom, DMARC_VENDORS)) rel(apexOf(dom), 'receives DMARC reports', k + '=' + u.trim()); } }); });
    Object.keys(re.reverseIp || {}).forEach(function (a) { re.reverseIp[a].forEach(function (x) { rel(apexOf(x), 'same IP address (co-hosted)', a); }); });
    Object.keys(re.sharedNs || {}).forEach(function (ns) { re.sharedNs[ns].forEach(function (x) { rel(apexOf(x), 'same name server', ns); }); });
    (ty.registered || []).forEach(function (c) { rel(c.domain, 'lookalike (' + c.kind + ')', (c.ips && c.ips.length ? 'resolves to ' + c.ips[0] : 'parked') + (c.mx ? ', has MX' : '')); });
    (ex.domains || []).forEach(function (x) { if (related[x.domain]) { related[x.domain].expanded = x; if (x.sharesInfra) { related[x.domain].relations.unshift('same network'); } } });

    /* services & vendors */
    if (dns.dnsProvider && dns.dnsProvider !== '—') svc(dns.dnsProvider.replace(/^Self-hosted.*$/, 'Self-hosted DNS'), 'DNS hosting', ((dns.records || {}).NS || []).map(function (a) { return norm(a.data); }).join(', '));
    if (rd.registrar) svc(rd.registrar, 'Registrar', 'RDAP');
    if (em.mailProvider && em.mailProvider !== '—') svc(em.mailProvider.replace(/^Self-hosted.*$/, 'Self-hosted mail'), 'Email hosting', (em.mx || []).map(function (m) { return m.host; }).filter(Boolean).join(', '));
    (em.spfSenders || []).forEach(function (s) { svc(s, 'Email sending (SPF)', 'SPF include'); });
    (em.dkim || []).forEach(function (k) { var p = (k.cname && fingerprint(k.cname, DKIM_CNAME)) || fingerprint(k.selector, DKIM_PROVIDERS); if (p) svc(p, 'Email sending (DKIM)', 'selector ' + k.selector + (k.cname ? ' → ' + k.cname : '')); });
    if (em.dmarcTags) (em.dmarcTags.rua || '').split(',').forEach(function (u) { var v = fingerprint(norm(u), DMARC_VENDORS); if (v) svc(v, 'Email security (DMARC reporting)', u.trim()); });
    (dns.saas || []).forEach(function (s) { svc(s, 'SaaS (domain verification)', 'TXT token at apex'); });
    Object.keys(hosts).forEach(function (n) { var h = hosts[n]; if (h.sources.length === 1 && h.sources[0] === 'dkim') return; if (h.service) svc(h.service, 'Hosting / SaaS (CNAME)', n + ' → ' + h.cname); else if (h.cname && !endsWithDomain(h.cname, d)) { var vend = fingerprint(h.cname, MX_PROVIDERS) || fingerprint(h.cname, NS_PROVIDERS) || fingerprint(h.cname, DKIM_CNAME) || apexOf(h.cname); svc(vend, 'Hosting / SaaS (CNAME)', n + ' → ' + h.cname); } });
    if (ho.cdn) svc(ho.cdn, 'CDN / WAF', 'apex addresses'); 
    Object.keys(nets).forEach(function (k) { var n = nets[k]; if (n.org && n.org !== '—' && !(ho.cdn && new RegExp(ho.cdn.split(',')[0].trim(), 'i').test(n.org))) svc(n.org, 'Infrastructure (' + k + ')', plural(n.ips, 'address') + ', ' + plural(n.hosts.length, 'host')); });
    (sv.records || []).forEach(function (r) { if (r.service) svc(r.service, 'Product (service record)', r.name + ' → ' + r.target); });
    (ce.issuers || []).forEach(function (i) { svc(i.replace(/\s*\(\d+\)$/, ''), 'Certificate authority', i.match(/\((\d+)\)$/) ? i.match(/\((\d+)\)$/)[1] + ' certificates' : ''); });
    (st.hits || []).forEach(function (b) { svc('Microsoft Azure', 'Cloud storage (account exists)', b.host); host(b.host, { status: 0 }, 'storage'); });
    /* Microsoft 365 / Google tenant names */
    var tenants = [];
    (em.dkim || []).forEach(function (k) { if (k.cname) { var m = k.cname.match(/([a-z0-9-]+)\.onmicrosoft\.com$/); if (m) tenants.push('Microsoft 365 tenant: ' + m[1]); var g = k.cname.match(/([a-z0-9-]+)\._domainkey\.([a-z0-9-]+)\.google/); } });
    (sv.records || []).forEach(function (r) { if (/enterpriseregistration/.test(r.name) && /windows\.net|microsoft/.test(r.target)) tenants.push('Microsoft Entra ID (device registration)'); });
    ((dns.saas) || []).forEach(function () {});
    uniq(tenants).forEach(function (t) { svc(t.split(':')[0], 'Identity tenant', t.indexOf(':') !== -1 ? t.split(': ')[1] : 'DNS records'); });
    (tk.delegated || []).forEach(function (z) { if (z.provider) svc(z.provider, 'Delegated subzone DNS', z.name); });
    (mx.spfNetworks || []).forEach(function (r) { svc('Own mail egress ' + r, 'Network (SPF ip4)', 'authorised sender range'); });
    (ex.domains || []).forEach(function (x) { if (x.org) svc(x.org, 'Related-domain hosting', x.domain + (x.sharesInfra ? ' (same network as target)' : '')); });
    if (data.archive && (data.archive.first || data.archive.last)) svc('Internet Archive', 'History', 'captures since ' + fmtTs((data.archive.first || data.archive.last).timestamp).slice(0, 4));

    /* contacts */
    if (dns.soa && dns.soa.hostmaster) contact(dns.soa.hostmaster, 'SOA record');
    if (em.dmarcTags) ['rua', 'ruf'].forEach(function (k) { (em.dmarcTags[k] || '').split(',').forEach(function (u) { if (/mailto:/i.test(u)) contact(u.replace(/!.*$/, ''), 'DMARC ' + k); }); });
    (em.tlsRpt || []).forEach(function (t) { (t.match(/mailto:[^;,\s]+/gi) || []).forEach(function (u) { contact(u, 'TLS-RPT'); }); });
    if (rd.abuse) contact(rd.abuse, 'registrar abuse (RDAP)');
    ((data.http || {}).securityContacts || []).forEach(function (c) { if (/@/.test(c)) contact(c, 'security.txt'); });
    ((dns.records || {}).CAA || []).forEach(function (c) { (c.data.match(/mailto:[^"\s]+/gi) || []).forEach(function (u) { contact(u, 'CAA iodef'); }); });

    var hostList = Object.keys(hosts).map(function (k) { return hosts[k]; }).sort(function (a, b) {
      var pa = a.name === state.domain ? 0 : a.name === 'www.' + state.domain ? 1 : 2, pb = b.name === state.domain ? 0 : b.name === 'www.' + state.domain ? 1 : 2;
      return pa - pb || (b.ips.length || b.cname ? 1 : 0) - (a.ips.length || a.cname ? 1 : 0) || a.name.localeCompare(b.name);
    });
    return {
      hosts: hostList,
      ips: Object.keys(ips).map(function (k) { return ips[k]; }).sort(function (a, b) { return (b.primary ? 1 : 0) - (a.primary ? 1 : 0) || b.hosts.length - a.hosts.length; }),
      networks: Object.keys(nets).map(function (k) { return nets[k]; }).sort(function (a, b) { return b.hosts.length - a.hosts.length; }),
      related: Object.keys(related).map(function (k) { return related[k]; }).sort(function (a, b) { return b.relations.length - a.relations.length || a.domain.localeCompare(b.domain); }),
      services: Object.keys(services).map(function (k) { return services[k]; }).sort(function (a, b) { return a.category.localeCompare(b.category) || a.name.localeCompare(b.name); }),
      contacts: Object.keys(contacts).map(function (k) { return contacts[k]; }),
      certs: ce.certs || []
    };
  }

  /* ------------------------------------------------------------------ */
  /* Module: Name-server intelligence (self-hosted DNS only)             */
  /* ------------------------------------------------------------------ */
  function modNsIntel(ctx) {
    var d = ctx.apex, out = ctx.data.nsintel = { servers: [] };
    var dns = ctx.data.dns || {};
    var NS = ((dns.records || {}).NS || []).map(function (a) { return norm(a.data); });
    var vanity = NS.filter(function (n) { return !fingerprint(n, NS_PROVIDERS); });
    if (!vanity.length) { ctx.log('Name-server intel skipped: DNS is on a managed provider'); out.managed = true; return Promise.resolve(); }
    ctx.log('Probing ' + vanity.length + ' self-hosted name server(s) for software banners and recursion');
    return pool(vanity, 4, function (ns) {
      return Promise.all([doh(ns, 'A', 6000), doh(ns, 'AAAA', 6000)]).then(function (r) {
        var ips = r[0].answers.filter(function (a) { return a.type === T.A; }).map(function (a) { return a.data; }).concat(r[1].answers.filter(function (a) { return a.type === T.AAAA; }).map(function (a) { return a.data; }));
        return { ns: ns, ips: ips, glue: ips.length > 0 };
      });
    }).then(function (servers) {
      out.servers = servers;
      var noGlue = servers.filter(function (s) { return !s.glue; });
      if (noGlue.length) ctx.findings.push(F('low', 'Self-hosted name server without an address record', noGlue.map(function (s) { return s.ns; }).join(', ') + '. A name server that does not itself resolve breaks delegation for resolvers that need glue.', 'Publish A/AAAA (and glue at the registrar) for every authoritative name server.'));
      var v4 = uniq([].concat.apply([], servers.map(function (s) { return s.ips; }))).filter(function (i) { return /^\d+\.\d+\.\d+\.\d+$/.test(i); });
      if (v4.length && v4.length < 2) ctx.findings.push(F('low', 'Authoritative DNS served from a single address', 'All self-hosted name servers resolve to ' + v4[0] + '. One host or subnet failing takes the whole zone offline.', 'Spread name servers across separate networks and providers.'));
      out.nsIps = v4;
      ctx.log('Name servers: ' + servers.length + ' self-hosted, ' + v4.length + ' distinct IPv4');
    });
  }

  /* ------------------------------------------------------------------ */
  /* Module: Cloud storage naming (DNS existence only, never fetched)     */
  /* ------------------------------------------------------------------ */
  function modStorage(ctx) {
    var d = ctx.apex, out = ctx.data.storage = { hits: [], candidates: [] };
    var org = d.split('.')[0];
    var labels = uniq([org, org + '-backup', org + '-backups', org + '-assets', org + '-static', org + '-media', org + '-files', org + '-data', org + '-uploads', org + '-public', org + '-private', org + '-prod', org + '-dev', org + '-staging', org + '-logs', org + '-cdn', org + '-images', org + '-docs', org + '-web', org + '-app']).filter(function (l) { return /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(l); });
    /* S3, GCS and DO Spaces wildcard-resolve every name, so DNS proves nothing: surface those as manual candidates.
       Azure Blob returns NXDOMAIN for a non-existent account, so DNS existence there is a real signal. */
    out.candidates = labels.map(function (l) { return { label: l, s3: 'https://' + l + '.s3.amazonaws.com/?list-type=2', gcs: 'https://storage.googleapis.com/' + l + '/', spaces: 'https://' + l + '.nyc3.digitaloceanspaces.com/' }; });
    var azure = labels.map(function (l) { return { account: l.replace(/[^a-z0-9]/g, ''), host: l.replace(/[^a-z0-9]/g, '') + '.blob.core.windows.net' }; }).filter(function (a) { return a.account.length >= 3 && a.account.length <= 24; });
    ctx.log('Checking ' + azure.length + ' Azure storage-account names (DNS); ' + labels.length + ' S3/GCS names listed as manual candidates');
    return pool(azure, 12, function (a) {
      return doh(a.host, 'A', 6000).then(function (r) { return (r.status === 0 && r.answers.length) ? a : null; });
    }).then(function (res) {
      out.hits = res.filter(Boolean);
      if (out.hits.length) ctx.findings.push(F('low', plural(out.hits.length, 'Azure storage account') + ' exist for this organisation', out.hits.map(function (h) { return h.host; }).join(', ') + '. An Azure blob account resolves in DNS only when it exists. Contents were not requested; a public container is a common leak source.', 'Confirm each account\'s containers block anonymous and public-list access.'));
      ctx.findings.push(F('info', labels.length + ' cloud-storage bucket names worth checking manually', 'S3, Google Cloud Storage and DigitalOcean Spaces resolve every name in DNS, so they cannot be confirmed passively. The Cloud storage section lists open-in-browser links for each candidate under ' + org + '.', ''));
      ctx.log('Cloud storage: ' + out.hits.length + ' Azure accounts exist, ' + labels.length + ' manual candidates');
    });
  }

  /* ------------------------------------------------------------------ */
  /* Module: Subdomain takeover verification (stage 2)                    */
  /* ------------------------------------------------------------------ */
  function modTakeover(ctx) {
    var d = ctx.apex, out = ctx.data.takeover = { checked: [], delegated: [] };
    var sd = ctx.data.subdomains || {};
    var probe = (sd.resolved || []).concat((ctx.data.probe || {}).hits || []);
    var dangling = probe.filter(function (x) { return x && x.target && (!x.ips || !x.ips.length); });
    var uniqTargets = {};
    dangling = dangling.filter(function (x) { var k = x.name; if (uniqTargets[k]) return false; uniqTargets[k] = 1; return true; });
    /* delegated subzones: hosts whose own NS set differs from the apex */
    var live = (sd.resolved || []).filter(function (x) { return x.ips && x.ips.length; });
    var deepHosts = uniq(live.map(function (x) { return x.name; })).filter(function (n) { return n.split('.').length > (d.split('.').length + 1) ? false : true; }).slice(0, 12);
    ctx.log('Verifying ' + dangling.length + ' dangling alias(es) and checking for delegated subzones');
    var tasks = dangling.slice(0, 25).map(function (x) {
      var t = x.target;
      return Promise.all([doh(t, 'NS', 6000), doh(t, 'SOA', 6000), doh(apexOf(t), 'NS', 6000)]).then(function (r) {
        var targetApex = apexOf(t);
        var apexRegistered = r[2].status === 0 && (r[2].answers.some(function (a) { return a.type === T.NS; }) || (r[2].authority || []).some(function (a) { return a.type === T.SOA; }));
        var verdict, sev;
        if (!apexRegistered && r[2].status === 3) { verdict = 'base domain ' + targetApex + ' is unregistered — anyone can register it and claim ' + x.name; sev = 'high'; }
        else if (x.service) { verdict = 'points at ' + x.service + ' but the specific resource is gone (NXDOMAIN); likely claimable on that platform'; sev = 'high'; }
        else { verdict = 'alias target does not resolve, but its base domain ' + targetApex + ' is registered; takeover depends on the provider'; sev = 'medium'; }
        return { name: x.name, target: t, service: x.service || null, verdict: verdict, severity: sev, targetApex: targetApex, apexRegistered: apexRegistered };
      });
    });
    var delTasks = deepHosts.map(function (n) {
      return doh(n, 'NS', 6000).then(function (r) {
        var ns = r.answers.filter(function (a) { return a.type === T.NS && norm(a.name) === n; }).map(function (a) { return norm(a.data); });
        if (!ns.length) return null;
        var apexNs = ((ctx.data.dns.records || {}).NS || []).map(function (a) { return norm(a.data); }).sort().join();
        if (ns.sort().join() === apexNs) return null;
        return { name: n, ns: ns, provider: uniq(ns.map(function (x) { return fingerprint(x, NS_PROVIDERS); }).filter(Boolean)).join(', ') };
      });
    });
    return Promise.all([Promise.all(tasks), Promise.all(delTasks)]).then(function (r) {
      out.checked = r[0].filter(Boolean);
      out.delegated = r[1].filter(Boolean);
      out.checked.forEach(function (v) { ctx.findings.push(F(v.severity, (v.severity === 'high' ? 'Likely takeover: ' : 'Possible takeover: ') + v.name, v.name + ' → ' + v.target + '. ' + v.verdict + '.', 'Confirm with SubdomainTKO (https://tko.marulecha.com/), then remove the record or reclaim the resource.')); });
      if (out.delegated.length) ctx.findings.push(F('info', plural(out.delegated.length, 'delegated subzone') + ' with their own name servers', out.delegated.map(function (z) { return z.name + ' (' + (z.provider || z.ns[0]) + ')'; }).join(', ') + '. Each is a separate administrative boundary, often a different team or a third party running part of the namespace.', ''));
      if (!out.checked.length && dangling.length) ctx.findings.push(F('ok', 'No confirmed takeovers among ' + dangling.length + ' dangling alias(es)', 'Every alias target still has a registered base domain.', ''));
      ctx.log('Takeover: ' + out.checked.filter(function (v) { return v.severity === 'high'; }).length + ' likely, ' + out.checked.length + ' total, ' + out.delegated.length + ' delegated zones');
    });
  }

  /* ------------------------------------------------------------------ */
  /* Module: Extra mail intelligence (stage 2)                            */
  /* ------------------------------------------------------------------ */
  var CT_DKIM_SELECTORS = ['selector1', 'selector2', 'google', 'default', 's1', 's2', 'k1', 'k2', 'k3', 'dkim', 'mail', 'smtp', 'mandrill', 'mailjet', 'mailgun', 'mg', 'sendgrid', 'sg', 'zendesk1', 'zendesk2', 'zoho', 'protonmail', 'protonmail2', 'protonmail3', 'amazonses', 'ses', 'hs1', 'hs2', 'cm', 'klaviyo', 'sparkpost', 'mimecast20180101', 'pic', 'sf', 'sf1', 'brevo', 'sib', 'postmark', 'everlytickey1', 'everlytickey2', 'ml', 'fd', 'fd2'];
  function modMailx(ctx) {
    var d = ctx.apex, out = ctx.data.mailx = { extraDkim: [], reportsFor: [], spfNetworks: [] };
    var em = ctx.data.email || {}, sd = ctx.data.subdomains || {};
    ctx.log('Extra mail intel: DKIM on discovered hosts, DMARC report authorisation, SPF network ranges');
    /* selectors that already showed up as _domainkey hostnames in CT logs */
    var ctSelectors = Object.keys(sd.names || {}).map(function (n) { var m = n.match(/^([^.]+)\._domainkey\./); return m ? m[1] : null; }).filter(Boolean);
    var known = {}; (em.dkim || []).forEach(function (k) { known[k.selector] = 1; });
    var toTry = uniq(ctSelectors.concat(CT_DKIM_SELECTORS)).filter(function (s) { return !known[s]; }).slice(0, 40);
    var tasks = [
      pool(toTry, 12, function (s) {
        return doh(s + '._domainkey.' + d, 'TXT', 6000).then(function (r) {
          var txt = r.answers.filter(function (a) { return a.type === T.TXT; }).map(function (a) { return a.data; }).join('');
          var cn = r.answers.filter(function (a) { return a.type === T.CNAME; }).map(function (a) { return norm(a.data); });
          if (!/v=DKIM1|k=|p=/i.test(txt) && !cn.length) return null;
          return { selector: s, cname: cn[0] || null, fromCt: ctSelectors.indexOf(s) !== -1 };
        });
      }),
      doh('_report._dmarc.' + d, 'TXT', 6000)
    ];
    return Promise.all(tasks).then(function (r) {
      out.extraDkim = r[0].filter(Boolean);
      if (out.extraDkim.length) { (em.dkim = em.dkim || []); out.extraDkim.forEach(function (k) { em.dkim.push({ selector: k.selector, cname: k.cname, bits: null, k: 'rsa' }); }); ctx.findings.push(F('info', plural(out.extraDkim.length, 'additional DKIM selector') + ' found', out.extraDkim.map(function (k) { return k.selector + (k.cname ? ' → ' + k.cname : ''); }).join(', ') + '. Each names a mail platform authorised to sign as the domain.', '')); }
      var rep = r[1].answers.filter(function (a) { return a.type === T.TXT; }).map(function (a) { return a.data; });
      if (rep.length) ctx.findings.push(F('info', 'Domain is authorised to receive DMARC reports for others', rep.join(' | ') + '. The _report._dmarc record lists external domains whose DMARC reports may be sent here, which usually means shared ownership or a monitoring relationship.', ''));
      /* SPF ip4 ranges as networks */
      var ranges = (em.spfTerms || []).map(function (t) { var m = t.match(/^[+\-~?]?ip4:(\d+\.\d+\.\d+\.\d+\/\d+)$/i); return m ? m[1] : null; }).filter(Boolean);
      out.spfNetworks = ranges;
      if (ranges.length) ctx.findings.push(F('info', plural(ranges.length, 'IPv4 range') + ' authorised to send mail (SPF)', ranges.join(', ') + '. These are the organisation\'s own mail egress ranges; useful for mapping infrastructure.', ''));
      ctx.log('Extra mail: ' + out.extraDkim.length + ' new DKIM, ' + ranges.length + ' SPF ranges');
    });
  }

  /* ------------------------------------------------------------------ */
  /* Module: Expand related domains (recursive, light)                    */
  /* ------------------------------------------------------------------ */
  function modExpand(ctx) {
    var out = ctx.data.expand = { domains: [] };
    if (state.enabled.expand === false) { out.skipped = true; return Promise.resolve(); }
    var inv = buildInventory();
    var apexes = uniq(inv.related.map(function (r) { return r.domain; }).filter(function (x) { return /\./.test(x) && x.split('.').length <= 4; })).slice(0, 8);
    if (!apexes.length) { ctx.log('Expand: no related domains to follow'); return Promise.resolve(); }
    ctx.log('Following ' + apexes.length + ' related domain(s): NS, A, MX and apex network');
    var myNets = {}; (ctx.data.hosting || {}).ips && ctx.data.hosting.ips.forEach(function (i) { if (i.asn) myNets['AS' + i.asn] = 1; });
    return pool(apexes, 4, function (dom) {
      return Promise.all([rr(dom, 'NS'), rr(dom, 'A'), rr(dom, 'MX')]).then(function (r) {
        var rec = { domain: dom, ns: r[0].map(norm), ips: r[1], mx: r[2].map(function (m) { return norm(m.split(/\s+/)[1] || ''); }).filter(Boolean), registered: r[0].length > 0 || r[1].length > 0 };
        rec.dnsProvider = uniq(rec.ns.map(function (n) { return fingerprint(n, NS_PROVIDERS); }).filter(Boolean)).join(', ');
        rec.mailProvider = uniq(rec.mx.map(function (m) { return fingerprint(m, MX_PROVIDERS); }).filter(Boolean)).join(', ');
        if (!rec.ips.length) return rec;
        return getJSON('https://get.geojs.io/v1/ip/geo/' + encodeURIComponent(rec.ips[0]) + '.json', {}, 7000).then(function (j) { rec.asn = j.asn ? 'AS' + j.asn : null; rec.org = j.organization_name || String(j.organization || '').replace(/^AS\d+\s+/, ''); rec.country = j.country_code; rec.sharesInfra = rec.asn && myNets[rec.asn] && !CDN_ORGS.test(rec.org || '') && !CLOUD_ORGS.test(rec.org || ''); return rec; }).catch(function () { return rec; });
      });
    }).then(function (res) {
      out.domains = res.filter(function (x) { return x && x.registered; });
      var shared = out.domains.filter(function (x) { return x.sharesInfra; });
      if (shared.length) ctx.findings.push(F('info', plural(shared.length, 'related domain') + ' share a dedicated network with the target', shared.map(function (x) { return x.domain + ' (' + x.asn + ' ' + (x.org || '') + ')'; }).join(', ') + '. Sharing a non-CDN network is strong evidence of common ownership.', ''));
      if (out.domains.length) ctx.findings.push(F('info', 'Expanded ' + plural(out.domains.length, 'related domain'), out.domains.map(function (x) { return x.domain + (x.org ? ' → ' + x.org : ''); }).slice(0, 10).join(', ') + '. Each was resolved one level deep; run a full discovery on any of them from the Related domains table.', ''));
      ctx.log('Expand: ' + out.domains.length + ' related domains resolved');
    });
  }

  /* ------------------------------------------------------------------ */
  /* Relationship graph (inline SVG, theme-aware, no dependencies)        */
  /* ------------------------------------------------------------------ */
  function buildGraph(inv) {
    var groups = [
      { key: 'networks', label: 'Networks', color: 'var(--cyan)', nodes: inv.networks.slice(0, 7).map(function (n) { return { id: n.asn, label: (n.org || n.asn).split(',')[0].slice(0, 16), title: n.asn + ' ' + n.org + ' · ' + plural(n.hosts.length, 'host') }; }) },
      { key: 'services', label: 'Services & vendors', color: 'var(--green)', nodes: inv.services.filter(function (s) { return !/Certificate authority|Network \(SPF/.test(s.category); }).slice(0, 9).map(function (s) { return { id: s.name, label: s.name.slice(0, 18), title: s.name + ' — ' + s.category }; }) },
      { key: 'related', label: 'Related domains', color: 'var(--pink)', nodes: inv.related.slice(0, 10).map(function (r) { return { id: r.domain, label: r.domain.length > 18 ? r.domain.slice(0, 17) + '…' : r.domain, title: r.domain + ' — ' + r.relations.join('; '), href: location.pathname + '?d=' + encodeURIComponent(r.domain) }; }) },
      { key: 'hosts', label: 'Key hostnames', color: 'var(--amber)', nodes: inv.hosts.filter(function (h) { return h.ips.length && h.name !== state.domain; }).slice(0, 9).map(function (h) { return { id: h.name, label: (h.name.slice(0, -(state.apex.length + 1)) || h.name).slice(0, 16), title: h.name + ' → ' + h.ips.join(', ') }; }) }
    ].filter(function (g) { return g.nodes.length; });
    return groups;
  }
  function renderGraph(inv) {
    var groups = buildGraph(inv);
    if (!groups.length) return '<div class="ds-empty">nothing to plot yet</div>';
    var W = 760, H = 620, cx = W / 2, cy = H / 2;
    var svg = ['<svg viewBox="0 0 ' + W + ' ' + H + '" class="ds-graph" role="img" aria-label="Relationship graph for ' + esc(state.apex) + '" preserveAspectRatio="xMidYMid meet">'];
    var edges = [], nodes = [], legend = [];
    var totalNodes = groups.reduce(function (s, g) { return s + g.nodes.length; }, 0);
    var pad = 0.10 * Math.PI * 2;                 /* gap between group wedges */
    var avail = Math.PI * 2 - pad * groups.length;
    var cursor = -Math.PI / 2 + pad / 2;          /* start at top */
    groups.forEach(function (g) {
      var wedge = avail * (g.nodes.length / totalNodes) + 0.0001;
      var n = g.nodes.length;
      g.nodes.forEach(function (node, i) {
        var frac = n === 1 ? 0.5 : i / (n - 1);
        var ang = cursor + wedge * frac;
        var tier = i % 3;                          /* stagger radius so labels do not collide */
        var r = 132 + tier * 52 + (n > 6 ? 0 : 10);
        var x = cx + Math.cos(ang) * r, y = cy + Math.sin(ang) * r;
        edges.push('<line x1="' + cx.toFixed(1) + '" y1="' + cy.toFixed(1) + '" x2="' + x.toFixed(1) + '" y2="' + y.toFixed(1) + '" stroke="' + g.color + '" stroke-opacity="0.20"/>');
        var right = Math.cos(ang) >= 0;
        var text = '<text x="' + (right ? 8 : -8) + '" y="3.5" text-anchor="' + (right ? 'start' : 'end') + '" class="ds-graph__t">' + esc(node.label) + '</text>';
        var g0 = '<g class="ds-graph__n" transform="translate(' + x.toFixed(1) + ',' + y.toFixed(1) + ')"><title>' + esc(node.title) + '</title><circle r="4.5" fill="' + g.color + '"/>' + text + '</g>';
        nodes.push(node.href ? '<a href="' + esc(node.href) + '">' + g0 + '</a>' : g0);
      });
      cursor += wedge + pad;
      legend.push('<span><i style="background:' + g.color + '"></i>' + esc(g.label) + ' (' + g.nodes.length + ')</span>');
    });
    svg.push('<g>' + edges.join('') + '</g>');
    svg.push('<g class="ds-graph__hub"><circle cx="' + cx + '" cy="' + cy + '" r="36" fill="var(--surface-solid)" stroke="var(--cyan)" stroke-width="1.5"/><text x="' + cx + '" y="' + (cy - 2) + '" text-anchor="middle" class="ds-graph__c">' + esc(state.apex.split('.')[0].slice(0, 12)) + '</text><text x="' + cx + '" y="' + (cy + 13) + '" text-anchor="middle" class="ds-graph__c dim">.' + esc(state.apex.split('.').slice(1).join('.')) + '</text></g>');
    svg.push(nodes.join(''));
    svg.push('</svg>');
    return '<div class="ds-graph-wrap">' + svg.join('') + '</div><div class="ds-graph__legend">' + legend.join('') + '</div><div class="ds-note">Center is the domain; each coloured wedge is one kind of discovered asset. Hover a node for detail; related-domain nodes open a new run.</div>';
  }

  /* ------------------------------------------------------------------ */
  /* Module: HTTP surface (via relay — touches the target, so ACTIVE)    */
  /* ------------------------------------------------------------------ */
  var TECH_HDRS = [
    ['server', 'Web server'], ['x-powered-by', 'Application platform'], ['x-aspnet-version', 'ASP.NET version'],
    ['x-aspnetmvc-version', 'ASP.NET MVC version'], ['x-generator', 'Generator'], ['x-drupal-cache', 'Drupal'],
    ['x-wix-request-id', 'Wix'], ['x-shopify-stage', 'Shopify'], ['x-github-request-id', 'GitHub Pages'],
    ['x-vercel-id', 'Vercel'], ['x-served-by', 'Fastly/Varnish'], ['x-amz-cf-id', 'AWS CloudFront'],
    ['cf-ray', 'Cloudflare'], ['x-litespeed-cache', 'LiteSpeed'], ['x-nginx', 'nginx'], ['via', 'Proxy/CDN']
  ];
  function modHttp(ctx) {
    var d = ctx.apex, out = ctx.data.http = {};
    if (!proxyOn()) { out.skipped = 'relay not configured'; ctx.log('HTTP surface skipped: no relay configured'); return Promise.resolve(); }
    ctx.log('HTTP surface via relay (ACTIVE — this touches ' + d + '): headers, security.txt, robots.txt');
    return Promise.all([
      relaySite(d, '/').catch(function (e) { return { ok: false, error: e.message }; }),
      relaySite(d, '/.well-known/security.txt').catch(function (e) { return { ok: false, error: e.message }; }),
      relaySite(d, '/robots.txt').catch(function (e) { return { ok: false, error: e.message }; })
    ]).then(function (r) {
      var root = r[0], sec = r[1], rob = r[2];
      if (!root || root.ok === false || !root.headers) {
        ctx.findings.push(F('info', 'Could not fetch ' + d + ' over HTTPS through the relay', (root && (root.error || ('HTTP ' + root.status))) || 'no response', ''));
        ctx.log('HTTP: root fetch failed'); return;
      }
      var h = root.headers; out.status = root.status; out.finalUrl = root.finalUrl; out.headers = h;
      function has(n) { return h[n] != null; }
      /* HSTS */
      if (has('strict-transport-security')) {
        var m = /max-age=(\d+)/i.exec(h['strict-transport-security']); var age = m ? +m[1] : 0;
        if (age < 15552000) ctx.findings.push(F('low', 'HSTS max-age is short (' + age + 's)', 'RFC recommends at least 15552000 (180 days). A short max-age weakens protection against SSL-stripping.', 'Raise max-age; add includeSubDomains and preload once confident.'));
        else ctx.findings.push(F('ok', 'HSTS enabled', h['strict-transport-security'], ''));
      } else ctx.findings.push(F('medium', 'No HSTS header', 'Without Strict-Transport-Security, a first-visit or typed-URL request can be downgraded to HTTP and intercepted.', 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains.'));
      /* CSP */
      if (!has('content-security-policy')) ctx.findings.push(F('low', 'No Content-Security-Policy', 'CSP is the main defence-in-depth against XSS and data injection. Its absence is common but worth noting.', 'Add a Content-Security-Policy header scoped to the app.'));
      else ctx.findings.push(F('ok', 'Content-Security-Policy present', String(h['content-security-policy']).slice(0, 160) + (h['content-security-policy'].length > 160 ? '…' : ''), ''));
      /* clickjacking */
      var xfo = has('x-frame-options'), fa = /frame-ancestors/i.test(h['content-security-policy'] || '');
      if (!xfo && !fa) ctx.findings.push(F('low', 'No clickjacking protection', 'Neither X-Frame-Options nor CSP frame-ancestors is set, so the page can be framed by any site.', 'Add X-Frame-Options: DENY or CSP frame-ancestors none.'));
      /* nosniff / referrer / permissions */
      if (!has('x-content-type-options')) ctx.findings.push(F('info', 'No X-Content-Type-Options: nosniff', 'Browsers may MIME-sniff responses, occasionally turning uploads into executable content.', 'Add X-Content-Type-Options: nosniff.'));
      if (!has('referrer-policy')) ctx.findings.push(F('info', 'No Referrer-Policy header', 'Full URLs may leak to third parties via the Referer header.', 'Add Referrer-Policy: strict-origin-when-cross-origin.'));
      /* banners / fingerprint */
      var tech = [];
      TECH_HDRS.forEach(function (t) { if (has(t[0])) tech.push(t[1] + ': ' + h[t[0]]); });
      out.tech = tech;
      var versiony = tech.filter(function (t) { return /\d+\.\d+/.test(t) || /aspnet|php\/|apache\/|nginx\/|iis\//i.test(t); });
      if (versiony.length) ctx.findings.push(F('low', 'Version information disclosed in HTTP headers', versiony.join(' · ') + '. Precise versions let an attacker match known CVEs to the stack.', 'Suppress version banners (server_tokens off, remove X-Powered-By / X-AspNet-Version).'));
      else if (tech.length) ctx.findings.push(F('info', 'Technology identified from HTTP headers', tech.join(' · '), ''));
      /* cookies */
      var sc = h['set-cookie'];
      if (sc) { var bad = []; if (!/;\s*secure/i.test(sc)) bad.push('missing Secure'); if (!/;\s*httponly/i.test(sc)) bad.push('missing HttpOnly'); if (!/;\s*samesite/i.test(sc)) bad.push('missing SameSite');
        if (bad.length) ctx.findings.push(F('low', 'Cookie set without hardening flags', bad.join(', ') + ' on a Set-Cookie from the home page.', 'Set Secure, HttpOnly and SameSite on session cookies.')); }
      /* https redirect */
      if (out.finalUrl && out.finalUrl.indexOf('https://') !== 0) ctx.findings.push(F('medium', 'Home page did not end on HTTPS', 'Final URL was ' + out.finalUrl + '.', 'Redirect all HTTP to HTTPS and enable HSTS.'));
      /* security.txt */
      if (sec && sec.ok !== false && sec.status === 200 && /contact:/i.test(sec.body || '')) {
        out.securityTxt = sec.body;
        var contacts = (sec.body.match(/^Contact:\s*(.+)$/gim) || []).map(function (l) { return l.replace(/^Contact:\s*/i, '').trim(); });
        var exp = (sec.body.match(/^Expires:\s*(.+)$/im) || [])[1];
        ctx.findings.push(F('ok', 'security.txt published', 'Contacts: ' + contacts.join(', ') + (exp ? ' · expires ' + exp.trim() : ''), ''));
        out.securityContacts = contacts;
        if (exp && new Date(exp) < Date.now()) ctx.findings.push(F('low', 'security.txt has expired', 'Expires ' + exp.trim() + '. An expired policy signals it is unmaintained.', 'Update the Expires field.'));
      } else ctx.findings.push(F('info', 'No security.txt', 'RFC 9116 security.txt gives researchers a disclosure contact. Absent here.', 'Publish /.well-known/security.txt with a Contact and Expires field.'));
      /* robots.txt */
      if (rob && rob.ok !== false && rob.status === 200 && /(dis)?allow:/i.test(rob.body || '')) {
        var dis = (rob.body.match(/^Disallow:\s*(\S+)/gim) || []).map(function (l) { return l.replace(/^Disallow:\s*/i, '').trim(); }).filter(function (x) { return x && x !== '/'; });
        out.robotsDisallow = uniq(dis);
        var juicy = out.robotsDisallow.filter(function (p2) { return /admin|login|internal|private|backup|config|api|test|dev|staging|upload|cgi|wp-admin|\.git|secret|token|beta/i.test(p2); });
        if (juicy.length) ctx.findings.push(F('info', 'robots.txt hides interesting paths', juicy.slice(0, 15).join(', ') + (juicy.length > 15 ? ' …' : '') + '. Disallow entries advertise exactly the paths worth looking at.', ''));
        else if (out.robotsDisallow.length) ctx.findings.push(F('info', 'robots.txt lists ' + out.robotsDisallow.length + ' disallowed paths', out.robotsDisallow.slice(0, 12).join(', '), ''));
      }
      ctx.log('HTTP: status ' + out.status + ', ' + tech.length + ' tech header(s)' + (out.securityTxt ? ', security.txt ✓' : ''));
    });
  }

  /* ------------------------------------------------------------------ */
  /* Module: Archived URLs (via relay — Wayback CDX, passive)            */
  /* ------------------------------------------------------------------ */
  function modWaybackUrls(ctx) {
    var d = ctx.apex, out = ctx.data.wayback = { urls: [], sensitive: [] };
    if (!proxyOn()) { out.skipped = 'relay not configured'; ctx.log('Archived URLs skipped: no relay configured'); return Promise.resolve(); }
    ctx.log('Fetching archived URL history from the Wayback CDX index via relay');
    var cdx = 'https://web.archive.org/cdx/search/cdx?url=' + encodeURIComponent(d) + '/*&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit=1000';
    return relayData(cdx).then(function (r) {
      if (!r || r.ok === false || !r.body) { ctx.findings.push(F('info', 'Wayback CDX unavailable via relay', (r && (r.error || ('HTTP ' + r.status))) || 'no response', '')); return; }
      var rows;
      try { rows = JSON.parse(r.body); } catch (e) { ctx.findings.push(F('info', 'Wayback returned no parseable URL index', '', '')); return; }
      if (!Array.isArray(rows) || rows.length < 2) { ctx.findings.push(F('info', 'No archived URLs found', 'The CDX index is empty for ' + d + '.', '')); return; }
      var body = rows.slice(1).map(function (x) { return { url: x[0], ts: x[1], status: x[2], mime: x[3] }; });
      out.urls = body; out.total = body.length + (r.truncated ? '+' : '');
      var SENS = /\.(env|git|sql|bak|old|backup|config|conf|ini|log|zip|tar|gz|json|xml|yml|yaml|pem|key|p12|pfx|sql\.gz)(\?|$)|\/(admin|login|signin|wp-admin|phpmyadmin|api|graphql|actuator|\.git|backup|config|upload|internal|debug|test|staging|dev|swagger|cgi-bin)/i;
      var sens = uniq(body.filter(function (u) { return SENS.test(u.url); }).map(function (u) { return u.url.replace(/^https?:\/\//, ''); }));
      out.sensitive = sens;
      var docs = uniq(body.filter(function (u) { return /\.(pdf|docx?|xlsx?|pptx?|csv)(\?|$)/i.test(u.url); }).map(function (u) { return u.url.replace(/^https?:\/\//, ''); }));
      out.docs = docs;
      ctx.findings.push(F('info', out.total + ' archived URLs recovered', body.length + ' unique paths from the Wayback Machine. Historic URLs reveal endpoints, parameters and files that may still exist or hint at structure.', ''));
      if (sens.length) ctx.findings.push(F('medium', plural(sens.length, 'sensitive archived path'), sens.slice(0, 20).join('\n').slice(0, 600) + (sens.length > 20 ? ' …' : '') + '. These paths were once reachable; confirm they are gone, not just unlinked.', 'Check each still returns 404/401 today and that no backup or config file is served.'));
      if (docs.length) ctx.findings.push(F('info', plural(docs.length, 'archived document'), docs.slice(0, 12).join(', ') + (docs.length > 12 ? ' …' : '') + '. Old documents can carry metadata (authors, software, internal paths).', ''));
      ctx.log('Archived URLs: ' + body.length + ' paths, ' + sens.length + ' sensitive');
    }).catch(function (e) { ctx.findings.push(F('info', 'Wayback CDX failed', e.message, '')); });
  }

  /* ------------------------------------------------------------------ */
  /* Orchestration                                                        */
  /* ------------------------------------------------------------------ */
  var MODULES = [
    { id: 'dns', label: 'DNS records', stage: 0, locked: true, run: modDns, hint: 'apex + www records, DNSSEC, wildcard, TXT tokens' },
    { id: 'email', label: 'Email setup', stage: 1, run: modEmail, hint: 'SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI' },
    { id: 'rdap', label: 'Registration', stage: 1, run: modRdap, hint: 'RDAP: registrar, dates, status, registry NS' },
    { id: 'subdomains', label: 'Certificate logs', stage: 1, run: modSubdomains, hint: 'crt.sh, Certspotter, HackerTarget hostnames' },
    { id: 'probe', label: 'Hostname probe', stage: 1, run: modProbe, hint: '~170 well-known names resolved via DoH' },
    { id: 'services', label: 'Service records', stage: 1, run: modServices, hint: 'SRV and well-known names → products' },
    { id: 'nsintel', label: 'Name servers', stage: 1, run: modNsIntel, hint: 'self-hosted DNS: glue, redundancy' },
    { id: 'storage', label: 'Cloud storage', stage: 1, run: modStorage, hint: '~80 bucket names probed via DoH' },
    { id: 'archive', label: 'Web archive', stage: 1, run: modArchive, hint: 'Wayback first / latest capture' },
    { id: 'certs', label: 'Certificates', stage: 2, run: modCerts, hint: 'timeline, issuers, shared SANs' },
    { id: 'hosting', label: 'Addresses', stage: 2, run: modHosting, hint: 'ASN, geo, reverse DNS, CDN' },
    { id: 'mailx', label: 'Mail intel', stage: 2, run: modMailx, hint: 'extra DKIM, report auth, SPF ranges' },
    { id: 'takeover', label: 'Takeover check', stage: 2, run: modTakeover, hint: 'dangling aliases + delegated subzones' },
    { id: 'typosquat', label: 'Lookalikes', stage: 2, run: modTyposquat, hint: '~130 permutations incl. IDN homographs' },
    { id: 'waybackurls', label: 'Archived URLs', stage: 2, run: modWaybackUrls, proxy: true, hint: 'Wayback CDX full URL history (via relay)' },
    { id: 'http', label: 'HTTP surface', stage: 2, run: modHttp, proxy: true, active: true, def: false, hint: 'headers, security.txt, robots.txt (via relay — ACTIVE)' },
    { id: 'related', label: 'Related domains', stage: 3, run: modRelated, hint: 'co-hosted, shared NS, shared certificates' },
    { id: 'expand', label: 'Expand related', stage: 4, run: modExpand, hint: 'resolve related domains one level deep' },
    { id: 'pivot', label: 'Pivot links', stage: 3, run: modPivot, hint: 'manual follow-ups in other tools' }
  ].filter(function (m) { return !m.proxy || proxyOn(); });
  var SECTIONS = [
    { id: 'overview', label: 'Overview' }, { id: 'graph', label: 'Relationship graph' }, { id: 'hosts', label: 'Hostnames' }, { id: 'ips', label: 'Addresses & networks' }, { id: 'related', label: 'Related domains' },
    { id: 'services', label: 'Services & vendors' }, { id: 'contacts', label: 'Contact addresses' }, { id: 'certs', label: 'Certificates' }, { id: 'http', label: 'HTTP surface', proxy: true }, { id: 'urls', label: 'Archived URLs', proxy: true }, { id: 'email', label: 'Email setup' },
    { id: 'registration', label: 'Registration' }, { id: 'history', label: 'History' }, { id: 'observations', label: 'Observations' }, { id: 'pivot', label: 'Pivot links' }
  ].filter(function (x) { return !x.proxy || proxyOn(); });

  var state = { domain: null, apex: null, running: false, started: 0, results: {}, data: {}, shared: {}, enabled: {}, inventory: null };
  var UI = { stat: function () { var q = $('#stat-queries'); if (q) q.textContent = STATS.queries; } };

  function log(msg) {
    var el = $('#log'); if (!el) return;
    var t = ((Date.now() - state.started) / 1000).toFixed(1);
    var line = document.createElement('div');
    line.className = 'tline';
    line.innerHTML = '<time>+' + esc(t) + 's</time><span class="out">' + esc(msg) + '</span>';
    var cur = el.querySelector('.tline.is-cursor'); if (cur) cur.remove();
    el.appendChild(line);
    while (el.children.length > 250) el.removeChild(el.firstChild);
    var c = document.createElement('div'); c.className = 'tline is-cursor'; c.innerHTML = '<span class="p">kali@kali<i>:~</i>$</span> <span class="tcursor" aria-hidden="true"></span>';
    el.appendChild(c);
    el.scrollTop = el.scrollHeight;
  }

  function allFindings() {
    var out = [];
    MODULES.forEach(function (m) { var r = state.results[m.id]; if (r && r.findings) r.findings.forEach(function (f) { out.push(Object.assign({ module: m.id, moduleLabel: m.label }, f)); }); });
    return out.sort(function (a, b) { return SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity); });
  }

  /* ---------------- rendering helpers ---------------- */
  var CHEV = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>';
  function sevChip(s) { return '<span class="sev sev--' + s + '">' + s + '</span>'; }
  function linkify(s) { return s.replace(/(https?:\/\/[^\s)]+)/g, function (u) { return '<a href="' + u + '" target="_blank" rel="noopener noreferrer">' + u + '</a>'; }); }
  function renderFinding(f) {
    var hasBody = f.detail || f.fix;
    var open = SEV[f.severity] >= 15 ? ' open' : '';
    if (!hasBody) return '<div class="ds-f" data-sev="' + f.severity + '"><div class="ds-f__row">' + sevChip(f.severity) + '<span class="ds-f__title">' + esc(f.title) + '</span><span class="ds-f__mod">' + esc(f.moduleLabel || '') + '</span></div></div>';
    return '<details class="ds-f" data-sev="' + f.severity + '"' + open + '><summary>' + sevChip(f.severity) + '<span class="ds-f__title">' + esc(f.title) + '</span><span class="ds-f__mod">' + esc(f.moduleLabel || '') + '</span><span class="finding__chev">' + CHEV + '</span></summary>' +
      '<div class="ds-f__body">' + (f.detail ? '<p>' + linkify(esc(f.detail)) + '</p>' : '') + (f.fix ? '<p class="ds-f__fix"><b>Fix</b>' + linkify(esc(f.fix)) + '</p>' : '') + '</div></details>';
  }
  function table(cols, rows, opts) {
    if (!rows.length) return '<div class="ds-empty">' + esc((opts && opts.empty) || 'nothing discovered') + '</div>';
    return '<div class="ds-table-wrap"><table class="ds-table"' + (opts && opts.filterable ? ' data-filterable' : '') + '><thead><tr>' + cols.map(function (c) { return '<th>' + esc(c) + '</th>'; }).join('') + '</tr></thead><tbody>' +
      rows.map(function (r) { return '<tr>' + r.map(function (c, i) { return '<td' + (i === 0 ? ' class="k"' : '') + '>' + (c == null || c === '' ? '<span class="dim">—</span>' : c) + '</td>'; }).join('') + '</tr>'; }).join('') + '</tbody></table></div>';
  }
  function kv(rows) { return table(['field', 'value'], rows.map(function (r) { return [esc(r[0]), r[1] == null || r[1] === '' ? null : r[1]]; })); }
  function ext(url, text) { return '<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + esc(text || url) + '</a>'; }
  function okbad(v, okText, badText) { return v ? '<span class="ok">' + esc(okText) + '</span>' : '<span class="bad">' + esc(badText) + '</span>'; }
  function facts(items) { return '<dl class="ds-glance">' + items.filter(function (i) { return i[1] != null && i[1] !== ''; }).map(function (i) { return '<div><dt>' + esc(i[0]) + '</dt><dd>' + i[1] + '</dd></div>'; }).join('') + '</dl>'; }
  function srcChip(s) { return '<span class="ds-src">' + esc(s) + '</span>'; }

  /* ---------------- sections ---------------- */
  var SECTION_RENDER = {
    graph: function (inv) { return renderGraph(inv); },
    http: function () {
      var o = state.data.http; if (!o) return '<div class="ds-empty">not run</div>';
      if (o.skipped) return '<div class="ds-empty">' + esc(o.skipped) + '</div>';
      if (!o.headers) return '<div class="ds-empty">the home page could not be fetched over the relay</div>';
      var order = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy', 'server', 'x-powered-by', 'set-cookie'];
      var rows = order.filter(function (k) { return o.headers[k] != null; }).map(function (k) { return [esc(k), esc(String(o.headers[k]).slice(0, 200))]; });
      var extra = Object.keys(o.headers).filter(function (k) { return order.indexOf(k) === -1; }).sort().map(function (k) { return [esc(k), esc(String(o.headers[k]).slice(0, 200))]; });
      return facts([['Final URL', o.finalUrl ? ext(o.finalUrl, o.finalUrl) : null], ['Status', esc(String(o.status))], ['Technology', o.tech && o.tech.length ? esc(o.tech.join(' · ')) : null], ['security.txt', o.securityTxt ? '<span class="ok">present</span>' : '<span class="dim">absent</span>'], ['robots Disallow', o.robotsDisallow ? o.robotsDisallow.length : null]]) + table(['security header', 'value'], rows, { empty: 'no security headers set' }) + (extra.length ? '<details class="ds-raw"><summary><span>all response headers</span></summary>' + table(['header', 'value'], extra) + '</details>' : '');
    },
    urls: function () {
      var o = state.data.wayback; if (!o) return '<div class="ds-empty">not run</div>';
      if (o.skipped) return '<div class="ds-empty">' + esc(o.skipped) + '</div>';
      if (!o.urls || !o.urls.length) return '<div class="ds-empty">no archived URLs recovered</div>';
      var rows = o.urls.slice(0, 300).map(function (u) { return [esc(u.url.replace(/^https?:\/\//, '')), esc(u.status), esc(u.mime), esc(fmtTs(u.ts))]; });
      return facts([['Archived URLs', esc(String(o.total))], ['Sensitive paths', o.sensitive ? o.sensitive.length : 0], ['Documents', o.docs ? o.docs.length : 0]]) + table(['path', 'code', 'type', 'last seen'], rows, { filterable: true }) + (o.urls.length > 300 ? '<div class="ds-note">showing 300 of ' + o.urls.length + '</div>' : '');
    },
    overview: function (inv) {
      var d = state.data, dns = d.dns || {}, em = d.email || {}, rd = d.rdap || {}, ho = d.hosting || {}, ce = d.certs || {}, ar = d.archive || {};
      return facts([
        ['Domain', esc(state.domain) + (state.apex !== state.domain ? ' <span class="dim">(apex ' + esc(state.apex) + ')</span>' : '')],
        ['Registrar', rd.registrar ? esc(rd.registrar) : rd.unavailable ? '<span class="dim">no RDAP for this TLD</span>' : null],
        ['Registered', rd.registered ? esc(fmtDate(rd.registered)) : null], ['Expires', rd.expires ? esc(fmtDate(rd.expires)) + ' <span class="dim">(' + daysUntil(rd.expires) + 'd)</span>' : null],
        ['DNS hosting', dns.dnsProvider ? esc(dns.dnsProvider) : null], ['DNSSEC', dns.records ? (dns.dnssec ? '<span class="ok">validated</span>' : '<span class="dim">off</span>') : null],
        ['Mail hosting', em.mailProvider ? esc(em.mailProvider) : null], ['SPF · DMARC · DKIM', em.spf ? (em.spf.length ? 'SPF' : '<span class="dim">no SPF</span>') + ' · ' + (em.dmarcTags ? 'DMARC p=' + esc(em.dmarcTags.p || '?') : '<span class="dim">no DMARC</span>') + ' · ' + (em.dkim && em.dkim.length ? plural(em.dkim.length, 'DKIM selector') : '<span class="dim">no DKIM found</span>') : null],
        ['Web hosting', ho.cdn ? 'behind ' + esc(ho.cdn) : ho.summary ? esc(ho.summary) : null],
        ['Hostnames', inv.hosts.length ? inv.hosts.length + ' <span class="dim">(' + inv.hosts.filter(function (h) { return h.ips.length; }).length + ' resolve)</span>' : null],
        ['Addresses · networks', inv.ips.length ? inv.ips.length + ' · ' + inv.networks.length : null],
        ['Related domains', inv.related.length || null], ['Services & vendors', inv.services.length || null], ['Contact addresses', inv.contacts.length || null],
        ['Certificates', ce.total != null ? ce.active + ' valid <span class="dim">of ' + ce.total + ' logged</span>' : null],
        ['Archived since', ar.first ? esc(fmtTs(ar.first.timestamp).slice(0, 4)) + ' <span class="dim">(latest ' + esc(fmtTs((ar.last || ar.first).timestamp)) + ')</span>' : ar.error ? '<span class="dim">archive throttled</span>' : null],
        ['Wildcard DNS', dns.wildcard ? '<span class="bad">yes</span>' : null]
      ]);
    },
    hosts: function (inv) {
      var d = state.apex;
      return table(['hostname', 'resolves to', 'alias / service', 'found via'], inv.hosts.map(function (h) {
        var recordOnly = h.sources.length && h.sources.every(function (x) { return ['dkim', 'service-record', 'srv-target', 'mx', 'ns'].indexOf(x) !== -1; });
        var res = h.ips.length ? esc(h.ips.join(', ')) : recordOnly ? '<span class="dim">record only (not a web host)</span>' : h.cname ? '<span class="bad">alias target does not resolve</span>' : h.status === 3 ? '<span class="dim">NXDOMAIN (stale)</span>' : h.status === null ? '<span class="dim">not resolved</span>' : '<span class="dim">no address</span>';
        var alias = h.cname ? esc(h.cname) + (h.service ? ' <span class="ok">' + esc(h.service) + '</span>' : '') : (h.service ? '<span class="ok">' + esc(h.service) + '</span>' : null);
        return ['<b>' + esc(h.name.slice(0, -(d.length + 1)) || '@') + '</b><span class="dim">.' + esc(d) + '</span>', res, alias, h.sources.map(srcChip).join('')];
      }), { filterable: true, empty: 'no hostnames discovered yet' });
    },
    ips: function (inv) {
      var nets = table(['network', 'organisation', 'country', 'addresses', 'hosts'], inv.networks.map(function (n) { return [esc(n.asn), esc(n.org), esc(n.countries.join(', ')), n.ips, n.hosts.length ? n.hosts.slice(0, 4).map(esc).join('<br>') + (n.hosts.length > 4 ? '<br><span class="dim">+' + (n.hosts.length - 4) + ' more</span>' : '') : null]; }), { empty: 'no networks identified' });
      var ips = table(['address', 'reverse dns', 'network', 'location', 'used by'], inv.ips.map(function (i) { return [esc(i.ip) + (i.primary ? ' <span class="ok">apex</span>' : ''), esc(i.ptr), i.error ? '<span class="bad">' + esc(i.error) + '</span>' : i.asn ? esc('AS' + i.asn + ' ' + (i.org || '')) : '<span class="dim">not enriched</span>', esc([i.city, i.country].filter(Boolean).join(', ')), i.hosts.slice(0, 4).map(esc).join('<br>') + (i.hosts.length > 4 ? '<br><span class="dim">+' + (i.hosts.length - 4) + ' more</span>' : '')]; }), { filterable: true, empty: 'no addresses discovered yet' });
      return nets + ips;
    },
    related: function (inv) {
      var re = state.data.related || {};
      var note = re.skipped && re.skipped.length ? '<div class="ds-note">' + re.skipped.map(esc).join(' · ') + '</div>' : '';
      return table(['domain', 'relationship', 'evidence / hosting', 'lookup'], inv.related.map(function (r) { var ev = r.evidence.map(esc); if (r.expanded && r.expanded.org) ev.unshift('<span class="ok">hosted at ' + esc(r.expanded.org) + (r.expanded.sharesInfra ? ' — same network' : '') + '</span>'); return ['<b>' + esc(r.domain) + '</b>', r.relations.map(function (x) { return '<span class="ds-src">' + esc(x) + '</span>'; }).join(''), ev.join('<br>'), ext('https://rdap.org/domain/' + encodeURIComponent(r.domain), 'RDAP') + ' · ' + ext('https://who.is/whois/' + encodeURIComponent(r.domain), 'WHOIS') + ' · ' + ext(location.pathname + '?d=' + encodeURIComponent(r.domain), 'recon')]; }), { filterable: true, empty: 'no related domains found in certificates, DNS or hosting data' }) + note;
    },
    services: function (inv) {
      return table(['service / vendor', 'role', 'evidence'], inv.services.map(function (s) { return ['<b>' + esc(s.name) + '</b>', esc(s.category), s.evidence.map(esc).join('<br>')]; }), { filterable: true, empty: 'no third-party services identified' });
    },
    contacts: function (inv) {
      return table(['address', 'belongs to', 'found in'], inv.contacts.map(function (c) { return ['<b>' + esc(c.address) + '</b>', c.party === 'domain owner' ? '<span class="ok">domain owner</span>' : esc(c.party), c.sources.map(srcChip).join('')]; }), { empty: 'no contact addresses published in DNS or RDAP' }) + '<div class="ds-note">Role mailboxes published by the domain owner in public records only. No people search is performed.</div>';
    },
    certs: function (inv) {
      var c = state.data.certs || {};
      if (!c.certs) return '<div class="ds-empty">waiting for certificate data</div>';
      var rows = c.certs.slice(0, 60).map(function (x) { var exp = new Date(x.notAfter) < Date.now(); return [esc(fmtDate(x.notBefore)), x.names.slice(0, 8).map(esc).join('<br>') + (x.names.length > 8 ? '<br><span class="dim">+' + (x.names.length - 8) + ' more</span>' : ''), esc(x.issuer), esc(fmtDate(x.notAfter)) + (x.revoked ? ' <span class="bad">revoked</span>' : exp ? ' <span class="dim">expired</span>' : ' <span class="ok">valid</span>') + (x.link ? ' ' + ext(x.link, 'crt.sh') : '')]; });
      return facts([['Logged', c.total], ['Currently valid', c.active], ['Issuers', c.issuers ? esc(c.issuers.join(', ')) : null]]) + table(['issued', 'names', 'issuer', 'expires'], rows, { filterable: true, empty: 'no certificates in CT logs' }) + (c.certs.length > 60 ? '<div class="ds-note">showing the latest 60 of ' + c.certs.length + '</div>' : '');
    },
    email: function () {
      var e = state.data.email; if (!e) return '<div class="ds-empty">waiting for email data</div>';
      var rows = [['SPF', e.spf && e.spf.length ? esc(e.spf.join(' | ')) : '<span class="dim">absent</span>'], ['SPF DNS lookups', e.spfLookups != null ? e.spfLookups + ' / 10' : null], ['DMARC', e.dmarc && e.dmarc.length ? esc(e.dmarc.join(' | ')) : '<span class="dim">absent</span>'],
        ['DKIM selectors', e.dkim && e.dkim.length ? e.dkim.map(function (k) { return esc(k.selector) + (k.cname ? ' → ' + esc(k.cname) : k.bits ? ' (' + esc(k.k) + ' ' + k.bits + ')' : ''); }).join('<br>') : '<span class="dim">none of ' + DKIM_SELECTORS.length + ' common selectors</span>'],
        ['MTA-STS', e.mtaSts && e.mtaSts.length ? esc(e.mtaSts[0]) : '<span class="dim">absent</span>'], ['TLS-RPT', e.tlsRpt && e.tlsRpt.length ? esc(e.tlsRpt[0]) : '<span class="dim">absent</span>'], ['BIMI', e.bimi && e.bimi.length ? esc(e.bimi[0]) : '<span class="dim">absent</span>'], ['Mail hosting', esc(e.mailProvider)]];
      var mx = (e.mx || []).map(function (m) { var r = (e.mxResolve || []).filter(function (x) { return x && x.host === m.host; })[0]; return [esc(m.pref), esc(m.host || '(null MX)'), m.host ? okbad(r && r.ok, 'resolves', 'does not resolve') : '']; });
      return kv(rows) + (mx.length ? table(['pref', 'mail exchanger', 'status'], mx) : '');
    },
    registration: function () {
      var r = state.data.rdap; if (!r) return '<div class="ds-empty">waiting for RDAP</div>';
      if (r.unavailable) return '<div class="ds-empty">no RDAP service for this TLD — use the WHOIS pivot link</div>';
      return kv([['Registrar', esc(r.registrar) + (r.registrarId ? ' <span class="dim">(IANA ' + esc(r.registrarId) + ')</span>' : '')], ['Registrant', esc(r.registrant)], ['Registered', esc(fmtDate(r.registered))], ['Expires', esc(fmtDate(r.expires))], ['Last changed', esc(fmtDate(r.changed))],
        ['Status', (r.status || []).map(esc).join('<br>')], ['Registry name servers', (r.nameservers || []).map(esc).join('<br>')], ['DS at registry', okbad(r.dsSigned, 'delegation signed', 'unsigned')], ['Abuse contact', esc(r.abuse)], ['Source', r.source ? ext(r.source, r.source.replace(/^https?:\/\//, '').slice(0, 60)) : null]]);
    },
    history: function () {
      var a = state.data.archive, dns = state.data.dns || {}; if (!a) return '<div class="ds-empty">waiting for archive data</div>';
      var rows = [];
      if (!a.error) rows.push(['First capture', a.first ? ext(a.first.url, fmtTs(a.first.timestamp)) : '<span class="dim">none</span>'], ['Latest capture', a.last ? ext(a.last.url, fmtTs(a.last.timestamp)) : '<span class="dim">none</span>']);
      else rows.push(['Internet Archive', '<span class="dim">throttled or unreachable (' + esc(a.error) + ')</span>']);
      rows.push(['All archived URLs', ext('https://web.archive.org/web/*/' + state.apex + '/*', 'web.archive.org/web/*/' + state.apex + '/*')]);
      if (dns.soa) rows.push(['SOA serial', esc(dns.soa.serial) + ' <span class="dim">(' + (/^20\d{6}/.test(dns.soa.serial) ? 'date-style, last zone edit ' + dns.soa.serial.slice(0, 4) + '-' + dns.soa.serial.slice(4, 6) + '-' + dns.soa.serial.slice(6, 8) : 'counter-style') + ')</span>']);
      var t = state.data.typosquat; if (t && t.tested) rows.push(['Lookalikes tested', t.tested.length + ' <span class="dim">of ' + t.generated + ' generated · ' + (t.registered || []).length + ' registered</span>']);
      return kv(rows);
    },
    observations: function () {
      var fs = allFindings().filter(function (f) { return f.severity !== 'ok' || true; });
      var issues = fs.filter(function (f) { return SEV[f.severity] > 0; });
      if (!fs.length) return '<div class="ds-empty">nothing yet</div>';
      return '<div class="ds-note">' + plural(issues.length, 'observation') + ' worth a second look, plus context notes. Heuristics from public data, not verified vulnerabilities.</div><div class="ds-findings">' + fs.map(renderFinding).join('') + '</div>';
    },
    pivot: function () {
      var p = state.data.pivot; if (!p) return '<div class="ds-empty">waiting</div>';
      return '<div class="ds-links">' + p.map(function (g) { return '<div><h4>' + esc(g.group) + '</h4><ul>' + g.links.map(function (l) { return '<li>' + ext(l[1], l[0]) + '</li>'; }).join('') + '</ul></div>'; }).join('') + '</div>';
    }
  };
  function sectionCount(id, inv) {
    switch (id) {
      case 'graph': return null;
      case 'hosts': return inv.hosts.length; case 'ips': return inv.ips.length; case 'related': return inv.related.length; case 'services': return inv.services.length; case 'contacts': return inv.contacts.length;
      case 'certs': return inv.certs.length; case 'observations': return allFindings().filter(function (f) { return SEV[f.severity] > 0; }).length; default: return null;
    }
  }
  function sectionHint(id) {
    return { overview: 'what the public record says about the domain', graph: 'the domain at the centre of everything discovered', hosts: 'certificate logs · DNS probe · service records · MX/NS', ips: 'where the hostnames live', related: 'domains that share certificates, hosting, name servers, or look alike', services: 'vendors and products inferred from DNS, mail and hosting', contacts: 'role mailboxes published in DNS and RDAP', certs: 'public certificate-transparency logs', email: 'authentication and transport policy records', registration: 'registry data via RDAP', history: 'archive captures and zone age hints', http: 'live headers, security.txt and robots.txt (touches the target, via relay)', urls: 'every path the Wayback Machine has seen, via relay', observations: 'things a tester would note', pivot: 'continue in other tools (opens in your browser)' }[id] || '';
  }

  function renderSections(inv) {
    var host = $('#sections');
    SECTIONS.forEach(function (s) {
      var el = $('#s-' + s.id);
      if (!el) { el = document.createElement('section'); el.className = 'card ds-module'; el.id = 's-' + s.id; host.appendChild(el); }
      var n = sectionCount(s.id, inv);
      var filterVal = ''; var fi = el.querySelector('.ds-filter'); if (fi) filterVal = fi.value;
      var body = SECTION_RENDER[s.id](inv);
      var filterable = /data-filterable/.test(body);
      el.innerHTML = '<div class="check-head"><h2>' + esc(s.label) + ' <span class="n">' + esc(sectionHint(s.id)) + '</span></h2><div class="actions">' + (filterable ? '<input class="ds-filter" type="search" placeholder="filter…" aria-label="Filter ' + esc(s.label) + '" value="' + esc(filterVal) + '">' : '') + (n != null ? '<span class="chip ds-count">' + n + '</span>' : '') + '</div></div>' + body;
      if (filterVal) applyFilter(el, filterVal);
    });
  }
  function applyFilter(section, q) {
    q = q.trim().toLowerCase();
    Array.prototype.forEach.call(section.querySelectorAll('table[data-filterable] tbody tr'), function (tr) { tr.hidden = q ? tr.textContent.toLowerCase().indexOf(q) === -1 : false; });
  }
  function renderSidebar(inv) {
    var list = $('#section-list'); if (!list) return;
    list.innerHTML = SECTIONS.map(function (s) { var n = sectionCount(s.id, inv); return '<a class="side-item" href="#s-' + s.id + '"><span class="side-item__label">' + esc(s.label) + '</span>' + (n != null ? '<span class="side-item__count">' + n + '</span>' : '') + '</a>'; }).join('');
  }
  function renderSources() {
    var el = $('#sources'); if (!el) return;
    el.innerHTML = MODULES.map(function (m) {
      var r = state.results[m.id] || { status: state.enabled[m.id] === false ? 'skipped' : 'pending' };
      var t = r.status === 'done' && r.ms != null ? (r.ms / 1000).toFixed(1) + 's' : r.status === 'failed' ? 'failed' : r.status === 'skipped' ? 'off' : r.status === 'running' ? '…' : 'queued';
      return '<span class="chip ds-status is-' + r.status + '" title="' + esc(m.hint) + (r.error ? ' — ' + esc(r.error) : '') + '">' + esc(m.label) + ' <span class="dim">' + t + '</span></span>';
    }).join('');
  }
  function renderSummary(inv, final) {
    var tallies = [['hostnames', inv.hosts.length], ['addresses', inv.ips.length], ['networks', inv.networks.length], ['related', inv.related.length], ['services', inv.services.length], ['contacts', inv.contacts.length], ['certificates', inv.certs.length], ['observations', allFindings().filter(function (f) { return SEV[f.severity] > 0; }).length]];
    $('#tally').innerHTML = tallies.map(function (t) { return '<div><b>' + t[1] + '</b><span>' + t[0] + '</span></div>'; }).join('');
    $('#sum-domain').textContent = state.domain + (state.apex !== state.domain ? ' · apex ' + state.apex : '');
    $('#sum-state').textContent = final ? 'discovery complete · ' + STATS.queries + ' queries · ' + ((Date.now() - state.started) / 1000).toFixed(0) + 's · target never contacted' : 'discovering…';
    var si = $('#stat-items'); if (si) si.textContent = inv.hosts.length + inv.ips.length + inv.related.length + inv.services.length + inv.contacts.length;
  }
  function renderAll(final) {
    var inv = state.inventory = buildInventory();
    renderSummary(inv, final); renderSidebar(inv); renderSources(); renderSections(inv);
  }

  /* ---------------- run ---------------- */
  function runModule(m) {
    if (state.enabled[m.id] === false) { state.results[m.id] = { status: 'skipped', findings: [] }; renderSources(); return Promise.resolve(); }
    var r = state.results[m.id] = { status: 'running', findings: [], t0: Date.now() };
    renderSources();
    var ctx = { domain: state.domain, apex: state.apex, log: log, findings: r.findings, data: state.data, shared: state.shared };
    return Promise.resolve().then(function () { return m.run(ctx); }).then(function () { r.status = 'done'; }, function (e) { r.status = 'failed'; r.error = String(e && e.message || e); log(m.label + ' failed: ' + r.error); })
      .then(function () { r.ms = Date.now() - r.t0; renderAll(false); });
  }
  function scan(input) {
    if (state.running) return;
    var domain = parseDomain(input);
    if (!domain) { window.toast('Enter a valid domain name, e.g. example.com'); return; }
    state.domain = domain; state.apex = apexOf(domain);
    state.running = true; state.started = Date.now(); state.results = {}; state.data = {}; state.shared = {};
    STATS.queries = 0; UI.stat();
    for (var k in dnsCache) delete dnsCache[k];
    Array.prototype.forEach.call(document.querySelectorAll('.ds-toggle input'), function (cb) { state.enabled[cb.value] = cb.checked; });
    state.enabled.dns = true;
    var view = $('#scan-view'); view.hidden = false;
    $('#sections').innerHTML = ''; $('#log').innerHTML = '';
    var btn = $('#scan-btn'); btn.disabled = true; btn.textContent = 'Discovering…';
    document.title = 'marulecha | OSINT ' + domain;
    try { history.replaceState(null, '', location.pathname + '?d=' + encodeURIComponent(domain)); } catch (e) { /* noop */ }
    remember(domain);
    renderAll(false);
    log('passive_recon.sh ' + domain + (state.apex !== domain ? ' (registrable domain: ' + state.apex + ')' : ''));
    log('Target is never contacted. Sources: DNS-over-HTTPS, RDAP, CT logs, HackerTarget, GeoJS, Internet Archive.');
    var chain = Promise.resolve();
    [0, 1, 2, 3, 4].forEach(function (s) { chain = chain.then(function () { return Promise.all(MODULES.filter(function (m) { return m.stage === s; }).map(runModule)); }); });
    return chain.then(function () {
      state.running = false; btn.disabled = false; btn.textContent = 'Discover';
      renderAll(true);
      var inv = state.inventory;
      log('Done in ' + ((Date.now() - state.started) / 1000).toFixed(1) + 's: ' + plural(inv.hosts.length, 'hostname') + ', ' + plural(inv.ips.length, 'address', 'addresses') + ', ' + plural(inv.related.length, 'related domain') + ', ' + plural(inv.services.length, 'service') + '.');
      window.toast('Discovery complete: ' + plural(inv.hosts.length, 'hostname') + ', ' + plural(inv.services.length, 'service'));
      view.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }

  /* ---------------- history ---------------- */
  var HIST_KEY = 'domainscanHistory';
  function history_() { try { return JSON.parse(localStorage.getItem(HIST_KEY) || '[]'); } catch (e) { return []; } }
  function remember(d) {
    try { var h = history_().filter(function (x) { return x !== d; }); h.unshift(d); localStorage.setItem(HIST_KEY, JSON.stringify(h.slice(0, 8))); } catch (e) { /* noop */ }
    renderHistory();
  }
  function renderHistory() {
    var el = $('#recent'); if (!el) return;
    var h = history_();
    el.innerHTML = h.length ? '<span class="dim">recent:</span>' + h.map(function (d) { return '<button type="button" class="chip" data-domain="' + esc(d) + '">' + esc(d) + '</button>'; }).join('') + '<button type="button" class="chip" data-clear title="Forget recent domains">×</button>' : '';
  }

  /* ---------------- export ---------------- */
  function mdTable(cols, rows) { if (!rows.length) return '_none_\n'; var clean = function (s) { return String(s == null ? '' : s).replace(/\|/g, '\\|').replace(/\n/g, ' '); }; return '| ' + cols.join(' | ') + ' |\n|' + cols.map(function () { return ' --- '; }).join('|') + '|\n' + rows.map(function (r) { return '| ' + r.map(clean).join(' | ') + ' |'; }).join('\n') + '\n'; }
  function reportMarkdown() {
    var inv = state.inventory || buildInventory(), d = state.data, dns = d.dns || {}, em = d.email || {}, rd = d.rdap || {}, ho = d.hosting || {}, ce = d.certs || {}, ar = d.archive || {};
    var L = ['# Passive domain OSINT: ' + state.domain, '', 'Generated ' + new Date().toISOString() + ' with marulecha.com Passive Domain OSINT (browser-only, target never contacted). ' + STATS.queries + ' queries.', '', '## Overview', ''];
    [['Registrar', rd.registrar], ['Registered', rd.registered && fmtDate(rd.registered)], ['Expires', rd.expires && fmtDate(rd.expires)], ['DNS hosting', dns.dnsProvider], ['DNSSEC', dns.records ? (dns.dnssec ? 'validated' : 'off') : null], ['Mail hosting', em.mailProvider], ['SPF', em.spf && (em.spf[0] || 'absent')], ['DMARC', em.dmarc && (em.dmarc[0] || 'absent')], ['DKIM selectors', em.dkim && (em.dkim.map(function (k) { return k.selector; }).join(', ') || 'none found')], ['Web hosting', ho.cdn ? 'behind ' + ho.cdn : ho.summary], ['Certificates', ce.total != null ? ce.active + ' valid of ' + ce.total : null], ['Archived since', ar.first && fmtTs(ar.first.timestamp)]].forEach(function (i) { if (i[1]) L.push('- ' + i[0] + ': ' + i[1]); });
    L.push('', '## Hostnames (' + inv.hosts.length + ')', '', mdTable(['hostname', 'resolves to', 'alias / service', 'found via'], inv.hosts.map(function (h) { return [h.name, h.ips.join(', ') || (h.cname ? 'alias does not resolve' : h.status === 3 ? 'NXDOMAIN' : h.status === null ? 'not resolved' : 'no address'), (h.cname || '') + (h.service ? ' (' + h.service + ')' : ''), h.sources.join(', ')]; })));
    L.push('## Networks (' + inv.networks.length + ')', '', mdTable(['network', 'organisation', 'countries', 'addresses', 'hosts'], inv.networks.map(function (n) { return [n.asn, n.org, n.countries.join(', '), n.ips, n.hosts.length]; })));
    L.push('## Addresses (' + inv.ips.length + ')', '', mdTable(['address', 'reverse dns', 'network', 'location', 'used by'], inv.ips.map(function (i) { return [i.ip, i.ptr || '', i.asn ? 'AS' + i.asn + ' ' + (i.org || '') : '', [i.city, i.country].filter(Boolean).join(', '), i.hosts.slice(0, 6).join(', ') + (i.hosts.length > 6 ? ' …' : '')]; })));
    L.push('## Related domains (' + inv.related.length + ')', '', mdTable(['domain', 'relationship', 'evidence'], inv.related.map(function (r) { return [r.domain, r.relations.join('; '), r.evidence.join('; ')]; })));
    L.push('## Services & vendors (' + inv.services.length + ')', '', mdTable(['service', 'role', 'evidence'], inv.services.map(function (s) { return [s.name, s.category, s.evidence.join('; ')]; })));
    L.push('## Contact addresses (' + inv.contacts.length + ')', '', mdTable(['address', 'belongs to', 'found in'], inv.contacts.map(function (c) { return [c.address, c.party, c.sources.join(', ')]; })));
    L.push('## Certificates (latest 20 of ' + inv.certs.length + ')', '', mdTable(['issued', 'expires', 'issuer', 'names'], inv.certs.slice(0, 20).map(function (c) { return [fmtDate(c.notBefore), fmtDate(c.notAfter), c.issuer, c.names.join(', ')]; })));
    if (rd.status) L.push('## Registration', '', '- Status: ' + rd.status.join(', '), '- Registry NS: ' + (rd.nameservers || []).join(', '), '- DS at registry: ' + (rd.dsSigned ? 'yes' : 'no'), '');
    var fs = allFindings();
    L.push('## Observations', '');
    SEV_ORDER.forEach(function (s) { var g = fs.filter(function (f) { return f.severity === s; }); if (!g.length) return; L.push('### ' + s.charAt(0).toUpperCase() + s.slice(1) + ' (' + g.length + ')', ''); g.forEach(function (f) { L.push('- **' + f.title + '** _(' + f.moduleLabel + ')_' + (f.detail ? '  \n  ' + f.detail : '') + (f.fix ? '  \n  Fix: ' + f.fix : '')); }); L.push(''); });
    return L.join('\n');
  }
  function reportJSON() {
    return JSON.stringify({ tool: 'marulecha.com Passive Domain OSINT', generated: new Date().toISOString(), domain: state.domain, apex: state.apex, queries: STATS.queries, inventory: state.inventory || buildInventory(), observations: allFindings(), modules: Object.keys(state.results).map(function (k) { var r = state.results[k]; return { id: k, status: r.status, ms: r.ms, error: r.error }; }), data: state.data }, null, 2);
  }
  function download(name, text, type) {
    var blob = new Blob([text], { type: type || 'text/plain' });
    var a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }

  /* ---------------- wiring ---------------- */
  document.addEventListener('DOMContentLoaded', function () {
    var form = $('#scan-form'), input = $('#domain');
    if (!form) return;
    $('#toggles').innerHTML = MODULES.map(function (m) { return '<label class="ds-toggle' + (m.locked ? ' is-locked' : '') + (m.active ? ' is-active-chk' : '') + '" title="' + esc(m.hint) + '"><input type="checkbox" value="' + m.id + '"' + (m.def === false ? '' : ' checked') + (m.locked ? ' disabled' : '') + '><span class="chip">' + esc(m.label) + (m.active ? ' ⚡' : '') + '</span></label>'; }).join('');
    var sm = $('#stat-modules'); if (sm) sm.textContent = MODULES.length;
    form.addEventListener('submit', function (e) { e.preventDefault(); scan(input.value); });
    renderHistory();
    $('#recent').addEventListener('click', function (e) {
      var b = e.target.closest('button'); if (!b) return;
      if (b.hasAttribute('data-clear')) { try { localStorage.removeItem(HIST_KEY); } catch (x) { /* noop */ } renderHistory(); return; }
      input.value = b.getAttribute('data-domain'); scan(input.value);
    });
    $('#act-md').addEventListener('click', function () { window.copyText(reportMarkdown()).then(function () { window.toast('Report copied as Markdown'); }, function () { window.toast('Copy blocked by browser'); }); });
    $('#act-json').addEventListener('click', function () { download('recon-' + state.domain + '-' + new Date().toISOString().slice(0, 10) + '.json', reportJSON(), 'application/json'); window.toast('JSON downloaded'); });
    $('#act-link').addEventListener('click', function () { window.copyText(location.origin + location.pathname + '?d=' + encodeURIComponent(state.domain)).then(function () { window.toast('Link copied'); }, function () { window.toast('Copy blocked by browser'); }); });
    $('#act-rescan').addEventListener('click', function () { scan(state.domain); });
    $('#section-list').addEventListener('click', function (e) { var a = e.target.closest('a'); if (!a) return; e.preventDefault(); var t = $(a.getAttribute('href')); if (t) t.scrollIntoView({ behavior: 'smooth', block: 'start' }); });
    $('#sections').addEventListener('input', function (e) { var f = e.target.closest('.ds-filter'); if (f) applyFilter(f.closest('.ds-module'), f.value); });
    $('#sections').addEventListener('click', function (e) {
      var a = e.target.closest('a[href^="' + location.pathname + '?d="]'); if (!a) return;
      e.preventDefault(); var dom = new URLSearchParams(a.getAttribute('href').split('?')[1]).get('d'); input.value = dom; scan(dom);
    });
    document.addEventListener('keydown', function (e) {
      var tag = (e.target.tagName || '').toLowerCase();
      if (e.key === '/' && tag !== 'input' && tag !== 'textarea' && !e.metaKey && !e.ctrlKey && !e.altKey) { e.preventDefault(); input.focus(); input.select(); }
    });
    var pre = new URLSearchParams(location.search).get('d');
    if (pre) { input.value = pre; scan(pre); }
  });

  window.PassiveRecon = { stats: STATS, scan: scan, parseDomain: parseDomain, apexOf: apexOf, permutations: permutations, state: state, buildInventory: buildInventory, reportMarkdown: reportMarkdown, reportJSON: reportJSON };
})();
