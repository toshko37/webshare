/**
 * UI/UX audit: screenshots, axe-core accessibility, Web Vitals, tap targets, overflow.
 * Docs: docs/ui-ux-audit-2026-11-08.md
 * Setup (outside the repo): npm install puppeteer-core@22.15.0 axe-core@4.10.0
 * Run:   node tests/ui-audit.js https://HOST <PHPSESSID of a logged-in admin> <folder share token> <output dir>
 * Needs: /usr/bin/chromium. Each run issues one upload pass from the machine's IP.
 */
const puppeteer = require('puppeteer-core');
const fs = require('fs');
const axeSrc = fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const [,, BASE, SID, FT, OUT] = process.argv;
const pages = [
  { id: 'login', url: '/login.php' },
  { id: 'upload', url: '/u' },
  { id: 'chat', url: '/t' },
  { id: 'folder-share', url: '/f/' + FT },
  { id: 'bad-share', url: '/public.php?t=nonexistent' },
  { id: 'files', url: '/', auth: true },
  { id: 'texts', url: '/?tab=texts', auth: true },
  { id: 'settings', url: '/?tab=settings', auth: true },
  { id: 'audit', url: '/?tab=audit', auth: true },
  { id: 'sessions', url: '/?tab=sessions', auth: true },
  { id: 'help', url: '/?tab=help', auth: true },
];
const viewports = [
  { id: 'desktop', width: 1366, height: 900, isMobile: false },
  { id: 'mobile', width: 390, height: 844, isMobile: true, hasTouch: true, deviceScaleFactor: 2 },
];
(async () => {
  const browser = await puppeteer.launch({ executablePath: '/usr/bin/chromium', headless: 'new',
    args: ['--no-sandbox', '--ignore-certificate-errors', '--disable-dev-shm-usage'] });
  const results = [];
  for (const vp of viewports) for (const p of pages) {
    const ctx = await browser.createBrowserContext();
    const page = await ctx.newPage();
    await page.setViewport(vp);
    if (vp.isMobile) await page.setUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1');
    if (p.auth) await page.setCookie({ name: 'PHPSESSID', value: SID, domain: new URL(BASE).hostname, path: '/', secure: true, httpOnly: true });
    const consoleErrors = [];
    page.on('console', m => { if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 160)); });
    page.on('pageerror', e => consoleErrors.push('PAGEERROR ' + String(e.message).slice(0, 160)));
    await page.evaluateOnNewDocument(() => {
      window.__lcp = 0; window.__cls = 0;
      new PerformanceObserver(l => { for (const e of l.getEntries()) window.__lcp = e.startTime; }).observe({ type: 'largest-contentful-paint', buffered: true });
      new PerformanceObserver(l => { for (const e of l.getEntries()) if (!e.hadRecentInput) window.__cls += e.value; }).observe({ type: 'layout-shift', buffered: true });
    });
    let status = 0;
    try {
      const resp = await page.goto(BASE + p.url, { waitUntil: 'networkidle2', timeout: 30000 });
      status = resp ? resp.status() : 0;
    } catch (e) { consoleErrors.push('NAV ' + e.message); }
    await new Promise(r => setTimeout(r, 600));
    const m = await page.evaluate(() => {
      const nav = performance.getEntriesByType('navigation')[0] || {};
      const res = performance.getEntriesByType('resource');
      const vis = el => { const r = el.getBoundingClientRect(); const s = getComputedStyle(el); return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; };
      const taps = [...document.querySelectorAll('a,button,input:not([type=hidden]),select,label[onclick],[onclick]')].filter(vis);
      const small = taps.filter(el => { const r = el.getBoundingClientRect(); return r.width < 44 || r.height < 44; });
      const tiny = [...document.querySelectorAll('body *')].filter(el => el.childNodes.length && [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim()) && vis(el) && parseFloat(getComputedStyle(el).fontSize) < 12);
      const wide = [...document.querySelectorAll('body *')].filter(el => vis(el) && el.getBoundingClientRect().right > window.innerWidth + 2).slice(0, 5).map(el => el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + (el.className && typeof el.className === 'string' ? '.' + el.className.split(' ')[0] : ''));
      return {
        title: document.title, lang: document.documentElement.lang,
        h1: document.querySelectorAll('h1').length,
        ttfb: Math.round(nav.responseStart || 0), dcl: Math.round(nav.domContentLoadedEventEnd || 0),
        lcp: Math.round(window.__lcp), cls: +window.__cls.toFixed(3),
        htmlKB: Math.round((nav.transferSize || 0) / 1024), htmlDecodedKB: Math.round((nav.decodedBodySize || 0) / 1024),
        resources: res.length, resKB: Math.round(res.reduce((a, r) => a + (r.transferSize || 0), 0) / 1024),
        dom: document.getElementsByTagName('*').length,
        overflowX: document.documentElement.scrollWidth > window.innerWidth + 2, scrollW: document.documentElement.scrollWidth,
        wide, taps: taps.length, smallTaps: small.length, tinyText: tiny.length,
        inlineStyles: document.querySelectorAll('[style]').length,
        alerts: (document.documentElement.outerHTML.match(/\b(alert|confirm|prompt)\(/g) || []).length,
        emojiIconButtons: [...document.querySelectorAll('button')].filter(b => !b.getAttribute('aria-label') && !b.title && b.textContent.trim().length <= 2).length,
      };
    });
    await page.addScriptTag({ content: axeSrc });
    const axe = await page.evaluate(async () => {
      const r = await axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'best-practice'] } });
      return r.violations.map(v => ({ id: v.id, impact: v.impact, n: v.nodes.length, help: v.help, sample: v.nodes[0] && v.nodes[0].target.join(' ') }));
    });
    const shot = `${OUT}/${p.id}-${vp.id}.png`;
    await page.screenshot({ path: shot, fullPage: true, captureBeyondViewport: false }).catch(() => {});
    results.push({ page: p.id, vp: vp.id, status, ...m, consoleErrors, axe });
    await ctx.close();
  }
  // Upload flow on mobile: verification timing and pass state
  const fctx = await browser.createBrowserContext();
  const page = await fctx.newPage();
  await page.setViewport(viewports[1]);
  await page.setUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1');
  await page.goto(BASE + '/u', { waitUntil: 'networkidle2' });
  await page.screenshot({ path: `${OUT}/upload-flow-1-locked-mobile.png` });
  const t0 = Date.now();
  await page.click('#guardBtn');
  await page.waitForSelector('#passPanel', { visible: true, timeout: 30000 }).catch(() => {});
  const verifyMs = Date.now() - t0;
  await page.screenshot({ path: `${OUT}/upload-flow-2-pass-mobile.png`, fullPage: true });
  results.push({ page: 'upload-verify-flow', vp: 'mobile', verifyMs, passVisible: await page.$eval('#passPanel', e => getComputedStyle(e).display !== 'none').catch(() => false) });
  await browser.close();
  fs.writeFileSync(`${OUT}/results.json`, JSON.stringify(results, null, 1));
})();
