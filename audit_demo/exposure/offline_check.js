// Offline check of an engagement pack's index.html.
// Usage: node offline_check.js /abs/path/to/pack  -> prints JSON
// Blocks every network request, then confirms that every local link resolves to
// a file in the pack and every in-page anchor exists.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
(async () => {
  const pack = process.argv[2];
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ offline: true });
  const page = await ctx.newPage();
  const external = [];
  await page.route('**/*', r => {
    const u = r.request().url();
    if (u.startsWith('file://')) return r.continue();
    external.push(u); return r.abort();
  });
  await page.goto('file://' + path.join(pack, 'index.html'));
  const links = await page.$$eval('a[href]', as => as.map(a => a.getAttribute('href')));
  const ids = new Set(await page.$$eval('[id]', es => es.map(e => e.id)));
  const missingFiles = [], missingAnchors = [];
  for (const h of links) {
    if (h.startsWith('#')) { if (!ids.has(h.slice(1))) missingAnchors.push(h); }
    else if (/^[a-z]+:/i.test(h)) { external.push(h); }
    else if (!fs.existsSync(path.join(pack, decodeURIComponent(h.split('#')[0])))) missingFiles.push(h);
  }
  const overflow = await (async () => {
    await page.setViewportSize({ width: 390, height: 800 });
    return page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  })();
  console.log(JSON.stringify({ links: links.length, anchors_checked: links.filter(h => h.startsWith('#')).length,
    missing_files: missingFiles, missing_anchors: missingAnchors, external_requests: external,
    phone_width_horizontal_overflow: overflow }));
  await browser.close();
})();
