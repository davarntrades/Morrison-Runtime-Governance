// Render scene.html to MP4, frame by frame, deterministically.
//   node render.js [out.mp4]            full render (needs ffmpeg on PATH, or FFMPEG=/path/to/ffmpeg)
//   node render.js --stills 12,30,55    write stills at those seconds (PNG) for a quick check
//   SCENE=ad.html node render.js ad.mp4           renders the advert cut instead (also writes ad.cues.json)
//   SCENE=ad.html FORMAT=v node render.js ad-v.mp4  the advert in 9:16 (1080x1920)
const path = require('path');
const { spawn } = require('child_process');
let chromium;
try { ({ chromium } = require('playwright')); } catch { ({ chromium } = require(path.join(require('child_process').execSync('npm root -g').toString().trim(), 'playwright'))); }
const FPS = 30, FF = process.env.FFMPEG || 'ffmpeg', VERT = process.env.FORMAT === 'v';
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: VERT ? { width: 1080, height: 1920 } : { width: 1920, height: 1080 } });
  await p.goto('file://' + path.join(__dirname, process.env.SCENE || 'scene.html') + '?render' + (VERT ? '&format=v' : ''));
  const canvas = p.locator('canvas');
  const frame = async t => { await p.evaluate(t => render(t), t); return canvas.screenshot({ type: 'png' }); };
  if (process.argv[2] === '--stills') {
    for (const s of process.argv[3].split(',')) require('fs').writeFileSync(`still-${s}.png`, await frame(+s));
  } else {
    const out = process.argv[2] || 'hf-incident-reproduced.mp4';
    const total = await p.evaluate(() => TOTAL);
    const enc = spawn(FF, ['-y', '-loglevel', 'error', '-f', 'image2pipe', '-framerate', String(FPS), '-i', '-',
      '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-crf', '20', '-preset', 'slow', '-movflags', '+faststart', out], { stdio: ['pipe', 'inherit', 'inherit'] });
    for (let f = 0; f < Math.round(total * FPS); f++) enc.stdin.write(await frame(f / FPS));
    enc.stdin.end(); await new Promise(r => enc.on('close', r));
    const cues = await p.evaluate(() => window.CUES || null);
    if (cues) require('fs').writeFileSync(out.replace(/\.mp4$/, '') + '.cues.json', JSON.stringify({ total, cues }));
    console.log(`${out}: ${total}s @ ${FPS}fps`);
  }
  await b.close();
})();
