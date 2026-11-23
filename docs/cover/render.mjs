// Render cover.html to an H.264 video, deterministically (seeks the animation
// timeline per frame rather than screen-recording in real time).
//
//   npm i --prefix /some/dir playwright && npx --prefix /some/dir playwright install chromium
//   PW_HOME=/some/dir node docs/cover/render.mjs [out.mp4] [fps] [layout]
//
// layout: "card" (default, content high, for the portfolio card) or "page"
// (content centred, for the project-page hero).
//
// Needs ffmpeg on PATH. Output is 2880x1800 (1440x900 canvas at 2x).
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(join(resolve(process.env.PW_HOME ?? here), "noop.js"));
const { chromium } = require("playwright");

const out = resolve(process.argv[2] ?? join(here, "secreview-cover.mp4"));
const fps = Number(process.argv[3] ?? 30);
const layout = process.argv[4] ?? "card";
const frames = mkdtempSync(join(tmpdir(), "cover-frames-"));

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
const url = pathToFileURL(join(here, "cover.html"));
if (layout !== "card") url.searchParams.set("layout", layout);
await page.goto(url.href);
await page.evaluate(() => document.fonts.ready);
const duration = await page.evaluate(() => window.DURATION);

const total = Math.round((duration / 1000) * fps);
for (let i = 0; i < total; i++) {
  await page.evaluate((t) => window.seek(t), (i * 1000) / fps);
  await page.screenshot({ path: join(frames, `f${String(i).padStart(5, "0")}.png`) });
  if (i % fps === 0) process.stdout.write(`\r${i}/${total}`);
}
await browser.close();

execFileSync("ffmpeg", [
  "-v", "error", "-y", "-framerate", String(fps), "-i", join(frames, "f%05d.png"),
  "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "20", "-preset", "slow",
  "-movflags", "+faststart", out,
], { stdio: "inherit" });
rmSync(frames, { recursive: true, force: true });
console.log(`\nwrote ${out}`);
