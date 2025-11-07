import { ExifTool } from "exiftool-vendored";
import fs from "fs";
import os from "os";
import path from "path";
import readline from "readline";
import chalk from "chalk";
import Table from "cli-table3";

const exiftool = new ExifTool({ taskTimeoutMillis: 15000 });
function clearScreen() { process.stdout.write("\x1Bc"); }
function showLogo() {
  const logo = `
                           █████                  █████            █████             
                          ░░███                  ░░███            ░░███              
 █████████████    ██████  ███████    ██████    ███████   ██████   ███████    ██████  
░░███░░███░░███  ███░░███░░░███░    ░░░░░███  ███░░███  ░░░░░███ ░░░███░    ░░░░░███ 
 ░███ ░███ ░███ ░███████   ░███      ███████ ░███ ░███   ███████   ░███      ███████ 
 ░███ ░███ ░███ ░███░░░    ░███ ███ ███░░███ ░███ ░███  ███░░███   ░███ ███ ███░░███ 
 █████░███ █████░░██████   ░░█████ ░░████████░░████████░░████████  ░░█████ ░░████████
░░░░░ ░░░ ░░░░░  ░░░░░░     ░░░░░   ░░░░░░░░  ░░░░░░░░  ░░░░░░░░    ░░░░░   ░░░░░░░░ `;
  const logo1 = `
       d8888                   888                                    
      d88888                   888                                    
     d88P888                   888                                    
    d88P 888 88888b.   8888b.  888 888  888 88888888  .d88b.  888d888 
   d88P  888 888 "88b     "88b 888 888  888    d88P  d8P  Y8b 888P"   
  d88P   888 888  888 .d888888 888 888  888   d88P   88888888 888     
 d8888888888 888  888 888  888 888 Y88b 888  d88P    Y8b.     888     
d88P     888 888  888 "Y888888 888  "Y88888 88888888  "Y8888  888     
                                        888                           
                                   Y8b d88P                           
                                    "Y88P"                                                           
  `;
  console.log(chalk.yellow(logo));
  console.log(chalk.red(logo1));
  console.log(chalk.gray("                              github.com/Filza2\n"));
}
function ask(q) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(res => rl.question(q, ans => { rl.close(); res(ans.trim()); }));
}
function ensureDir(d) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}
function listImages(dir = ".") {
  try {
    return fs.readdirSync(dir).filter(f =>
      /\.(jpg|jpeg|png|heic|heif|tif|tiff|webp|gif|bmp)$/i.test(f)
    );
  } catch {
    return [];
  }
}
function humanSize(bytes) {
  if (bytes == null) return "?";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let n = Number(bytes);
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(2)} ${units[i]}`;
}
function megapixels(w, h) {
  if (!w || !h) return "?";
  const mp = (Number(w) * Number(h)) / 1_000_000;
  return `${mp.toFixed(2)} MP`;
}
function detectMalware(tags) {
  const warnings = [];
  let score = 0;
  const SKIP_KEYS = new Set(["SourceFile", "Directory", "FileName", "FilePath", "FileModifyDate", "FilePermissions"]);
  const dangerous = [
    { re: /<\s*script\b/i, label: "<script> tag" },
    { re: /<\/\s*script\s*>/i, label: "</script> tag" },
    { re: /<\?php\b/i, label: "PHP code block" },
    { re: /\bjavascript:/i, label: "javascript URI" },
    { re: /\beval\s*\(/i, label: "eval() function" },
    { re: /\bdata:(?:application|text|image)\/[a-z0-9.+-]+;base64,/i, label: "data:*;base64 URI" },
    { re: /[A-Za-z0-9+/]{300,}={0,2}/, label: "very long base64-like data" },
    { re: /\bhttps?:\/\/[^\s"']+\.(exe|msi|scr|bat|cmd|ps1)\b/i, label: "executable download URL" },
    { re: /<\s*iframe\b/i, label: "<iframe> tag" },
  ];
  const mild = [
    { re: /\bjavascript\b/i, label: "mention of 'javascript'" },
    { re: /\bphp\b/i, label: "mention of 'php'" },
    { re: /\bscript\b/i, label: "mention of 'script'" },
  ];
  for (const [key, rawVal] of Object.entries(tags)) {
    if (SKIP_KEYS.has(key) || rawVal == null) continue;
    const val = String(rawVal);
    const low = val.toLowerCase();
    if (low.length > 4000) {
      warnings.push(`Very large text in "${key}" (${low.length} chars) — possible hidden payload`);
      score += 2;
    }
    let matchedDangerous = false;
    for (const d of dangerous) {
      if (d.re.test(val)) {
        warnings.push(`⚠ Found ${d.label} in "${key}" → "${val.slice(0,150)}..."`);
        score += 3;
        matchedDangerous = true;
      }
    }
    if (!matchedDangerous) {
      for (const m of mild) {
        if (m.re.test(val)) {
          score += 0.5;
        }
      }
    }
  }
  const finalScore = Math.min(Math.round(score), 10);
  return { warnings, score: finalScore };
}
function getRiskLevelFromScore(score) {
  if (score === 0) return { label: "Safe", colored: chalk.green("🟢 Safe") };
  if (score <= 2) return { label: "Caution", colored: chalk.hex("#FFA500")("🟠 Caution") };
  return { label: "Suspicious", colored: chalk.red("🔴 Suspicious") };
}
function getMapLink(lat, lon) {
  if (!lat || !lon) return "No GPS data";
  return `https://www.google.com/maps/search/?api=1&query=${lat},${lon}`;
}
async function stripAllMetadataTo(src, dest) {
  try {
    const tmp = path.join(os.tmpdir(), `clean_${Date.now()}_${Math.random().toString(36).slice(2)}_${path.basename(src)}`);
    fs.copyFileSync(src, tmp);
    await exiftool.write(tmp, {}, ["-all=", "-overwrite_original_in_place"]).catch(() => {});
    if (fs.existsSync(dest)) fs.unlinkSync(dest);
    fs.renameSync(tmp, dest);
  } catch (err) {
    console.warn("Warning during cleanup:", err.message);
    if (fs.existsSync(dest)) fs.unlinkSync(dest);
    fs.copyFileSync(src, dest);
  }
}
function summarize(tags, file) {
  const stat = fs.statSync(file);
  const w = tags.ImageWidth || tags.ExifImageWidth || tags.PixelXDimension;
  const h = tags.ImageHeight || tags.ExifImageHeight || tags.PixelYDimension;
  const lat = tags.GPSLatitude ?? null;
  const lon = tags.GPSLongitude ?? null;
  return {
    File: path.basename(file),
    FileSize: humanSize(stat.size),
    Ext: path.extname(file).replace(".", "").toUpperCase() || "?",
    Type: tags.FileType || "?",
    Dimensions: `${w || "?"}x${h || "?"}`,
    Megapixels: megapixels(w, h),
    Camera: `${tags.Make || "?"} ${tags.Model || ""}`.trim(),
    Lens: tags.LensModel || "?",
    Date: tags.DateTimeOriginal || tags.CreateDate || tags.ModifyDate || "?",
    ISO: tags.ISO || "?",
    Aperture: tags.FNumber || tags.ApertureValue || "?",
    Shutter: tags.ExposureTime || "?",
    Focal: tags.FocalLength || "?",
    Software: tags.Software || tags.XMPToolkit || tags.CreatorTool || "?",
    GPSLatitude: lat,
    GPSLongitude: lon,
    Location: getMapLink(lat, lon)
  };
}
function printTable(results) {
  const table = new Table({
    head: [
      chalk.yellow("Risk"),
      chalk.yellow("File"),
      chalk.yellow("Ext"),
      chalk.yellow("Camera"),
      chalk.yellow("Date"),
      chalk.yellow("ISO"),
      chalk.yellow("Aperture"),
      chalk.yellow("Shutter"),
      chalk.yellow("Focal"),
      chalk.yellow("Size"),
      chalk.yellow("MP"),
      chalk.yellow("Software"),
      chalk.yellow("Location")
    ],
    colWidths: [12, 16, 8, 18, 20, 7, 10, 10, 10, 12, 10, 18, 38],
    wordWrap: true
  });
  for (const r of results) {
    table.push([
      r.RiskColored,
      r.File,
      r.Ext,
      r.Camera,
      r.Date,
      r.ISO,
      r.Aperture,
      r.Shutter,
      r.Focal,
      r.FileSize,
      r.Megapixels,
      r.Software,
      r.Location
    ]);
  }
  console.log(table.toString());
}
function saveResultJSON(info, analysis, outDir) {
  const outPath = path.join(outDir, `${path.parse(info.File).name}.json`);
  const payload = {
    ...info,
    GoogleMapsUrl: info.Location && info.Location.startsWith("http") ? info.Location : null,
    RiskScore: analysis.score,
    RiskLevel: getRiskLevelFromScore(analysis.score).label,
    MalwareWarnings: analysis.warnings
  };
  fs.writeFileSync(outPath, JSON.stringify(payload, null, 2), "utf8");
}
async function processImages(files) {
  ensureDir("outputs");
  ensureDir("cleaned_images");
  const rows = [];
  for (const file of files) {
    const full = path.resolve(file);
    if (!fs.existsSync(full)) {
      console.log(chalk.red(`- Skipping missing file: ${file}`));
      continue;
    }
    console.log(chalk.cyan(`\n- Analyzing: ${file}`));
    const tags = await exiftool.read(full);
    const analysis = detectMalware(tags);
    const risk = getRiskLevelFromScore(analysis.score);
    if (analysis.warnings.length > 0) {
      console.log(chalk.hex("#FFA500")(`  › ${analysis.warnings.length} warning(s) detected — Risk: ${risk.label}`));
      console.log(chalk.red(`    Example: ${analysis.warnings[0].slice(0,200)}`));
    } else {
      console.log(chalk.green("  › No suspicious metadata patterns detected."));
    }
    const info = summarize(tags, full);
    saveResultJSON(info, analysis, "outputs");
    const cleaned = path.resolve("cleaned_images", path.basename(file));
    await stripAllMetadataTo(full, cleaned);
    rows.push({ ...info, RiskColored: risk.colored });
  }
  console.log(chalk.green("\n--- Analysis Results ---"));
  printTable(rows);
  console.log(chalk.gray("\n- Reports saved in ./outputs and cleaned images in ./cleaned_images\n"));
}
async function main() {
  clearScreen();
  showLogo();
  const mode = await ask("[-] Mode :\n\n [1] Single image\n [2] Multiple images\n\n>> : ");
  const multi = parseInt(mode, 10) !== 1;
  if (multi) {
    const imgs = listImages(".");
    if (!imgs.length) { console.log("- No images found."); await exiftool.end(); return; }
    console.log("- Found images:\n" + imgs.join("\n"));
    const confirm = await ask("- Analyze all? (y/n): ");
    if (confirm.toLowerCase().startsWith("y")) await processImages(imgs);
  } else {
    while (true) {
      const imgs = listImages(".");
      if (imgs.length > 0) console.log("\nImages in folder:\n" + imgs.join("\n"));
      const name = await ask("\n- Image file name : ");
      if (name && fs.existsSync(name) && fs.statSync(name).isFile()) { await processImages([name]); break; }
      else console.log(chalk.red(`- File "${name}" not found. Try again.\n`));
    }
  }
  await exiftool.end();
}
main().catch(async err => {
  console.error("- Fatal error:", err);
  await exiftool.end();
  process.exit(1);
});