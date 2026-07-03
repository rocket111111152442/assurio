import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const required = [
  "index.html",
  "moderateur/index.html",
  "support.js",
  "image-slot.js",
  "assets/loryance-logo.png",
  "assets/loryance-mark.png"
];

const missing = required.filter((file) => !fs.existsSync(path.join(root, file)));
if (missing.length) {
  console.error("Missing required files:");
  for (const file of missing) console.error(`- ${file}`);
  process.exit(1);
}

const badReferences = [];
for (const page of ["index.html", "moderateur/index.html"]) {
  const html = fs.readFileSync(path.join(root, page), "utf8");
  const references = [...html.matchAll(/\b(?:src|href)=["']([^"']+)["']/g)]
    .map((match) => match[1])
    .filter((ref) => {
      if (/^(https?:|data:|mailto:|tel:|#|\/$)/i.test(ref)) return false;
      if (ref.startsWith("//")) return false;
      return true;
    });

  for (const ref of references) {
    const clean = ref.split(/[?#]/, 1)[0].replace(/^\.\//, "").replace(/^\//, "");
    if (!clean) continue;
    if (!fs.existsSync(path.join(root, clean))) badReferences.push(`${page} -> ${ref}`);
  }
}

if (badReferences.length) {
  console.error("Broken local references:");
  for (const ref of badReferences) console.error(`- ${ref}`);
  process.exit(1);
}

console.log("Static verification passed.");
