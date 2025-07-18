#!/usr/bin/env node

const fs = require("fs/promises");
const path = require("path");
const yargs = require("yargs/yargs");
const { hideBin } = require("yargs/helpers");
const { mdToPdf } = require("md-to-pdf");

const argv = yargs(hideBin(process.argv))
  .option("paper", {
    describe: "Paper size (A4, Letter, etc.)",
    type: "string",
    default: "Letter",
  })
  .option("css", {
    describe: "Path to custom CSS file (relative to repo root or absolute)",
    type: "string",
  })
  .strict()
  .help()
  .argv;

const repoRoot = path.join(__dirname, "..");
const resolveFromRoot = (p) => (path.isAbsolute(p) ? p : path.join(repoRoot, p));

const chapters = [
  "README.md",
  "Threat_Intel.md",
  "Windows.md",
  "Linux.md",
  "Mac_OSX.md",
  "ICS.md",
  "Web.md",
  "Cloud.md",
].map(resolveFromRoot);

(async () => {
  // Verify chapter files exist
  for (const file of chapters) {
    try {
      await fs.access(file);
    } catch {
      console.error(`✗ Missing chapter: ${file}`);
      process.exit(1);
    }
  }

  const pageBreak = "\n\n<div class=\"page-break\"></div>\n\n";
  const combinedMarkdown = (
    await Promise.all(chapters.map((f) => fs.readFile(f, "utf8")))
  ).join(pageBreak);

  const guidesDir = path.join(repoRoot, "Guides");
  await fs.mkdir(guidesDir, { recursive: true });
  const outputPath = path.join(guidesDir, "Red_Teaming_TTPs.pdf");

  try {
    await mdToPdf(
      { content: combinedMarkdown },
      {
        dest: outputPath,
        stylesheet: argv.css ? [resolveFromRoot(argv.css)] : undefined,
        pdf_options: {
          format: argv.paper,
          margin: "25mm",
          printBackground: true,
        },
        launch_options: {
          args: ["--no-sandbox", "--disable-setuid-sandbox"], // for GitHub runner
        },
      }
    );
    console.log(`✓ PDF generated at ${path.relative(repoRoot, outputPath)}`);
  } catch (err) {
    console.error("PDF generation failed:", err);
    process.exit(1);
  }
})();

