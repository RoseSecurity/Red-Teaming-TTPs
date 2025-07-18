#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const yargs = require("yargs/yargs");
const { hideBin } = require("yargs/helpers");
const markdownpdf = require("markdown-pdf");

const argv = yargs(hideBin(process.argv))
  .option("paper", {
    describe: "Paper size (A4, Letter, etc.)",
    type: "string",
    default: "Letter",
  })
  .option("css", {
    describe: "Path to custom CSS file",
    type: "string",
  })
  .strict()
  .help()
  .argv;

const chapters = [
  "README.md",
  "Threat_Intel.md",
  "Windows.md",
  "Linux.md",
  "Mac_OSX.md",
  "ICS.md",
  "Web.md",
  "Cloud.md",
].map((f) => path.resolve(f));

// Verify that every chapter exists before starting
for (const file of chapters) {
  if (!fs.existsSync(file)) {
    console.error(`✗ Missing chapter: ${file}`);
    process.exit(1);
  }
}

const outputPath = path.resolve("Guides/Red_Teaming_TTPs.pdf");

markdownpdf({
  paperFormat: argv.paper,
  cssPath: argv.css ? path.resolve(argv.css) : undefined,
})
  .concat.from.paths(chapters)
  .to(outputPath, function (err) {
    if (err) {
      console.error("PDF generation failed:", err);
      process.exit(1);
    }
    console.log(`✓ PDF generated at ${outputPath}`);
  });
