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

(async () => {
  // Ensure all chapters exist
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

  await fs.mkdir(path.resolve("Guides"), { recursive: true });
  const outputPath = path.resolve("Guides/Red_Teaming_TTPs.pdf");

  try {
    await mdToPdf(
      { content: combinedMarkdown },
      {
        dest: outputPath,
        stylesheet: argv.css ? [path.resolve(argv.css)] : undefined,
        pdf_options: {
          format: argv.paper,
          margin: "25mm",
          printBackground: true,
        },
        launch_options: {
          args: ["--no-sandbox", "--disable-setuid-sandbox"], // for CI runners
        },
      }
    );
    console.log(`✓ PDF generated at ${outputPath}`);
  } catch (err) {
    console.error("PDF generation failed:", err);
    process.exit(1);
  }
})();
