#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const projectRoot = path.resolve(process.env.GITHUB_WORKSPACE || process.cwd());
const outputFlag = process.argv.indexOf("--output");
if (outputFlag >= 0 && !process.argv[outputFlag + 1]) {
  throw new Error("--output requires a directory");
}
const outputRoot = path.resolve(
  outputFlag >= 0 ? process.argv[outputFlag + 1] : path.join(projectRoot, "public"),
);
const config = JSON.parse(
  fs.readFileSync(path.join(projectRoot, ".infra/ci/pages.json"), "utf8"),
);
const fence = String.fromCharCode(96).repeat(3);

function isWithin(parent, child) {
  const relative = path.relative(parent, child);
  return relative !== "" && !relative.startsWith(".." + path.sep) && !path.isAbsolute(relative);
}

function rejectSymlinkPath(base, destination) {
  let current = base;
  for (const part of ["", ...path.relative(base, destination).split(path.sep)]) {
    if (part) current = path.join(current, part);
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) {
      throw new Error("pages output path must not contain symbolic links: " + current);
    }
  }
}

const projectPublic = path.join(projectRoot, "public");
const projectTarget = path.join(projectRoot, "target");
const temporaryRoot = path.resolve(os.tmpdir());
const safeTemporaryOutput =
  path.dirname(outputRoot) === temporaryRoot &&
  path.basename(outputRoot).startsWith("rs-redact-pages-");
if (
  outputRoot !== projectPublic &&
  !isWithin(projectTarget, outputRoot) &&
  !safeTemporaryOutput
) {
  throw new Error("pages output must be public, below target, or a dedicated rs-redact-pages-* temporary directory");
}
const allowedOutputBase = safeTemporaryOutput
  ? temporaryRoot
  : outputRoot === projectPublic
    ? projectRoot
    : projectTarget;
rejectSymlinkPath(allowedOutputBase, outputRoot);

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderInline(value) {
  return escapeHtml(value)
    .replace(/!\[([^\]]*)\]\(([^)]+)\)/g, (_, alt, url) =>
      '<img src="' + safeUrl(url) + '" alt="' + alt + '">',
    )
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, text, url) =>
      '<a href="' + safeUrl(url) + '">' + text + "</a>",
    )
    .replace(/\x60([^\x60]+)\x60/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>");
}

function safeUrl(value) {
  const trimmed = value.trim();
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) return "#";
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(trimmed)?.[1].toLowerCase();
  if (scheme && !["http", "https", "mailto"].includes(scheme)) return "#";
  return trimmed.replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

if (process.argv.includes("--self-test")) {
  for (const unsafe of ["javascript:alert(1)", "java\tscript:alert(1)", "java\nscript:alert(1)", "data:text/html,x", "vbscript:x"]) {
    if (safeUrl(unsafe) !== "#") throw new Error("unsafe URL was not rejected");
  }
  for (const safe of ["https://example.com", "mailto:test@example.com", "doc/guide.md", "#usage"]) {
    if (safeUrl(safe) === "#") throw new Error("safe URL was rejected: " + safe);
  }
  const rendered = renderMarkdown(
    "### Heading\n\n- item\n\n| A | B |\n| - | - |\n| 1 | 2 |\n\n" +
      fence +
      "rust\nfn main() {}\n" +
      fence +
      "\n\n[link](https://example.com) ![image](https://example.com/a.png)",
  );
  for (const fragment of ["<h3", "<ul>", "<table>", '<pre><code class="language-rust">', "<a href=", "<img src="]) {
    if (!rendered.includes(fragment)) {
      throw new Error("Markdown renderer omitted expected fragment: " + fragment);
    }
  }
  console.log("Pages renderer self-test passed");
  process.exit(0);
}

function slugify(value) {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^\p{L}\p{N}\s-]/gu, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-");
}

function joinSoftLines(lines) {
  return lines.reduce((text, line) => {
    const next = line.trim();
    if (!text) return next;
    const left = Array.from(text).at(-1) || "";
    const right = Array.from(next)[0] || "";
    const cjk = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]/u;
    return text + (cjk.test(left) && cjk.test(right) ? "" : " ") + next;
  }, "");
}

function splitTableRow(line) {
  return line
    .trim()
    .replace(/^\|/, "")
    .replace(/\|$/, "")
    .split("|")
    .map((cell) => cell.trim());
}

function renderMarkdown(markdown) {
  const lines = markdown.replace(/\r\n/g, "\n").split("\n");
  const html = [];
  let paragraph = [];
  let list = null;
  let codeLanguage = "";
  let codeLines = null;

  const flushParagraph = () => {
    if (paragraph.length) {
      html.push("<p>" + renderInline(joinSoftLines(paragraph)) + "</p>");
      paragraph = [];
    }
  };
  const closeList = () => {
    if (list) html.push("</" + list + ">");
    list = null;
  };

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const trimmed = line.trim();
    if (trimmed.startsWith(fence)) {
      if (codeLines) {
        html.push(
          '<pre><code class="language-' +
            escapeHtml(codeLanguage) +
            '">' +
            escapeHtml(codeLines.join("\n")) +
            "</code></pre>",
        );
        codeLines = null;
        codeLanguage = "";
      } else {
        flushParagraph();
        closeList();
        codeLanguage = trimmed.slice(3).trim();
        codeLines = [];
      }
      continue;
    }
    if (codeLines) {
      codeLines.push(line);
      continue;
    }
    if (!trimmed) {
      flushParagraph();
      closeList();
      continue;
    }
    if (
      trimmed.startsWith("|") &&
      /^\s*\|?[\s:-]+\|[\s|:-]*$/.test(lines[index + 1] || "")
    ) {
      flushParagraph();
      closeList();
      const rows = [];
      while (index < lines.length && lines[index].trim().startsWith("|")) {
        rows.push(splitTableRow(lines[index]));
        index += 1;
      }
      index -= 1;
      html.push(
        "<table><thead><tr>" +
          rows[0].map((cell) => "<th>" + renderInline(cell) + "</th>").join("") +
          "</tr></thead><tbody>" +
          rows
            .slice(2)
            .map(
              (row) =>
                "<tr>" +
                row.map((cell) => "<td>" + renderInline(cell) + "</td>").join("") +
                "</tr>",
            )
            .join("") +
          "</tbody></table>",
      );
      continue;
    }
    const heading = /^(#{1,6})\s+(.+)$/.exec(trimmed);
    if (heading) {
      flushParagraph();
      closeList();
      const level = heading[1].length;
      const text = heading[2].replace(/\s+#+$/, "");
      html.push(
        "<h" +
          level +
          ' id="' +
          escapeHtml(slugify(text)) +
          '">' +
          renderInline(text) +
          "</h" +
          level +
          ">",
      );
      continue;
    }
    const unordered = /^[-*]\s+(.+)$/.exec(trimmed);
    const ordered = /^\d+[.)]\s+(.+)$/.exec(trimmed);
    if (unordered || ordered) {
      flushParagraph();
      const type = unordered ? "ul" : "ol";
      if (list !== type) {
        closeList();
        list = type;
        html.push("<" + type + ">");
      }
      const parts = [(unordered || ordered)[1]];
      while (/^\s+\S/.test(lines[index + 1] || "")) {
        parts.push(lines[index + 1].trim());
        index += 1;
      }
      html.push("<li>" + renderInline(joinSoftLines(parts)) + "</li>");
      continue;
    }
    const quote = /^>\s*(.+)$/.exec(trimmed);
    if (quote) {
      flushParagraph();
      closeList();
      html.push("<blockquote>" + renderInline(quote[1]) + "</blockquote>");
      continue;
    }
    paragraph.push(trimmed);
  }
  flushParagraph();
  closeList();
  if (codeLines) {
    html.push("<pre><code>" + escapeHtml(codeLines.join("\n")) + "</code></pre>");
  }
  return html.join("\n");
}

function readLead(markdown, languageReadmes) {
  const lines = markdown.replace(/\r\n/g, "\n").split("\n");
  let index = 0;
  const badges = [];
  while (!lines[index]?.trim()) index += 1;
  if (/^#\s+/.test(lines[index]?.trim() || "")) index += 1;
  while (!lines[index]?.trim()) index += 1;
  while (/^\[!\[[^\]]*]\([^)]+\)]\([^)]+\)$/.test(lines[index]?.trim() || "")) {
    const badge = lines[index].trim();
    if (!languageReadmes.some((readme) => badge.endsWith("(" + readme + ")"))) {
      badges.push(badge);
    }
    index += 1;
  }
  while (!lines[index]?.trim()) index += 1;
  return { badges, body: lines.slice(index).join("\n") };
}

function relativePrefix(output) {
  return "../".repeat(output.split("/").length - 1);
}

function copyIfPresent(source, destination) {
  if (fs.existsSync(source)) {
    fs.cpSync(source, destination, { recursive: true });
  }
}

function coverageSummary() {
  const coverageFile = path.join(projectRoot, "coverage.json");
  if (!fs.existsSync(coverageFile)) {
    return {
      functionsPercent: "n/a",
      linePercent: "n/a",
      regionsPercent: "n/a",
      reportUrl: "coverage/",
    };
  }
  const totals = JSON.parse(fs.readFileSync(coverageFile, "utf8")).data.reduce(
    (result, item) => {
      for (const metric of ["functions", "lines", "regions"]) {
        result[metric].covered += item.totals?.[metric]?.covered || 0;
        result[metric].count += item.totals?.[metric]?.count || 0;
      }
      return result;
    },
    {
      functions: { covered: 0, count: 0 },
      lines: { covered: 0, count: 0 },
      regions: { covered: 0, count: 0 },
    },
  );
  const percent = (metric) =>
    metric.count ? ((metric.covered * 100) / metric.count).toFixed(2) + "%" : "n/a";
  return {
    functionsPercent: percent(totals.functions),
    linePercent: percent(totals.lines),
    regionsPercent: percent(totals.regions),
    reportUrl: "coverage/",
  };
}

const configuredLanguages = Object.entries(config.languages);
for (const [, item] of configuredLanguages) {
  if (path.isAbsolute(item.readme) || item.readme === "" || item.readme.split(/[\\/]/).includes("..")) {
    throw new Error("language README must be a contained relative path: " + item.readme);
  }
  const source = path.resolve(projectRoot, item.readme);
  if (!isWithin(projectRoot, source)) {
    throw new Error("language README must remain inside the project");
  }
  if (fs.existsSync(source)) {
    rejectSymlinkPath(projectRoot, source);
    const metadata = fs.lstatSync(source);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error("language README must be a regular non-symlink file: " + item.readme);
    }
  }
}
const languages = configuredLanguages.filter(([, item]) =>
  fs.existsSync(path.join(projectRoot, item.readme)),
);
if (!languages.some(([code]) => code === config.default_language)) {
  throw new Error("default language README is missing");
}
const destinations = new Set();
for (const [, item] of languages) {
  if (path.isAbsolute(item.output) || item.output === "" || item.output.split(/[\\/]/).includes("..")) {
    throw new Error("language output must be a contained relative path: " + item.output);
  }
  const destination = path.resolve(outputRoot, item.output);
  if (!isWithin(outputRoot, destination) || destinations.has(destination)) {
    throw new Error("language outputs must be unique and contained below the pages output");
  }
  destinations.add(destination);
}

fs.rmSync(outputRoot, { recursive: true, force: true });
fs.mkdirSync(path.join(outputRoot, "assets"), { recursive: true });
fs.copyFileSync(
  path.join(projectRoot, ".infra/pages/site.css"),
  path.join(outputRoot, "assets/site.css"),
);
copyIfPresent(
  path.join(projectRoot, "target/llvm-cov/html"),
  path.join(outputRoot, "coverage"),
);
copyIfPresent(
  path.join(projectRoot, "coverage-badge.json"),
  path.join(outputRoot, "coverage-badge.json"),
);
copyIfPresent(
  path.join(projectRoot, "ci-summary.json"),
  path.join(outputRoot, "ci-summary.json"),
);

const coverage = coverageSummary();
const repositoryName = process.env.GITHUB_REPOSITORY || "qubit-ltd/rs-redact";
const repositoryUrl = "https://github.com/" + repositoryName;
const runUrl = process.env.GITHUB_RUN_ID
  ? repositoryUrl + "/actions/runs/" + process.env.GITHUB_RUN_ID
  : repositoryUrl;
const metadata = {
  repository: repositoryName,
  runUrl,
  commit: process.env.GITHUB_SHA || "",
  branch: process.env.GITHUB_REF_NAME || "",
  coverage,
  generatedAt: new Date().toISOString(),
};
fs.writeFileSync(
  path.join(outputRoot, "ci-summary.json"),
  JSON.stringify(metadata, null, 2) + "\n",
);
if (!fs.existsSync(path.join(outputRoot, "coverage-badge.json"))) {
  const linePercent = Number.parseFloat(coverage.linePercent);
  const color = Number.isNaN(linePercent)
    ? "lightgrey"
    : linePercent >= 90
      ? "brightgreen"
      : linePercent >= 80
        ? "green"
        : linePercent >= 70
          ? "yellowgreen"
          : linePercent >= 60
            ? "orange"
            : "red";
  fs.writeFileSync(
    path.join(outputRoot, "coverage-badge.json"),
    JSON.stringify(
      {
        schemaVersion: 1,
        label: "coverage",
        message: coverage.linePercent,
        color,
      },
      null,
      2,
    ) + "\n",
  );
}

const languageReadmes = languages.map(([, item]) => item.readme);
for (const [code, item] of languages) {
  const prefix = relativePrefix(item.output);
  const nav = languages
    .map(([navCode, navItem]) => {
      const target = navItem.output.replace(/index\.html$/, "");
      const current = navCode === code ? ' aria-current="page"' : "";
      return (
        '<a href="' +
        escapeHtml(prefix + (target || "index.html")) +
        '"' +
        current +
        ">" +
        escapeHtml(navItem.label || navCode) +
        "</a>"
      );
    })
    .join("");
  const readme = fs.readFileSync(path.join(projectRoot, item.readme), "utf8");
  const lead = readLead(readme, languageReadmes);
  const destination = path.join(outputRoot, item.output);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  const title = config.site_title || "qubit-redact";
  const document =
    '<!doctype html><html lang="' +
    escapeHtml(code) +
    '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    "<title>" +
    escapeHtml(title + " - " + (item.label || code)) +
    '</title><link rel="stylesheet" href="' +
    prefix +
    'assets/site.css"></head><body><header><nav><a class="brand" href="' +
    prefix +
    'index.html">' +
    escapeHtml(title) +
    '</a><span class="links">' +
    nav +
    '<a href="' +
    prefix +
    'coverage/">Coverage ' +
    escapeHtml(coverage.linePercent) +
    '</a><a href="' +
    repositoryUrl +
    '">Repository</a></span></nav></header><main><section class="hero"><h1>' +
    escapeHtml(title) +
    '</h1><div class="badges">' +
    lead.badges.map(renderInline).join("") +
    '</div></section><article>' +
    renderMarkdown(lead.body) +
    "</article></main><footer>Generated with rs-infra tooling.</footer></body></html>\n";
  fs.writeFileSync(destination, document);
}

console.log("Pages site generated at " + outputRoot);
