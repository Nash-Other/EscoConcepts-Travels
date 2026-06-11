// build.js
const fs = require('fs');
const path = require('path');

// Read templates
const headerHtml = fs.readFileSync(path.join(__dirname, 'templates', 'header.html'), 'utf8');
const footerHtml = fs.readFileSync(path.join(__dirname, 'templates', 'footer.html'), 'utf8');

// Target all HTML files in public (skip admin.html if you want, but we'll update it too)
const publicDir = path.join(__dirname, 'public');
const files = fs.readdirSync(publicDir).filter(f => f.endsWith('.html'));

files.forEach(file => {
  const filePath = path.join(publicDir, file);
  let content = fs.readFileSync(filePath, 'utf8');

  // Replace header
  const headerRegex = /<header\s+class="site-header"[^>]*>[\s\S]*?<\/header>/;
  if (headerRegex.test(content)) {
    content = content.replace(headerRegex, headerHtml);
    console.log(`Updated header in ${file}`);
  } else {
    console.warn(`No header found in ${file}, skipping header replacement.`);
  }

  // Replace footer
  const footerRegex = /<footer\s+class="site-footer"[^>]*>[\s\S]*?<\/footer>/;
  if (footerRegex.test(content)) {
    content = content.replace(footerRegex, footerHtml);
    console.log(`Updated footer in ${file}`);
  } else {
    console.warn(`No footer found in ${file}, skipping footer replacement.`);
  }

  // Write back
  fs.writeFileSync(filePath, content, 'utf8');
});

console.log('Build completed.');