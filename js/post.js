const params     = new URLSearchParams(window.location.search);
const slug       = params.get('slug');

const titleEl   = document.getElementById('post-title');
const dateEl    = document.getElementById('post-date');
const tagsEl    = document.getElementById('post-tags');
const contentEl = document.getElementById('post-content');

async function loadPost() {
  if (!slug) {
    showError('No post slug specified.');
    return;
  }

  if (!/^[a-zA-Z0-9--]+$/.test(slug)) {
    showError('Invalid post slug.');
    return;
  }

  contentEl.innerHTML = '<div class="loading">Loading post</div>';

  try {
    const manifestRes = await fetch('posts.json');
    if (!manifestRes.ok) throw new Error(`Could not fetch post index (HTTP ${manifestRes.status}).`);
    const posts = await manifestRes.json();

    const meta = posts.find(p => p.slug === slug);
    if (!meta) throw new Error(`Post "${escapeHtml(slug)}" not found in index.`);

    const mdRes = await fetch(`posts/${slug}.md`);
    if (!mdRes.ok) throw new Error(`Could not fetch post content (HTTP ${mdRes.status}).`);
    const markdown = await mdRes.text();

    document.title = `${meta.title} // DanielSec`;

    titleEl.textContent = meta.title;
    dateEl.textContent  = formatDate(meta.date);
    tagsEl.innerHTML    = meta.tags
      .map(t => `<span class="tag ${resolveTagClass(t)}">${escapeHtml(t)}</span>`)
      .join('');

    marked.use({ breaks: true, gfm: true });
    contentEl.innerHTML = marked.parse(markdown);

    contentEl.querySelectorAll('pre code').forEach(block => {
      hljs.highlightElement(block);
    });

  } catch (err) {
    showError(err.message);
  }
}

function showError(msg) {
  contentEl.innerHTML = `<div class="error-msg">// error: ${escapeHtml(msg)}</div>`;
}

const KNOWN_TAGS = new Set([
  'ctf','cve','htb','web','pwn','rev','reversing','linux','privesc',
  'windows','crypto','forensics','misc','meta','mobile'
]);

function resolveTagClass(tag) {
  return KNOWN_TAGS.has(tag) ? `tag-${tag}` : 'tag-default';
}

function formatDate(dateStr) {
  const d = new Date(dateStr + 'T00:00:00');
  return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: '2-digit' });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

loadPost();
