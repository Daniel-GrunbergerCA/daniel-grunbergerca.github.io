const postsContainer = document.getElementById('posts-list');
const filterBar      = document.getElementById('filter-bar');

let allPosts  = [];
let activeTags = new Set(['all']);

async function init() {
  try {
    const res = await fetch('posts.json');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    allPosts = await res.json();
    allPosts.sort((a, b) => new Date(b.date) - new Date(a.date));
    buildTagFilter();
    renderPosts();
  } catch (err) {
    postsContainer.innerHTML =
      `<div class="error-msg">// error: could not load posts.json - ${escapeHtml(err.message)}</div>`;
  }
}

const ALLOWED_TAGS = new Set(['pwn', 'reversing', 'cve', 'mobile', 'web']);

function collectTags() {
  const seen = new Set();
  allPosts.forEach(p => p.tags.forEach(t => { if (ALLOWED_TAGS.has(t)) seen.add(t); }));
  return [...seen].sort();
}

function buildTagFilter() {
  filterBar.appendChild(makeFilterBtn('all', true));
  collectTags().forEach(tag => filterBar.appendChild(makeFilterBtn(tag, false)));
}

function makeFilterBtn(tag, active) {
  const btn = document.createElement('button');
  btn.className   = 'filter-tag' + (active ? ' active' : '');
  btn.dataset.tag = tag;
  btn.textContent = tag === 'all' ? '# all' : `# ${tag}`;
  btn.addEventListener('click', () => handleTagClick(tag));
  return btn;
}

function handleTagClick(tag) {
  if (tag === 'all') {
    activeTags = new Set(['all']);
  } else {
    activeTags.delete('all');
    if (activeTags.has(tag)) {
      activeTags.delete(tag);
      if (activeTags.size === 0) activeTags.add('all');
    } else {
      activeTags.add(tag);
    }
  }
  syncFilterButtons();
  renderPosts();
}

function syncFilterButtons() {
  filterBar.querySelectorAll('.filter-tag').forEach(btn => {
    btn.classList.toggle('active', activeTags.has(btn.dataset.tag));
  });
}

function renderPosts() {
  postsContainer.innerHTML = '';

  const visible = activeTags.has('all')
    ? allPosts
    : allPosts.filter(p => p.tags.some(t => activeTags.has(t)));

  if (visible.length === 0) {
    postsContainer.innerHTML =
      `<div class="no-results"><span class="accent">//</span> no posts match the selected filter</div>`;
    return;
  }

  visible.forEach(post => postsContainer.appendChild(makePostCard(post)));
}

function makePostCard(post) {
  const card = document.createElement('article');
  card.className = 'post-card';

  const tagsHtml = post.tags
    .filter(t => ALLOWED_TAGS.has(t))
    .map(t => `<span class="tag ${resolveTagClass(t)}">${escapeHtml(t)}</span>`)
    .join('');

  card.innerHTML = `
    <div class="post-meta">
      <span class="post-date">${formatDate(post.date)}</span>
      <div class="post-tags">${tagsHtml}</div>
    </div>
    <div class="post-title">${escapeHtml(post.title)}</div>
    <div class="post-excerpt">${escapeHtml(post.excerpt)}</div>
  `;

  card.addEventListener('click', () => {
    window.location.href = `post.html?slug=${encodeURIComponent(post.slug)}`;
  });

  return card;
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

init();
