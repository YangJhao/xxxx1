window.api = {
  async request(method, url, body) {
    try {
      const finalUrl = method === 'GET' ? api.cacheBust(url) : url;
      const opts = {
        method,
        headers: { 'Content-Type': 'application/json' },
        cache: 'no-store',
      };
      if (body !== undefined) opts.body = JSON.stringify(body);
      const r = await fetch(finalUrl, opts);
      if (r.status === 401) {
        location.href = '/login';
        return { ok: false, error: '未登录' };
      }
      const text = await r.text();
      try {
        return JSON.parse(text);
      } catch (e) {
        return {
          ok: false,
          status: r.status,
          error: `返回不是 JSON (${r.status})：${text.slice(0, 200) || '空响应'}`,
        };
      }
    } catch (e) {
      const message = e && e.message === 'Failed to fetch'
        ? '服务正在应用配置或网络短暂中断，请稍后刷新'
        : (e.message || '网络请求失败');
      return { ok: false, error: message };
    }
  },
  cacheBust(url) {
    const sep = String(url).includes('?') ? '&' : '?';
    return `${url}${sep}_ts=${Date.now()}`;
  },
  get: (url) => api.request('GET', url),
  post: (url, data) => api.request('POST', url, data || {}),
  put: (url, data) => api.request('PUT', url, data || {}),
  del: (url) => api.request('DELETE', url),
};

window.toast = function (msg, type = 'info', ms = 2500) {
  const c = document.getElementById('toast-container');
  if (!c) return;
  const fullText = String(msg == null ? '' : msg);
  const text = fullText.length > 180 ? `${fullText.slice(0, 180)}...` : fullText;
  const t = document.createElement('div');
  t.className = 'toast-msg ' + type;
  t.textContent = text;
  if (fullText.length > text.length) t.title = fullText;
  c.appendChild(t);
  setTimeout(() => {
    t.style.transition = 'opacity 0.3s';
    t.style.opacity = '0';
    setTimeout(() => t.remove(), 300);
  }, ms);
};

window.formatBytes = function (bytes) {
  if (bytes === 0 || bytes == null) return '0 B';
  const k = 1024;
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), units.length - 1);
  return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + units[i];
};

window.escapeHtml = function (value) {
  if (value == null) return '';
  return String(value).replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));
};

function legacyCopy(value) {
  const previousFocus = document.activeElement;
  const selection = document.getSelection();
  const ranges = [];
  if (selection) {
    for (let i = 0; i < selection.rangeCount; i += 1) ranges.push(selection.getRangeAt(i));
  }
  const ta = document.createElement('textarea');
  ta.value = value;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.left = '-9999px';
  ta.style.top = '0';
  ta.style.width = '2px';
  ta.style.height = '2px';
  ta.style.opacity = '0.01';
  ta.style.zIndex = '2147483647';
  document.body.appendChild(ta);
  let ok = false;
  try {
    ta.focus({ preventScroll: true });
    ta.select();
    ta.setSelectionRange(0, value.length);
    ok = document.execCommand('copy');
  } finally {
    ta.remove();
    if (selection) {
      selection.removeAllRanges();
      ranges.forEach(range => selection.addRange(range));
    }
    if (previousFocus && previousFocus.focus) {
      try { previousFocus.focus({ preventScroll: true }); } catch (e) { previousFocus.focus(); }
    }
  }
  return ok;
}

window.copyElementText = async function (elementOrId) {
  const el = typeof elementOrId === 'string' ? document.getElementById(elementOrId) : elementOrId;
  const value = String(el ? (el.innerText || el.textContent || '') : '').trim();
  if (!value) {
    toast('没有可复制的内容', 'error');
    return false;
  }

  if (el) {
    const selection = document.getSelection();
    const previousRanges = [];
    if (selection) {
      for (let i = 0; i < selection.rangeCount; i += 1) previousRanges.push(selection.getRangeAt(i));
    }
    try {
      const range = document.createRange();
      range.selectNodeContents(el);
      selection.removeAllRanges();
      selection.addRange(range);
      if (document.execCommand('copy')) {
        toast('已复制到剪贴板', 'success');
        return true;
      }
    } catch (e) {
      // Fallback below.
    } finally {
      if (selection) {
        selection.removeAllRanges();
        previousRanges.forEach(range => selection.addRange(range));
      }
    }
  }
  return copyText(value);
};

window.copyText = async function (text) {
  const value = String(text || '').trim();
  if (!value) {
    toast('没有可复制的内容', 'error');
    return false;
  }

  if (legacyCopy(value)) {
    toast('已复制到剪贴板', 'success');
    return true;
  }

  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
      toast('已复制到剪贴板', 'success');
      return true;
    }
  } catch (e) {
    // Fallback below.
  }

  toast('浏览器禁止自动复制，请点击复制按钮后再试', 'error', 4000);
  return false;
};

document.addEventListener('DOMContentLoaded', () => {
  if (document.fonts && document.fonts.check) {
    document.fonts.ready.then(() => {
      if (!document.fonts.check('1em bootstrap-icons') && !document.fonts.check('1em "bootstrap-icons"')) {
        document.body.classList.add('icons-fallback');
      }
    }).catch(() => {});
  }
  const current = location.pathname;
  document.querySelectorAll('.sidebar .nav-link').forEach(link => {
    const href = link.getAttribute('href');
    if (href === current || (href === '/nodes' && current === '/users')) {
      link.classList.add('active');
    }
  });
  const btn = document.getElementById('btnLogout');
  if (btn) {
    btn.addEventListener('click', async () => {
      await api.post('/api/logout');
      location.href = '/login';
    });
  }
});
