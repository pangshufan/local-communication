(() => {
  let appState = {
    self: {},
    discoverable: { enabled: false, pin: '', remaining_sec: 0, pair_uri: '' },
    peers: [],
    stats: { current_messages: 0, max_messages: 200, current_bytes: 0, max_bytes: 20971520 },
  };
  let messages = [];
  let selectedTargetPeerID = ''; // '' = All Devices Public Timeline
  let selectedTargetName = '';
  let countdownTimer = null;

  // DOM Elements
  const sidebar = document.getElementById('sidebar');
  const stealthBadge = document.getElementById('stealthBadge');
  const selfNameEl = document.getElementById('selfName');
  const selfAddrEl = document.getElementById('selfAddr');
  const selfPINEl = document.getElementById('selfPIN');
  const copyPairUriBtn = document.getElementById('copyPairUriBtn');
  const toggleDiscoverBtn = document.getElementById('toggleDiscoverBtn');
  const discoverSubText = document.getElementById('discoverSubText');
  const peerListEl = document.getElementById('peerList');
  const onlineCountText = document.getElementById('onlineCountText');
  const memText = document.getElementById('memText');
  const memBarFill = document.getElementById('memBarFill');
  const msgCountText = document.getElementById('msgCountText');
  const activeChannelTitle = document.getElementById('activeChannelTitle');
  const activeChannelSub = document.getElementById('activeChannelSub');
  const messageStream = document.getElementById('messageStream');
  const emptyState = document.getElementById('emptyState');
  const msgInput = document.getElementById('msgInput');
  const sendBtn = document.getElementById('sendBtn');
  const fileInput = document.getElementById('fileInput');
  const uploadStatus = document.getElementById('uploadStatus');
  const uploadStatusText = document.getElementById('uploadStatusText');
  const uploadPercentText = document.getElementById('uploadPercentText');
  const dropOverlay = document.getElementById('dropOverlay');

  function formatBytes(bytes) {
    if (!bytes || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 2) + ' ' + units[i];
  }

  function formatTime(ms) {
    const d = new Date(ms);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function osIcon(os) {
    switch ((os || '').toLowerCase()) {
      case 'darwin': return '🍎 macOS';
      case 'windows': return '🪟 Windows';
      case 'linux': return '🐧 Linux';
      default: return '📱 ' + (os || 'Device');
    }
  }

  function renderState() {
    const { self, discoverable, peers, stats } = appState;
    if (self && self.name) {
      selfNameEl.textContent = `${self.name}`;
      selfAddrEl.textContent = self.primary_addr || '-';
    }
    if (discoverable) {
      selfPINEl.textContent = discoverable.pin || '------';
      if (discoverable.enabled && discoverable.remaining_sec > 0) {
        stealthBadge.textContent = `📡 可被发现 (${discoverable.remaining_sec}s)`;
        stealthBadge.classList.add('discoverable');
        toggleDiscoverBtn.textContent = '点击关闭';
        toggleDiscoverBtn.classList.add('active');
        discoverSubText.textContent = `限时开放扫描中，剩余 ${discoverable.remaining_sec} 秒自动恢复隐身`;
      } else {
        stealthBadge.textContent = '🔒 默认隐身';
        stealthBadge.classList.remove('discoverable');
        toggleDiscoverBtn.textContent = '开启 3 分钟';
        toggleDiscoverBtn.classList.remove('active');
        discoverSubText.textContent = '当前静默：不响应任何公开广播探测';
      }
    }

    renderPeers(peers || []);
    renderStats(stats || {});
  }

  function renderStats(stats) {
    const curB = stats.current_bytes || 0;
    const maxB = stats.max_bytes || 20971520;
    const curM = stats.current_messages || 0;
    const maxM = stats.max_messages || 200;
    const pct = Math.min(100, Math.round((curB / maxB) * 100));

    memText.textContent = `${formatBytes(curB)} / ${formatBytes(maxB)}`;
    memBarFill.style.width = `${pct}%`;
    msgCountText.textContent = `${curM} / ${maxM} 条记录`;
  }

  function renderPeers(peers) {
    peerListEl.innerHTML = '';

    // 1. Public All-Device Channel
    const pubItem = document.createElement('div');
    pubItem.className = 'peer-item' + (selectedTargetPeerID === '' ? ' active' : '');
    pubItem.innerHTML = `
      <div class="peer-info">
        <span style="font-size:18px">🌐</span>
        <div>
          <div class="peer-name">全设备公共消息流</div>
          <div class="peer-meta">一处发送 · 全端与手机实时同步</div>
        </div>
      </div>
    `;
    pubItem.onclick = () => selectChannel('', '');
    peerListEl.appendChild(pubItem);

    let onlineCount = 0;
    peers.sort((a, b) => (b.online ? 1 : 0) - (a.online ? 1 : 0));

    peers.forEach((p) => {
      if (p.online) onlineCount++;
      const item = document.createElement('div');
      item.className = 'peer-item' + (selectedTargetPeerID === p.peer_id ? ' active' : '');
      item.innerHTML = `
        <div class="peer-info">
          <span class="status-dot ${p.online ? 'online' : ''}"></span>
          <div style="min-width:0">
            <div class="peer-name">${escapeHtml(p.name)}</div>
            <div class="peer-meta">${osIcon(p.os)} · ${escapeHtml(p.last_addr || '')}</div>
          </div>
        </div>
        <button class="btn btn-sm" title="取消信任配对" data-remove="${escapeHtml(p.peer_id)}">✕</button>
      `;
      item.onclick = (e) => {
        if (e.target.dataset.remove) {
          e.stopPropagation();
          removePeer(e.target.dataset.remove);
          return;
        }
        selectChannel(p.peer_id, p.name);
      };
      peerListEl.appendChild(item);
    });

    onlineCountText.textContent = `${onlineCount} / ${peers.length} 在线`;
  }

  function selectChannel(peerID, peerName) {
    selectedTargetPeerID = peerID;
    selectedTargetName = peerName;
    if (!peerID) {
      activeChannelTitle.textContent = '🌐 全设备公共消息流';
      activeChannelSub.textContent = '在此发送的文字、粘贴截图与文件将实时同步至所有已配对设备与手机';
    } else {
      activeChannelTitle.textContent = `🎯 定向私发：${peerName}`;
      activeChannelSub.textContent = '仅本机与该目标设备可见（点对点专属通道）';
    }
    sidebar.classList.remove('open');
    renderPeers(appState.peers || []);
    renderMessages();
  }

  function renderMessages() {
    const filtered = messages.filter((m) => {
      if (!selectedTargetPeerID) return true;
      return m.target_peer_id === selectedTargetPeerID || m.sender_id === selectedTargetPeerID;
    });

    messageStream.querySelectorAll('.msg-card').forEach((el) => el.remove());

    if (filtered.length === 0) {
      emptyState.style.display = 'block';
      return;
    }
    emptyState.style.display = 'none';

    filtered.forEach((m) => {
      messageStream.appendChild(buildMessageCard(m));
    });
    messageStream.scrollTop = messageStream.scrollHeight;
  }

  function buildMessageCard(m) {
    const isSelf = appState.self && m.sender_id === appState.self.peer_id;
    const card = document.createElement('div');
    card.className = 'msg-card' + (isSelf ? ' self' : '');

    const targetBadge = m.target_peer_id
      ? `<span class="target-pill">私发 → ${escapeHtml(m.target_name || m.target_peer_id)}</span>`
      : '';

    let bodyHtml = '';
    if (m.kind === 'text') {
      bodyHtml = `
        <div class="msg-text">${escapeHtml(m.text)}</div>
        <div style="display:flex;justify-content:flex-end">
          <button class="btn btn-sm copy-btn">📋 复制内容</button>
        </div>
      `;
    } else if (m.kind === 'image') {
      const imgUrl = m.inline_url || `/api/inline/${m.id}`;
      bodyHtml = `
        <a href="${imgUrl}" target="_blank" rel="noopener">
          <img class="msg-image" src="${imgUrl}" alt="剪贴板图片" loading="lazy" />
        </a>
        ${m.text ? `<div class="msg-text">${escapeHtml(m.text)}</div>` : ''}
      `;
    } else if (m.kind === 'file' && m.file) {
      const f = m.file;
      const dlUrl = f.download_url || `/api/files/stream/${f.file_id}`;
      const shaShort = f.sha256 ? ` · SHA256: ${f.sha256.slice(0, 10)}...` : ' · 本机磁盘零拷贝流';
      bodyHtml = `
        <div class="file-box">
          <div style="min-width:0">
            <div class="file-title">📄 ${escapeHtml(f.file_name)}</div>
            <div class="file-sub">${formatBytes(f.file_size)}${escapeHtml(shaShort)}</div>
          </div>
          <a class="btn btn-primary btn-sm" href="${dlUrl}" download="${escapeHtml(f.file_name)}" style="text-decoration:none;white-space:nowrap">
            ⬇ 下载
          </a>
        </div>
      `;
    }

    card.innerHTML = `
      <div class="msg-header">
        <div>
          <span class="msg-sender">${escapeHtml(m.sender_name || 'Device')}</span>
          <span>(${osIcon(m.sender_os)})</span>
          ${targetBadge}
        </div>
        <span>${formatTime(m.created_at)}</span>
      </div>
      ${bodyHtml}
    `;

    const copyBtn = card.querySelector('.copy-btn');
    if (copyBtn) {
      copyBtn.onclick = () => copyToClipboard(m.text, copyBtn);
    }
    return card;
  }

  function copyToClipboard(text, btnEl) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        if (btnEl) {
          const orig = btnEl.textContent;
          btnEl.textContent = '✅ 已复制';
          setTimeout(() => (btnEl.textContent = orig), 1400);
        }
      });
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      if (btnEl) {
        const orig = btnEl.textContent;
        btnEl.textContent = '✅ 已复制';
        setTimeout(() => (btnEl.textContent = orig), 1400);
      }
    }
  }

  function escapeHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // Send Text Message
  async function sendTextMessage() {
    const text = msgInput.value.trim();
    if (!text) return;
    msgInput.value = '';
    const res = await fetch('/api/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        kind: 'text',
        text,
        target_peer_id: selectedTargetPeerID,
        target_name: selectedTargetName,
      }),
    });
    if (!res.ok) {
      alert('发送失败: ' + (await res.text()));
    }
  }

  // Send Inline Clipboard Image (< 2MB) or Fallback to File Upload (> 2MB)
  async function sendClipboardImage(file) {
    if (file.size > 1.8 * 1024 * 1024) {
      return uploadFiles([file]);
    }
    const reader = new FileReader();
    reader.onload = async () => {
      const result = String(reader.result || '');
      const base64 = result.split(',')[1];
      if (!base64) return;
      const res = await fetch('/api/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          kind: 'image',
          image_base64: base64,
          image_mime: file.type || 'image/png',
          target_peer_id: selectedTargetPeerID,
          target_name: selectedTargetName,
        }),
      });
      if (!res.ok) {
        alert('发送图片失败: ' + (await res.text()));
      }
    };
    reader.readAsDataURL(file);
  }

  // Stream Multi-File Upload via XMLHttpRequest with progress & speed indicator
  function uploadFiles(fileList) {
    if (!fileList || fileList.length === 0) return;
    const formData = new FormData();
    formData.append('target_peer_id', selectedTargetPeerID);
    formData.append('target_name', selectedTargetName);
    let totalBytes = 0;
    for (let i = 0; i < fileList.length; i++) {
      formData.append('file', fileList[i]);
      totalBytes += fileList[i].size;
    }

    const xhr = new XMLHttpRequest();
    const startTime = Date.now();
    uploadStatus.style.display = 'flex';
    uploadStatusText.textContent = `正在流式传输 ${fileList.length} 个文件 (${formatBytes(totalBytes)})...`;
    uploadPercentText.textContent = '0%';

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) {
        const pct = Math.round((e.loaded / e.total) * 100);
        const elapsedSec = Math.max(0.1, (Date.now() - startTime) / 1000);
        const speed = formatBytes(e.loaded / elapsedSec) + '/s';
        uploadPercentText.textContent = `${pct}% (${speed})`;
      }
    };
    xhr.onload = () => {
      uploadStatus.style.display = 'none';
      fileInput.value = '';
      if (xhr.status !== 200) {
        alert('文件传输失败: ' + xhr.responseText);
      }
    };
    xhr.onerror = () => {
      uploadStatus.style.display = 'none';
      alert('网络中断，文件传输失败');
    };
    xhr.open('POST', '/api/files/upload');
    xhr.send(formData);
  }

  // Event Listeners
  sendBtn.onclick = sendTextMessage;
  msgInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendTextMessage();
    }
  });

  // Paste Clipboard Image or Files directly (Ctrl+V / Cmd+V)
  window.addEventListener('paste', (e) => {
    const items = (e.clipboardData && e.clipboardData.items) || [];
    const filesToUpload = [];
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      if (item.kind === 'file') {
        const f = item.getAsFile();
        if (f) {
          if (f.type && f.type.startsWith('image/')) {
            e.preventDefault();
            sendClipboardImage(f);
            return;
          }
          filesToUpload.push(f);
        }
      }
    }
    if (filesToUpload.length > 0) {
      e.preventDefault();
      uploadFiles(filesToUpload);
    }
  });

  // Drag & Drop File Streaming
  let dragDepth = 0;
  window.addEventListener('dragenter', (e) => {
    e.preventDefault();
    dragDepth++;
    dropOverlay.classList.add('active');
  });
  window.addEventListener('dragleave', (e) => {
    e.preventDefault();
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) dropOverlay.classList.remove('active');
  });
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => {
    e.preventDefault();
    dragDepth = 0;
    dropOverlay.classList.remove('active');
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      uploadFiles(e.dataTransfer.files);
    }
  });

  document.getElementById('selectFileBtn').onclick = () => fileInput.click();
  fileInput.onchange = () => uploadFiles(fileInput.files);

  // Discoverable Switch Toggle
  toggleDiscoverBtn.onclick = async () => {
    const nextState = !(appState.discoverable && appState.discoverable.enabled);
    const res = await fetch('/api/discoverable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: nextState, duration_sec: 180 }),
    });
    if (res.ok) {
      appState = await res.json();
      renderState();
    }
  };

  copyPairUriBtn.onclick = () => {
    if (appState.discoverable && appState.discoverable.pair_uri) {
      copyToClipboard(appState.discoverable.pair_uri, copyPairUriBtn);
    }
  };

  // Clear Memory Buttons
  document.getElementById('clearLocalBtn').onclick = async () => {
    await fetch('/api/messages/clear', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ all_devices: false }),
    });
  };
  document.getElementById('clearAllBtn').onclick = async () => {
    if (!confirm('确定要同时清空所有已连接设备上的内存聊天记录吗？')) return;
    await fetch('/api/messages/clear', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ all_devices: true }),
    });
  };

  async function removePeer(peerID) {
    if (!confirm('确定从信任列表中移除该设备吗？')) return;
    const res = await fetch('/api/peers/remove', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ peer_id: peerID }),
    });
    if (res.ok) {
      appState = await res.json();
      if (selectedTargetPeerID === peerID) selectChannel('', '');
      renderState();
    }
  }

  // Modals
  function openModal(id) {
    document.getElementById(id).classList.add('open');
  }
  function closeModal(id) {
    document.getElementById(id).classList.remove('open');
  }
  document.querySelectorAll('[data-close]').forEach((btn) => {
    btn.onclick = () => closeModal(btn.dataset.close);
  });

  document.getElementById('openPairModalBtn').onclick = () => openModal('pairModal');
  document.getElementById('localPathBtn').onclick = () => openModal('localPathModal');
  document.getElementById('openSidebarBtn').onclick = () => sidebar.classList.add('open');
  document.getElementById('closeSidebarBtn').onclick = () => sidebar.classList.remove('open');

  // Pair Direct (IP:Port#PIN)
  document.getElementById('pairDirectBtn').onclick = async () => {
    const val = document.getElementById('pairDirectInput').value.trim();
    if (!val) return;
    const btn = document.getElementById('pairDirectBtn');
    btn.textContent = '连接中...';
    const res = await fetch('/api/peers/pair', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ addr: val, pin: '' }),
    });
    btn.textContent = '立即配对';
    if (!res.ok) {
      alert('配对失败: ' + (await res.text()));
      return;
    }
    document.getElementById('pairDirectInput').value = '';
    closeModal('pairModal');
  };

  // Scan LAN for Discoverable Peers
  document.getElementById('scanLanBtn').onclick = async () => {
    const listEl = document.getElementById('scanResultList');
    listEl.innerHTML = '<div style="font-size:12px;color:var(--text-muted);text-align:center;padding:12px">正在扫描局域网内已开启「允许被发现」的设备...</div>';
    const res = await fetch('/api/peers/scan');
    if (!res.ok) {
      listEl.innerHTML = '<div style="color:var(--danger);font-size:12px;padding:12px">扫描失败</div>';
      return;
    }
    const data = await res.json();
    const nodes = data.discovered || [];
    if (nodes.length === 0) {
      listEl.innerHTML = '<div style="font-size:12px;color:var(--text-muted);text-align:center;padding:12px">未发现处于开放状态的设备。请确认目标设备已点击「允许被发现」，或直接使用上方 IP:Port#配对码 隐身直连。</div>';
      return;
    }
    listEl.innerHTML = '';
    nodes.forEach((n) => {
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;align-items:center;justify-content:space-between;padding:8px 10px;background:#0b1120;border:1px solid var(--border);border-radius:8px;gap:8px';
      row.innerHTML = `
        <div>
          <div style="font-size:13px;font-weight:600">${escapeHtml(n.name)}</div>
          <div style="font-size:11px;color:var(--text-muted)">${osIcon(n.os)} · ${escapeHtml(n.addr)}</div>
        </div>
        <div style="display:flex;gap:6px">
          <input class="input-field" style="width:95px;padding:5px 8px" placeholder="6位配对码" data-pin-for="${escapeHtml(n.addr)}" />
          <button class="btn btn-primary btn-sm" data-pair-addr="${escapeHtml(n.addr)}">配对</button>
        </div>
      `;
      row.querySelector('[data-pair-addr]').onclick = async () => {
        const pin = row.querySelector('[data-pin-for]').value.trim();
        if (!pin) {
          alert('请输入对方设备上显示的 6 位配对码');
          return;
        }
        const r = await fetch('/api/peers/pair', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ addr: n.addr, pin }),
        });
        if (!r.ok) {
          alert('配对失败: ' + (await r.text()));
          return;
        }
        closeModal('pairModal');
      };
      listEl.appendChild(row);
    });
  };

  // Mobile QR Modal
  const mobileIpSelect = document.getElementById('mobileIpSelect');
  async function loadMobileQR(ip) {
    const q = ip ? `?ip=${encodeURIComponent(ip)}` : '';
    const res = await fetch('/api/mobile-qr' + q);
    if (!res.ok) return;
    const data = await res.json();
    document.getElementById('qrSvgContainer').innerHTML = data.svg;
    document.getElementById('mobileUrlText').textContent = data.url;
    if (!ip && data.ips && data.ips.length > 0) {
      mobileIpSelect.innerHTML = '';
      data.ips.forEach((addr) => {
        const opt = document.createElement('option');
        opt.value = addr;
        opt.textContent = addr;
        mobileIpSelect.appendChild(opt);
      });
    }
  }
  document.getElementById('openMobileQRBtn').onclick = () => {
    openModal('mobileModal');
    loadMobileQR('');
  };
  mobileIpSelect.onchange = () => loadMobileQR(mobileIpSelect.value);

  // Zero-Copy Local File Path Registration
  document.getElementById('confirmLocalPathBtn').onclick = async () => {
    const filePath = document.getElementById('localFilePathInput').value.trim();
    if (!filePath) return;
    const res = await fetch('/api/files/register-path', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        file_path: filePath,
        target_peer_id: selectedTargetPeerID,
        target_name: selectedTargetName,
      }),
    });
    if (!res.ok) {
      alert('无法注册文件路径: ' + (await res.text()));
      return;
    }
    document.getElementById('localFilePathInput').value = '';
    closeModal('localPathModal');
  };

  // Countdown ticker for discoverable mode
  if (!countdownTimer) {
    countdownTimer = setInterval(() => {
      if (appState.discoverable && appState.discoverable.enabled && appState.discoverable.remaining_sec > 0) {
        appState.discoverable.remaining_sec--;
        if (appState.discoverable.remaining_sec <= 0) {
          appState.discoverable.enabled = false;
        }
        renderState();
      }
    }, 1000);
  }

  // WebSocket Connection with Auto-Reconnect
  function connectWS() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${location.host}/ws`);
    ws.onmessage = (ev) => {
      try {
        const pkt = JSON.parse(ev.data);
        switch (pkt.type) {
          case 'init':
            appState = pkt.data.state || appState;
            messages = pkt.data.messages || [];
            renderState();
            renderMessages();
            break;
          case 'state_update':
            appState = pkt.data || appState;
            renderState();
            break;
          case 'stats_update':
            appState.stats = pkt.data || appState.stats;
            renderStats(appState.stats);
            break;
          case 'new_message':
            if (pkt.data && !messages.some((m) => m.id === pkt.data.id)) {
              messages.push(pkt.data);
              renderMessages();
              if (document.hidden && 'Notification' in window && Notification.permission === 'granted') {
                new Notification(`LanChat · ${pkt.data.sender_name}`, {
                  body: pkt.data.kind === 'text' ? pkt.data.text : `[收到${pkt.data.kind === 'image' ? '截图' : '文件'}]`,
                });
              }
            }
            break;
          case 'clear_messages':
            messages = [];
            renderMessages();
            break;
        }
      } catch (err) {
        console.error(err);
      }
    };
    ws.onclose = () => {
      setTimeout(connectWS, 2000);
    };
  }

  if ('Notification' in window && Notification.permission === 'default') {
    window.addEventListener('click', () => Notification.requestPermission(), { once: true });
  }

  connectWS();
})();
