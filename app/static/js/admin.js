(function () {
  'use strict';

  const state = { groups: [], users: [], tabs: [], fazTargets: [] };

  function el(tag, attrs, children) {
    const e = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (k === 'text') e.textContent = v;
      else e.setAttribute(k, v);
    });
    (children || []).forEach((c) => e.appendChild(c));
    return e;
  }

  // ── Admin sub-tab switching ────────────────────────────────────────────────
  document.querySelectorAll('.admin-tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.admin-tab').forEach((b) => b.classList.remove('active'));
      document.querySelectorAll('.admin-panel').forEach((p) => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.panel).classList.add('active');
      if (btn.dataset.panel === 'panel-logs') loadLogs();
    });
  });

  // ── Groups ─────────────────────────────────────────────────────────────────
  function renderGroups() {
    const tbody = document.getElementById('groupsTbody');
    tbody.innerHTML = '';
    state.groups.forEach((g) => {
      const tr = el('tr', {});
      tr.appendChild(el('td', { text: g.name }));
      tr.appendChild(el('td', { text: g.members.join(', ') || '—' }));
      tr.appendChild(el('td', { text: g.allowed_tabs.join(', ') || '—' }));
      const actions = el('td', {});
      const editBtn = el('button', { class: 'btn btn-sm', text: 'Edit' });
      editBtn.addEventListener('click', () => openGroupModal(g));
      const delBtn = el('button', { class: 'btn btn-sm', text: 'Delete' });
      delBtn.addEventListener('click', () => deleteGroup(g.name));
      actions.appendChild(editBtn);
      actions.appendChild(delBtn);
      tr.appendChild(actions);
      tbody.appendChild(tr);
    });
  }

  async function loadGroups() {
    const resp = await fetch('/admin/api/groups');
    state.groups = await resp.json();
    renderGroups();
  }

  async function deleteGroup(name) {
    if (!confirm(`Delete group "${name}"?`)) return;
    await fetch(`/admin/api/groups/${encodeURIComponent(name)}`, { method: 'DELETE' });
    await loadGroups();
  }

  function openGroupModal(group) {
    const modal = document.getElementById('groupModal');
    document.getElementById('groupModalMode').value = group ? 'edit' : 'create';
    document.getElementById('groupModalOrigName').value = group ? group.name : '';
    document.getElementById('groupModalTitle').textContent = group ? 'Edit Group' : 'New Group';
    document.getElementById('groupNameInput').value = group ? group.name : '';
    document.getElementById('groupNameInput').disabled = !!group;
    document.getElementById('groupModalError').classList.add('hidden');

    const tabWrap = document.getElementById('tabCheckboxes');
    tabWrap.innerHTML = '';
    state.tabs.forEach((t) => {
      const label = el('label', { class: 'checkbox-item' });
      const input = el('input', { type: 'checkbox', value: t.key });
      input.checked = !!(group && group.allowed_tabs.includes(t.key));
      label.appendChild(input);
      label.appendChild(document.createTextNode(' ' + t.name));
      tabWrap.appendChild(label);
    });

    const memberWrap = document.getElementById('memberCheckboxes');
    memberWrap.innerHTML = '';
    state.users.forEach((u) => {
      const label = el('label', { class: 'checkbox-item' });
      const input = el('input', { type: 'checkbox', value: u.username });
      input.checked = !!(group && group.members.includes(u.username));
      label.appendChild(input);
      label.appendChild(document.createTextNode(' ' + u.username));
      memberWrap.appendChild(label);
    });

    document.getElementById('groupAdomRestrictInput').checked = !!(group && group.adom_restrict);
    const targetWrap = document.getElementById('groupTargetCheckboxes');
    targetWrap.innerHTML = '';
    state.fazTargets.forEach((t) => {
      const label = el('label', { class: 'checkbox-item' });
      const input = el('input', { type: 'checkbox', value: t.label });
      input.checked = !!(group && group.allowed_adoms && group.allowed_adoms.includes(t.label));
      label.appendChild(input);
      label.appendChild(document.createTextNode(' ' + t.label));
      targetWrap.appendChild(label);
    });

    modal.classList.remove('hidden');
  }

  function closeGroupModal() {
    document.getElementById('groupModal').classList.add('hidden');
  }

  async function saveGroup() {
    const mode = document.getElementById('groupModalMode').value;
    const origName = document.getElementById('groupModalOrigName').value;
    const name = document.getElementById('groupNameInput').value.trim();
    const allowed_tabs = Array.from(
      document.querySelectorAll('#tabCheckboxes input:checked')
    ).map((i) => i.value);
    const members = Array.from(
      document.querySelectorAll('#memberCheckboxes input:checked')
    ).map((i) => i.value);
    const adom_restrict = document.getElementById('groupAdomRestrictInput').checked;
    const allowed_adoms = Array.from(
      document.querySelectorAll('#groupTargetCheckboxes input:checked')
    ).map((i) => i.value);

    const errBox = document.getElementById('groupModalError');
    errBox.classList.add('hidden');

    let resp;
    if (mode === 'create') {
      resp = await fetch('/admin/api/groups', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, members, allowed_tabs, adom_restrict, allowed_adoms }),
      });
    } else {
      resp = await fetch(`/admin/api/groups/${encodeURIComponent(origName)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ members, allowed_tabs, adom_restrict, allowed_adoms }),
      });
    }
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      errBox.textContent = body.error || 'Save failed.';
      errBox.classList.remove('hidden');
      return;
    }
    closeGroupModal();
    await loadGroups();
  }

  document.getElementById('btnNewGroup').addEventListener('click', () => openGroupModal(null));
  document.getElementById('groupModalClose').addEventListener('click', closeGroupModal);
  document.getElementById('groupModalCancel').addEventListener('click', closeGroupModal);
  document.getElementById('groupModalSave').addEventListener('click', saveGroup);

  // ── FAZ Targets ────────────────────────────────────────────────────────────
  function renderFazTargets() {
    const tbody = document.getElementById('fazTargetsTbody');
    tbody.innerHTML = '';
    state.fazTargets.forEach((t) => {
      const tr = el('tr', {});
      tr.appendChild(el('td', { text: t.label }));
      tr.appendChild(el('td', { text: t.host }));
      tr.appendChild(el('td', { text: t.adom }));
      const actions = el('td', {});
      const editBtn = el('button', { class: 'btn btn-sm', text: 'Edit' });
      editBtn.addEventListener('click', () => openFazTargetModal(t));
      const delBtn = el('button', { class: 'btn btn-sm', text: 'Delete' });
      delBtn.addEventListener('click', () => deleteFazTarget(t.label));
      actions.appendChild(editBtn);
      actions.appendChild(delBtn);
      tr.appendChild(actions);
      tbody.appendChild(tr);
    });
  }

  async function loadFazTargets() {
    const resp = await fetch('/admin/api/faz-targets');
    state.fazTargets = await resp.json();
    renderFazTargets();
  }

  async function deleteFazTarget(label) {
    if (!confirm(`Delete FAZ target "${label}"?`)) return;
    await fetch(`/admin/api/faz-targets/${encodeURIComponent(label)}`, { method: 'DELETE' });
    await loadFazTargets();
  }

  function openFazTargetModal(target) {
    const modal = document.getElementById('fazTargetModal');
    document.getElementById('fazTargetModalMode').value = target ? 'edit' : 'create';
    document.getElementById('fazTargetModalOrigLabel').value = target ? target.label : '';
    document.getElementById('fazTargetModalTitle').textContent = target ? 'Edit FAZ Target' : 'New FAZ Target';
    document.getElementById('fazTargetLabelInput').value = target ? target.label : '';
    document.getElementById('fazTargetLabelInput').disabled = !!target;
    document.getElementById('fazTargetHostInput').value = target ? target.host : '';
    document.getElementById('fazTargetAdomInput').value = target ? target.adom : 'root';
    // Never redisplay a stored bearer token — the server no longer sends
    // the raw value anyway (see token_set). Leave blank on edit; the save
    // handler only sends a token if the admin types a new one.
    const tokenInput = document.getElementById('fazTargetTokenInput');
    tokenInput.value = '';
    tokenInput.placeholder = target ? 'Leave blank to keep existing token' : 'Bearer token';
    document.getElementById('fazTargetModalError').classList.add('hidden');
    modal.classList.remove('hidden');
  }

  function closeFazTargetModal() {
    document.getElementById('fazTargetModal').classList.add('hidden');
  }

  async function saveFazTarget() {
    const mode = document.getElementById('fazTargetModalMode').value;
    const origLabel = document.getElementById('fazTargetModalOrigLabel').value;
    const label = document.getElementById('fazTargetLabelInput').value.trim();
    const host = document.getElementById('fazTargetHostInput').value.trim();
    const adom = document.getElementById('fazTargetAdomInput').value.trim() || 'root';
    const token = document.getElementById('fazTargetTokenInput').value.trim();

    const errBox = document.getElementById('fazTargetModalError');
    errBox.classList.add('hidden');

    let resp;
    if (mode === 'create') {
      resp = await fetch('/admin/api/faz-targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label, host, adom, token }),
      });
    } else {
      // A blank token field means "keep the existing token" — only send it
      // if the admin actually typed a replacement value.
      const body = { host, adom };
      if (token) body.token = token;
      resp = await fetch(`/admin/api/faz-targets/${encodeURIComponent(origLabel)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    }
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      errBox.textContent = body.error || 'Save failed.';
      errBox.classList.remove('hidden');
      return;
    }
    closeFazTargetModal();
    await loadFazTargets();
  }

  document.getElementById('btnNewFazTarget').addEventListener('click', () => openFazTargetModal(null));
  document.getElementById('fazTargetModalClose').addEventListener('click', closeFazTargetModal);
  document.getElementById('fazTargetModalCancel').addEventListener('click', closeFazTargetModal);
  document.getElementById('fazTargetModalSave').addEventListener('click', saveFazTarget);

  // ── Users ──────────────────────────────────────────────────────────────────
  function renderUsers() {
    const tbody = document.getElementById('usersTbody');
    tbody.innerHTML = '';
    state.users.forEach((u) => {
      const tr = el('tr', {});
      tr.appendChild(el('td', { text: u.username }));
      tr.appendChild(el('td', { text: u.role }));
      tbody.appendChild(tr);
    });
  }

  async function loadUsers() {
    const resp = await fetch('/admin/api/users');
    state.users = await resp.json();
    renderUsers();
  }

  // ── Logs ───────────────────────────────────────────────────────────────────
  async function loadLogLevels() {
    const resp = await fetch('/admin/api/logs?limit=1');
    const body = await resp.json();
    const select = document.getElementById('logLevelSelect');
    select.innerHTML = '';
    body.levels.forEach((lvl) => {
      const opt = el('option', { value: lvl, text: lvl });
      if (lvl === body.current_level) opt.selected = true;
      select.appendChild(opt);
    });
    document.getElementById('logCurrentLevel').textContent = body.current_level;
  }

  async function loadLogs() {
    const resp = await fetch('/admin/api/logs?limit=200');
    const body = await resp.json();
    document.getElementById('logCurrentLevel').textContent = body.current_level;
    document.getElementById('logCount').textContent = body.count;
    const container = document.getElementById('logContainer');
    container.innerHTML = '';
    body.entries.slice().reverse().forEach((entry) => {
      const line = el('div', {
        class: 'log-line',
        text: `[${entry.ts}] ${entry.level} ${entry.component}: ${entry.message}`,
      });
      container.appendChild(line);
    });
  }

  document.getElementById('btnSetLevel').addEventListener('click', async () => {
    const level = document.getElementById('logLevelSelect').value;
    await fetch('/admin/api/logs/level', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ level }),
    });
    await loadLogs();
  });
  document.getElementById('btnRefreshLogs').addEventListener('click', loadLogs);
  document.getElementById('btnClearLogs').addEventListener('click', async () => {
    if (!confirm('Clear the log buffer?')) return;
    await fetch('/admin/api/logs', { method: 'DELETE' });
    await loadLogs();
  });

  // ── Init ───────────────────────────────────────────────────────────────────
  async function init() {
    const tabsResp = await fetch('/admin/api/tabs');
    state.tabs = await tabsResp.json();
    await loadUsers();
    await loadFazTargets();
    await loadGroups();
    await loadLogLevels();
  }

  init();
})();
