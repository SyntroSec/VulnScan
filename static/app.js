(() => {
  "use strict";

  const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];
  const SEV_COLORS = {
    Critical: "#fb7185",
    High: "#ffb45c",
    Medium: "#fde047",
    Low: "#7dd3fc",
    Info: "#94a3b8",
  };

  const PORT_PRESETS = {
    common: null,
    web: "80,443,8080,8443",
    remote: "22,3389,5900",
    fulltop: "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443,27017",
    custom: "",
  };

  const state = {
    activeScanId: null,
    eventSource: null,
    findings: [],
    filter: "all",
    expanded: new Set(),
    pieChart: null,
    barChart: null,
  };

  const el = {
    form: document.getElementById("scanForm"),
    targets: document.getElementById("targets"),
    portPreset: document.getElementById("portPreset"),
    ports: document.getElementById("ports"),
    concurrency: document.getElementById("concurrency"),
    timeout: document.getElementById("timeout"),
    grabBanners: document.getElementById("grabBanners"),
    runPlugins: document.getElementById("runPlugins"),
    skipDiscovery: document.getElementById("skipDiscovery"),
    startBtn: document.getElementById("startBtn"),
    formError: document.getElementById("formError"),
    healthBadge: document.getElementById("healthBadge"),
    healthDot: document.getElementById("healthDot"),
    healthText: document.getElementById("healthText"),
    refreshScansBtn: document.getElementById("refreshScansBtn"),
    activeScanMeta: document.getElementById("activeScanMeta"),
    statusPill: document.getElementById("statusPill"),
    phaseLabel: document.getElementById("phaseLabel"),
    progressLabel: document.getElementById("progressLabel"),
    progressBar: document.getElementById("progressBar"),
    progressMessage: document.getElementById("progressMessage"),
    metricAlive: document.getElementById("metricAlive"),
    metricPorts: document.getElementById("metricPorts"),
    metricFindings: document.getElementById("metricFindings"),
    metricHot: document.getElementById("metricHot"),
    hostStatusList: document.getElementById("hostStatusList"),
    scanList: document.getElementById("scanList"),
    scanCount: document.getElementById("scanCount"),
    findingsBody: document.getElementById("findingsBody"),
    findingsEmpty: document.getElementById("findingsEmpty"),
    pluginsGrid: document.getElementById("pluginsGrid"),
    reloadPluginsBtn: document.getElementById("reloadPluginsBtn"),
    severityFilters: document.getElementById("severityFilters"),
  };

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {
      headers: { Accept: "application/json", ...(options.headers || {}) },
      ...options,
    });
    let payload = null;
    const text = await response.text();
    try {
      payload = text ? JSON.parse(text) : null;
    } catch {
      payload = { detail: text };
    }
    if (!response.ok) {
      const detail = payload?.detail;
      const message = typeof detail === "string"
        ? detail
        : Array.isArray(detail)
          ? detail.map((d) => d.msg || JSON.stringify(d)).join("; ")
          : response.statusText;
      throw new Error(message || `Request failed (${response.status})`);
    }
    return payload;
  }

  function setFormError(message) {
    if (!message) {
      el.formError.classList.add("hidden");
      el.formError.textContent = "";
      return;
    }
    el.formError.textContent = message;
    el.formError.classList.remove("hidden");
  }

  function setStatusPill(status) {
    const normalized = (status || "idle").toLowerCase();
    el.statusPill.textContent = status || "Idle";
    el.statusPill.className = `status-pill status-${normalized}`;
  }

  function updateProgress(payload) {
    const progress = Number(payload.progress ?? 0);
    el.progressBar.style.width = `${Math.max(0, Math.min(100, progress))}%`;
    el.progressLabel.textContent = `${Math.round(progress)}%`;
    el.phaseLabel.textContent = (payload.phase || "waiting").toString();
    el.progressMessage.textContent = payload.message || "";
    setStatusPill(payload.status || "idle");

    const summary = payload.summary || {};
    el.metricAlive.textContent = `${summary.hosts_alive ?? 0}/${summary.hosts_total ?? 0}`;
    el.metricPorts.textContent = String(summary.open_ports ?? 0);
    el.metricFindings.textContent = String(summary.findings_total ?? 0);
    const by = summary.by_severity || {};
    el.metricHot.textContent = String((by.Critical || 0) + (by.High || 0));

    updateCharts(by, payload.host_status || []);
    renderHostStatus(payload.host_status || []);
  }

  function ensureCharts() {
    const pieCtx = document.getElementById("severityPie");
    const barCtx = document.getElementById("severityBar");
    if (!state.pieChart) {
      state.pieChart = new Chart(pieCtx, {
        type: "doughnut",
        data: {
          labels: SEVERITIES,
          datasets: [{
            data: [0, 0, 0, 0, 0],
            backgroundColor: SEVERITIES.map((s) => SEV_COLORS[s]),
            borderWidth: 0,
            hoverOffset: 6,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: "bottom",
              labels: { color: "#94a3b8", boxWidth: 12, font: { family: "IBM Plex Mono", size: 11 } },
            },
          },
          cutout: "62%",
        },
      });
    }
    if (!state.barChart) {
      state.barChart = new Chart(barCtx, {
        type: "bar",
        data: {
          labels: ["Alive", "Down", "Scanned", "Error"],
          datasets: [{
            label: "Hosts",
            data: [0, 0, 0, 0],
            backgroundColor: ["#3ee6d4", "#64748b", "#86efac", "#fb7185"],
            borderRadius: 6,
            maxBarThickness: 36,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: {
              ticks: { color: "#94a3b8", font: { family: "IBM Plex Mono", size: 10 } },
              grid: { color: "rgba(255,255,255,0.04)" },
            },
            y: {
              beginAtZero: true,
              ticks: { color: "#94a3b8", precision: 0, font: { family: "IBM Plex Mono", size: 10 } },
              grid: { color: "rgba(255,255,255,0.06)" },
            },
          },
        },
      });
    }
  }

  function updateCharts(bySeverity, hostStatus) {
    ensureCharts();
    const values = SEVERITIES.map((s) => Number(bySeverity?.[s] || 0));
    state.pieChart.data.datasets[0].data = values;
    state.pieChart.update("none");

    const counts = { alive: 0, down: 0, scanned: 0, error: 0 };
    (hostStatus || []).forEach((h) => {
      const st = (h.state || "").toLowerCase();
      if (st === "scanned") counts.scanned += 1;
      else if (st === "error") counts.error += 1;
      else if (st === "alive" || h.alive) counts.alive += 1;
      else counts.down += 1;
    });
    state.barChart.data.datasets[0].data = [
      counts.alive,
      counts.down,
      counts.scanned,
      counts.error,
    ];
    state.barChart.update("none");
  }

  function renderHostStatus(hosts) {
    if (!hosts.length) {
      el.hostStatusList.innerHTML = '<li class="text-slate-500">No host updates yet</li>';
      return;
    }
    el.hostStatusList.innerHTML = hosts.map((h) => {
      const tone = h.state === "scanned" || h.alive
        ? "text-mint-400"
        : h.state === "error"
          ? "text-rose-400"
          : "text-slate-500";
      return `<li class="${tone}">
        <span class="text-slate-300">${escapeHtml(h.host)}</span>
        · ${escapeHtml(h.state || (h.alive ? "alive" : "down"))}
        ${h.open_ports ? `· ${h.open_ports} open` : ""}
      </li>`;
    }).join("");
  }

  function closeEventSource() {
    if (state.eventSource) {
      state.eventSource.close();
      state.eventSource = null;
    }
  }

  function subscribeToScan(scanId) {
    closeEventSource();
    state.activeScanId = scanId;
    el.activeScanMeta.textContent = `Scan ${scanId}`;
    const source = new EventSource(`/api/scan/${scanId}/events`);
    state.eventSource = source;

    const onPayload = async (event) => {
      let payload;
      try {
        payload = JSON.parse(event.data);
      } catch {
        return;
      }
      updateProgress(payload);
      if (payload.status === "completed" || payload.status === "failed") {
        closeEventSource();
        await loadScanDetail(scanId);
        await loadScans();
      }
    };

    source.addEventListener("progress", onPayload);
    source.addEventListener("queued", onPayload);
    source.addEventListener("started", onPayload);
    source.addEventListener("completed", onPayload);
    source.addEventListener("failed", onPayload);
    source.onerror = () => {
      // Browser will retry; if scan finished elsewhere, detail fetch covers it
    };
  }

  async function loadScanDetail(scanId) {
    const detail = await api(`/api/scan/${scanId}`);
    state.activeScanId = scanId;
    state.findings = detail.findings || [];
    state.expanded.clear();
    el.activeScanMeta.textContent = `Scan ${scanId} · ${(detail.targets || []).join(", ")}`;
    updateProgress({
      progress: detail.progress,
      phase: detail.phase,
      message: detail.message,
      status: detail.status,
      summary: detail.summary,
      host_status: detail.host_status || [],
    });
    renderFindings();
    highlightActiveScan();
  }

  function renderFindings() {
    const filtered = state.filter === "all"
      ? state.findings
      : state.findings.filter((f) => f.severity === state.filter);

    el.findingsBody.innerHTML = "";
    if (!filtered.length) {
      el.findingsEmpty.classList.remove("hidden");
      el.findingsEmpty.textContent = state.findings.length
        ? "No findings for this severity filter."
        : "No findings for this scan.";
      return;
    }
    el.findingsEmpty.classList.add("hidden");

    const frag = document.createDocumentFragment();
    filtered.forEach((finding, index) => {
      const rowId = `${finding.finding_id}-${index}`;
      const open = state.expanded.has(rowId);
      const tr = document.createElement("tr");
      tr.className = "findings-row";
      tr.dataset.rowId = rowId;
      const hostLabel = finding.port != null
        ? `${finding.host}:${finding.port}`
        : finding.host;
      tr.innerHTML = `
        <td class="py-3 pr-3 align-top"><span class="sev-badge sev-${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span></td>
        <td class="py-3 pr-3 align-top text-slate-100">${escapeHtml(finding.title)}</td>
        <td class="py-3 pr-3 align-top font-mono text-xs text-slate-400">${escapeHtml(hostLabel)}</td>
        <td class="py-3 pr-3 align-top font-mono text-xs text-slate-500">${escapeHtml(finding.plugin_id)}</td>
        <td class="py-3 align-top"><span class="chevron ${open ? "open" : ""}">▸</span></td>
      `;
      frag.appendChild(tr);

      const detail = document.createElement("tr");
      detail.className = `findings-detail ${open ? "" : "hidden"}`;
      detail.dataset.detailFor = rowId;
      const cves = (finding.cve_ids && finding.cve_ids.length)
        ? finding.cve_ids.join(", ")
        : "n/a";
      const refs = (finding.references || [])
        .map((r) => `<li><a class="text-mint-400 hover:underline break-all" href="${escapeHtml(r)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r)}</a></li>`)
        .join("") || "<li class='text-slate-500'>None</li>";
      detail.innerHTML = `
        <td colspan="5" class="px-3 py-4">
          <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 text-sm">
            <div>
              <p class="text-xs font-mono uppercase tracking-wider text-slate-500 mb-1">Description</p>
              <p class="text-slate-300">${escapeHtml(finding.description || "—")}</p>
              <p class="text-xs font-mono uppercase tracking-wider text-slate-500 mt-3 mb-1">CVE</p>
              <p class="font-mono text-ember-400">${escapeHtml(cves)}</p>
              <p class="text-xs font-mono uppercase tracking-wider text-slate-500 mt-3 mb-1">Remediation</p>
              <p class="text-slate-300">${escapeHtml(finding.remediation || "—")}</p>
            </div>
            <div>
              <p class="text-xs font-mono uppercase tracking-wider text-slate-500 mb-1">Evidence / Proof</p>
              <pre>${escapeHtml(finding.evidence || "")}</pre>
              <p class="text-xs font-mono uppercase tracking-wider text-slate-500 mt-3 mb-1">References</p>
              <ul class="space-y-1">${refs}</ul>
            </div>
          </div>
        </td>
      `;
      frag.appendChild(detail);

      tr.addEventListener("click", () => {
        if (state.expanded.has(rowId)) {
          state.expanded.delete(rowId);
        } else {
          state.expanded.add(rowId);
        }
        renderFindings();
      });
    });
    el.findingsBody.appendChild(frag);
  }

  function highlightActiveScan() {
    el.scanList.querySelectorAll(".scan-item").forEach((node) => {
      node.classList.toggle("active", node.dataset.scanId === state.activeScanId);
    });
  }

  async function loadScans() {
    const data = await api("/api/scans");
    const scans = data.scans || [];
    el.scanCount.textContent = String(scans.length);
    if (!scans.length) {
      el.scanList.innerHTML = '<p class="text-sm text-slate-500">No scans yet.</p>';
      return;
    }
    el.scanList.innerHTML = scans.map((scan) => {
      const summary = scan.summary || {};
      const by = summary.by_severity || {};
      const hot = (by.Critical || 0) + (by.High || 0);
      return `
        <button type="button" class="scan-item ${scan.scan_id === state.activeScanId ? "active" : ""}" data-scan-id="${escapeHtml(scan.scan_id)}">
          <div class="flex items-center justify-between gap-2">
            <span class="font-mono text-xs text-mint-400">${escapeHtml(scan.scan_id)}</span>
            <span class="status-pill status-${escapeHtml((scan.status || "").toLowerCase())}">${escapeHtml(scan.status)}</span>
          </div>
          <p class="mt-1 text-sm text-slate-200 truncate">${escapeHtml((scan.targets || []).join(", "))}</p>
          <p class="mt-1 text-xs font-mono text-slate-500">
            findings ${summary.findings_total ?? 0} · hot ${hot} · ${escapeHtml(scan.started_at || "")}
          </p>
        </button>
      `;
    }).join("");

    el.scanList.querySelectorAll(".scan-item").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const scanId = btn.dataset.scanId;
        const scan = scans.find((s) => s.scan_id === scanId);
        if (scan && (scan.status === "running" || scan.status === "queued")) {
          subscribeToScan(scanId);
        }
        await loadScanDetail(scanId);
      });
    });
  }

  async function loadPlugins() {
    const data = await api("/api/plugins");
    const plugins = data.plugins || [];
    if (!plugins.length) {
      el.pluginsGrid.innerHTML = '<p class="text-sm text-slate-500">No plugins loaded.</p>';
      return;
    }
    el.pluginsGrid.innerHTML = plugins.map((p) => `
      <article class="plugin-card">
        <h3>${escapeHtml(p.name)}</h3>
        <p class="mt-1 text-xs font-mono text-mint-400">${escapeHtml(p.plugin_id)} · ${escapeHtml(p.type)}</p>
        <p class="mt-2 text-sm text-slate-400">${escapeHtml(p.description || "No description")}</p>
        ${p.signature_count != null ? `<p class="mt-2 text-xs font-mono text-slate-500">${p.signature_count} signature rule(s)</p>` : ""}
      </article>
    `).join("");
  }

  async function checkHealth() {
    try {
      await api("/api/health");
      el.healthDot.className = "h-2 w-2 rounded-full bg-mint-400";
      el.healthText.textContent = "API online";
    } catch {
      el.healthDot.className = "h-2 w-2 rounded-full bg-rose-400";
      el.healthText.textContent = "API offline";
    }
  }

  function syncPortPreset() {
    const preset = el.portPreset.value;
    if (preset === "custom") {
      el.ports.classList.remove("hidden");
      el.ports.required = true;
      return;
    }
    el.ports.classList.add("hidden");
    el.ports.required = false;
    el.ports.value = PORT_PRESETS[preset] || "";
  }

  el.portPreset.addEventListener("change", syncPortPreset);

  el.form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setFormError("");
    const rawTargets = el.targets.value
      .split(/[\n,]+/)
      .map((t) => t.trim())
      .filter(Boolean);
    if (!rawTargets.length) {
      setFormError("Enter at least one target.");
      return;
    }

    const preset = el.portPreset.value;
    const ports = preset === "common"
      ? null
      : (preset === "custom" ? el.ports.value.trim() : PORT_PRESETS[preset]);

    const body = {
      targets: rawTargets,
      ports,
      concurrency: Number(el.concurrency.value || 100),
      timeout: Number(el.timeout.value || 1.5),
      grab_banners: el.grabBanners.checked,
      run_plugins: el.runPlugins.checked,
      skip_discovery: el.skipDiscovery.checked,
    };

    el.startBtn.disabled = true;
    try {
      const result = await api("/api/scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const scanId = result.scan.scan_id;
      await loadScans();
      subscribeToScan(scanId);
      updateProgress({
        progress: 0,
        phase: "queued",
        message: "Scan queued",
        status: "queued",
        summary: result.scan.summary,
        host_status: [],
      });
      state.findings = [];
      renderFindings();
    } catch (err) {
      setFormError(err.message || String(err));
    } finally {
      el.startBtn.disabled = false;
    }
  });

  el.refreshScansBtn.addEventListener("click", () => {
    loadScans().catch((err) => setFormError(err.message));
  });

  el.reloadPluginsBtn.addEventListener("click", () => {
    loadPlugins().catch((err) => setFormError(err.message));
  });

  el.severityFilters.addEventListener("click", (event) => {
    const btn = event.target.closest("[data-sev]");
    if (!btn) return;
    state.filter = btn.dataset.sev;
    el.severityFilters.querySelectorAll(".filter-chip").forEach((chip) => {
      chip.classList.toggle("active", chip === btn);
    });
    renderFindings();
  });

  async function boot() {
    ensureCharts();
    syncPortPreset();
    await checkHealth();
    await Promise.all([loadScans(), loadPlugins()]);
    // Auto-select newest completed/active scan if present
    const data = await api("/api/scans");
    const scans = data.scans || [];
    if (scans.length) {
      const preferred = scans.find((s) => s.status === "running" || s.status === "queued") || scans[0];
      if (preferred.status === "running" || preferred.status === "queued") {
        subscribeToScan(preferred.scan_id);
      }
      await loadScanDetail(preferred.scan_id);
    }
  }

  boot().catch((err) => {
    console.error(err);
    setFormError(err.message || String(err));
  });
})();
