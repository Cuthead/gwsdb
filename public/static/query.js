// On-demand probe button for the query page. POSTs to /check, which
// synchronously calls the China box's probe server via the gwsdb-probe Worker
// and returns the result. Updates the button + status span in place —
// no page reload, no queue polling. CSP allows connect-src 'self'.
(function () {
	const btn = document.getElementById("probeBtn");
	if (!btn) return;
	const status = document.getElementById("probeStatus");
	const ip = btn.dataset.ip;

	btn.addEventListener("click", async function () {
		btn.disabled = true;
		status.textContent = "检测中…";
		status.style.color = "#666666";
		try {
			const resp = await fetch("/check?ip=" + encodeURIComponent(ip), { method: "POST" });
			const data = await resp.json();
			if (data.error) {
				status.textContent = data.error;
				status.style.color = "#CC0000";
			} else if (data.ok) {
				status.innerHTML = '<font color="#008000">&#x2713; 可达 (' + (data.rttMs || 0) + " ms)</font>";
			} else {
				status.innerHTML = '<font color="#CC0000">&#x2717; 不可达</font>';
			}
			document.dispatchEvent(new CustomEvent("gwsdb:history-refresh"));
		} catch (e) {
			status.textContent = "请求失败";
			status.style.color = "#CC0000";
		} finally {
			btn.disabled = false;
		}
	});
})();

// Check history cache + client-side pagination. The complete retained history
// for one IP is stored as one IndexedDB snapshot. Cached data renders first;
// /api/history then returns no rows when its version is unchanged, or a full
// replacement snapshot when a new check has arrived.
(function () {
	var section = document.getElementById("historySection");
	if (!section) return;

	var DB_NAME = "gwsdb-check-history";
	var DB_VERSION = 1;
	var STORE_NAME = "snapshots";
	var ip = section.dataset.ip;
	var checks = [];
	var page = 1;
	var db = null;
	var cache = null;

	var reasonLabels = {
		dial: "tcp: TCP dial timeout",
		handshake: "tls: TLS handshake failed",
		cn: "tls: Certificate CN mismatch",
		http: "http: HTTP timeout",
		status: "http: HTTP status code mismatch",
		ping: "icmp: ICMP ping timeout"
	};

	// Checks recorded by the scanner carry a "scan:"/"recheck:" origin prefix
	// on their reason (successes use the bare "scan:ok"/"recheck:ok"); strip
	// it for the label and show it as a tag. Rows without a prefix (older
	// data, on-demand probes) render as before.
	function originTag(check) {
		var split = (check.reason || "").match(/^(scan|recheck):(.*)$/);
		return split ? { tag: "[" + split[1] + "] ", reason: split[2] } : { tag: "", reason: check.reason || "" };
	}

	function reasonLabel(check) {
		var origin = originTag(check);
		if (origin.reason === "ping") {
			return origin.tag + ((check.detail || "").indexOf("rtt_too_low") !== -1 ? "icmp: RTT too low" : "icmp: ICMP ping timeout");
		}
		return origin.tag + (reasonLabels[origin.reason] || origin.reason || "");
	}

	function formatTime(value) {
		if (!value) return "-";
		var date = new Date(value);
		if (isNaN(date.getTime())) return "-";
		function pad(n) { return String(n).padStart(2, "0"); }
		return date.getUTCFullYear() + "-" + pad(date.getUTCMonth() + 1) + "-" + pad(date.getUTCDate()) + " " +
			pad(date.getUTCHours()) + ":" + pad(date.getUTCMinutes()) + ":" + pad(date.getUTCSeconds());
	}

	function pageSize() {
		var value = document.getElementById("historyPageSize").value;
		return value === "all" ? Infinity : parseInt(value, 10);
	}

	function buildRow(check) {
		var tr = document.createElement("tr");

		var time = document.createElement("td");
		time.textContent = formatTime(check.checkedAt);
		tr.appendChild(time);

		var result = document.createElement("td");
		var resultFont = document.createElement("font");
		resultFont.color = check.ok ? "#008000" : "#CC0000";
		resultFont.textContent = (check.ok ? "✓ " : "✗ ") + (check.ok ? "Reachable" : "Unreachable");
		result.appendChild(resultFont);
		tr.appendChild(result);

		var reason = document.createElement("td");
		var label = check.ok ? originTag(check).tag.trim() : reasonLabel(check);
		if (label) reason.appendChild(document.createTextNode(label));
		if (label && check.detail) reason.appendChild(document.createElement("br"));
		if (check.detail) {
			var detail = document.createElement("tt");
			detail.textContent = check.detail;
			reason.appendChild(detail);
		}
		if (!label && !check.detail) reason.textContent = "-";
		tr.appendChild(reason);

		var rtt = document.createElement("td");
		rtt.textContent = check.rttMs ? check.rttMs + " ms" : "-";
		tr.appendChild(rtt);

		return tr;
	}

	function render() {
		var status = document.getElementById("historyStatus");
		var tableWrap = document.getElementById("historyTableWrap");
		var pager = document.getElementById("historyPager");
		if (!checks.length) {
			status.textContent = "No check history.";
			status.classList.remove("gwsdb-hidden");
			tableWrap.classList.add("gwsdb-hidden");
			pager.classList.add("gwsdb-hidden");
			return;
		}

		var size = pageSize();
		var totalPages = size === Infinity ? 1 : Math.ceil(checks.length / size);
		if (page > totalPages) page = totalPages;
		if (page < 1) page = 1;
		var start = size === Infinity ? 0 : (page - 1) * size;
		var end = size === Infinity ? checks.length : Math.min(checks.length, start + size);
		var tbody = document.getElementById("historyTableBody");
		tbody.textContent = "";
		for (var i = start; i < end; i++) tbody.appendChild(buildRow(checks[i]));

		document.getElementById("historyCount").textContent = checks.length;
		document.getElementById("historyPageInfo").textContent = "Page " + page + " of " + totalPages;
		document.getElementById("historyPrev").disabled = page <= 1;
		document.getElementById("historyNext").disabled = page >= totalPages;
		status.classList.add("gwsdb-hidden");
		tableWrap.classList.remove("gwsdb-hidden");
		pager.classList.remove("gwsdb-hidden");
	}

	function openCache() {
		return new Promise(function (resolve, reject) {
			if (!window.indexedDB) return reject(new Error("IndexedDB unavailable"));
			var request = indexedDB.open(DB_NAME, DB_VERSION);
			request.onupgradeneeded = function () {
				if (!request.result.objectStoreNames.contains(STORE_NAME)) {
					request.result.createObjectStore(STORE_NAME, {keyPath: "ip"});
				}
			};
			request.onsuccess = function () {
				request.result.onversionchange = function () { request.result.close(); };
				resolve(request.result);
			};
			request.onerror = function () { reject(request.error || new Error("could not open IndexedDB")); };
			request.onblocked = function () { reject(new Error("IndexedDB open blocked")); };
		});
	}

	function readCache(database) {
		return new Promise(function (resolve, reject) {
			var request = database.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(ip);
			request.onsuccess = function () { resolve(request.result || null); };
			request.onerror = function () { reject(request.error || new Error("could not read IndexedDB")); };
		});
	}

	function writeCache(database, snapshot, force) {
		return new Promise(function (resolve, reject) {
			var tx = database.transaction(STORE_NAME, "readwrite");
			var store = tx.objectStore(STORE_NAME);
			var saved = snapshot;
			var currentRequest = store.get(ip);
			currentRequest.onsuccess = function () {
				var current = currentRequest.result;
				if (!force && current && current.version > snapshot.version) saved = current;
				else store.put(snapshot);
			};
			tx.oncomplete = function () { resolve(saved); };
			tx.onerror = function () { reject(tx.error || new Error("could not write IndexedDB")); };
		});
	}

	function fetchJSON(url) {
		return fetch(url).then(function (response) {
			if (!response.ok) throw new Error("bad status");
			return response.json();
		});
	}

	function sync() {
		var url = "/api/history?ip=" + encodeURIComponent(ip);
		if (cache) url += "&since=" + encodeURIComponent(cache.version);
		return fetchJSON(url).then(function (data) {
			if (cache && data.version === cache.version) return cache;
			if (cache && !data.reset && data.version < cache.version) return cache;
			var snapshot = {ip: ip, version: data.version, checks: data.checks || []};
			if (!db) return snapshot;
			return writeCache(db, snapshot, data.reset);
		}).then(function (fresh) {
			if (!cache || fresh.version !== cache.version) {
				cache = fresh;
				checks = fresh.checks || [];
				page = 1;
				render();
			}
			return fresh;
		});
	}

	function showLoadError() {
		var status = document.getElementById("historyStatus");
		status.textContent = cache
			? "Showing cached history -- could not reach the server to check for updates."
			: "Could not load check history from the server.";
		status.classList.remove("gwsdb-hidden");
	}

	document.getElementById("historyPrev").addEventListener("click", function () { page--; render(); });
	document.getElementById("historyNext").addEventListener("click", function () { page++; render(); });
	document.getElementById("historyPageSize").addEventListener("change", function () { page = 1; render(); });
	document.addEventListener("gwsdb:history-refresh", function () { sync().catch(showLoadError); });

	openCache().then(function (database) {
		db = database;
		return readCache(db);
	}).then(function (cached) {
		cache = cached;
		if (cache) {
			checks = cache.checks || [];
			render();
		}
		return sync().catch(showLoadError);
	}).catch(function () {
		db = null;
		cache = null;
		sync().catch(showLoadError);
	});
})();
