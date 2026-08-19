// @license magnet:?xt=urn:btih:1f739d935676111cfff4b4693e3816e664797050&dn=gpl-3.0.txt GPL-3.0

// Fetches the known-IP pool from /api/pool, caches rows in IndexedDB, and
// renders + provides client-side search/sort/filter/pagination over it.
//
// Cached rows render before any network request. The background sync asks
// /api/pool/changes for rows changed after the cached revision and merges
// them by IP; only an empty/new cache downloads /api/pool in full.
//
// /api/pool sends ptrList only, not a precomputed country -- this decodes
// each row's PTR hostnames client-side with the same logic the server uses
// for the no-JS/crawler-rendered page (see geo.js/geoData.ts).
import { decodeBest, countryCode } from './geo.js';
// Client-side DoH PTR resolution (ptrResolve.js) is disabled -- superseded
// by functions/ingest.ts triggering cron-ptr-refresh on demand
// (src/ptrRefreshTrigger.ts), which fills ptr_cache server-side within the
// same ingest run instead of leaving new IPs unresolved client-side. Left
// in place, wiring commented out below, in case the on-demand trigger ever
// needs a client-side fallback again.
// import { resolvePTR } from './ptrResolve.js';

(function () {
	var DB_NAME = 'gwsdb';
	var DB_VERSION = 1;
	var ROW_STORE = 'pool';
	var META_STORE = 'meta';
	var META_KEY = 'snapshot';
	var OLD_CACHE_KEY = 'gwsdb_pool_v1';

	var sortState = {col: null, desc: false};
	var statusRank = {"Reachable": 2, "Unreachable": 1, "-": 0};
	var page = 1;
	// allRows is the full data set from /api/pool, kept in memory but never
	// attached to the DOM. matched is the subset passing the current filter,
	// derived from allRows. renderPage builds only the current page's slice
	// of matched into the DOM and clears it on every page/sort/filter change
	// (virtualization): with ~7600 IPs, building all rows once on load took
	// ~1.5s and dominated time-to-table; building 100 per page is ~10ms and
	// keeps first paint fast. The matched array stays in display order —
	// sort/filter mutate it and call renderPage.
	var allRows = [];
	var matched = [];

	function pageSize() {
		var v = document.getElementById('pageSizeInput').value;
		return v === 'all' ? Infinity : parseInt(v, 10);
	}

	// renderPage rebuilds the current page's slice of matched from data
	// (not DOM) — the old approach built all 7600 rows up front and hid
	// 7500, wasting ~1.5s on first paint. This virtualizes by clearing the
	// tbody and rebuilding only the visible page's rows each time, which
	// is ~10ms for 100 rows vs ~1.5s for the full set.
	function renderPage() {
		var size = pageSize();
		var totalPages = size === Infinity ? 1 : Math.max(1, Math.ceil(matched.length / size));
		if (page > totalPages) page = totalPages;
		if (page < 1) page = 1;
		var start = size === Infinity ? 0 : (page - 1) * size;
		var end = size === Infinity ? matched.length : start + size;

		var tbody = document.getElementById('ipTableBody');
		tbody.textContent = '';
		for (var j = start; j < end && j < matched.length; j++) {
			tbody.appendChild(buildRow(matched[j]));
		}

		document.getElementById('visibleCount').textContent = matched.length;
		document.getElementById('pageInfo').textContent = 'Page ' + page + ' of ' + totalPages;
		document.getElementById('prevButton').disabled = page <= 1;
		document.getElementById('nextButton').disabled = page >= totalPages;
	}

	// filter recomputes the matched set from the data (not the DOM) and
	// jumps back to the first page. Matched entries are the same objects
	// allRows holds, so sort/filter/renderPage can read them without
	// touching DOM — necessary for virtualization (only the current page
	// exists in the DOM at any time).
	function filter() {
		var q = document.getElementById('searchInput').value.trim().toLowerCase();
		var family = document.getElementById('familyInput').value;
		var status = document.getElementById('statusInput').value;
		var familyTotal = 0;
		matched = [];
		for (var i = 0; i < allRows.length; i++) {
			var r = allRows[i];
			var isIPv6 = r.ip.indexOf(':') !== -1;
			var familyMatch = family === '6' ? isIPv6 : !isIPv6;
			if (familyMatch) familyTotal++;
			var statusMatch = status === 'all' || r.status === 'Reachable';
			var hay = (r.ip + ' ' + (r.ptrList || []).join(' ') + ' ' + r.country).toLowerCase();
			if (familyMatch && statusMatch && hay.indexOf(q) !== -1) {
				matched.push(r);
			}
		}
		document.getElementById('familyCount').textContent = familyTotal;
		page = 1;
		renderPage();
	}

	// sort reorders the matched data array (not DOM rows) and re-renders
	// the current page. Sorting the in-memory array is O(n log n) over
	// ~7600 objects — cheap compared to the old approach of sorting
	// DOM nodes and re-appending them, which forced a layout pass per
	// row. After sort, stay on the same page so re-sorting a long list
	// doesn't lose the reader's place.
	function sort(col, defaultDesc) {
		var desc = sortState.col === col ? !sortState.desc : defaultDesc;
		sortState = {col: col, desc: desc};

		matched.sort(function (a, b) {
			var av, bv;
			if (col === 'rtt') {
				av = a.lastRttMs || 0;
				bv = b.lastRttMs || 0;
				return desc ? bv - av : av - bv;
			}
			if (col === 'status') {
				av = statusRank[a.status] || 0;
				bv = statusRank[b.status] || 0;
				return desc ? bv - av : av - bv;
			}
			if (col === 'ip') {
				return desc ? (a.ip < b.ip ? 1 : -1) : (a.ip < b.ip ? -1 : 1);
			}
			if (col === 'ptr') {
				av = (a.ptrList || []).join(' ');
				bv = (b.ptrList || []).join(' ');
			} else if (col === 'country') {
				av = a.country || '';
				bv = b.country || '';
			} else {
				av = (a[col] || '').toString();
				bv = (b[col] || '').toString();
			}
			av = av.toLowerCase();
			bv = bv.toLowerCase();
			if (av < bv) return desc ? 1 : -1;
			if (av > bv) return desc ? -1 : 1;
			return 0;
		});

		var arrows = document.getElementsByClassName('arrow');
		for (var i = 0; i < arrows.length; i++) {
			arrows[i].textContent = arrows[i].dataset.col === col ? (desc ? '▼' : '▲') : '';
		}

		renderPage();
	}

	function initControls() {
		var search = document.getElementById('searchInput');
		search.addEventListener('keyup', filter);
		document.getElementById('clearButton').addEventListener('click', function () {
			search.value = '';
			filter();
		});
		document.getElementById('familyInput').addEventListener('change', filter);
		document.getElementById('statusInput').addEventListener('change', filter);
		document.getElementById('pageSizeInput').addEventListener('change', function () {
			page = 1;
			renderPage();
		});
		document.getElementById('prevButton').addEventListener('click', function () {
			page--;
			renderPage();
		});
		document.getElementById('nextButton').addEventListener('click', function () {
			page++;
			renderPage();
		});

		var links = document.querySelectorAll('a[data-sort]');
		for (var i = 0; i < links.length; i++) {
			links[i].addEventListener('click', function (e) {
				e.preventDefault();
				sort(this.dataset.sort, this.dataset.sortDesc === '1');
			});
		}
	}

	// fillPtrCell (re)populates td with ptrList's hostnames, each linking to
	// /query -- shared by buildRow's initial render and resolveClientPTR's
	// update once a client-side DoH lookup fills in a previously-empty list.
	function fillPtrCell(td, ptrList) {
		td.textContent = '';
		if (ptrList && ptrList.length) {
			var ptrTt = document.createElement('tt');
			ptrList.forEach(function (h, i) {
				if (i) ptrTt.appendChild(document.createElement('br'));
				var a = document.createElement('a');
				a.href = '/query?ip=' + encodeURIComponent(h);
				a.textContent = h;
				ptrTt.appendChild(a);
			});
			td.appendChild(ptrTt);
		} else {
			td.textContent = '-';
		}
	}

	// fillCountryCell (re)populates td with the flag + country name for a
	// decoded location -- shared the same way as fillPtrCell.
	function fillCountryCell(td, country, code) {
		td.textContent = '';
		if (code) {
			var img = document.createElement('img');
			img.src = '/static/flags/' + encodeURIComponent(code) + '.gif';
			img.alt = code;
			img.title = country;
			img.height = 11;
			td.appendChild(img);
			td.appendChild(document.createTextNode(' '));
		}
		td.appendChild(document.createTextNode(country || '-'));
	}

	// scheduleRefilter coalesces bursts of resolveClientPTR updates (a fresh
	// ingest can leave hundreds of rows unresolved at once) into a single
	// filter() re-run, so a search/sort that depends on country or PTR text
	// picks up newly-resolved rows without re-filtering on every single one.
	var refilterTimer = null;
	function scheduleRefilter() {
		if (refilterTimer) return;
		refilterTimer = setTimeout(function () {
			refilterTimer = null;
			filter();
		}, 300);
	}

	// resolveClientPTR looks up ip.ip's PTR client-side (see ptrResolve.js)
	// when the server sent an empty ptrList -- happens for IPs a fresh
	// ingest just discovered, before cron-ptr-refresh has caught up. Updates
	// the row in place; a no-op if the lookup also comes back empty.
	function resolveClientPTR(tr, ptrTd, countryTd, ip) {
		resolvePTR(ip).then(function (result) {
			if (!result.ok || !result.hostnames.length) return;
			var loc = decodeBest(result.hostnames);
			var code = countryCode(loc.country);
			tr.dataset.ptr = result.hostnames.join(' ');
			tr.dataset.country = loc.country;
			fillPtrCell(ptrTd, result.hostnames);
			fillCountryCell(countryTd, loc.country, code);
			scheduleRefilter();
		});
	}

	// buildRow creates one <tr> for an IP entry via the DOM API (never
	// innerHTML) since PTR hostnames and the decoded country are derived from
	// live DNS data, not trusted input. country/countryCode are decoded here
	// (lazily, only for the current page's rows) and cached on the data
	// object so subsequent renders/sorts/filters don't re-run decodeBest.
	function buildRow(ip) {
		if (ip.country === undefined) {
			var loc = decodeBest(ip.ptrList || []);
			ip.country = loc.country;
			ip.countryCode = countryCode(loc.country);
		}
		var country = ip.country || '';
		var code = ip.countryCode || '';

		var tr = document.createElement('tr');

		var ipTd = document.createElement('td');
		var ipTt = document.createElement('tt');
		var ipA = document.createElement('a');
		ipA.href = '/query?ip=' + encodeURIComponent(ip.ip);
		ipA.textContent = ip.ip;
		ipTt.appendChild(ipA);
		ipTd.appendChild(ipTt);
		tr.appendChild(ipTd);

		var ptrTd = document.createElement('td');
		fillPtrCell(ptrTd, ip.ptrList);
		tr.appendChild(ptrTd);

		var countryTd = document.createElement('td');
		fillCountryCell(countryTd, country, code);
		tr.appendChild(countryTd);

		// Client-side PTR resolution disabled -- see the import comment above.
		// Deferred, not fired here: a fresh ingest can leave hundreds of rows
		// pending, but only the page(s) the user actually scrolls/pages to
		// need the client-side lookup. renderPage picks this up and fires it
		// the first time the row becomes visible, then clears it.
		// if (!ip.ptrList || !ip.ptrList.length) {
		// 	tr._pendingPTR = ip.ip;
		// 	tr._ptrTd = ptrTd;
		// 	tr._countryTd = countryTd;
		// }

		var statusTd = document.createElement('td');
		if (ip.status === 'Reachable' || ip.status === 'Unreachable') {
			var font = document.createElement('font');
			font.color = ip.status === 'Reachable' ? '#008000' : '#CC0000';
			font.textContent = (ip.status === 'Reachable' ? '✓ ' : '✗ ') + ip.status;
			statusTd.appendChild(font);
		} else {
			statusTd.textContent = '-';
		}
		tr.appendChild(statusTd);

		var firstTd = document.createElement('td');
		firstTd.textContent = ip.firstSeen;
		tr.appendChild(firstTd);

		var lastTd = document.createElement('td');
		lastTd.textContent = ip.lastSeen;
		tr.appendChild(lastTd);

		var rttTd = document.createElement('td');
		rttTd.textContent = ip.lastRttMs ? ip.lastRttMs + ' ms' : '-';
		tr.appendChild(rttTd);

		return tr;
	}

	function renderData(data) {
		document.getElementById('totalKnownIPs').textContent = data.totalKnownIPs;
		document.getElementById('totalChecks').textContent = data.totalChecks;
		document.getElementById('lastCheck').textContent = data.lastCheckAt + (data.scanMode ? ' (' + data.scanMode + ')' : '');

		// allRows holds the raw API data; country/countryCode are decoded
		// lazily in buildRow (only for the current page's ~100 rows) rather
		// than precomputed for all ~7600 here — decodeBest's 4 regex passes
		// per hostname dominated first-paint time (~3.5s for 7600 IPs).
		// filter() still works because it reads r.country which buildRow
		// fills in on first render; until then country is undefined and
		// matches any search query (same as IPs with no PTR).
		allRows = (data.ips || []).map(function (ip) {
			return ip;
		});

		var status = document.getElementById('poolStatus');
		if (data.ips && data.ips.length) {
			status.classList.add('gwsdb-hidden');
			document.getElementById('ipTableWrap').classList.remove('gwsdb-hidden');
			document.getElementById('pagerWrap').classList.remove('gwsdb-hidden');
			filter();
		} else {
			status.classList.remove('gwsdb-hidden');
			status.textContent = 'No data yet. Please run a scan and import the results first.';
			document.getElementById('ipTableWrap').classList.add('gwsdb-hidden');
			document.getElementById('pagerWrap').classList.add('gwsdb-hidden');
		}
	}

	function openCache() {
		return new Promise(function (resolve, reject) {
			if (!window.indexedDB) {
				reject(new Error('IndexedDB unavailable'));
				return;
			}
			var settled = false;
			var request = indexedDB.open(DB_NAME, DB_VERSION);
			request.onupgradeneeded = function () {
				var db = request.result;
				if (!db.objectStoreNames.contains(ROW_STORE)) db.createObjectStore(ROW_STORE, {keyPath: 'ip'});
				if (!db.objectStoreNames.contains(META_STORE)) db.createObjectStore(META_STORE);
			};
			request.onsuccess = function () {
				if (settled) {
					request.result.close();
					return;
				}
				settled = true;
				request.result.onversionchange = function () { request.result.close(); };
				resolve(request.result);
			};
			request.onerror = function () {
				if (settled) return;
				settled = true;
				reject(request.error || new Error('could not open IndexedDB'));
			};
			request.onblocked = function () {
				if (settled) return;
				settled = true;
				reject(new Error('IndexedDB upgrade blocked'));
			};
		});
	}

	function readCache(db) {
		return new Promise(function (resolve, reject) {
			var tx = db.transaction([ROW_STORE, META_STORE], 'readonly');
			var rowsRequest = tx.objectStore(ROW_STORE).getAll();
			var metaRequest = tx.objectStore(META_STORE).get(META_KEY);
			tx.oncomplete = function () {
				var meta = metaRequest.result;
				if (!meta) {
					resolve(null);
					return;
				}
				meta.ips = rowsRequest.result || [];
				resolve(meta);
			};
			tx.onerror = function () { reject(tx.error || new Error('could not read IndexedDB')); };
		});
	}

	function metadata(data) {
		return {
			version: data.version,
			count: data.count,
			scanMode: data.scanMode,
			totalKnownIPs: data.totalKnownIPs,
			totalChecks: data.totalChecks,
			lastCheckAt: data.lastCheckAt
		};
	}

	function removeOldCache() {
		try { localStorage.removeItem(OLD_CACHE_KEY); } catch (e) {}
	}

	function writeFullCache(db, data) {
		return new Promise(function (resolve, reject) {
			var tx = db.transaction([ROW_STORE, META_STORE], 'readwrite');
			var rows = tx.objectStore(ROW_STORE);
			var metas = tx.objectStore(META_STORE);
			var currentRequest = metas.get(META_KEY);
			currentRequest.onsuccess = function () {
				var current = currentRequest.result;
				if (current && current.version > data.version) return;
				rows.clear();
				(data.ips || []).forEach(function (row) { rows.put(row); });
				metas.put(metadata(data), META_KEY);
			};
			tx.oncomplete = function () {
				removeOldCache();
				resolve();
			};
			tx.onerror = function () { reject(tx.error || new Error('could not write IndexedDB')); };
		});
	}

	function applyChanges(db, data) {
		return new Promise(function (resolve, reject) {
			var tx = db.transaction([ROW_STORE, META_STORE], 'readwrite');
			var rows = tx.objectStore(ROW_STORE);
			var metas = tx.objectStore(META_STORE);
			var currentRequest = metas.get(META_KEY);

			(data.ips || []).forEach(function (row) {
				var oldRequest = rows.get(row.ip);
				oldRequest.onsuccess = function () {
					var old = oldRequest.result;
					if (!old || (old.revision || 0) <= row.revision) rows.put(row);
				};
			});
			currentRequest.onsuccess = function () {
				var current = currentRequest.result;
				if (!current || current.version <= data.version) metas.put(metadata(data), META_KEY);
			};
			tx.oncomplete = function () { resolve(); };
			tx.onerror = function () { reject(tx.error || new Error('could not update IndexedDB')); };
		});
	}

	function fetchJSON(url) {
		return fetch(url).then(function (resp) {
			if (!resp.ok) throw new Error('bad status');
			return resp.json();
		});
	}

	function fetchFull(db) {
		return fetchJSON('/api/pool').then(function (data) {
			return writeFullCache(db, data).then(function () { return readCache(db); });
		});
	}

	function syncCache(db, cache) {
		if (!cache) return fetchFull(db);
		return fetchJSON('/api/pool/changes?since=' + encodeURIComponent(cache.version)).then(function (data) {
			if (data.reset) return fetchFull(db);
			if (data.version === cache.version) return cache;
			return applyChanges(db, data).then(function () { return readCache(db); });
		});
	}

	function showLoadError(cache) {
		var status = document.getElementById('poolStatus');
		if (cache) {
			status.textContent = 'Showing cached data -- could not reach the server to check for updates.';
			status.classList.remove('gwsdb-hidden');
		} else {
			status.textContent = 'Could not load data from the server.';
		}
	}

	function loadWithoutCache() {
		fetchJSON('/api/pool').then(renderData).catch(function () { showLoadError(null); });
	}

	function load() {
		openCache().then(function (db) {
			return readCache(db).then(function (cache) {
				if (cache) renderData(cache);
				return syncCache(db, cache).then(function (fresh) {
					if (fresh && (!cache || fresh.version !== cache.version)) renderData(fresh);
				}).catch(function () {
					showLoadError(cache);
				});
			});
		}).catch(loadWithoutCache);
	}

	function init() {
		initControls();
		load();
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init);
	} else {
		init();
	}
})();
// @license-end
