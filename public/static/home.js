// @license magnet:?xt=urn:btih:1f739d935676111cfff4b4693e3816e664797050&dn=gpl-3.0.txt GPL-3.0

// Fetches the known-IP pool from /api/pool, caches it in localStorage, and
// renders + provides client-side search/sort/filter/pagination over it.
//
// The pool is only ever refetched when /api/pool/version (a single cheap
// query) reports a version the cache doesn't have -- ingest and recheck are
// the only things that bump it, since both write ip_checks rows. A repeat
// visit between those events renders entirely from localStorage, no request
// to /api/pool at all.
(function () {
	var CACHE_KEY = 'gwsdb_pool_v1';

	var sortState = {col: null, desc: false};
	var statusRank = {"Reachable": 2, "Unreachable": 1, "-": 0};
	var page = 1;
	var matched = []; // rows passing the current filter, in tbody order

	function pageSize() {
		var v = document.getElementById('pageSizeInput').value;
		return v === 'all' ? Infinity : parseInt(v, 10);
	}

	// renderPage shows the current page's slice of the matched rows and hides
	// everything else, then updates the counters and pager controls.
	function renderPage() {
		var size = pageSize();
		var totalPages = size === Infinity ? 1 : Math.max(1, Math.ceil(matched.length / size));
		if (page > totalPages) page = totalPages;
		if (page < 1) page = 1;
		var start = size === Infinity ? 0 : (page - 1) * size;
		var end = size === Infinity ? matched.length : start + size;

		var rows = document.getElementById('ipTableBody').rows;
		for (var i = 0; i < rows.length; i++) {
			rows[i].classList.add('gwsdb-hidden');
		}
		for (var j = start; j < end && j < matched.length; j++) {
			matched[j].classList.remove('gwsdb-hidden');
		}

		document.getElementById('visibleCount').textContent = matched.length;
		document.getElementById('pageInfo').textContent = 'Page ' + page + ' of ' + totalPages;
		document.getElementById('prevButton').disabled = page <= 1;
		document.getElementById('nextButton').disabled = page >= totalPages;
	}

	// filter recomputes the matched set from the filter inputs and jumps back
	// to the first page.
	function filter() {
		var q = document.getElementById('searchInput').value.trim().toLowerCase();
		var family = document.getElementById('familyInput').value;
		var status = document.getElementById('statusInput').value;
		var rows = document.getElementById('ipTableBody').rows;
		var familyTotal = 0;
		matched = [];
		for (var i = 0; i < rows.length; i++) {
			var r = rows[i];
			var isIPv6 = r.dataset.ip.indexOf(':') !== -1;
			var familyMatch = family === '6' ? isIPv6 : !isIPv6;
			if (familyMatch) familyTotal++;
			var statusMatch = status === 'all' || r.dataset.status === 'Reachable';
			var hay = (r.dataset.ip + ' ' + r.dataset.ptr + ' ' + r.dataset.country).toLowerCase();
			if (familyMatch && statusMatch && hay.indexOf(q) !== -1) {
				matched.push(r);
			}
		}
		document.getElementById('familyCount').textContent = familyTotal;
		page = 1;
		renderPage();
	}

	function sort(col, defaultDesc) {
		var desc = sortState.col === col ? !sortState.desc : defaultDesc;
		sortState = {col: col, desc: desc};

		var tbody = document.getElementById('ipTableBody');
		var rows = Array.prototype.slice.call(tbody.rows);
		rows.sort(function (a, b) {
			var av, bv;
			if (col === 'rtt') {
				av = parseInt(a.dataset.rtt, 10) || 0;
				bv = parseInt(b.dataset.rtt, 10) || 0;
				return desc ? bv - av : av - bv;
			}
			if (col === 'status') {
				av = statusRank[a.dataset.status] || 0;
				bv = statusRank[b.dataset.status] || 0;
				return desc ? bv - av : av - bv;
			}
			av = (a.dataset[col] || '').toLowerCase();
			bv = (b.dataset[col] || '').toLowerCase();
			if (av < bv) return desc ? 1 : -1;
			if (av > bv) return desc ? -1 : 1;
			return 0;
		});
		rows.forEach(function (r) { tbody.appendChild(r); });

		var arrows = document.getElementsByClassName('arrow');
		for (var i = 0; i < arrows.length; i++) {
			arrows[i].textContent = arrows[i].dataset.col === col ? (desc ? '▼' : '▲') : '';
		}

		// Re-derive the matched set in the new row order; stay on the same
		// page so re-sorting a long list doesn't lose the reader's place.
		var keep = page;
		filter();
		page = keep;
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

	// buildRow creates one <tr> for an IP entry via the DOM API (never
	// innerHTML) since PTR hostnames and the decoded country are derived from
	// live DNS data, not trusted input.
	function buildRow(ip) {
		var tr = document.createElement('tr');
		tr.dataset.ip = ip.ip;
		tr.dataset.ptr = (ip.ptrList || []).join(' ');
		tr.dataset.country = ip.country;
		tr.dataset.status = ip.status;
		tr.dataset.firstSeen = ip.firstSeen;
		tr.dataset.lastSeen = ip.lastSeen;
		tr.dataset.rtt = ip.lastRttMs;

		var ipTd = document.createElement('td');
		var ipTt = document.createElement('tt');
		var ipA = document.createElement('a');
		ipA.href = '/query?ip=' + encodeURIComponent(ip.ip);
		ipA.textContent = ip.ip;
		ipTt.appendChild(ipA);
		ipTd.appendChild(ipTt);
		tr.appendChild(ipTd);

		var ptrTd = document.createElement('td');
		if (ip.ptrList && ip.ptrList.length) {
			var ptrTt = document.createElement('tt');
			ip.ptrList.forEach(function (h, i) {
				if (i) ptrTt.appendChild(document.createElement('br'));
				var a = document.createElement('a');
				a.href = '/query?ip=' + encodeURIComponent(h);
				a.textContent = h;
				ptrTt.appendChild(a);
			});
			ptrTd.appendChild(ptrTt);
		} else {
			ptrTd.textContent = '-';
		}
		tr.appendChild(ptrTd);

		var countryTd = document.createElement('td');
		if (ip.countryCode) {
			var img = document.createElement('img');
			img.src = '/static/flags/' + encodeURIComponent(ip.countryCode) + '.gif';
			img.alt = ip.countryCode;
			img.title = ip.country;
			img.height = 11;
			countryTd.appendChild(img);
			countryTd.appendChild(document.createTextNode(' '));
		}
		countryTd.appendChild(document.createTextNode(ip.country || '-'));
		tr.appendChild(countryTd);

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
		document.getElementById('totalScans').textContent = data.totalScans;
		document.getElementById('lastScan').textContent = data.lastScanAt + (data.scanMode ? ' (' + data.scanMode + ')' : '');

		var tbody = document.getElementById('ipTableBody');
		tbody.textContent = '';
		(data.ips || []).forEach(function (ip) {
			tbody.appendChild(buildRow(ip));
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

	function readCache() {
		try {
			var raw = localStorage.getItem(CACHE_KEY);
			return raw ? JSON.parse(raw) : null;
		} catch (e) {
			return null;
		}
	}

	function writeCache(data) {
		try {
			localStorage.setItem(CACHE_KEY, JSON.stringify(data));
		} catch (e) {
			// Storage full or unavailable (e.g. private browsing) -- the page
			// still works, just refetches every visit.
		}
	}

	function load() {
		var cache = readCache();

		fetch('/api/pool/version').then(function (resp) {
			if (!resp.ok) throw new Error('bad status');
			return resp.json();
		}).then(function (v) {
			if (cache && cache.version === v.version) {
				renderData(cache);
				return;
			}
			return fetch('/api/pool').then(function (resp) {
				if (!resp.ok) throw new Error('bad status');
				return resp.json();
			}).then(function (data) {
				writeCache(data);
				renderData(data);
			});
		}).catch(function () {
			var status = document.getElementById('poolStatus');
			if (cache) {
				renderData(cache);
				status.textContent = 'Showing cached data -- could not reach the server to check for updates.';
				status.classList.remove('gwsdb-hidden');
			} else {
				status.textContent = 'Could not load data from the server.';
			}
		});
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
