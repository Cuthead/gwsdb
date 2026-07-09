// Client-side search/sort/filter over the rows the home page already
// rendered. Lives in its own file rather than an inline <script> so the
// Content-Security-Policy can be script-src 'self' with no 'unsafe-inline'.
(function () {
	var sortState = {col: null, desc: false};
	var statusRank = {"Reachable": 2, "Unreachable": 1, "-": 0};

	function filter() {
		var q = document.getElementById('searchInput').value.trim().toLowerCase();
		var family = document.getElementById('familyInput').value;
		var status = document.getElementById('statusInput').value;
		var rows = document.getElementById('ipTableBody').rows;
		var shown = 0;
		var familyTotal = 0;
		for (var i = 0; i < rows.length; i++) {
			var r = rows[i];
			var isIPv6 = r.dataset.ip.indexOf(':') !== -1;
			var familyMatch = family === '6' ? isIPv6 : !isIPv6;
			if (familyMatch) familyTotal++;
			var statusMatch = status === 'all' || r.dataset.status === 'Reachable';
			var hay = (r.dataset.ip + ' ' + r.dataset.ptr).toLowerCase();
			var match = familyMatch && statusMatch && hay.indexOf(q) !== -1;
			r.style.display = match ? '' : 'none';
			if (match) shown++;
		}
		document.getElementById('visibleCount').textContent = shown;
		document.getElementById('familyCount').textContent = familyTotal;
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
	}

	function init() {
		var search = document.getElementById('searchInput');
		if (!search || !document.getElementById('ipTableBody')) {
			return; // no rows rendered
		}
		search.addEventListener('keyup', filter);
		document.getElementById('clearButton').addEventListener('click', function () {
			search.value = '';
			filter();
		});
		document.getElementById('familyInput').addEventListener('change', filter);
		document.getElementById('statusInput').addEventListener('change', filter);

		var links = document.querySelectorAll('a[data-sort]');
		for (var i = 0; i < links.length; i++) {
			links[i].addEventListener('click', function (e) {
				e.preventDefault();
				sort(this.dataset.sort, this.dataset.sortDesc === '1');
			});
		}
		filter();
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init);
	} else {
		init();
	}
})();
