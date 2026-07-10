// Client-side search/sort/filter/pagination over the rows the home page
// already rendered. Lives in its own file rather than an inline <script> so
// the Content-Security-Policy can be script-src 'self' with no
// 'unsafe-inline'.
(function () {
	var sortState = {col: null, desc: false};
	var statusRank = {"Reachable": 2, "Unreachable": 1, "-": 0};
	var page = 1;
	var matched = []; // rows passing the current filter, in tbody order

	function pageSize() {
		var v = document.getElementById('pageSizeInput').value;
		return v === 'all' ? Infinity : parseInt(v, 10);
	}

	// render shows the current page's slice of the matched rows and hides
	// everything else, then updates the counters and pager controls.
	function render() {
		var size = pageSize();
		var totalPages = size === Infinity ? 1 : Math.max(1, Math.ceil(matched.length / size));
		if (page > totalPages) page = totalPages;
		if (page < 1) page = 1;
		var start = size === Infinity ? 0 : (page - 1) * size;
		var end = size === Infinity ? matched.length : start + size;

		var rows = document.getElementById('ipTableBody').rows;
		for (var i = 0; i < rows.length; i++) {
			rows[i].style.display = 'none';
		}
		for (var j = start; j < end && j < matched.length; j++) {
			matched[j].style.display = '';
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
		render();
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
		render();
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
		document.getElementById('pageSizeInput').addEventListener('change', function () {
			page = 1;
			render();
		});
		document.getElementById('prevButton').addEventListener('click', function () {
			page--;
			render();
		});
		document.getElementById('nextButton').addEventListener('click', function () {
			page++;
			render();
		});

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
