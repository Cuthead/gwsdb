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
		} catch (e) {
			status.textContent = "请求失败";
			status.style.color = "#CC0000";
		} finally {
			btn.disabled = false;
		}
	});
})();
