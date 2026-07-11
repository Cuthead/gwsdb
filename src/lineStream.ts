// Splits a byte stream into text lines without ever materializing the whole
// stream as one JS string. Needed because the decompressed gscan_quic log
// can be ~100MB+ -- well past a Worker isolate's 128MB memory ceiling if
// read via `Response.text()`/`Blob.text()` in one shot.
export async function* streamLines(stream: ReadableStream<Uint8Array>): AsyncGenerator<string> {
	const reader = stream.pipeThrough(new TextDecoderStream()).getReader();
	let buf = "";
	for (;;) {
		const { value, done } = await reader.read();
		if (done) break;
		buf += value;
		let nl: number;
		while ((nl = buf.indexOf("\n")) >= 0) {
			yield buf.slice(0, nl);
			buf = buf.slice(nl + 1);
		}
	}
	if (buf.length > 0) yield buf;
}
