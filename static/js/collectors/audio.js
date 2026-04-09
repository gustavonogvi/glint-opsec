export async function collectAudio() {
    try {
        const OfflineCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;

        if (!OfflineCtx) {
            return { audio_hash: null, audio_blocked: true };
        }

        const ctx = new OfflineCtx(1, 4096, 44100);

        const oscillator = ctx.createOscillator();
        oscillator.type = "triangle";
        oscillator.frequency.value = 10000;

        const compressor = ctx.createDynamicsCompressor();
        compressor.threshold.value = -50;
        compressor.knee.value = 40;
        compressor.ratio.value = 12;
        compressor.attack.value = 0;
        compressor.release.value = 0.25;

        oscillator.connect(compressor);
        compressor.connect(ctx.destination);
        oscillator.start(0);

        const buffer = await ctx.startRendering();
        const samples = buffer.getChannelData(0);

        const hashBuffer = await crypto.subtle.digest("SHA-256", samples.buffer);
        const hash = Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, "0"))
            .join("");

        return { audio_hash: hash, audio_blocked: false };

    } catch (_) {
        return { audio_hash: null, audio_blocked: true };
    }
}
