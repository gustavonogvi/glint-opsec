export async function collectCanvas() {
    try {
        const canvas = document.createElement("canvas");
        canvas.width = 280;
        canvas.height = 60;

        const ctx = canvas.getContext("2d");

        if (!ctx) {
            return { canvas_hash: null, canvas_blocked: true };
        }

        ctx.fillStyle = "#f0f0f0";
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        ctx.fillStyle = "#069";
        ctx.font = "14px Arial";
        ctx.fillText("Cwm fjordbank glyphs vext quiz", 2, 15);

        ctx.font = "14px serif";
        ctx.fillText("\uD83D\uDE00 \uD83D\uDD12 \uD83C\uDF0D", 2, 35);

        const gradient = ctx.createLinearGradient(0, 40, canvas.width, 60);
        gradient.addColorStop(0, "#ff0000");
        gradient.addColorStop(0.5, "#00ff00");
        gradient.addColorStop(1, "#0000ff");
        ctx.fillStyle = gradient;
        ctx.fillRect(0, 40, canvas.width, 20);

        ctx.beginPath();
        ctx.arc(canvas.width - 20, 20, 14, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(255, 102, 0, 0.7)";
        ctx.fill();

        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const hashBuffer = await crypto.subtle.digest("SHA-256", imageData.data.buffer);
        const hash = Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, "0"))
            .join("");

        return { canvas_hash: hash, canvas_blocked: false };

    } catch (_) {
        return { canvas_hash: null, canvas_blocked: true };
    }
}
