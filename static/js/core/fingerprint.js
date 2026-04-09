import { collectCanvas }    from "../collectors/canvas.js";
import { collectAudio }     from "../collectors/audio.js";
import { collectFonts }     from "../collectors/fonts.js";
import { collectNavigator } from "../collectors/navigator.js";
import { collectScreen }    from "../collectors/screen.js";
import { collectWebRTC }    from "../collectors/webrtc.js";
import { collectWebGL }     from "../collectors/webgl.js";

export async function collectFingerprint() {
    const [canvas, audio, fonts, navigator, screen, webrtc, webgl] = await Promise.all([
        collectCanvas(),
        collectAudio(),
        collectFonts(),
        collectNavigator(),
        collectScreen(),
        collectWebRTC(),
        collectWebGL(),
    ]);

    return {
        canvas_hash:   canvas.canvas_hash,
        canvas_blocked: canvas.canvas_blocked,
        audio_hash:    audio.audio_hash,
        audio_blocked: audio.audio_blocked,
        fonts:         fonts.fonts,
        font_count:    fonts.font_count,
        font_groups:   fonts.font_groups,
        fonts_blocked: fonts.fonts_blocked,
        navigator:     navigator,
        screen:        screen,
        webrtc:        webrtc,
        webgl:         webgl,
    };
}
