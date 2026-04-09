export function collectScreen() {
    try {
        return {
            screen_width:        window.screen.width,
            screen_height:       window.screen.height,
            avail_width:         window.screen.availWidth,
            avail_height:        window.screen.availHeight,
            window_inner_width:  window.innerWidth,
            window_inner_height: window.innerHeight,
            window_outer_width:  window.outerWidth,
            window_outer_height: window.outerHeight,
            color_depth:         window.screen.colorDepth,
            pixel_ratio:         window.devicePixelRatio,
            orientation:         screen.orientation.type,
        };

    } catch (_) {
        return null;
    }
}
