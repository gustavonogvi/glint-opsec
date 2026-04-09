export function collectScreen() {
    try {
        const s = window.screen;
        return {
            screen_width:        s?.width ?? null,
            screen_height:       s?.height ?? null,
            avail_width:         s?.availWidth ?? null,
            avail_height:        s?.availHeight ?? null,
            window_inner_width:  window.innerWidth ?? null,
            window_inner_height: window.innerHeight ?? null,
            window_outer_width:  window.outerWidth ?? null,
            window_outer_height: window.outerHeight ?? null,
            color_depth:         s?.colorDepth ?? null,
            pixel_ratio:         window.devicePixelRatio ?? null,
            orientation:         s.orientation?.type ?? null, 

        };

    } catch (error) {
        console.warn(error)
        return {error: "permission_denied_or_unsupported"};
    }
}
