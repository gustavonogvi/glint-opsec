export function collectNavigator() {
    try {
        const nav = window.navigator;

        const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        const timezoneOffset = new Date().getTimezoneOffset();

        const touchSupport = {
            max_touch_points: nav.maxTouchPoints ?? 0,
            touch_event: "ontouchstart" in window,
        };

        const connection = nav.connection ?? nav.mozConnection ?? nav.webkitConnection;

        let uaData = null;
        if (nav.userAgentData) {
            uaData = {
                brands:   nav.userAgentData.brands,
                mobile:   nav.userAgentData.mobile,
                platform: nav.userAgentData.platform,
            };
        }

        let plugins = [];
        if (nav.plugins && nav.plugins.length > 0) {
            plugins = Array.from(nav.plugins).map(p => p.name);
        }

        let connectionType = null;
        if (connection && connection.effectiveType) {
            connectionType = connection.effectiveType;
        }

        let hardwareConcurrency = null;
        if (nav.hardwareConcurrency !== undefined && nav.hardwareConcurrency !== null) {
            hardwareConcurrency = nav.hardwareConcurrency;
        }

        let deviceMemory = null;
        if (nav.deviceMemory !== undefined && nav.deviceMemory !== null) {
            deviceMemory = nav.deviceMemory;
        }

        let pdfViewerEnabled = null;
        if (nav.pdfViewerEnabled !== undefined && nav.pdfViewerEnabled !== null) {
            pdfViewerEnabled = nav.pdfViewerEnabled;
        }

        return {
            user_agent:           nav.userAgent,
            ua_client_hints:      uaData,
            language:             nav.language,
            languages:            Array.from(nav.languages || []),
            platform:             nav.platform,
            hardware_concurrency: hardwareConcurrency,
            device_memory:        deviceMemory,
            cookie_enabled:       nav.cookieEnabled,
            do_not_track:         nav.doNotTrack,
            timezone,
            timezone_offset:      timezoneOffset,
            touch_support:        touchSupport,
            pdf_viewer_enabled:   pdfViewerEnabled,
            connection_type:      connectionType,
            plugins,
            plugins_hidden:       nav.plugins && nav.plugins.length === 0,
        };

    } catch (_) {
        return null;
    }
}
