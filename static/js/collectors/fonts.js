const FONT_GROUPS = {
    // Core OS fonts
    windows_core:  ["Arial", "Verdana", "Tahoma", "Trebuchet MS", "Georgia", "Comic Sans MS", "Impact", "Courier New"],
    mac_core:      ["Helvetica Neue", "Helvetica", "Optima", "Futura", "Geneva", "Monaco", "Palatino"],
    linux_core:    ["Ubuntu", "DejaVu Sans", "Liberation Sans", "FreeSans", "Noto Sans", "Cantarell"],

    // OS version fingerprinting
    windows_11:    ["Segoe UI Variable"],
    windows_10:    ["Segoe UI", "Segoe UI Semibold", "Segoe UI Light"],
    mac_modern:    ["SF Pro", "SF Mono", ".AppleSystemUIFont", "Helvetica Neue"],
    android:       ["Roboto Condensed", "Product Sans", "Droid Sans"],

    // Productivity suites
    ms_office:     ["Calibri", "Cambria", "Constantia", "Corbel", "Candara", "Consolas", "Cambria Math"],
    google_fonts:  ["Roboto", "Open Sans", "Lato", "Montserrat", "Oswald", "Raleway", "Noto Serif"],

    // Creative software
    adobe_cc:      ["Minion Pro", "Myriad Pro", "Adobe Garamond Pro", "Adobe Caslon Pro", "Frutiger", "Bodoni MT"],
    design_print:  ["Helvetica Neue LT Std", "Garamond", "Futura PT", "Gill Sans MT"],

    // Symbolic & emoji (high entropy — very distinct metrics)
    symbolic:      ["Wingdings", "Wingdings 2", "Wingdings 3", "Webdings", "Symbol"],
    emoji:         ["Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji", "Android Emoji"],

    // Font weight variants (extra entropy bits)
    font_weights:  ["Arial Black", "Arial Narrow", "Verdana Bold", "Georgia Bold", "Impact"],

    // Professional / field-specific
    cad:           ["CityBlueprint", "Stylus BT", "Architects Daughter", "CountryBlueprint"],
    academic:      ["STIX General", "Latin Modern Math", "CMU Serif", "Computer Modern"],

    // CJK and non-latin
    cjk:           ["MS Gothic", "MS Mincho", "SimSun", "SimHei", "NSimSun", "MingLiU", "Yu Gothic"],
    arabic:        ["Arial Unicode MS", "Traditional Arabic", "Simplified Arabic", "Sakkal Majalla"],

    // Hardware manufacturer pre-installs
    hardware_hp:   ["HP Simplified", "HP Simplified Light"],
    hardware_sony: ["SST"],
    hardware_apple:["Myriad Set Pro"],

    // Developer tools
    coding:        ["Fira Code", "JetBrains Mono", "Cascadia Code", "Source Code Pro", "Inconsolata", "Hack"],
};

const ALL_FONTS = [...new Set(Object.values(FONT_GROUPS).flat())];

const TEST_STRING = "mmmmmmmmmmlli";
const BASELINE_FONT = "monospace";
const FONT_SIZE = "16px";

function measureWidth(ctx, font) {
    ctx.font = `${FONT_SIZE} '${font}', ${BASELINE_FONT}`;
    return ctx.measureText(TEST_STRING).width;
}

function detectBlocked(widths) {
    const unique = new Set(widths);
    return unique.size <= 2;
}

export function collectFonts() {
    try {
        const canvas = document.createElement("canvas");
        canvas.width = 400;
        canvas.height = 50;
        const ctx = canvas.getContext("2d");

        if (!ctx) {
            return { fonts: [], font_groups: [], font_count: 0, fonts_blocked: true };
        }

        const baselineWidth = measureWidth(ctx, "__nonexistent_font__");

        const detectedFonts = [];
        const allWidths = [];

        for (const font of ALL_FONTS) {
            const width = measureWidth(ctx, font);
            allWidths.push(width);
            if (width !== baselineWidth) {
                detectedFonts.push(font);
            }
        }

        if (detectBlocked(allWidths)) {
            return { fonts: [], font_groups: [], font_count: 0, fonts_blocked: true };
        }

        const detectedGroups = Object.entries(FONT_GROUPS)
            .filter(([_, fonts]) => fonts.some(f => detectedFonts.includes(f)))
            .map(([group]) => group);

        return {
            fonts: detectedFonts,
            font_groups: detectedGroups,
            font_count: detectedFonts.length,
            fonts_blocked: false,
        };

    } catch (_) {
        return { fonts: [], font_groups: [], font_count: 0, fonts_blocked: true };
    }
}
