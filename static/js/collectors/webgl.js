const GL_PARAMETERS = [
    "MAX_TEXTURE_SIZE",
    "MAX_VIEWPORT_DIMS",
    "MAX_RENDERBUFFER_SIZE",
    "MAX_VERTEX_ATTRIBS",
    "MAX_VERTEX_UNIFORM_VECTORS",
    "MAX_VARYING_VECTORS",
    "MAX_FRAGMENT_UNIFORM_VECTORS",
    "MAX_COMBINED_TEXTURE_IMAGE_UNITS",
    "MAX_TEXTURE_IMAGE_UNITS",
    "ALIASED_LINE_WIDTH_RANGE",
    "ALIASED_POINT_SIZE_RANGE",
    "RED_BITS",
    "GREEN_BITS",
    "BLUE_BITS",
    "ALPHA_BITS",
    "DEPTH_BITS",
    "STENCIL_BITS",
];

const VERT_SRC = `
    attribute vec2 a_position;
    void main() {
        gl_Position = vec4(a_position, 0.0, 1.0);
    }
`;

const FRAG_SRC = `
    precision highp float;
    void main() {
        float x = gl_FragCoord.x / 16.0;
        float y = gl_FragCoord.y / 16.0;
        float r = sin(x) * cos(y) + pow(x + y + 0.1, 2.718281828459045);
        float g = fract(sin(x * 127.1 + y * 311.7) * 43758.5453123);
        float b = cos(x * y * 3.141592653589793);
        float a = fract(cos(x * 12.9898 + y * 78.233) * 43758.5453);
        gl_FragColor = vec4(r, g, b, a);
    }
`;

function compileShader(gl, type, source) {
    const shader = gl.createShader(type);
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    return shader;
}

async function collectPrecisionHash(gl) {
    const vert    = compileShader(gl, gl.VERTEX_SHADER,   VERT_SRC);
    const frag    = compileShader(gl, gl.FRAGMENT_SHADER, FRAG_SRC);
    const program = gl.createProgram();

    gl.attachShader(program, vert);
    gl.attachShader(program, frag);
    gl.linkProgram(program);
    gl.useProgram(program);

    const positions = new Float32Array([
        -1, -1,   1, -1,  -1,  1,
        -1,  1,   1, -1,   1,  1,
    ]);

    const buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(gl.ARRAY_BUFFER, positions, gl.STATIC_DRAW);

    const loc = gl.getAttribLocation(program, "a_position");
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

    gl.viewport(0, 0, 16, 16);  
    gl.drawArrays(gl.TRIANGLES, 0, 6);

    const pixels = new Uint8Array(16 * 16 * 4);
    gl.readPixels(0, 0, 16, 16, gl.RGBA, gl.UNSIGNED_BYTE, pixels);

    gl.deleteProgram(program);
    gl.deleteShader(vert);
    gl.deleteShader(frag);
    gl.deleteBuffer(buffer);

    const hashBuffer = await crypto.subtle.digest("SHA-256", pixels);
    const hashArray  = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(function(b) { return b.toString(16).padStart(2, "0"); }).join("");
}

function readParameters(gl) {
    const result = {};

    GL_PARAMETERS.forEach(function(name) {
        const value = gl.getParameter(gl[name]);

        if (value === null || value === undefined) {
            return;
        }

        if (value instanceof Float32Array || value instanceof Int32Array) {
            result[name.toLowerCase()] = Array.from(value);
        } else {
            result[name.toLowerCase()] = value;
        }
    });

    return result;
}

export async function collectWebGL() {
    try {
        const canvas = document.createElement("canvas");
        canvas.width  = 16;
        canvas.height = 16;
        const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");

        if (!gl) {
            return { vendor: null, renderer: null, webgl_blocked: true };
        }

        let vendor   = gl.getParameter(gl.VENDOR);
        let renderer = gl.getParameter(gl.RENDERER);
        let unmasked = false;

        const debugInfo = gl.getExtension("WEBGL_debug_renderer_info");

        if (debugInfo) {
            const unmaskedVendor   = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
            const unmaskedRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);

            if (unmaskedVendor && unmaskedRenderer) {
                vendor   = unmaskedVendor;
                renderer = unmaskedRenderer;
                unmasked = true;
            }
        }

        const extensions    = gl.getSupportedExtensions() || [];
        const parameters    = readParameters(gl);
        const precisionHash = await collectPrecisionHash(gl);

        return {
            vendor:         vendor,
            renderer:       renderer,
            unmasked:       unmasked,
            version:        gl.getParameter(gl.VERSION),
            shading_lang:   gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
            extensions:     extensions,
            parameters:     parameters,
            precision_hash: precisionHash,
            webgl_blocked:  false,
        };

    } catch (_) {
        return { vendor: null, renderer: null, precision_hash: null, webgl_blocked: true };
    }
}
