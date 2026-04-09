const STUN_SERVERS = [
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun.cloudflare.com:3478" },
];

const PRIVATE_RANGES = [
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^127\./,
    /^169\.254\./,
    /^::1$/,        // IPv6 loopback
    /^fe80:/i,      // IPv6 link-local
    /^fc00:/i,      // iPv6 unique local
    /^fd/i,         // IPv6 unique local (fd00::/8)
];

function isPrivateIP(ip) {
    return PRIVATE_RANGES.some(function(range) {
        return range.test(ip);
    });
}

function classifyIP(ip) {
    if (/^10\./.test(ip))                          return "private_corporate";
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip))    return "private_corporate";
    if (/^192\.168\./.test(ip))                    return "private_home";
    if (/^127\./.test(ip))                         return "loopback";
    if (/^169\.254\./.test(ip))                    return "link_local";
    if (/^fe80:/i.test(ip))                        return "ipv6_link_local";
    if (/^fc00:/i.test(ip) || /^fd/i.test(ip))     return "ipv6_private";
    return "public";
}

function isMDNS(candidate) {
    return candidate.includes(".local");
}

function extractIPs(candidateString) {
    const ipv4 = /([0-9]{1,3}(?:\.[0-9]{1,3}){3})/g;
    const ipv6 = /([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})/g;
    const v4 = candidateString.match(ipv4);
    const v6 = candidateString.match(ipv6);
    return [...v4, ...v6];
}

export async function collectWebRTC() {
    try {
        const RTCPeerConnection = window.RTCPeerConnection
            || window.mozRTCPeerConnection
            || window.webkitRTCPeerConnection;

        if (!RTCPeerConnection) {
            return { local_ips: [], public_ip_via_stun: null, webrtc_blocked: true, mdns_protected: false };
        }

        const localIPs = new Set();
        let publicIP = null;
        let mdnsProtected = false;
        const mdnsHostnames = new Set();

        const pc = new RTCPeerConnection({ iceServers: STUN_SERVERS });

        pc.createDataChannel("");

        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);

        await new Promise(function(resolve) {
            const timeout = setTimeout(resolve, 4000);

            pc.onicecandidate = function(event) {
                if (!event.candidate) {
                    clearTimeout(timeout);
                    resolve();
                    return;
                }

                const candidate = event.candidate.candidate;

                if (isMDNS(candidate)) {
                    mdnsProtected = true;
                    const mdnsMatch = candidate.match(/[\w-]+\.local/);
                    if (mdnsMatch) {
                        mdnsHostnames.add(mdnsMatch[0]);
                    }
                    return;
                }

                const ips = extractIPs(candidate);

                ips.forEach(function(ip) {
                    if (isPrivateIP(ip)) {
                        localIPs.add({ ip: ip, type: classifyIP(ip) });
                    } else {
                        publicIP = ip;
                    }
                });
            };
        });

        pc.close();

        return {
            local_ips:          Array.from(localIPs),
            public_ip_via_stun: publicIP,
            mdns_hostnames:     Array.from(mdnsHostnames),
            webrtc_blocked:     false,
            mdns_protected:     mdnsProtected,
        };

    } catch (_) {
        return { local_ips: [], public_ip_via_stun: null, webrtc_blocked: true, mdns_protected: false };
    }
}
