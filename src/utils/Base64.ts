
var r = 3e3;
function a(e, t, a, n) {
    var s = Array.isArray(e) || e instanceof ArrayBuffer ? new Uint8Array(e) : e;
    if (s.length <= r)
        return i(s, t, a, n);
    for (var o = [], l = 0; l < s.length; l += r)
        o.push(i(s.subarray(l, l + r), t, a, n));
    return o.join("")
}
function i(e, t, r, a) {
    for (var i = Math.ceil(4 * e.length / 3), n = 4 * Math.ceil(e.length / 3), s = new Array(n), o = 0, l = 0; o < n; o += 4,
    l += 3) {
        var d = e[l] << 16 | e[l + 1] << 8 | e[l + 2];
        s[o] = d >> 18,
        s[o + 1] = d >> 12 & 63,
        s[o + 2] = d >> 6 & 63,
        s[o + 3] = 63 & d
    }
    for (var u = 0; u < i; u++) {
        var c = s[u];
        s[u] = c < 26 ? 65 + c : c < 52 ? 71 + c : c < 62 ? c - 4 : 62 === c ? t : r
    }
    for (var p = i; p < n; p++)
        s[p] = 61;
    var f = String.fromCharCode.apply(String, s);
    return a ? f : f.substring(0, i)
}
function n(e, t, r, a) {
    for (var i = e.length, n = new Int32Array(i + i % 4), s = 0; s < i; s++) {
        var o = e.charCodeAt(s);
        if (65 <= o && o <= 90)
            n[s] = o - 65;
        else if (97 <= o && o <= 122)
            n[s] = o - 71;
        else if (48 <= o && o <= 57)
            n[s] = o + 4;
        else if (o === t)
            n[s] = 62;
        else {
            if (o !== r) {
                if (o === a) {
                    i = s;
                    break
                }
                return null
            }
            n[s] = 63
        }
    }
    for (var l = n.length / 4, d = 0, u = 0; d < l; d++,
    u += 4)
        n[d] = n[u] << 18 | n[u + 1] << 12 | n[u + 2] << 6 | n[u + 3];
    for (var c = Math.floor(3 * i / 4), p = new Uint8Array(c), f = 0, h = 0; h + 3 <= c; f++,
    h += 3) {
        var _ = n[f];
        p[h] = _ >> 16,
        p[h + 1] = _ >> 8 & 255,
        p[h + 2] = 255 & _
    }
    switch (c - h) {
    case 2:
        p[h] = n[f] >> 16,
        p[h + 1] = n[f] >> 8 & 255;
        break;
    case 1:
        p[h] = n[f] >> 16
    }
    return p
}

export const BASE64_DATA_URL_SCHEME = "data:image/jpeg;base64,"

export const encodeB64 = function(e) {
    return a(e, 43, 47, !0)
}

export const encodeB64UrlSafe = function(e, t=!1) {
    return a(e, 45, 95, t)
}

export const decodeB64 = function(e) {
    var t = n(e, 43, 47, 61);
    if (t)
        return t.buffer;
    throw new Error("Base64.decode given invalid string")
}

export const decodeB64UrlSafe = function(e) {
    var t = n(e, 45, 95, -1);
    if (t)
        return t.buffer;
    throw new Error("Base64.decode given invalid string")
}

export const decodeB64ToJsArray = function(e) {
    var t = e instanceof ArrayBuffer ? new Uint8Array(e) : n(e, 43, 47, 61);
    return t && [...t]
}

export const sizeWhenB64Decoded = function(e) {
    return Math.floor(3 * e.length / 4)
}