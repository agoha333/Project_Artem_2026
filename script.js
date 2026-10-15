function sha1HexFromString(input) {
    var utf8 = unescape(encodeURIComponent(input));
    var bytes = new Array(utf8.length);
    for (var i = 0; i < utf8.length; i++) {
        bytes[i] = utf8.charCodeAt(i);
    }
    return sha1FromBytes(bytes);
}

function sha1HexFromArrayBuffer(buffer) {
    var view = new Uint8Array(buffer);
    var bytes = new Array(view.length);
    for (var i = 0; i < view.length; i++) {
        bytes[i] = view[i];
    }
    return sha1FromBytes(bytes);
}

function sha1FromBytes(bytes) {
    var ml = bytes.length * 8;
    var withOne = bytes.slice();
    withOne.push(0x80);
    while ((withOne.length % 64) !== 56) {
        withOne.push(0);
    }
    var hi = Math.floor(ml / 0x100000000);
    var lo = ml >>> 0;
    withOne.push((hi >>> 24) & 0xff);
    withOne.push((hi >>> 16) & 0xff);
    withOne.push((hi >>> 8) & 0xff);
    withOne.push(hi & 0xff);
    withOne.push((lo >>> 24) & 0xff);
    withOne.push((lo >>> 16) & 0xff);
    withOne.push((lo >>> 8) & 0xff);
    withOne.push(lo & 0xff);

    var h0 = 0x67452301;
    var h1 = 0xEFCDAB89;
    var h2 = 0x98BADCFE;
    var h3 = 0x10325476;
    var h4 = 0xC3D2E1F0;
    var w = new Array(80);

    for (var chunk = 0; chunk < withOne.length; chunk += 64) {
        for (var j = 0; j < 16; j++) {
            w[j] = (withOne[chunk + j * 4] << 24) |
                   (withOne[chunk + j * 4 + 1] << 16) |
                   (withOne[chunk + j * 4 + 2] << 8) |
                   (withOne[chunk + j * 4 + 3]);
        }
        for (var j2 = 16; j2 < 80; j2++) {
            w[j2] = rotl(w[j2 - 3] ^ w[j2 - 8] ^ w[j2 - 14] ^ w[j2 - 16], 1);
        }

        var a = h0, b = h1, c = h2, d = h3, e = h4;

        for (var k = 0; k < 80; k++) {
            var f, kk;
            if (k < 20) {
                f = (b & c) | ((~b) & d);
                kk = 0x5A827999;
            } else if (k < 40) {
                f = b ^ c ^ d;
                kk = 0x6ED9EBA1;
            } else if (k < 60) {
                f = (b & c) | (b & d) | (c & d);
                kk = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                kk = 0xCA62C1D6;
            }

            var tmp = (rotl(a, 5) + f + e + kk + w[k]) >>> 0;
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = tmp;
        }

        h0 = (h0 + a) >>> 0;
        h1 = (h1 + b) >>> 0;
        h2 = (h2 + c) >>> 0;
        h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0;
    }

    return toHex(h0) + toHex(h1) + toHex(h2) + toHex(h3) + toHex(h4);
}

function rotl(n, s) {
    return ((n << s) | (n >>> (32 - s))) >>> 0;
}

function toHex(n) {
    var s = (n >>> 0).toString(16);
    while (s.length < 8) {
        s = "0" + s;
    }
    return s;
}

function normalizeHashText(text) {
    var t = String(text);
    if (t.charCodeAt(0) === 0xFEFF) {
        t = t.substring(1);
    }
    t = t.replace(/[\s\r\n\t]+/g, "");
    return t.toLowerCase();
}

function looksLikeSha1Hex(text) {
    return /^[0-9a-f]{40}$/.test(text);
}

var tabs = document.querySelectorAll(".tab");
var pages = document.querySelectorAll(".page");

for (var i = 0; i < tabs.length; i++) {
    tabs[i].addEventListener("click", function () {
        for (var j = 0; j < tabs.length; j++) {
            tabs[j].classList.remove("active");
        }
        for (var k = 0; k < pages.length; k++) {
            pages[k].classList.remove("active");
        }
        this.classList.add("active");
        document.getElementById("page-" + this.getAttribute("data-tab")).classList.add("active");
    });
}

var inputText = document.getElementById("inputText");
var outputHash = document.getElementById("outputHash");
var encryptBtn = document.getElementById("encryptBtn");

encryptBtn.addEventListener("click", function () {
    if (inputText.value.length === 0) {
        outputHash.value = "";
        return;
    }
    outputHash.value = sha1HexFromString(inputText.value);
});

var loadHashBtn = document.getElementById("loadHashBtn");
var hashFileInput = document.getElementById("hashFileInput");
var loadFileBtn = document.getElementById("loadFileBtn");
var targetFileInput = document.getElementById("targetFileInput");
var compareBtn = document.getElementById("compareBtn");
var resultBox = document.getElementById("resultBox");

var storedHash = "";
var storedFileBuffer = null;

loadHashBtn.addEventListener("click", function () {
    hashFileInput.click();
});

hashFileInput.addEventListener("change", function () {
    var f = hashFileInput.files[0];
    if (!f) {
        return;
    }
    var reader = new FileReader();
    reader.onload = function (e) {
        var raw = String(e.target.result);
        var cleaned = normalizeHashText(raw);
        if (looksLikeSha1Hex(cleaned)) {
            storedHash = cleaned;
        } else {
            storedHash = raw.trim().toLowerCase();
        }
        loadHashBtn.textContent = "Хэш загружен";
        resultBox.className = "result-box";
        resultBox.textContent = "";
    };
    reader.readAsText(f);
});

loadFileBtn.addEventListener("click", function () {
    targetFileInput.click();
});

targetFileInput.addEventListener("change", function () {
    var f = targetFileInput.files[0];
    if (!f) {
        return;
    }
    var reader = new FileReader();
    reader.onload = function (e) {
        storedFileBuffer = e.target.result;
        loadFileBtn.textContent = "Файл загружен";
        resultBox.className = "result-box";
        resultBox.textContent = "";
    };
    reader.readAsArrayBuffer(f);
});

compareBtn.addEventListener("click", function () {
    if (!storedHash || !storedFileBuffer) {
        return;
    }
    var fileHash = sha1HexFromArrayBuffer(storedFileBuffer).toLowerCase();
    resultBox.className = "result-box";
    if (fileHash === storedHash) {
        resultBox.classList.add("match");
        resultBox.textContent = "Хэш совпадает";
    } else {
        resultBox.classList.add("mismatch");
        resultBox.textContent = "Хэш не совпадает";
    }
});