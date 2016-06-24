(function () {
var enpaco = {};
enpaco.encrypt = enpaco.encrypt.mode.nacl;
enpaco.decrypt = enpaco.decrypt.mode.nacl;

enpaco.encrypt.mode.nacl = function(message) {
    var msg = nacl.util.decodeUTF8(message);
    var key = nacl.randomBytes(nacl.secretbox.keyLength);
    var nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    var box = nacl.secretbox(msg, nonce, key);

    var payload = new Uint8Array(nonce.byteLength + box.byteLength);
    payload.set(nonce, 0);
    payload.set(box, nonce.byteLength);

    var ascii_payload = nacl.util.encodeBase64(payload);
    var ascii_key = nacl.util.encodeBase64(key);

    return {
        payload: ascii_payload,
        key: ascii_key
    }
}

enpaco.decrypt.mode.nacl = function(ascii_payload, ascii_key) {
    var key = nacl.util.decodeBase64(ascii_key);
    var payload = nacl.util.decodeBase64(ascii_payload);
    var nonce = payload.slice(0, nacl.secretbox.nonceLength);
    var box = payload.slice(nacl.secretbox.nonceLength);

    var message = nacl.secretbox.open(box, nonce, key);
    message = nacl.util.encodeUTF8(message);

    return message;
}

window.enpaco = enpaco;
}());