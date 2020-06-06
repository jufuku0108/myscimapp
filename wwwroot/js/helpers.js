coerceToArrayBuffer = function (thing, name) {
    if (typeof thing === "string") {
        thing = thing.replace(/-/g, "+").replace(/_/g, "/");

        var str = window.atob(thing);
        var bytes = new Uint8Array(str.length);
        for (var i = 0; i < str.length; i++){
            bytes[i] = str.charCodeAt(i);
        }
        thing = bytes;
    }
    if(Array.isArray(thing)) {
        thing = new Uint8Array(thing);
    }
    if(thing instanceof Uint8Array){
        thing = thing.buffer;
    }
    if(!(thing instanceof ArrayBuffer)) {
        throw new TypeError("could not coerce " + name + " to ArrayBuffer");
    }
    return thing;
}

coerceToBase64Url = function (thing) {
    if(Array.isArray(thing)){
        thing = Uint8Array.from(thing)
    }
    if (thing instanceof ArrayBuffer){
        thing = new Uint8Array(thing)
    }

    if(thing instanceof Uint8Array){
        var str = "";
        var len = thing.byteLength;

        for(var i = 0; i < len; i++){
            str += String.fromCharCode(thing[i]);
        }
        thing = window.btoa(str);
    }
    if(typeof thing !== "string"){
        throw new Error("Could not coerce to string");
    }
    thing = thing.replace(/\+/g, "-").replace(/\//g, "_").replace(/=*$/g, "");
    return thing;
}

function showErrorAlert(message, error) {
    let footmsg = '';
    if(error){
        footmsg = 'exception:' + error.toString();
    }
    Swal.fire({
        icon: 'error',
        title: 'Error',
        text: message,
        footer: footmsg
    })
}
function detectFIDOSupport() {
    if(window.PublicKeyCredential === undefined || 
        typeof window.PublicKeyCredential !== "function") {
            var el = document.getElementById("notSupportedWarning");
            if(el) {
                el.style.display = 'block';
            }
            return;
    }
    
}
function value(selector) {
    var el = document.querySelector(selector);
    if(el.type === "checkbox") {
        return el.checked;
    }
    return el.value;
}