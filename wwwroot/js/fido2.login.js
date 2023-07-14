window.addEventListener("load", function () {
    document.getElementById('fido2signin').addEventListener('click', handleSigninSubmit);
})


async function handleSigninSubmit(event) {
    event.preventDefault();

    // Fetch assertion options.
    let makeAssertionOptions;
    try {
        makeAssertionOptions = await fetchAssertionOptions();

        if(makeAssertionOptions.status !== "ok") {
            console.log('Error creating assertion options.');
            console.log(makeAssertionOptions.errorMessage);
            return;
        }

        const challenge = makeAssertionOptions.challenge.replace(/-/g, "+").replace(/_/g, "/");
        makeAssertionOptions.challenge = Uint8Array.from(atob(challenge), c => c.charCodeAt(0));
        
        makeAssertionOptions.allowCredentials.forEach(function (listitem) {
            var fixId = listitem.id.replace(/\_/g, "/").replace(/\-/g, "+");
            listitem.id = Uint8Array.from(atob(fixId), c => c.charCodeAt(0));
        })
        
    } catch (e) {
        showErrorAlert("Failed to create assertion options.", e)
        return;
    }

    // Get credential from authenticator
    let credential;
    try {
        Swal.fire({
            title: 'Logging in...',
            text: 'Tap your security key to log in.',
            imageUrl: '/images/securitykey.min.svg',
            showCancelButton: true,
            showConfirmButton: false,
            focusConfirm: false,
            focusCancel: false
        });

        credential = await navigator.credentials.get({publicKey: makeAssertionOptions});
    } catch (err) {
        showErrorAlert(err.message ? err.message : err);
        return;
    }

    // Verify assertion
    try {
        var result = await verifyAssertionWithServer(credential);

        if(result.status !== "ok") {
            console.log('Error doing assertion.');
            console.log(result.errorMessage);
            showErrorAlert(result.errorMessage)
            return;
        }
        
        await Swal.fire({
            title: 'Logged in!',
            text: 'You\'ved logged in successfully.',
            icon: 'success',
            timer: 2000
        });

        var urlParams = new URLSearchParams(window.location.search);
        if(urlParams.has('ReturnUrl')){
            let redirectUri = urlParams.get('ReturnUrl');
            redirectUri = redirectUri.replace('~/', '/');
            window.location.href = redirectUri;
        } else {
            window.location.href = "/AccountManage/Index";
        }
    
    } catch (e) {
        showErrorAlert('Could not verify assertion.', e)
        return;
    }
}

async function fetchAssertionOptions(){
    var formData = new FormData;
    var response = await fetch('/assertionOptions', {
        method: 'POST',
        body: formData,
        headers: {
            'Accept': 'application/json'
        }
    });
    let result =  response.json();
    return result;
}

async function verifyAssertionWithServer(assertedCredential) {
    let authData = new Uint8Array(assertedCredential.response.authenticatorData);
    let clientDataJSON = new Uint8Array(assertedCredential.response.clientDataJSON);
    let rawId = new Uint8Array(assertedCredential.rawId);
    let sig = new Uint8Array(assertedCredential.response.signature);
    let userHandle = new Uint8Array(assertedCredential.response.userHandle);

    const data = {
        id: assertedCredential.id,
        rawId: coerceToBase64Url(rawId),
        type: assertedCredential.type,
        extentions: assertedCredential.getClientExtensionResults(),
        response: {
            authenticatorData: coerceToBase64Url(authData),
            signature: coerceToBase64Url(sig),
            clientDataJSON: coerceToBase64Url(clientDataJSON),
            userHandle: userHandle !== null ? coerceToBase64Url(userHandle) : null
        }
    }
    
    let result;    
    let response = await fetch("/makeAssertion", {
        method: 'POST',
        body: JSON.stringify(data),
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    });
    result = response.json();
    return result;
}