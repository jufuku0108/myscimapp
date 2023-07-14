window.addEventListener("load", function () {
    document.getElementById('register').addEventListener('click', handleRegisterSubmit);
})

async function handleRegisterSubmit(event) {
    event.preventDefault();

    // makeCredentialOptions
    let makeCredentialOptions;
    try{
        makeCredentialOptions = await fetchMakeCredentialOptions();

        if(makeCredentialOptions.status !== 'ok'){
            console.log('Error creating credential options.');
            console.log(makeCredentialOptions.errorMessage);
            showErrorAlert(makeCredentialOptions.errorMessage);
            return;
        }

        makeCredentialOptions.challenge = coerceToArrayBuffer(makeCredentialOptions.challenge);
        makeCredentialOptions.user.id = coerceToArrayBuffer(makeCredentialOptions.user.id);
        makeCredentialOptions.excludeCredentials = makeCredentialOptions.excludeCredentials.map((c) => {
            c.id = coerceToArrayBuffer(c.id);
            return c;
        })
        if(makeCredentialOptions.authenticatorSelection.authenticatorAttachment === null) {
            makeCredentialOptions.authenticatorSelection.authenticatorAttachment = undefined;
        }
        
    } catch(e){
        console.log(e);
        let msg = "Something went wrong.";
        showErrorAlert(msg);
        return;
    }
    
    // Create new credential
    let newCredential;
    try {

        Swal.fire({
            title: 'Registering...',
            text: 'Tap your security key to finish registration.',
            imageUrl: "/images/securitykey.min.svg",
            showCancelButton: true,
            showConfirmButton: false,
            focusConfirm: false,
            focusCancel: false
        });
    
        newCredential = await navigator.credentials.create({
            publicKey: makeCredentialOptions
        });

    } catch(e) {
        var msg = "Could not create credentials in browser. Probably because the username is already registered with your authenticatior. Please change your username or authenticator."
        console.log(msg, e);
        showErrorAlert(msg, e);
        return;
    }

    // Register new credential
    let result;
    try {
        result = await registerNewCredential(newCredential)

        if(result.status !== "ok") {
            console.log("Error creating credential.");
            console.log(result.errorMessage);
            showErrorAlert(result.errorMessage);
            return;
        }
        await Swal.fire({
            title: 'Registration successful!',
            text: 'You\'ve registered successfully.',
            icon: 'success',
            timer: 2000
        });
    } catch (e) {
        showErrorAlert(e.message ? e.message : e);
        return;
    }

}

async function fetchMakeCredentialOptions() {

    let attestation_type = "none";
    let authenticator_attachment = "";
    let user_verification = "preferred";
    let require_resident_key = true;

    var formData = new FormData();
    formData.append('attType', attestation_type);
    formData.append('authType', authenticator_attachment);
    formData.append('userVerification', user_verification);
    formData.append('requireResidentKey', require_resident_key);

    let response = await fetch('/makeCredentialOptions', {
        method: 'POST',
        body: formData,
        headers: {
            'Accept': 'application/json'
        }
    });
    let result = response.json();
    return result;
}

async function registerNewCredential(newCredential) {

    let result;
    let attestationObject = new Uint8Array(newCredential.response.attestationObject);
    let clientDataJSON = new Uint8Array(newCredential.response.clientDataJSON);
    let rawId = new Uint8Array(newCredential.rawId);
        
    const formData = {
        id: newCredential.id,
        rawId: coerceToBase64Url(rawId),
        type: newCredential.type,
        extension: newCredential.getClientExtensionResults(),
        response: {
            AttestationObject: coerceToBase64Url(attestationObject),
            clientDataJSON: coerceToBase64Url(clientDataJSON)
        }
    };

    response = await fetch('/makeCredential', {
        method: 'POST',
        body:  JSON.stringify(formData),
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    });
    result = response.json();
    return result;
}

