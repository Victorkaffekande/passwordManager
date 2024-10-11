function copyToClipboard(elementId) {
    let element = document.getElementById(elementId);
    let val = element.value

    navigator.clipboard.writeText(val)
}

function generatePassword(inputId) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
    let password = "";
    const length = 20

    for (let i = 0, n = charset.length; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * n));
    }
    let inputElement = document.getElementById(inputId)
    inputElement.value = password
}