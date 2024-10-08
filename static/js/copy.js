function copyToClipboard(elementId) {
    let copyGfGText = document.getElementById(elementId);
    let val = copyGfGText.value

    navigator.clipboard.writeText(val)
}