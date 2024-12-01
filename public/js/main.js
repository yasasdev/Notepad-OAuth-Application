function loginButton() {
    window.location.href = "/login";
}

document.getElementById("google-login").addEventListener("click", function () {
    window.location.href = "/auth/google";
});