document.addEventListener("DOMContentLoaded", function () {
  const beginButton = document.getElementById("begin-button");

  beginButton.addEventListener("click", function () {
    // Using a relative URL for security (prevents open redirect vulnerabilities)
    window.location.href = "/home";
  });
});
