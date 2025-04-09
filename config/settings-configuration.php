<?php
// Start a new session or resume the existing session.
session_start();

// Enable the display of errors for debugging purposes.
ini_set('display_errors', 1);
// Enable the display of startup errors for debugging purposes.
ini_set('display_startup_errors', 1);
// Set the error reporting level to display all errors, warnings, and notices.
error_reporting(E_ALL);

// Check if the CSRF token is not already set in the session.
if (empty($_SESSION['csrf_token'])) {
    // Generate a new random CSRF token using 32 bytes of random data.
    $csrf_token = bin2hex(random_bytes(32));
    // Store the generated CSRF token in the session.
    $_SESSION['csrf_token'] = $csrf_token;
} else {
    // If the CSRF token already exists in the session, retrieve it.
    $csrf_token = $_SESSION['csrf_token'];
}
?>