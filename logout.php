<?php
require 'db.php';

if (isset($_SESSION['username'])) {
    log_system_event($conn, $_SESSION['username'], 'USER_LOGOUT_EXPLICIT');
}

$_SESSION = array();

if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httonly"]
    );
}

session_destroy();
header("Location: index.php");
exit;
?>