<?php
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1); 
    ini_set('session.use_only_cookies', 1);
    ini_set('session.cookie_samesite', 'Strict');
    session_start();
}

$host = "localhost";
$user = "root"; 
$pass = "";     
$dbname = "daboreypass";

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

try {
    $conn = new mysqli($host, $user, $pass, $dbname);
    $conn->set_charset("utf8mb4");
} catch (Exception $e) {
    die("System connection exception. Check internal system logs.");
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function log_system_event($conn, $username, $action) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP';
    $log_stmt = $conn->prepare("INSERT INTO audit_logs (username, action_performed, network_ip) VALUES (?, ?, ?)");
    $log_stmt->bind_param("sss", $username, $action, $ip);
    $log_stmt->execute();
    $log_stmt->close();
}
?>