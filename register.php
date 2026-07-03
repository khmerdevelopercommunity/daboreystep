<?php
require 'db.php';

$message = "";
$status = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Security token validation failed.");
    }

    $username = trim($_POST['username']);
    $password = trim($_POST['password']);

    if (strlen($password) < 12 || 
        !preg_match('/[A-Z]/', $password) || 
        !preg_match('/[a-z]/', $password) || 
        !preg_match('/[0-9]/', $password) || 
        !preg_match('/[^a-zA-Z0-9]/', $password)) {
        
        $message = "Registration Rejected: Password strength policy violation.";
        $status = "error";
    } else if (!empty($username)) {
        $hashed_password = password_hash($password, PASSWORD_ARGON2ID);

        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $message = "Identity identifier unavailable.";
            $status = "error";
        } else {
            $stmt->close();
            $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
            $stmt->bind_param("ss", $username, $hashed_password);

            if ($stmt->execute()) {
                log_system_event($conn, $username, 'USER_REGISTRATION_SUCCESSFUL');
                $message = "Identity provisioned successfully.";
                $status = "success";
            } else {
                $message = "System runtime parsing failure.";
                $status = "error";
            }
        }
        $stmt->close();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Identity Registration</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #0f172a; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; color: #f8fafc; }
        .box { background: #1e293b; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); width: 350px; border: 1px solid #334155; }
        h2 { margin-top: 0; color: #10b981; text-align: center; }
        input { width: 100%; padding: 12px; margin: 10px 0; box-sizing: border-box; border: 1px solid #475569; border-radius: 4px; background: #0f172a; color: #fff; }
        button { width: 100%; padding: 12px; background: #10b981; border: none; color: white; font-weight: bold; border-radius: 4px; cursor: pointer; }
        .error { color: #f87171; background: rgba(248,113,113,0.1); border: 1px solid rgba(248,113,113,0.2); padding: 10px; font-size: 14px; border-radius: 4px; margin-bottom: 15px; }
        .success { color: #34d399; background: rgba(52,211,153,0.1); border: 1px solid rgba(52,211,153,0.2); padding: 10px; font-size: 14px; border-radius: 4px; margin-bottom: 15px; }
        .links { text-align: center; margin-top: 20px; }
        .links a { color: #38bdf8; text-decoration: none; font-size: 14px; }
    </style>
</head>
<body>
    <div class="box">
        <h2>Register Node</h2>
        <?php 
        if ($status === "success") echo "<div class='success'>".htmlspecialchars($message)." <a href='index.php' style='color:#38bdf8;'>Sign In</a></div>";
        if ($status === "error") echo "<div class='error'>".htmlspecialchars($message)."</div>";
        ?>
        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="text" name="username" placeholder="Username" required autocomplete="off">
            <input type="password" name="password" placeholder="Complex Password Profile" required>
            <button type="submit">Provision Account</button>
        </form>
        <div class="links"><a href="index.php">Return to System Sign In</a></div>
    </div>
</body>
</html>