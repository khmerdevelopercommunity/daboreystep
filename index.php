<?php
require 'db.php';

if (isset($_SESSION['user_id'])) {
    header("Location: home.php");
    exit;
}

$error = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        log_system_event($conn, 'ANONYMOUS', 'CSRF_VALIDATION_FAILURE');
        die("Security token validation failed.");
    }

    $username = trim($_POST['username']);
    $password = trim($_POST['password']);
    $now = date('Y-m-d H:i:s');

    $stmt = $conn->prepare("SELECT id, password, login_attempts, lock_until FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();
    
    if ($stmt->num_rows > 0) {
        $stmt->bind_result($id, $hashed_password, $login_attempts, $lock_until);
        $stmt->fetch();
        
        if ($lock_until && $lock_until > $now) {
            log_system_event($conn, $username, 'LOGIN_REJECTED_ACCOUNT_LOCKED');
            $error = "This account is temporarily locked due to multiple failed login attempts. Try again later.";
        } else {
            if (password_verify($password, $hashed_password)) {
                $reset_stmt = $conn->prepare("UPDATE users SET login_attempts = 0, lock_until = NULL WHERE id = ?");
                $reset_stmt->bind_param("i", $id);
                $reset_stmt->execute();
                $reset_stmt->close();

                session_regenerate_id(true);
                $_SESSION['user_id'] = $id;
                $_SESSION['username'] = $username;
                $_SESSION['last_activity'] = time();
                
                log_system_event($conn, $username, 'LOGIN_SUCCESSFUL');
                header("Location: home.php");
                exit;
            } else {
                $login_attempts++;
                if ($login_attempts >= 5) {
                    $lock_time = date('Y-m-d H:i:s', strtotime('+15 minutes'));
                    $lock_stmt = $conn->prepare("UPDATE users SET login_attempts = ?, lock_until = ? WHERE id = ?");
                    $lock_stmt->bind_param("isi", $login_attempts, $lock_time, $id);
                    log_system_event($conn, $username, 'ACCOUNT_TRIGGERED_LOCKOUT');
                } else {
                    $lock_stmt = $conn->prepare("UPDATE users SET login_attempts = ? WHERE id = ?");
                    $lock_stmt->bind_param("ii", $login_attempts, $id);
                    log_system_event($conn, $username, 'LOGIN_FAILED_WRONG_PASSWORD');
                }
                $lock_stmt->execute();
                $lock_stmt->close();
                
                $error = "Invalid username or password.";
            }
        }
    } else {
        log_system_event($conn, $username, 'LOGIN_FAILED_NONEXISTENT_USER');
        $error = "Invalid username or password.";
    }
    $stmt->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Portal Login</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #0f172a; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; color: #f8fafc; }
        .box { background: #1e293b; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); width: 350px; border: 1px solid #334155; }
        h2 { margin-top: 0; color: #38bdf8; text-align: center; }
        input { width: 100%; padding: 12px; margin: 10px 0; box-sizing: border-box; border: 1px solid #475569; border-radius: 4px; background: #0f172a; color: #fff; }
        button { width: 100%; padding: 12px; background: #0284c7; border: none; color: white; border-radius: 4px; cursor: pointer; font-weight: bold; }
        .error { color: #f87171; background: rgba(248,113,113,0.1); border: 1px solid rgba(248,113,113,0.2); padding: 10px; font-size: 14px; border-radius: 4px; margin-bottom: 15px; text-align: center; }
        .links { text-align: center; margin-top: 20px; }
        .links a { color: #38bdf8; text-decoration: none; font-size: 14px; }
    </style>
</head>
<body>
    <div class="box">
        <h2>Secure Authorization</h2>
        <?php if ($error) echo "<div class='error'>".htmlspecialchars($error)."</div>"; ?>
        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="text" name="username" placeholder="Username" required autocomplete="off">
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Verify Credentials</button>
        </form>
        <div class="links"><a href="register.php">Register System Identity</a></div>
    </div>
</body>
</html>