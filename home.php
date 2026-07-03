<?php
require 'db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

$max_idle_seconds = 900;
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $max_idle_seconds)) {
    log_system_event($conn, $_SESSION['username'], 'SESSION_TIMEOUT_EXPIRED');
    session_unset();
    session_destroy();
    header("Location: index.php?expired=1");
    exit;
}
$_SESSION['last_activity'] = time();

$encryption_key = 'YourSuperSecretEncryptionKeyGoesHere';
$message = "";
$status = "";

// HANDLE DELETING A 2FA TOKEN ELEMENT
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action']) && $_POST['action'] === 'delete_2fa') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Security token validation failed.");
    }

    $token_id = intval($_POST['token_id']);

    if ($token_id > 0) {
        // Enforce ownership parity checking by chaining user_id to the query parameter array
        $stmt = $conn->prepare("DELETE FROM two_factor_tokens WHERE id = ? AND user_id = ?");
        $stmt->bind_param("ii", $token_id, $_SESSION['user_id']);
        
        if ($stmt->execute()) {
            log_system_event($conn, $_SESSION['username'], '2FA_TOKEN_DELETED_ID_' . $token_id);
            $message = "2FA entry detached and purged successfully.";
            $status = "success";
        } else {
            $message = "Failed to purge structural data record.";
            $status = "error";
        }
        $stmt->close();
    }
}

// HANDLE REGISTERING AN EXTRACTED OR MANUALLY ENTERED 2FA SEED
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action']) && $_POST['action'] === 'add_2fa') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Security token validation failed.");
    }

    $service_name = trim($_POST['service_name']); 
    $secret_seed = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', trim($_POST['secret_seed']))); 

    if (!empty($service_name) && !empty($secret_seed)) {
        $stmt = $conn->prepare("INSERT INTO two_factor_tokens (user_id, service_name, secret_seed) VALUES (?, ?, AES_ENCRYPT(?, ?))");
        $stmt->bind_param("isss", $_SESSION['user_id'], $service_name, $secret_seed, $encryption_key);
        
        if ($stmt->execute()) {
            log_system_event($conn, $_SESSION['username'], '2FA_KEY_ADDED_' . strtoupper($service_name));
            $message = "2FA Token securely linked to your vault.";
            $status = "success";
        } else {
            $message = "Failed to store 2FA metadata.";
            $status = "error";
        }
        $stmt->close();
    }
}

// FETCH ACTIVE SECURE TOKENS FROM THE SEPARATE TABLE
$stmt = $conn->prepare("SELECT id, service_name, AES_DECRYPT(secret_seed, ?) AS decrypted_seed FROM two_factor_tokens WHERE user_id = ?");
$stmt->bind_param("si", $encryption_key, $_SESSION['user_id']);
$stmt->execute();
$two_factor_tokens = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DaboreyPass - 2FA Control Console</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }
        .container { max-width: 1100px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 20px; margin-bottom: 30px; }
        h1 { color: #38bdf8; margin: 0; font-size: 28px; }
        .logout-btn { padding: 8px 16px; background: #ef4444; color: white; text-decoration: none; border-radius: 4px; font-weight: bold; font-size: 14px; }
        
        .grid-layout { display: grid; grid-template-columns: 1.2fr 1fr; gap: 30px; }
        .box { background: #1e293b; padding: 25px; border-radius: 8px; border: 1px solid #334155; height: fit-content; margin-bottom: 25px; }
        h3 { margin-top: 0; color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 10px; margin-bottom: 15px; }
        
        label { font-size: 13px; color: #94a3b8; display: block; margin-top: 10px; }
        input { width: 100%; padding: 10px; margin: 6px 0 14px 0; box-sizing: border-box; border: 1px solid #475569; border-radius: 4px; background: #0f172a; color: #fff; }
        
        .dropzone-area { border: 2px dashed #475569; background: #0f172a; border-radius: 6px; padding: 20px; text-align: center; cursor: pointer; color: #94a3b8; transition: border-color 0.2s; }
        .dropzone-area:hover, .dropzone-area.dragover { border-color: #38bdf8; color: #f8fafc; }
        .dropzone-area input { display: none; }

        #scanner-viewport { width: 100%; min-height: 200px; background: #0f172a; border-radius: 6px; border: 1px solid #475569; overflow: hidden; margin-bottom: 15px; }
        .cam-controls { display: flex; gap: 10px; margin-bottom: 15px; }
        .cam-btn { background: #0284c7; color: white; border: none; padding: 10px; border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 13px; width: 50%; }
        .cam-btn.stop { background: #ef4444; }
        
        .submit-btn { width: 100%; padding: 12px; background: #10b981; border: none; color: white; border-radius: 4px; cursor: pointer; font-weight: bold; }
        .submit-btn:hover { background: #059669; }

        .error { color: #f87171; background: rgba(248,113,113,0.1); border: 1px solid rgba(248,113,113,0.2); padding: 10px; font-size: 14px; border-radius: 4px; margin-bottom: 15px; }
        .success { color: #34d399; background: rgba(52,211,153,0.1); border: 1px solid rgba(52,211,153,0.2); padding: 10px; font-size: 14px; border-radius: 4px; margin-bottom: 15px; }
        
        .token-row { background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 15px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .token-label { font-size: 12px; color: #94a3b8; text-transform: uppercase; font-weight: bold; }
        .token-code { font-size: 32px; color: #38bdf8; font-family: monospace; font-weight: bold; letter-spacing: 2px; margin-top: 4px; }
        
        .action-tray { display: flex; flex-direction: column; gap: 8px; }
        .copy-btn { background: #334155; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: bold; min-width: 70px; }
        .copy-btn:hover { background: #475569; }
        .del-btn { background: rgba(239, 68, 68, 0.1); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.2); padding: 5px 12px; border-radius: 4px; cursor: pointer; font-size: 11px; font-weight: bold; }
        .del-btn:hover { background: #ef4444; color: white; }

        .progress-wrapper { display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; background: rgba(56, 189, 248, 0.05); padding: 10px; border-radius: 6px; border: 1px solid rgba(56, 189, 248, 0.1); font-size: 13px;}
        .bar-container { background: #334155; height: 6px; width: 120px; border-radius: 3px; overflow: hidden; }
        .bar-fill { background: #38bdf8; height: 100%; width: 100%; transition: width 1s linear; }
    </style>
    <script src="https://unpkg.com/html5-qrcode"></script>
    <script src="https://cdn.jsdelivr.net/npm/otpauth@9.3.6/dist/otpauth.umd.min.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>DaboreyPass 2-Step Terminal</h1>
                <span style="color:#94a3b8; font-size:14px;">Logged in as: <strong><?php echo htmlspecialchars($_SESSION['username']); ?></strong></span>
            </div>
            <a href="logout.php" class="logout-btn">Logout</a>
        </div>

        <?php 
        if ($status === "success") echo "<div class='success'>".htmlspecialchars($message)."</div>";
        if ($status === "error") echo "<div class='error'>".htmlspecialchars($message)."</div>";
        ?>

        <div class="grid-layout">
            <div>
                <div class="box">
                    <h3>Option 1: Scan with Webcam</h3>
                    <div class="cam-controls">
                        <button type="button" class="cam-btn" id="start-cam-btn" onclick="activateWebcamScanner()">Open Camera</button>
                        <button type="button" class="cam-btn stop" id="stop-cam-btn" onclick="killWebcamScanner()" disabled>Close Camera</button>
                    </div>
                    <div id="scanner-viewport"></div>
                </div>

                <div class="box">
                    <h3>Option 2: Upload QR Screenshot</h3>
                    <div class="dropzone-area" id="drop-zone" onclick="document.getElementById('qr-file-input').click()">
                        <div style="font-size: 24px; margin-bottom: 5px;">📁</div>
                        <span>Click or drop your 2FA QR code image here</span>
                        <input type="file" id="qr-file-input" accept="image/*">
                    </div>
                </div>

                <div class="box">
                    <h3>Option 3: Enter Setup Key Manually</h3>
                    <form method="POST" action="">
                        <input type="hidden" name="action" value="add_2fa">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        
                        <label>Account Name / Issuer</label>
                        <input type="text" name="service_name" placeholder="e.g. Google:me@gmail.com, GitHub" required autocomplete="off">
                        
                        <label>Your Secret Key (Base32 String)</label>
                        <input type="text" name="secret_seed" placeholder="e.g. JBSWY3DPEHPK3PXP" required autocomplete="off">
                        
                        <button type="submit" class="submit-btn">Save Key</button>
                    </form>
                </div>

                <form method="POST" action="" id="qr-submit-form">
                    <input type="hidden" name="action" value="add_2fa">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <input type="hidden" id="final-name" name="service_name">
                    <input type="hidden" id="final-seed" name="secret_seed">
                </form>

                <form method="POST" action="" id="delete-token-form">
                    <input type="hidden" name="action" value="delete_2fa">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <input type="hidden" id="delete-target-id" name="token_id">
                </form>
            </div>

            <div class="box">
                <h3>Your Authenticator Codes</h3>
                
                <div class="progress-wrapper">
                    <span id="timer-label">Awaiting clock sync...</span>
                    <div class="bar-container"><div class="bar-fill" id="timer-bar"></div></div>
                </div>

                <div id="token-container">
                    <?php if (empty($two_factor_tokens)): ?>
                        <p style="text-align: center; color: #64748b; font-size: 14px; padding: 20px 0;">No active codes. Register an account using any option on the left.</p>
                    <?php else: ?>
                        <?php foreach ($two_factor_tokens as $token): ?>
                            <div class="token-row">
                                <div>
                                    <div class="token-label"><?php echo htmlspecialchars($token['service_name']); ?></div>
                                    <div class="token-code" id="code-<?php echo $token['id']; ?>" data-seed="<?php echo htmlspecialchars($token['decrypted_seed']); ?>">000 000</div>
                                </div>
                                <div class="action-tray">
                                    <button class="copy-btn" onclick="copyTokenValue('code-<?php echo $token['id']; ?>', this)">Copy</button>
                                    <button class="del-btn" onclick="triggerTokenDeletion(<?php echo $token['id']; ?>, '<?php echo htmlspecialchars(addslashes($token['service_name'])); ?>')">Delete</button>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <script>
    let qrEngineInstance = null;
    const fileInput = document.getElementById('qr-file-input');
    const dropZone = document.getElementById('drop-zone');

    // 1. ENGINE FOR WEBCAM SCANNING
    function activateWebcamScanner() {
        document.getElementById('start-cam-btn').disabled = true;
        document.getElementById('stop-cam-btn').disabled = false;
        qrEngineInstance = new Html5Qrcode("scanner-viewport");
        
        qrEngineInstance.start(
            { facingMode: "user" }, { fps: 15, qrbox: 180 },
            (decodedText) => { handleDecodedText(decodedText); }, () => {}
        ).catch(() => { alert("Camera access denied."); killWebcamScanner(); });
    }

    function killWebcamScanner() {
        document.getElementById('start-cam-btn').disabled = false;
        document.getElementById('stop-cam-btn').disabled = true;
        if (qrEngineInstance) {
            qrEngineInstance.stop().then(() => { document.getElementById('scanner-viewport').innerHTML = ""; });
        }
    }

    // 2. ENGINE FOR FILE UPLOAD SCANNING
    ['dragenter', 'dragover'].forEach(name => dropZone.addEventListener(name, (e) => { e.preventDefault(); dropZone.classList.add('dragover'); }));
    ['dragleave', 'drop'].forEach(name => dropZone.addEventListener(name, (e) => { e.preventDefault(); dropZone.classList.remove('dragover'); }));
    
    dropZone.addEventListener('drop', (e) => {
        if (e.dataTransfer.files.length) { processUploadedFile(e.dataTransfer.files[0]); }
    });
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) { processUploadedFile(e.target.files[0]); }
    });

    function processUploadedFile(file) {
        const engine = new Html5Qrcode("drop-zone");
        engine.scanFile(file, true)
            .then(decodedText => { handleDecodedText(decodedText); })
            .catch(() => { alert("Failed to read image. Ensure the QR code is clearly visible."); });
    }

    // SHARED RECOGNITION DATA PARSER
    function handleDecodedText(text) {
        if (text.startsWith('otpauth://')) {
            try {
                killWebcamScanner();
                let parsed = OTPAuth.URI.parse(text);
                document.getElementById('final-name').value = (parsed.issuer ? parsed.issuer + ":" : "") + parsed.label;
                document.getElementById('final-seed').value = parsed.secret.base32;
                document.getElementById('qr-submit-form').submit();
            } catch (err) { alert("Error parsing QR structural metrics."); }
        } else {
            alert("This QR code is not a valid Google 2FA configuration format.");
        }
    }

    // 3. SECURE DELETION INTERACTION TRIGGER
    function triggerTokenDeletion(id, serviceName) {
        if (confirm("Are you sure you want to permanently delete the 2FA key for '" + serviceName + "'? You will lose access to generating codes for this entry.")) {
            document.getElementById('delete-target-id').value = id;
            document.getElementById('delete-token-form').submit();
        }
    }

    // LIVE TOTP DISPLAY RUNTIME HANDLERS
    function calculateLiveWebTokens() {
        document.querySelectorAll('[id^="code-"]').forEach(el => {
            const seed = el.getAttribute('data-seed');
            try {
                let totp = new OTPAuth.TOTP({ secret: seed });
                let token = totp.generate();
                if(token && token.length === 6) { el.innerText = token.substr(0, 3) + " " + token.substr(3); }
            } catch (err) { el.innerText = "ERR SEED"; }
        });
    }

    function startSyncClock() {
        const timerBar = document.getElementById('timer-bar');
        const timerLabel = document.getElementById('timer-label');
        function updateClockCycle() {
            const remaining = 30 - (Math.floor(new Date().getTime() / 1000) % 30);
            if (timerBar) timerBar.style.width = (remaining / 30) * 100 + '%';
            if (timerLabel) timerLabel.innerText = "Codes change in: " + remaining + "s";
            if (remaining === 30) { calculateLiveWebTokens(); }
        }
        setInterval(updateClockCycle, 1000);
        updateClockCycle();
        calculateLiveWebTokens();
    }

    function copyTokenValue(id, btn) {
        const code = document.getElementById(id).innerText.replace(" ", "");
        navigator.clipboard.writeText(code).then(() => {
            const old = btn.innerText; btn.innerText = "Copied!"; setTimeout(() => { btn.innerText = old; }, 1200);
        });
    }

    window.addEventListener('DOMContentLoaded', startSyncClock);
    </script>
</body>
</html>