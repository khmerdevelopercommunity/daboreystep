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

// FETCH ACTIVE SECURE TOKENS FROM THE DATABASE
function fetchUserTokens($conn, $userId, $encKey) {
    $stmt = $conn->prepare("SELECT id, service_name, AES_DECRYPT(secret_seed, ?) AS decrypted_seed FROM two_factor_tokens WHERE user_id = ?");
    $stmt->bind_param("si", $encKey, $userId);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    return $result;
}

// ACTION: UNIVERSAL JSON EXPORT
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action']) && $_POST['action'] === 'export_backup') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Security token validation failed.");
    }
    
    $tokens = fetchUserTokens($conn, $_SESSION['user_id'], $encryption_key);
    log_system_event($conn, $_SESSION['username'], '2FA_UNIVERSAL_JSON_EXPORTED');
    
    $exportData = [];
    foreach ($tokens as $t) {
        if (!empty($t['decrypted_seed'])) {
            $exportData[] = [
                'name'   => $t['service_name'],
                'secret' => strtoupper($t['decrypted_seed'])
            ];
        }
    }
    
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="Vault_Backup_' . date('Ymd_His') . '.json"');
    echo json_encode($exportData, JSON_PRETTY_PRINT);
    exit;
}

// ACTION: UNIVERSAL MULTI-CONDITION PLUG-AND-PLAY IMPORT ENGINE
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action']) && $_POST['action'] === 'import_backup') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Security token validation failed.");
    }

    if (isset($_FILES['backup_file']) && $_FILES['backup_file']['error'] === UPLOAD_ERR_OK) {
        $fileContent = file_get_contents($_FILES['backup_file']['tmp_name']);
        $payload = json_decode($fileContent, true);
        
        if (is_array($payload)) {
            $items = $payload;
            if (!isset($payload[0])) { 
                foreach ($payload as $key => $value) {
                    if (is_array($value)) {
                        $items = $value;
                        break;
                    }
                }
            }

            $success_count = 0;
            $stmt = $conn->prepare("INSERT INTO two_factor_tokens (user_id, service_name, secret_seed) VALUES (?, ?, AES_ENCRYPT(?, ?))");
            
            foreach ($items as $item) {
                if (!is_array($item)) continue;
                $cleanItem = array_change_key_case($item, CASE_LOWER);
                $name = trim($cleanItem['name'] ?? $cleanItem['label'] ?? $cleanItem['issuer'] ?? $cleanItem['originalname'] ?? $cleanItem['issuername'] ?? 'Imported Account');
                
                $seed = '';
                if (isset($cleanItem['secret']) && !empty($cleanItem['secret'])) {
                    $seed = trim($cleanItem['secret']);
                } elseif (isset($cleanItem['seed']) && !empty($cleanItem['seed'])) {
                    $seed = trim($cleanItem['seed']);
                } elseif (isset($cleanItem['key']) && !empty($cleanItem['key'])) {
                    $seed = trim($cleanItem['key']);
                } elseif (isset($cleanItem['secretname']) && !empty($cleanItem['secretname'])) {
                    $seed = trim($cleanItem['secretname']);
                } elseif (isset($cleanItem['totp']['secret']) && !empty($cleanItem['totp']['secret'])) {
                    $seed = trim($cleanItem['totp']['secret']);
                } elseif (isset($cleanItem['uri']) && !empty($cleanItem['uri'])) {
                    parse_str(parse_url($cleanItem['uri'], PHP_URL_QUERY), $queryOpts);
                    $seed = $queryOpts['secret'] ?? '';
                }

                $seed = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', $seed));
                
                if (!empty($name) && !empty($seed)) {
                    $stmt->bind_param("isss", $_SESSION['user_id'], $name, $seed, $encryption_key);
                    if ($stmt->execute()) {
                        $success_count++;
                    }
                }
            }
            $stmt->close();
            
            if ($success_count > 0) {
                log_system_event($conn, $_SESSION['username'], '2FA_UNIVERSAL_JSON_IMPORTED_COUNT_' . $success_count);
                $message = "Migration Complete! Successfully loaded " . $success_count . " profiles.";
                $status = "success";
            } else {
                $message = "Could not parse data pairs out of this file structure.";
                $status = "error";
            }
        } else {
            $message = "Invalid JSON structure framework syntax.";
            $status = "error";
        }
    } else {
        $message = "File upload failure. Check properties and retry.";
        $status = "error";
    }
}

// ACTION: DELETING A 2FA TOKEN ELEMENT
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action']) && $_POST['action'] === 'delete_2fa') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Security token validation failed.");
    }

    $token_id = intval($_POST['token_id']);
    if ($token_id > 0) {
        $stmt = $conn->prepare("DELETE FROM two_factor_tokens WHERE id = ? AND user_id = ?");
        $stmt->bind_param("ii", $token_id, $_SESSION['user_id']);
        
        if ($stmt->execute()) {
            log_system_event($conn, $_SESSION['username'], '2FA_TOKEN_DELETED_ID_' . $token_id);
            $message = "2FA entry purged successfully.";
            $status = "success";
        } else {
            $message = "Failed to purge database entry.";
            $status = "error";
        }
        $stmt->close();
    }
}

// ACTION: REGISTERING AN EXTRACTED OR MANUALLY ENTERED 2FA SEED
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

// Fetch all elements once (filtering handles inside DOM dynamically via Javascript)
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
        
        /* Modernized Active Live Search Interface Bar */
        .search-container { position: relative; margin-bottom: 20px; }
        .search-input { width: 100%; padding: 12px 14px; box-sizing: border-box; border: 1px solid #0284c7; border-radius: 6px; background: #0f172a; color: #fff; font-size: 14px; margin: 0; }
        .search-input:focus { outline: none; border-color: #38bdf8; box-shadow: 0 0 8px rgba(56, 189, 248, 0.2); }
        
        /* Highlighting syntax style color rules */
        mark.highlight { background: #eab308; color: #0f172a; padding: 1px 3px; border-radius: 2px; font-weight: bold; }

        .dropzone-area { border: 2px dashed #475569; background: #0f172a; border-radius: 6px; padding: 20px; text-align: center; cursor: pointer; color: #94a3b8; }
        .dropzone-area:hover, .dropzone-area.dragover { border-color: #38bdf8; color: #f8fafc; }
        .dropzone-area input { display: none; }

        .viewport-box { width: 100%; min-height: 200px; background: #0f172a; border-radius: 6px; border: 1px solid #475569; overflow: hidden; margin-bottom: 15px; margin-top: 5px; }
        .cam-segment { background: rgba(15, 23, 42, 0.4); padding: 15px; border-radius: 6px; border: 1px solid #334155; margin-bottom: 20px; }
        .cam-btn { background: #0284c7; color: white; border: none; padding: 8px 14px; border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 12px; }
        .cam-btn.stop { background: #ef4444; }
        
        .submit-btn { width: 100%; padding: 12px; background: #10b981; border: none; color: white; border-radius: 4px; cursor: pointer; font-weight: bold; }
        .submit-btn:hover { background: #059669; }

        .backup-tray { display: flex; flex-direction: column; gap: 15px; border-top: 2px dashed #334155; padding-top: 20px; margin-top: 25px; }
        .btn-backup { background: #4f46e5; border: none; color: white; font-weight: bold; padding: 12px; border-radius: 4px; cursor: pointer; width: 100%; font-size: 14px; text-align: center; display: block; text-decoration: none;}
        .btn-backup:hover { background: #4338ca; }
        .import-box-area { background: #0f172a; border: 1px dashed #475569; border-radius: 6px; padding: 15px; text-align: center; cursor: pointer; color: #94a3b8; font-size: 13px; }
        .import-box-area:hover { border-color: #a855f7; color: #fff; }

        .error { color: #f87171; background: rgba(248,113,113,0.1); border: 1px solid rgba(248,113,113,0.2); padding: 10px; font-size: 14px; border-radius: 4px; margin-bottom: 15px; }
        .success { color: #34d399; background: rgba(52,211,153,0.1); border: 1px solid rgba(52,211,153,0.2); padding: 10px; font-size: 14px; border-radius: 4px; margin-bottom: 15px; }
        
        .token-row { background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 15px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; transition: all 0.15s ease; }
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
        
        #no-results-message { text-align: center; color: #64748b; font-size: 14px; padding: 30px 0; display: none; }
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
                    <h3>Option 1: Scan via Live Viewport</h3>
                    <div class="cam-segment">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-size:14px; font-weight:bold; color:#f8fafc;">📷 Option 1A: Back Camera (Rear Lens)</span>
                            <div>
                                <button type="button" class="cam-btn" id="start-env-btn" onclick="startCameraEngine('env')">Open</button>
                                <button type="button" class="cam-btn stop" id="stop-env-btn" onclick="stopCameraEngine('env')" disabled>Close</button>
                            </div>
                        </div>
                        <div id="env-viewport" class="viewport-box"></div>
                    </div>

                    <div class="cam-segment" style="margin-bottom: 0;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-size:14px; font-weight:bold; color:#f8fafc;">🤳 Option 1B: Front Camera (Selfie Lens)</span>
                            <div>
                                <button type="button" class="cam-btn" id="start-usr-btn" onclick="startCameraEngine('usr')">Open</button>
                                <button type="button" class="cam-btn stop" id="stop-usr-btn" onclick="stopCameraEngine('usr')" disabled>Close</button>
                            </div>
                        </div>
                        <div id="usr-viewport" class="viewport-box"></div>
                    </div>
                </div>

                <div class="box">
                    <h3>Option 2: Upload QR Screenshot</h3>
                    <div class="dropzone-area" id="drop-zone" onclick="document.getElementById('qr-file-input').click()">
                        <div style="font-size: 24px; margin-bottom: 5px;">🖼️</div>
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
                        <input type="text" name="service_name" placeholder="e.g. Google:me@gmail.com" required autocomplete="off">
                        
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
                
                <div class="search-container">
                    <input type="text" id="live-search-bar" class="search-input" placeholder="Type to search & filter tokens instantly..." autocomplete="off">
                </div>

                <div class="progress-wrapper">
                    <span id="timer-label">Awaiting clock sync...</span>
                    <div class="bar-container"><div class="bar-fill" id="timer-bar"></div></div>
                </div>

                <div id="token-container">
                    <p id="no-results-message">No matching active codes found.</p>
                    
                    <?php if (!empty($two_factor_tokens)): ?>
                        <?php foreach ($two_factor_tokens as $token): ?>
                            <div class="token-row" data-searchable-name="<?php echo htmlspecialchars(strtolower($token['service_name'])); ?>">
                                <div>
                                    <div class="token-label" data-raw-text="<?php echo htmlspecialchars($token['service_name']); ?>"><?php echo htmlspecialchars($token['service_name']); ?></div>
                                    <div class="token-code" id="code-<?php echo $token['id']; ?>" data-seed="<?php echo htmlspecialchars($token['decrypted_seed']); ?>">000 000</div>
                                </div>
                                <div class="action-tray">
                                    <button class="copy-btn" onclick="copyTokenValue('code-<?php echo $token['id']; ?>', this)">Copy</button>
                                    <button class="del-btn" onclick="triggerTokenDeletion(<?php echo $token['id']; ?>, '<?php echo htmlspecialchars(addslashes($token['service_name'])); ?>')">Delete</button>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <p id="empty-db-fallback" style="text-align: center; color: #64748b; font-size: 14px; padding: 20px 0;">No profiles found inside your vault.</p>
                    <?php endif; ?>
                </div>

                <div class="backup-tray">
                    <h4 style="margin: 0; color: #a855f7; border-bottom: 1px solid #334155; padding-bottom: 6px;">🔄 Cross-Platform Data Migration</h4>
                    
                    <form method="POST" action="">
                        <input type="hidden" name="action" value="export_backup">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <button type="submit" class="btn-backup">Export Backup</button>
                    </form>

                    <form method="POST" action="" enctype="multipart/form-data" id="import-form">
                        <input type="hidden" name="action" value="import_backup">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="import-box-area" onclick="document.getElementById('import-file-input').click()">
                            <span>Import Backup</span>
                            <input type="file" id="import-file-input" name="backup_file" accept=".json" style="display:none;" onchange="document.getElementById('import-form').submit();">
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script>
    let envCamInstance = null;
    let usrCamInstance = null;
    let fileEngineInstance = null;

    const fileInput = document.getElementById('qr-file-input');
    const dropZone = document.getElementById('drop-zone');
    const searchBar = document.getElementById('live-search-bar');

    function initScannerEngines() {
        fileEngineInstance = new Html5Qrcode("drop-zone");
        startSyncClock();
        
        // Connect Live Filter Search Input Event Listener
        if (searchBar) {
            searchBar.addEventListener('input', runLiveTokenSearchFilter);
        }
    }

    // REAL TIME SEARCH, VISIBILITY TOGGLING, AND HIGHLIGHTING ENGINE
    function runLiveTokenSearchFilter() {
        const query = searchBar.value.trim().toLowerCase();
        const rows = document.querySelectorAll('.token-row');
        const noResultsMsg = document.getElementById('no-results-message');
        let visibleCount = 0;

        rows.forEach(row => {
            const labelNode = row.querySelector('.token-label');
            const originalText = labelNode.getAttribute('data-raw-text');
            
            if (!query) {
                // If query is empty, reset display and restore text
                row.style.display = 'flex';
                labelNode.textContent = originalText;
                visibleCount++;
            } else {
                if (originalText.toLowerCase().includes(query)) {
                    row.style.display = 'flex';
                    visibleCount++;
                    
                    // Generate regular expression match layout safely
                    const regex = new RegExp(`(${query.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&')})`, 'gi');
                    labelNode.innerHTML = originalText.replace(regex, '<mark class="highlight">$1</mark>');
                } else {
                    // Match failed: hide component node seamlessly
                    row.style.display = 'none';
                }
            }
        });

        // Toggle fallback "No Results Found" node notice label block
        if (noResultsMsg) {
            noResultsMsg.style.display = (rows.length > 0 && visibleCount === 0) ? 'block' : 'none';
        }
    }

    function startCameraEngine(type) {
        if (type === 'env') {
            document.getElementById('start-env-btn').disabled = true;
            document.getElementById('stop-env-btn').disabled = false;
            envCamInstance = new Html5Qrcode("env-viewport");
            envCamInstance.start(
                { facingMode: "environment" }, { fps: 15, qrbox: 180 },
                (decodedText) => { handleDecodedText(decodedText, 'env'); }, () => {}
            ).catch(() => { alert("Back camera failed."); stopCameraEngine('env'); });
        } else {
            document.getElementById('start-usr-btn').disabled = true;
            document.getElementById('stop-usr-btn').disabled = false;
            usrCamInstance = new Html5Qrcode("usr-viewport");
            usrCamInstance.start(
                { facingMode: "user" }, { fps: 15, qrbox: 180 },
                (decodedText) => { handleDecodedText(decodedText, 'usr'); }, () => {}
            ).catch(() => { alert("Front camera failed."); stopCameraEngine('usr'); });
        }
    }

    function stopCameraEngine(type) {
        if (type === 'env') {
            document.getElementById('start-env-btn').disabled = false;
            document.getElementById('stop-env-btn').disabled = true;
            if (envCamInstance) {
                envCamInstance.stop().then(() => { 
                    document.getElementById('env-viewport').innerHTML = ""; 
                    envCamInstance = null; 
                });
            }
        } else {
            document.getElementById('start-usr-btn').disabled = false;
            document.getElementById('stop-usr-btn').disabled = true;
            if (usrCamInstance) {
                usrCamInstance.stop().then(() => { 
                    document.getElementById('usr-viewport').innerHTML = ""; 
                    usrCamInstance = null; 
                });
            }
        }
    }

    function killAllActiveCameras() {
        stopCameraEngine('env');
        stopCameraEngine('usr');
    }

    ['dragenter', 'dragover'].forEach(name => dropZone.addEventListener(name, (e) => { e.preventDefault(); dropZone.classList.add('dragover'); }));
    ['dragleave', 'drop'].forEach(name => dropZone.addEventListener(name, (e) => { e.preventDefault(); dropZone.classList.remove('dragover'); }));
    
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        if (e.dataTransfer.files.length) { processUploadedFile(e.dataTransfer.files[0]); }
    });
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) { processUploadedFile(e.target.files[0]); }
    });

    function processUploadedFile(file) {
        if (!fileEngineInstance) return;
        fileEngineInstance.scanFile(file, true)
            .then(decodedText => { handleDecodedText(decodedText, 'file'); })
            .catch(() => { alert("Failed to parse image."); });
    }

    function handleDecodedText(text, triggerSource) {
        let lowerText = text.toLowerCase();
        if (lowerText.includes('otpauth://') && lowerText.includes('secret=')) {
            try {
                killAllActiveCameras();
                let parts = text.split(/[?&]secret=/i);
                let secretPart = parts[1].split('&')[0];
                let labelPart = "2FA Token";
                if (lowerText.includes('totp/')) {
                    let labelExtract = text.split(/totp\//i)[1].split('?')[0];
                    labelPart = decodeURIComponent(labelExtract);
                }
                document.getElementById('final-name').value = labelPart;
                document.getElementById('final-seed').value = secretPart.toUpperCase().replace(/\s+/g, '');
                document.getElementById('qr-submit-form').submit();
            } catch (err) { alert("Processing failed."); }
        } else {
            alert("Invalid 2FA layout format.");
        }
    }

    function triggerTokenDeletion(id, serviceName) {
        if (confirm("Permanently delete '" + serviceName + "'?")) {
            document.getElementById('delete-target-id').value = id;
            document.getElementById('delete-token-form').submit();
        }
    }

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

    window.addEventListener('DOMContentLoaded', initScannerEngines);
    </script>
</body>
</html>