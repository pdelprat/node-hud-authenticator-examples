<?php
session_start();
load_dotenv(__DIR__ . '/.env');

$AUTH_SERVER_URL = rtrim(getenv('AUTH_SERVER_URL') ?: 'https://mfa.node-hub.com', '/');
$AUTH_APP_TOKEN = getenv('AUTH_APP_TOKEN') ?: '';
$AUTH_USER_HINT = getenv('AUTH_USER_HINT') ?: 'demo@example.local';

function load_dotenv(string $path): void {
    if (!is_file($path)) {
        return;
    }

    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) {
            continue;
        }

        [$key, $value] = explode('=', $line, 2);
        if (getenv(trim($key)) === false) {
            putenv(trim($key) . '=' . trim($value, " \t\n\r\0\x0B'\""));
        }
    }
}

function client_ip(): string {
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
    }

    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function mfa_request(string $method, string $url, ?array $body = null, ?string $token = null): array {
    global $AUTH_APP_TOKEN;

    $headers = ['Content-Type: application/json'];
    $headers[] = 'Authorization: Bearer ' . ($token ?? $AUTH_APP_TOKEN);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_TIMEOUT => 10,
    ]);

    if ($body !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
    }

    $raw = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if ($raw === false || $status < 200 || $status >= 300) {
        throw new RuntimeException('MFA request failed: HTTP ' . $status . ' ' . $error . ' ' . $raw);
    }

    return json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
}

function create_challenge(): string {
    global $AUTH_SERVER_URL, $AUTH_USER_HINT;

    $result = mfa_request('POST', $AUTH_SERVER_URL . '/api/challenges', [
        'userHint' => $AUTH_USER_HINT,
        'resource' => 'PHP basic /admin.php',
        'mode' => 'push_with_number',
        'location' => 'PHP basic',
        'ipAddress' => client_ip(),
    ]);

    return $result['challenge']['id'];
}

function get_challenge(string $challengeId): array {
    global $AUTH_SERVER_URL;
    return mfa_request('GET', $AUTH_SERVER_URL . '/api/challenges/' . rawurlencode($challengeId))['challenge'];
}

try {
    if (isset($_GET['logout'])) {
        session_destroy();
        header('Location: admin.php');
        exit;
    }

    if (!empty($_SESSION['mfa_ok'])) {
        echo '<h1>PHP basic protected page</h1><p>Access granted.</p><p><a href="?logout=1">Logout</a></p>';
        exit;
    }

    $challengeId = $_GET['challenge'] ?? null;
    if (!$challengeId) {
        $challengeId = create_challenge();
        header('Location: admin.php?challenge=' . rawurlencode($challengeId));
        exit;
    }

    $challenge = get_challenge($challengeId);
    if ($challenge['status'] === 'approved') {
        $_SESSION['mfa_ok'] = true;
        header('Location: admin.php');
        exit;
    }

    if (in_array($challenge['status'], ['denied', 'expired'], true)) {
        echo '<h1>Access refused</h1><p>Status: <code>' . htmlspecialchars($challenge['status']) . '</code></p><p><a href="admin.php">Retry</a></p>';
        exit;
    }

    echo '<h1>MFA required</h1>';
    if (!empty($challenge['numberMatch'])) {
        echo '<p>Confirm this number: <strong style="font-size:42px">' . htmlspecialchars($challenge['numberMatch']) . '</strong></p>';
    }
    echo '<p>Status: <code>' . htmlspecialchars($challenge['status']) . '</code></p>';
    echo '<script>setTimeout(function(){ location.reload(); }, 2000);</script>';
} catch (Throwable $e) {
    http_response_code(500);
    echo '<h1>MFA error</h1><pre>' . htmlspecialchars($e->getMessage()) . '</pre>';
}
