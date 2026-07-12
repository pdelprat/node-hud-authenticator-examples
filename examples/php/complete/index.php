<?php
session_start();
load_dotenv(__DIR__ . '/.env');

$AUTH_SERVER_URL = rtrim(getenv('AUTH_SERVER_URL') ?: 'https://mfa.node-hub.com', '/');
$AUTH_APP_TOKEN = getenv('AUTH_APP_TOKEN') ?: '';
$AUTH_TENANT_ADMIN_TOKEN = getenv('AUTH_TENANT_ADMIN_TOKEN') ?: '';
$AUTH_TENANT_ID = getenv('AUTH_TENANT_ID') ?: 'default';
$AUTH_ADMIN_USER_HINT = getenv('AUTH_ADMIN_USER_HINT') ?: 'admin@example.local';
$DATA_PATH = getenv('DATA_PATH') ?: __DIR__ . '/.data/users.json';

try {
    route();
} catch (Throwable $e) {
    http_response_code(500);
    echo page('<h1>Error</h1><pre>' . h($e->getMessage()) . '</pre>');
}

function route(): void {
    $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/';

    if ($path === '/') {
        echo page('<h1>PHP complete</h1><p><a href="/admin">Admin</a> - <a href="/app">User app</a></p>');
        return;
    }

    if ($path === '/admin') {
        admin();
        return;
    }

    if ($path === '/admin/start' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        global $AUTH_ADMIN_USER_HINT;
        $challenge = create_challenge($AUTH_ADMIN_USER_HINT, 'PHP complete admin');
        redirect('/admin?challenge=' . rawurlencode($challenge['id']));
        return;
    }

    if ($path === '/admin/logout') {
        unset($_SESSION['admin_ok']);
        redirect('/');
        return;
    }

    if ($path === '/admin/users') {
        require_admin();
        users();
        return;
    }

    if (preg_match('#^/admin/invite/([^/]+)$#', $path, $matches)) {
        require_admin();
        admin_invite(rawurldecode($matches[1]));
        return;
    }

    if (preg_match('#^/invite/([^/]+)$#', $path, $matches)) {
        invite(rawurldecode($matches[1]));
        return;
    }

    if ($path === '/app') {
        user_app();
        return;
    }

    if ($path === '/app/start' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $email = strtolower(trim($_POST['email'] ?? ''));
        if (!find_user_by_email($email)) {
            http_response_code(404);
            echo page('<h1>User not found</h1>');
            return;
        }
        $challenge = create_challenge($email, 'PHP complete user app');
        redirect('/app?challenge=' . rawurlencode($challenge['id']) . '&user=' . rawurlencode($email));
        return;
    }

    if ($path === '/app/logout') {
        unset($_SESSION['user_email']);
        redirect('/');
        return;
    }

    http_response_code(404);
    echo page('<h1>Not found</h1>');
}

function admin(): void {
    global $AUTH_ADMIN_USER_HINT;

    if (!empty($_SESSION['admin_ok'])) {
        redirect('/admin/users');
        return;
    }

    $challengeId = $_GET['challenge'] ?? null;
    if (!$challengeId) {
        echo page('<h1>Admin access</h1><p><code>' . h($AUTH_ADMIN_USER_HINT) . '</code></p><form method="post" action="/admin/start"><button>Request access</button></form>');
        return;
    }

    $challenge = get_challenge($challengeId);
    if ($challenge['status'] === 'approved') {
        $_SESSION['admin_ok'] = true;
        redirect('/admin/users');
        return;
    }

    echo page(render_challenge($challenge, '/admin'));
}

function users(): void {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $email = strtolower(trim($_POST['email'] ?? ''));
        $name = trim($_POST['name'] ?? '');
        $users = read_users();

        foreach ($users as $user) {
            if ($user['email'] === $email) {
                http_response_code(409);
                echo page('<h1>User already exists</h1>');
                return;
            }
        }

        $token = bin2hex(random_bytes(32));
        $users[] = [
            'id' => bin2hex(random_bytes(16)),
            'email' => $email,
            'name' => $name,
            'status' => 'invited',
            'token' => $token,
            'enrollmentUrl' => create_enrollment($email),
        ];
        write_users($users);
        redirect('/admin/invite/' . rawurlencode($token));
        return;
    }

    $rows = '';
    foreach (read_users() as $user) {
        $rows .= '<tr><td>' . h($user['email']) . '</td><td>' . h($user['name']) . '</td><td>' . h($user['status']) . '</td><td><a href="/admin/invite/' . rawurlencode($user['token']) . '">Invite</a></td></tr>';
    }

    echo page('<h1>Users</h1><p><a href="/admin/logout">Logout</a></p><form method="post"><input name="email" type="email" placeholder="email" required> <input name="name" placeholder="name" required> <button>Create + enroll</button></form><table>' . $rows . '</table>');
}

function admin_invite(string $token): void {
    $user = find_user_by_token($token);
    if (!$user) {
        http_response_code(404);
        echo page('<h1>Invite not found</h1>');
        return;
    }

    $inviteUrl = base_url() . '/invite/' . rawurlencode($token);
    echo page('<h1>Invitation</h1><p>User: <code>' . h($user['email']) . '</code></p><p><a href="' . h($inviteUrl) . '">' . h($inviteUrl) . '</a></p>');
}

function invite(string $token): void {
    $user = find_user_by_token($token);
    if (!$user) {
        http_response_code(404);
        echo page('<h1>Invite not found</h1>');
        return;
    }

    $qr = 'https://api.qrserver.com/v1/create-qr-code/?size=280x280&data=' . rawurlencode($user['enrollmentUrl']);
    echo page('<h1>Invite ' . h($user['name']) . '</h1><p>Scan this enrollment QR code.</p><p><img src="' . h($qr) . '" width="280" height="280" alt="Enrollment QR"></p><p><a href="/app?user=' . rawurlencode($user['email']) . '">Open app</a></p>');
}

function user_app(): void {
    if (!empty($_SESSION['user_email'])) {
        echo page('<h1>User app</h1><p>Access granted for <code>' . h($_SESSION['user_email']) . '</code>.</p><p><a href="/app/logout">Logout</a></p>');
        return;
    }

    $challengeId = $_GET['challenge'] ?? null;
    $email = strtolower(trim($_GET['user'] ?? ''));
    if ($challengeId && $email) {
        $challenge = get_challenge($challengeId);
        if ($challenge['status'] === 'approved') {
            activate_user($email);
            $_SESSION['user_email'] = $email;
            redirect('/app');
            return;
        }
        echo page(render_challenge($challenge, '/app'));
        return;
    }

    echo page('<h1>User access</h1><form method="post" action="/app/start"><input name="email" type="email" value="' . h($email) . '" required> <button>Request access</button></form>');
}

function create_challenge(string $userHint, string $resource): array {
    global $AUTH_SERVER_URL, $AUTH_APP_TOKEN;
    if ($AUTH_APP_TOKEN === '') {
        throw new RuntimeException('AUTH_APP_TOKEN is required.');
    }

    return mfa_request('POST', $AUTH_SERVER_URL . '/api/challenges', [
        'userHint' => $userHint,
        'resource' => $resource,
        'mode' => 'push_with_number',
        'location' => 'PHP complete',
        'ipAddress' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
    ], $AUTH_APP_TOKEN)['challenge'];
}

function get_challenge(string $challengeId): array {
    global $AUTH_SERVER_URL;
    return mfa_request('GET', $AUTH_SERVER_URL . '/api/challenges/' . rawurlencode($challengeId), null, null)['challenge'];
}

function create_enrollment(string $email): string {
    global $AUTH_SERVER_URL, $AUTH_TENANT_ADMIN_TOKEN, $AUTH_TENANT_ID;
    if ($AUTH_TENANT_ADMIN_TOKEN === '') {
        throw new RuntimeException('AUTH_TENANT_ADMIN_TOKEN is required.');
    }

    $url = $AUTH_SERVER_URL . '/api/enrollments/new?tenant=' . rawurlencode($AUTH_TENANT_ID) . '&user=' . rawurlencode($email);
    return mfa_request('GET', $url, null, $AUTH_TENANT_ADMIN_TOKEN)['enrollmentUrl'];
}

function mfa_request(string $method, string $url, ?array $body, ?string $token): array {
    $headers = ['Content-Type: application/json'];
    if ($token !== null && $token !== '') {
        $headers[] = 'Authorization: Bearer ' . $token;
    }

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

function read_users(): array {
    global $DATA_PATH;
    return is_file($DATA_PATH) ? json_decode(file_get_contents($DATA_PATH), true, flags: JSON_THROW_ON_ERROR) : [];
}

function write_users(array $users): void {
    global $DATA_PATH;
    if (!is_dir(dirname($DATA_PATH))) {
        mkdir(dirname($DATA_PATH), 0777, true);
    }
    file_put_contents($DATA_PATH, json_encode($users, JSON_PRETTY_PRINT) . PHP_EOL);
}

function find_user_by_token(string $token): ?array {
    foreach (read_users() as $user) {
        if (($user['token'] ?? '') === $token) {
            return $user;
        }
    }
    return null;
}

function find_user_by_email(string $email): ?array {
    foreach (read_users() as $user) {
        if (($user['email'] ?? '') === $email && ($user['status'] ?? '') !== 'disabled') {
            return $user;
        }
    }
    return null;
}

function activate_user(string $email): void {
    $users = read_users();
    foreach ($users as &$user) {
        if (($user['email'] ?? '') === $email && ($user['status'] ?? '') === 'invited') {
            $user['status'] = 'active';
            write_users($users);
            return;
        }
    }
}

function require_admin(): void {
    if (empty($_SESSION['admin_ok'])) {
        redirect('/admin');
        exit;
    }
}

function render_challenge(array $challenge, string $retryPath): string {
    $number = !empty($challenge['numberMatch']) ? '<p>Confirm: <strong style="font-size:42px">' . h($challenge['numberMatch']) . '</strong></p>' : '';
    return '<h1>MFA required</h1>' . $number . '<p>Status: <code>' . h($challenge['status']) . '</code></p><script>setTimeout(function(){ location.reload(); }, 2000);</script><p><a href="' . h($retryPath) . '">Cancel</a></p>';
}

function page(string $body): string {
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PHP complete</title><body>' . $body . '</body></html>';
}

function redirect(string $path): void {
    header('Location: ' . $path);
}

function base_url(): string {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    return $scheme . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost');
}

function h(mixed $value): string {
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

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
