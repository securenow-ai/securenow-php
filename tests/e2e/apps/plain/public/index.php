<?php

// Plain PHP front controller. No Composer, no SecureNow code except where the public API is
// exercised: the SDK starts from auto_prepend_file.

use SecureNow\SecureNow;

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
header('Content-Type: application/json');

if ($path === '/') {
    echo json_encode(['app' => 'plain', 'ok' => true]);
} elseif (preg_match('~^/users/(\d+)$~', $path, $m)) {
    SecureNow::setRoute('/users/{id}');
    echo json_encode(['id' => (int) $m[1]]);
} elseif ($path === '/echo') {
    // The app reads its own body after SecureNow looked at it.
    echo json_encode(['received' => json_decode(file_get_contents('php://input'), true), 'post' => $_POST, 'files' => array_keys($_FILES)]);
} elseif ($path === '/boom') {
    throw new RuntimeException('plain boom');
} elseif ($path === '/fatal') {
    this_function_does_not_exist();
} elseif ($path === '/warn') {
    $undefined = [];
    echo json_encode(['value' => $undefined['missing'] ?? null, 'warned' => @$undefined['x'], 'len' => strlen(file_get_contents('/nonexistent/file') ?: '')]);
} elseif ($path === '/log') {
    SecureNow::log('warning', 'plain log line password=hunter2 for {user}', ['user' => 'bob']);
    echo json_encode(['logged' => true]);
} elseif ($path === '/event') {
    SecureNow::track('auth.login.failure', ['userId' => 'u1', 'attributes' => ['method' => 'password']]);
    echo json_encode(['tracked' => true, 'ip' => SecureNow::clientIp()]);
} elseif ($path === '/span') {
    $value = SecureNow::span('compute', static function () {
        usleep(15000);
        return 42;
    }, ['compute.kind' => 'test']);
    echo json_encode(['value' => $value]);
} elseif ($path === '/session') {
    echo json_encode(SecureNow::checkSession());
} else {
    http_response_code(404);
    echo json_encode(['error' => 'not found']);
}
