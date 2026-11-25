<?php

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use SecureNow\SecureNow;
use Slim\Factory\AppFactory;

require __DIR__ . '/../vendor/autoload.php';

$app = AppFactory::create();

// Added first = innermost: it runs after routing, so it sees the matched route.
$app->add(new \SecureNow\Integrations\Psr15\SecureNowMiddleware());
$app->addRoutingMiddleware();
$app->addErrorMiddleware(false, false, false);

$json = static function (Response $response, $data, int $status = 200): Response {
    $response->getBody()->write(json_encode($data));
    return $response->withHeader('Content-Type', 'application/json')->withStatus($status);
};

$app->get('/', fn (Request $request, Response $response) => $json($response, ['app' => 'slim', 'ok' => true]));
$app->get('/users/{id}', fn (Request $request, Response $response, array $args) => $json($response, ['id' => (int) $args['id']]));
$app->post('/echo', fn (Request $request, Response $response) => $json($response, ['received' => json_decode((string) $request->getBody(), true)]));
$app->get('/boom', function () {
    throw new RuntimeException('slim boom');
});
$app->get('/log', function (Request $request, Response $response) use ($json) {
    SecureNow::logger('slim')->warning('slim log line password=hunter2 for {user}', ['user' => 'bob']);
    return $json($response, ['logged' => true]);
});
$app->get('/event', function (Request $request, Response $response) use ($json) {
    SecureNow::track('auth.login.failure', ['userId' => 'u1', 'attributes' => ['method' => 'password']]);
    return $json($response, ['tracked' => true]);
});
$app->get('/db', function (Request $request, Response $response) use ($json) {
    $pdo = new PDO('sqlite::memory:');
    $pdo->exec('CREATE TABLE t (id INTEGER)');
    $count = $pdo->query('SELECT COUNT(*) FROM t')->fetchColumn();
    return $json($response, ['count' => (int) $count]);
});

$app->run();
