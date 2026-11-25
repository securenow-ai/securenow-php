<?php

namespace App\Controller;

use Psr\Log\LoggerInterface;
use SecureNow\SecureNow;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

final class E2eController
{
    #[Route('/', methods: ['GET'])]
    public function home(): JsonResponse
    {
        return new JsonResponse(['app' => 'symfony', 'ok' => true]);
    }

    #[Route('/users/{id}', methods: ['GET'], requirements: ['id' => '\d+'])]
    public function user(int $id): JsonResponse
    {
        return new JsonResponse(['id' => $id]);
    }

    #[Route('/echo', methods: ['POST'])]
    public function echo(Request $request): JsonResponse
    {
        return new JsonResponse(['received' => json_decode($request->getContent(), true)]);
    }

    #[Route('/boom', methods: ['GET'])]
    public function boom(): JsonResponse
    {
        throw new \RuntimeException('symfony boom');
    }

    #[Route('/log', methods: ['GET'])]
    public function log(LoggerInterface $logger): JsonResponse
    {
        $logger->warning('symfony log line password=hunter2 for {user}', ['user' => 'bob']);
        return new JsonResponse(['logged' => true]);
    }

    #[Route('/event', methods: ['GET'])]
    public function event(): JsonResponse
    {
        SecureNow::track('auth.login.failure', ['userId' => 'u1', 'attributes' => ['method' => 'password']]);
        return new JsonResponse(['tracked' => true]);
    }

    #[Route('/db', methods: ['GET'])]
    public function db(): JsonResponse
    {
        $pdo = new \PDO('sqlite::memory:');
        $pdo->exec('CREATE TABLE t (id INTEGER)');
        return new JsonResponse(['count' => (int) $pdo->query('SELECT COUNT(*) FROM t')->fetchColumn()]);
    }
}
