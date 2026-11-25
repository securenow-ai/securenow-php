<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use SecureNow\SecureNow;

// No SecureNow setup here: the package is auto-discovered. The routes only exercise the app.

$csrf = array_values(array_filter([
    'Illuminate\Foundation\Http\Middleware\ValidateCsrfToken',
    'Illuminate\Foundation\Http\Middleware\VerifyCsrfToken',
    'Illuminate\Foundation\Http\Middleware\PreventRequestForgery',
    'App\Http\Middleware\VerifyCsrfToken',
], 'class_exists'));

Route::get('/', fn () => response()->json(['app' => 'laravel', 'ok' => true]));
Route::get('/users/{id}', fn (string $id) => response()->json(['id' => (int) $id]));
Route::post('/echo', fn (Request $request) => response()->json(['received' => $request->json()->all()]))->withoutMiddleware($csrf);
Route::get('/boom', function () {
    throw new RuntimeException('laravel boom');
});
Route::get('/log', function () {
    Log::warning('laravel log line password=hunter2 for {user}', ['user' => 'bob']);
    return response()->json(['logged' => true]);
});
Route::get('/event', function () {
    SecureNow::track('auth.login.failure', ['userId' => 'u1', 'attributes' => ['method' => 'password']]);
    return response()->json(['tracked' => true]);
});
Route::post('/login', function (Request $request) {
    // A failed sign-in: Laravel fires Illuminate\Auth\Events\Failed, SecureNow reports it.
    $ok = Auth::attempt(['email' => (string) $request->input('email'), 'password' => (string) $request->input('password')]);
    return response()->json(['ok' => $ok], $ok ? 200 : 401);
})->withoutMiddleware($csrf);
Route::get('/db', fn () => response()->json(['users' => DB::table('users')->count()]));
Route::get('/session', fn (Request $request) => response()->json(['session' => substr($request->session()->getId(), 0, 6)]));
