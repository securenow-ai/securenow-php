#!/bin/sh
set -e

# Credentials for every app: the backend to talk to comes from the environment, so the same
# image runs against the fake backend (matrix) and against SecureNow itself (live test).
BACKEND="${SECURENOW_E2E_BACKEND:-http://backend:4000}"
API_KEY="${SECURENOW_E2E_API_KEY:-snk_live_e2e0000000000000}"

write_creds() {
  dir="$1"; key="$2"; name="$3"
  mkdir -p "$dir/.securenow"
  if [ -n "$SECURENOW_E2E_LIVE" ]; then
    cat > "$dir/.securenow/runtime.json" <<EOF
{ "apiKey": "$API_KEY", "app": { "key": "$key", "name": "$name" },
  "config": { "runtime": { "deploymentEnvironment": "${SECURENOW_E2E_ENV:-production}" }, "otel": { "logLevel": "info" }, "firewall": { "log": true } } }
EOF
  else
    cat > "$dir/.securenow/runtime.json" <<EOF
{ "apiKey": "$API_KEY", "app": { "key": "$key", "name": "$name" },
  "config": {
    "otel": { "endpoint": "$BACKEND", "logLevel": "info" },
    "firewall": { "apiUrl": "$BACKEND", "versionCheckInterval": 1, "log": true },
    "export": { "flushIntervalMs": 200 },
    "sessions": { "guard": true, "capture": true }
  } }
EOF
  fi
  chown -R www-data:www-data "$dir/.securenow"
}

write_creds /apps/plain   "${SECURENOW_E2E_APP_PLAIN:-00000000-0000-4000-8000-000000000001}"   e2e-plain
write_creds /apps/slim    "${SECURENOW_E2E_APP_SLIM:-00000000-0000-4000-8000-000000000002}"    e2e-slim
write_creds /apps/laravel "${SECURENOW_E2E_APP_LARAVEL:-00000000-0000-4000-8000-000000000003}" e2e-laravel
write_creds /apps/symfony "${SECURENOW_E2E_APP_SYMFONY:-00000000-0000-4000-8000-000000000004}" e2e-symfony

# PHP-FPM passes no environment to workers by default: errors go to the container log.
cat > /usr/local/etc/php-fpm.d/zz-e2e.conf <<EOF
[www]
catch_workers_output = yes
decorate_workers_output = no
pm = static
pm.max_children = 6
php_admin_value[error_log] = /proc/self/fd/2
php_admin_flag[log_errors] = on
php_admin_flag[display_errors] = off
EOF

php-fpm -D
exec nginx -g 'daemon off;'
