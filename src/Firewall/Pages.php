<?php

declare(strict_types=1);

namespace SecureNow\Firewall;

/** The pages the firewall serves: the same ones as the Node SDK. */
final class Pages
{
    public static function blocked(string $ip, int $status = 403): string
    {
        $shown = htmlspecialchars($ip !== '' ? $ip : 'unknown', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $encoded = rawurlencode($ip !== '' ? $ip : 'unknown');
        $time = gmdate('Y-m-d\TH:i:s\Z');
        $encodedTime = rawurlencode($time);
        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access Blocked - Security Alert</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0a0a0a;color:#e5e5e5}
.wrap{text-align:center;max-width:540px;padding:2.5rem 2rem}
.icon{width:64px;height:64px;margin:0 auto 1.5rem;border-radius:50%;background:rgba(220,38,38,.12);display:flex;align-items:center;justify-content:center}
.icon svg{width:32px;height:32px;fill:none;stroke:#dc2626;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.badge{display:inline-block;padding:.25rem .75rem;border-radius:999px;background:rgba(220,38,38,.15);color:#f87171;font-size:.7rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;margin-bottom:1.25rem}
h1{font-size:1.6rem;font-weight:700;margin-bottom:.6rem;color:#fff}
.sub{font-size:1rem;color:#f87171;font-weight:600;margin-bottom:1.25rem}
p{font-size:.9rem;line-height:1.7;color:#a1a1aa;margin-bottom:.5rem}
.ip-box{display:inline-block;margin:1rem 0;padding:.6rem 1.5rem;border-radius:8px;background:rgba(255,255,255,.04);border:1px solid rgba(220,38,38,.25);font-family:"SF Mono",SFMono-Regular,Consolas,"Liberation Mono",Menlo,monospace;font-size:.95rem;color:#fca5a5;letter-spacing:.03em}
.divider{width:48px;height:2px;background:rgba(220,38,38,.3);margin:1.5rem auto}
.contact{font-size:.85rem;color:#71717a;line-height:1.7}
.contact a{color:#f87171;text-decoration:none;font-weight:500}
.contact a:hover{text-decoration:underline}
.footer{margin-top:2rem;font-size:.7rem;color:#3f3f46}
.powered{margin-top:1.5rem;font-size:.75rem;color:#52525b}.powered a{color:#a1a1aa;text-decoration:none;font-weight:600;transition:color .2s}.powered a:hover{color:#f87171;text-decoration:underline}
</style>
</head>
<body>
<div class="wrap">
<div class="icon"><svg viewBox="0 0 24 24"><path d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg></div>
<span class="badge">Security Alert</span>
<h1>Access Blocked</h1>
<p class="sub">Malicious activity detected from your IP address</p>
<p>Your IP has been flagged and blocked due to suspicious or malicious behavior originating from your network. Our security team has been notified and is actively investigating.</p>
<div class="ip-box">{$shown}</div>
<div class="divider"></div>
<p class="contact">If you believe this is a mistake, please contact us at<br><a href="mailto:contact@securenow.ai?subject=Blocked%20IP%20Appeal%20-%20{$encoded}&body=IP:%20{$encoded}%0ATimestamp:%20{$encodedTime}%0A%0APlease%20describe%20why%20you%20believe%20this%20block%20is%20incorrect:">contact@securenow.ai</a><br>Include your IP address and the time of this incident.</p>
<p class="footer">Ref: {$shown} &mdash; {$time} &mdash; HTTP {$status}</p>
<p class="powered">Protected by <a href="https://securenow.ai" rel="dofollow" target="_blank">SecureNow</a></p>
</div>
</body>
</html>
HTML;
    }

    public static function rateLimited(): string
    {
        return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Too Many Requests</title></head><body><h1>Too Many Requests</h1><p>Please retry later.</p></body></html>';
    }

    public static function challenge(string $token, int $difficulty, string $submitPath, string $returnPath, string $ip): string
    {
        // HEX flags: the config sits inside a <script>, and the return path comes from the request.
        $cfg = json_encode(
            ['token' => $token, 'diff' => max(1, $difficulty), 'submit' => $submitPath, 'ret' => $returnPath !== '' ? $returnPath : '/'],
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
        );
        $safeIp = htmlspecialchars($ip !== '' ? $ip : 'unknown', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verifying your browser - SecureNow</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0a0a0a;color:#e5e5e5}
.wrap{text-align:center;max-width:540px;padding:2.5rem 2rem}
.icon{width:64px;height:64px;margin:0 auto 1.5rem;border-radius:50%;background:rgba(59,130,246,.12);display:flex;align-items:center;justify-content:center}
.icon svg{width:32px;height:32px;fill:none;stroke:#3b82f6;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.badge{display:inline-block;padding:.25rem .75rem;border-radius:999px;background:rgba(59,130,246,.15);color:#93c5fd;font-size:.7rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;margin-bottom:1.25rem}
h1{font-size:1.5rem;font-weight:700;margin-bottom:.6rem;color:#fff}
p{font-size:.9rem;line-height:1.7;color:#a1a1aa;margin-bottom:.5rem}
.spinner{width:34px;height:34px;margin:1.5rem auto .5rem;border:3px solid rgba(255,255,255,.12);border-top-color:#3b82f6;border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.status{font-size:.82rem;color:#71717a;margin-top:.75rem;min-height:1.2em}
.ip-box{display:inline-block;margin:1rem 0 .25rem;padding:.5rem 1.25rem;border-radius:8px;background:rgba(255,255,255,.04);border:1px solid rgba(59,130,246,.25);font-family:"SF Mono",SFMono-Regular,Consolas,Menlo,monospace;font-size:.85rem;color:#93c5fd}
.footer{margin-top:2rem;font-size:.7rem;color:#3f3f46}
.powered{margin-top:1.5rem;font-size:.75rem;color:#52525b}.powered a{color:#a1a1aa;text-decoration:none;font-weight:600}
noscript{color:#f87171}
</style>
</head>
<body>
<div class="wrap">
<div class="icon"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
<span class="badge">Security Check</span>
<h1>Verifying your browser</h1>
<p>Automated traffic from your network triggered an extra verification step. This runs automatically &mdash; no action needed.</p>
<div class="spinner" id="sp"></div>
<p class="status" id="st">Starting verification&hellip;</p>
<div class="ip-box">{$safeIp}</div>
<noscript><p>JavaScript is required to complete this verification.</p></noscript>
<p class="footer">Protected by SecureNow &mdash; proof-of-work challenge</p>
<p class="powered">Protected by <a href="https://securenow.ai" rel="dofollow" target="_blank">SecureNow</a></p>
</div>
<script>
(function(){
  var C={$cfg};
  var st=document.getElementById('st');
  function setStatus(t){ if(st) st.textContent=t; }
  function lzbits(bytes){var bits=0;for(var i=0;i<bytes.length;i++){var b=bytes[i];if(b===0){bits+=8;continue;}bits+=Math.clz32(b)-24;break;}return bits;}
  if(!(window.crypto&&window.crypto.subtle)){setStatus('Your browser does not support this verification.');return;}
  var enc=new TextEncoder();
  var nonce=0;
  function step(){
    var batch=0;
    (function loop(){
      if(batch++>400){ setStatus('Verifying… ('+nonce+' attempts)'); setTimeout(step,0); return; }
      var data=enc.encode(C.token+'.'+nonce);
      window.crypto.subtle.digest('SHA-256',data).then(function(buf){
        var bytes=new Uint8Array(buf);
        if(lzbits(bytes)>=C.diff){ submit(nonce); return; }
        nonce++; loop();
      }).catch(function(){ setStatus('Verification error. Please refresh.'); });
    })();
  }
  function submit(n){
    setStatus('Solved. Finalizing…');
    fetch(C.submit,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({token:C.token,nonce:String(n)})})
      .then(function(r){ if(r.ok){ window.location.replace(C.ret); } else { return r.text().then(function(){ setStatus('Verification rejected. Refreshing…'); setTimeout(function(){window.location.reload();},1500); }); } })
      .catch(function(){ setStatus('Network error. Refreshing…'); setTimeout(function(){window.location.reload();},1500); });
  }
  step();
})();
</script>
</body>
</html>
HTML;
    }
}
