<?php
declare(strict_types=1);

/*
 * First-run installer and multi-user portal.
 * Included by index.php after $method and $path are initialized.
 */
function portal_h(string $v): string { return htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function portal_page(string $title, string $body, int $status=200): never {
    http_response_code($status);
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'.portal_h($title).' · Anti-Bypass</title><style>
    *{box-sizing:border-box}body{margin:0;background:#080d18;color:#e8eefb;font:15px system-ui,Arial;min-height:100vh}
    a{color:#65d9ff;text-decoration:none}.wrap{width:min(100% - 32px,980px);margin:0 auto;padding:34px 0}
    .nav{display:flex;align-items:center;justify-content:space-between;padding:18px 0;border-bottom:1px solid #1e2a40}
    .brand{font-weight:800;font-size:20px;letter-spacing:-.5px}.muted{color:#9aabc5}.hero{padding:70px 0 48px;text-align:center}
    h1{font-size:clamp(32px,6vw,54px);line-height:1.05;margin:12px 0}h2{margin-top:0}.card{background:#101a2b;border:1px solid #25344c;border-radius:18px;padding:26px;margin:22px auto;max-width:560px}
    .btn{display:inline-block;border:0;border-radius:10px;padding:12px 20px;background:#12b8e8;color:#03101b;font-weight:750;cursor:pointer;font-size:14px}
    .btn.alt{background:#202d43;color:#e8eefb;border:1px solid #344762}.actions{display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin-top:26px}
    label{display:block;font-size:13px;color:#aebbd0;margin:14px 0 6px}input,select{width:100%;padding:12px;border-radius:9px;border:1px solid #344762;background:#091322;color:#fff}
    button{font:inherit}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.tile{padding:20px;border:1px solid #26364e;border-radius:14px;background:#111d30}.tile strong{display:block;font-size:28px;margin-top:8px}
    .menu{display:flex;gap:10px;flex-wrap:wrap;margin:22px 0}.menu a,.pill{padding:9px 14px;border-radius:9px;background:#17263b;color:#dbeafe}
    .notice{padding:12px 14px;border-radius:10px;background:#192b42;color:#b9d8f7;margin:14px 0}.danger{color:#ff9d9d}
    @media(max-width:600px){.grid{grid-template-columns:1fr}.hero{padding:48px 0 24px}}
    </style></head><body><div class="wrap">'.$body.'</div></body></html>';
    exit;
}
function portal_pdo_install(string $host,string $port,string $db,string $user,string $pass): PDO {
    return new PDO("mysql:host={$host};port={$port};dbname={$db};charset=utf8mb4",$user,$pass,[
        PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES=>false
    ]);
}
function portal_installed(): bool { return is_file(__DIR__.'/config.php') && is_file(__DIR__.'/.installed'); }
function portal_csrf(): string {
    if (session_status() !== PHP_SESSION_ACTIVE) { session_name('antibypass_session'); session_start(); }
    if (empty($_SESSION['csrf'])) $_SESSION['csrf']=bin2hex(random_bytes(32));
    return (string)$_SESSION['csrf'];
}
function portal_check_csrf(): void {
    if (session_status() !== PHP_SESSION_ACTIVE) { session_name('antibypass_session'); session_start(); }
    $v=(string)($_POST['csrf']??'');
    if (empty($_SESSION['csrf']) || !hash_equals((string)$_SESSION['csrf'],$v)) {
        portal_page('Request expired','<div class="card"><h2>Request expired</h2><p>Please go back and try again.</p><a href="/">Home</a></div>',419);
    }
}
function portal_user(): ?array {
    if (session_status() !== PHP_SESSION_ACTIVE) { session_name('antibypass_session'); session_start(); }
    if (empty($_SESSION['user_id'])) return null;
    try {
        $s=pdo()->prepare("SELECT id,username,email,role,status,created_at FROM users WHERE id=? LIMIT 1");
        $s->execute([(int)$_SESSION['user_id']]); $u=$s->fetch();
        if (!$u || $u['status']!=='active') { $_SESSION=[]; session_destroy(); return null; }
        return $u;
    } catch (Throwable $e) { return null; }
}
function portal_require_user(): array {
    $u=portal_user(); if(!$u){header('Location: /login',true,302);exit;} return $u;
}
function portal_header(string $title,array $u): string {
    $admin=$u['role']==='super_admin' ? '<a class="pill" href="/admin-dashboard">Admin Dashboard</a>' : '';
    return '<div class="nav"><a class="brand" href="/">ANTI-BYPASS</a><div>'.$admin.' <a class="pill" href="/logout">Logout</a></div></div><h2 style="margin-top:28px">'.portal_h($title).'</h2><nav class="menu"><a href="/dashboard">Dashboard</a><a href="/links">Links</a><a href="/api-docs">API</a><a href="/settings">Settings</a></nav>';
}
function portal_handle(string $path,string $method): void {
    if (in_array($path,['/install','/setup'],true)) {
        if (portal_installed()) portal_page('Already installed','<div class="card"><h2>Installation is complete</h2><p>The installer is locked.</p><a class="btn" href="/">Go to homepage</a></div>');
        if ($method==='POST') {
            portal_check_csrf();
            $host=trim((string)($_POST['db_host']??'localhost'));$port=trim((string)($_POST['db_port']??'3306'));
            $db=trim((string)($_POST['db_name']??''));$user=trim((string)($_POST['db_user']??''));$pass=(string)($_POST['db_pass']??'');
            $username=trim((string)($_POST['admin_username']??''));$email=trim((string)($_POST['admin_email']??''));$password=(string)($_POST['admin_password']??'');
            if(!preg_match('/^[a-zA-Z0-9_]{1,64}$/',$db)||$username===''||!filter_var($email,FILTER_VALIDATE_EMAIL)||strlen($password)<12) portal_page('Invalid setup','<div class="card"><p class="danger">Database name/username/email invalid. Admin password must be at least 12 characters.</p><a href="/install">Try again</a></div>',422);
            try {
                $dbx=portal_pdo_install($host,$port,$db,$user,$pass);
                $schema=file_get_contents(__DIR__.'/database/schema.sql');
                if($schema===false) throw new RuntimeException('database/schema.sql is missing');
                $schema=preg_replace('/^CREATE DATABASE[^;]+;\s*/mi','',$schema);
                $schema=preg_replace('/^USE\s+[^;]+;\s*/mi','',$schema);
                foreach(array_filter(array_map('trim',explode(';',$schema))) as $sql) $dbx->exec($sql);
                $hash=password_hash($password,PASSWORD_DEFAULT);
                $q=$dbx->prepare("INSERT INTO users(username,email,password_hash,role,status,created_at) VALUES(?,?,?,'super_admin','active',UTC_TIMESTAMP())");
                $q->execute([$username,$email,$hash]);
                $cfg="<?php\nreturn ".var_export(['host'=>$host,'port'=>$port,'name'=>$db,'user'=>$user,'pass'=>$pass,'site'=>'','secret'=>'','admin'=>'','base'=>''],true).";\n";
                if(file_put_contents(__DIR__.'/config.php',$cfg,LOCK_EX)===false) throw new RuntimeException('Unable to write config.php');
                @chmod(__DIR__.'/config.php',0600);
                file_put_contents(__DIR__.'/.installed',gmdate('c'),LOCK_EX); @chmod(__DIR__.'/.installed',0600);
                header('Location: /',true,302);exit;
            } catch(Throwable $e) {
                error_log('[Anti-Bypass installer] '.$e->getMessage());
                portal_page('Setup failed','<div class="card"><h2>Database setup failed</h2><p class="danger">'.portal_h($e->getMessage()).'</p><a href="/install">Go back</a></div>',500);
            }
        }
        $csrf=portal_csrf();
        portal_page('First-time setup','<div class="card"><h2>First-time setup</h2><p class="muted">Connect MySQL and create the first Super Admin account.</p><form method="post"><input type="hidden" name="csrf" value="'.portal_h($csrf).'"><h3>Database details</h3><label>Database host</label><input name="db_host" value="localhost" required><label>Port</label><input name="db_port" value="3306" required><label>Database name</label><input name="db_name" required><label>Database username</label><input name="db_user" required><label>Database password</label><input type="password" name="db_pass"><h3 style="margin-top:26px">First Super Admin</h3><label>Username</label><input name="admin_username" required><label>Email address</label><input type="email" name="admin_email" required><label>Password (minimum 12 characters)</label><input type="password" name="admin_password" minlength="12" required><p><button class="btn">Install and create admin</button></p></form></div>');
    }
    if (!portal_installed() && in_array($path,['/','/login','/signup','/dashboard','/settings','/admin-dashboard'],true)) { header('Location: /install',true,302);exit; }
    if ($path==='/' && $method==='GET') {
        $u=portal_user();
        $buttons=$u?'<a class="btn" href="/dashboard">Dashboard</a>':'<a class="btn" href="/login">Login</a><a class="btn alt" href="/signup">Sign Up</a>';
        portal_page('Anti-Bypass','<div class="nav"><a class="brand" href="/">ANTI-BYPASS</a>'.($u?'<span class="muted">Signed in as '.portal_h($u['username']).'</span>':'<span class="muted">Link protection platform</span>').'</div><section class="hero"><div class="pill">Secure link verification</div><h1>Smart Anti-Bypass<br>Protection</h1><p class="muted">Protect and manage links with verification, CAPTCHA and secure redirect handling.</p><div class="actions">'.$buttons.'</div></section><div class="grid"><div class="tile"><h3>Link protection</h3><p class="muted">Verification and protected redirect flows.</p></div><div class="tile"><h3>Analytics</h3><p class="muted">Track link activity and verification outcomes.</p></div><div class="tile"><h3>API integration</h3><p class="muted">Manage your own API credentials.</p></div><div class="tile"><h3>Account dashboard</h3><p class="muted">Keep your links and settings organized.</p></div></div>');
    }
    if ($path==='/login') {
        if ($method==='POST') {
            portal_check_csrf(); if(session_status()!==PHP_SESSION_ACTIVE){session_name('antibypass_session');session_start();}
            $login=trim((string)($_POST['login']??''));$pw=(string)($_POST['password']??'');
            $s=pdo()->prepare("SELECT id,password_hash,status FROM users WHERE username=? OR email=? LIMIT 1");$s->execute([$login,$login]);$u=$s->fetch();
            if(!$u||$u['status']!=='active'||!password_verify($pw,$u['password_hash'])) portal_page('Login failed','<div class="card"><h2>Login failed</h2><p class="danger">Invalid credentials or inactive account.</p><a href="/login">Try again</a></div>',401);
            session_regenerate_id(true);$_SESSION['user_id']=(int)$u['id'];
            pdo()->prepare('UPDATE users SET last_login_at=UTC_TIMESTAMP() WHERE id=?')->execute([(int)$u['id']]);
            header('Location: /dashboard',true,302);exit;
        }
        $csrf=portal_csrf();portal_page('Login','<div class="card"><h2>Login</h2><form method="post"><input type="hidden" name="csrf" value="'.portal_h($csrf).'"><label>Username or email</label><input name="login" autocomplete="username" required><label>Password</label><input type="password" name="password" autocomplete="current-password" required><p><button class="btn">Login</button></p></form><p class="muted">New registration is temporarily paused. <a href="/signup">Sign up information</a></p></div>');
    }
    if ($path==='/signup') portal_page('Registration paused','<div class="card"><h2>Registration Temporarily Paused</h2><p class="muted">New user registration is currently unavailable. Please check back later.</p><a class="btn" href="/">Home</a></div>');
    if ($path==='/logout') { if(session_status()!==PHP_SESSION_ACTIVE){session_name('antibypass_session');session_start();} $_SESSION=[];session_destroy();header('Location: /',true,302);exit; }
    if ($path==='/dashboard') {
        $u=portal_require_user();
        $s=pdo()->prepare("SELECT COUNT(*) total_links,COALESCE(SUM(clicks),0) total_clicks,COALESCE(SUM(visits),0) verified,COALESCE(SUM(captcha_fails),0) captcha_failed FROM urls WHERE user_id=?");$s->execute([(int)$u['id']]);$stats=$s->fetch()?:[];
        $body=portal_header('User Dashboard',$u).'<div class="grid"><div class="tile">Total Links<strong>'.(int)($stats['total_links']??0).'</strong></div><div class="tile">Total Clicks<strong>'.(int)($stats['total_clicks']??0).'</strong></div><div class="tile">Verified<strong>'.(int)($stats['verified']??0).'</strong></div><div class="tile">Captcha Failed<strong>'.(int)($stats['captcha_failed']??0).'</strong></div></div>';
        portal_page('User Dashboard',$body);
    }
    if ($path==='/admin-dashboard') {
        $u=portal_require_user(); if($u['role']!=='super_admin') portal_page('Forbidden','<div class="card"><h2>Access denied</h2></div>',403);
        if($method==='POST') { portal_check_csrf(); $name=trim((string)($_POST['username']??''));$mail=trim((string)($_POST['email']??''));$pw=(string)($_POST['password']??''); if($name===''||!filter_var($mail,FILTER_VALIDATE_EMAIL)||strlen($pw)<12) portal_page('Invalid user','<div class="card"><p class="danger">Enter a username, valid email and password of at least 12 characters.</p><a href="/admin-dashboard">Back</a></div>',422); try{pdo()->prepare("INSERT INTO users(username,email,password_hash,role,status,created_at) VALUES(?,?,?,'user','active',UTC_TIMESTAMP())")->execute([$name,$mail,password_hash($pw,PASSWORD_DEFAULT)]);}catch(Throwable $e){portal_page('Could not create user','<div class="card"><p class="danger">Username or email may already exist.</p><a href="/admin-dashboard">Back</a></div>',409);} header('Location: /admin-dashboard?created=1',true,302);exit; }
        $count=(int)pdo()->query('SELECT COUNT(*) FROM users')->fetchColumn();
        portal_page('Admin Dashboard',portal_header('Admin Dashboard',$u).(!empty($_GET['created'])?'<div class="notice">User created.</div>':'').'<div class="grid"><div class="tile">Registered users<strong>'.$count.'</strong></div><div class="tile">System status<strong>Active</strong></div></div><div class="card"><h3>Create normal user</h3><form method="post"><input type="hidden" name="csrf" value="'.portal_h(portal_csrf()).'"><label>Username</label><input name="username" required><label>Email</label><input type="email" name="email" required><label>Temporary password (12+ characters)</label><input type="password" name="password" minlength="12" required><p><button class="btn">Create user</button></p></form></div><p><a href="/dashboard">← Switch to User Dashboard</a></p>');
    }
    if ($path==='/settings') {
        $u=portal_require_user();
        if($method==='POST') {
            portal_check_csrf(); if(($_POST['action']??'')==='password'){ $cur=(string)($_POST['current_password']??'');$new=(string)($_POST['new_password']??'');$q=pdo()->prepare('SELECT password_hash FROM users WHERE id=?');$q->execute([(int)$u['id']]);$hash=(string)$q->fetchColumn();if(!password_verify($cur,$hash)||strlen($new)<12) portal_page('Password update failed','<div class="card"><p class="danger">Current password is incorrect or new password is shorter than 12 characters.</p><a href="/settings">Back</a></div>',422);pdo()->prepare('UPDATE users SET password_hash=? WHERE id=?')->execute([password_hash($new,PASSWORD_DEFAULT),(int)$u['id']]);header('Location: /settings?password_changed=1',true,302);exit; } $theme=(string)($_POST['theme']??'dark');$timezone=(string)($_POST['timezone']??'UTC');$domain=trim((string)($_POST['shortener_domain']??''));$api=trim((string)($_POST['shortener_api_key']??''));
            if(!in_array($theme,['light','dark'],true)||!in_array($timezone,timezone_identifiers_list(),true)||($domain!==''&&!filter_var($domain,FILTER_VALIDATE_URL))) portal_page('Invalid settings','<div class="card"><p class="danger">Please check the values and try again.</p><a href="/settings">Back</a></div>',422);
            $q=pdo()->prepare("INSERT INTO user_settings(user_id,theme,timezone,shortener_domain,shortener_api_key_encrypted) VALUES(?,?,?,?,?) ON DUPLICATE KEY UPDATE theme=VALUES(theme),timezone=VALUES(timezone),shortener_domain=VALUES(shortener_domain),shortener_api_key_encrypted=VALUES(shortener_api_key_encrypted)");
            $encrypted=null; if($api!==''){ $ek=(string)(getenv('APP_ENCRYPTION_KEY')?:''); if(strlen($ek)<32) portal_page('Encryption key required','<div class="card"><p class="danger">Set APP_ENCRYPTION_KEY (at least 32 characters) in the server environment before saving a shortener API key.</p><a href="/settings">Back to settings</a></div>',503); $iv=random_bytes(12); $tag=''; $cipher=openssl_encrypt($api,'aes-256-gcm',hash('sha256',$ek,true),OPENSSL_RAW_DATA,$iv,$tag); if($cipher===false) throw new RuntimeException('Unable to encrypt shortener key'); $encrypted=base64_encode($iv.$tag.$cipher); }
            $q->execute([(int)$u['id'],$theme,$timezone,$domain,$encrypted]);
            header('Location: /settings?saved=1',true,302);exit;
        }
        $q=pdo()->prepare('SELECT * FROM user_settings WHERE user_id=?');$q->execute([(int)$u['id']]);$v=$q->fetch()?:[];
        $csrf=portal_csrf();$masked=!empty($v['shortener_api_key_encrypted'])?'Configured (hidden)':'';
        portal_page('User Settings',portal_header('User Settings',$u).(!empty($_GET['saved'])?'<div class="notice">Settings saved.</div>':'').(!empty($_GET['password_changed'])?'<div class="notice">Password updated.</div>':'').'<div class="card"><form method="post"><input type="hidden" name="csrf" value="'.portal_h($csrf).'"><label>Username</label><input value="'.portal_h($u['username']).'" disabled><label>Email (read-only)</label><input value="'.portal_h($u['email']).'" disabled><label>Theme</label><select name="theme"><option value="dark" '.(($v['theme']??'dark')==='dark'?'selected':'').'>Dark</option><option value="light" '.(($v['theme']??'')==='light'?'selected':'').'>Light</option></select><label>Timezone</label><input name="timezone" value="'.portal_h($v['timezone']??'UTC').'"><label>Shortener domain (optional)</label><input type="url" name="shortener_domain" value="'.portal_h($v['shortener_domain']??'').'" placeholder="https://your-shortener.example"><label>Shortener API key</label><input name="shortener_api_key" value="" placeholder="'.portal_h($masked?:'Initially empty; enter to set or replace').'"><p class="muted">API key is stored encrypted at rest when APP_ENCRYPTION_KEY is configured; otherwise setup should configure a private encryption key before production use.</p><button class="btn">Save settings</button></form><hr style="border-color:#26364e;margin:28px 0"><h3>Change password</h3><form method="post"><input type="hidden" name="csrf" value="'.portal_h($csrf).'"><input type="hidden" name="action" value="password"><label>Current password</label><input type="password" name="current_password" required><label>New password (minimum 12 characters)</label><input type="password" name="new_password" minlength="12" required><p><button class="btn">Update password</button></p></form></div>');
    }
    if ($path==='/links') { $u=portal_require_user(); portal_page('Links',portal_header('Links',$u).'<div class="card"><p>Links workspace is reserved for the next implementation phase.</p></div>'); }
    if ($path==='/api-docs') {
        $u=portal_require_user();
        if($method==='POST') {
            portal_check_csrf(); $action=(string)($_POST['action']??'');
            if($action==='create') { $key='ab_'.bin2hex(random_bytes(24)); pdo()->prepare('INSERT INTO apikeys(user_id,key_value,label,active,usage_count,created) VALUES(?,?,?,1,0,UTC_TIMESTAMP())')->execute([(int)$u['id'],$key,trim((string)($_POST['label']??'My API key'))]); if(session_status()!==PHP_SESSION_ACTIVE){session_name('antibypass_session');session_start();} $_SESSION['new_api_key']=$key; }
            if($action==='revoke') { pdo()->prepare('DELETE FROM apikeys WHERE id=? AND user_id=?')->execute([(int)($_POST['id']??0),(int)$u['id']]); }
            header('Location: /api-docs',true,302);exit;
        }
        $keys=pdo()->prepare('SELECT id,label,active,usage_count,created,last_used FROM apikeys WHERE user_id=? ORDER BY created DESC');$keys->execute([(int)$u['id']]);
        $items='';foreach($keys->fetchAll() as $k){$items.='<div class="tile"><strong style="font-size:16px">'.portal_h($k['label']).'</strong><p class="muted">Usage: '.(int)$k['usage_count'].' · '.portal_h($k['active']?'Active':'Inactive').'</p><form method="post"><input type="hidden" name="csrf" value="'.portal_h(portal_csrf()).'"><input type="hidden" name="action" value="revoke"><input type="hidden" name="id" value="'.(int)$k['id'].'"><button class="btn alt">Revoke key</button></form></div>';}
        $flash=''; if(session_status()!==PHP_SESSION_ACTIVE){session_name('antibypass_session');session_start();} if(!empty($_SESSION['new_api_key'])){$flash='<div class="notice">Copy your new API key now: <code>'.portal_h((string)$_SESSION['new_api_key']).'</code></div>';unset($_SESSION['new_api_key']);} $body=portal_header('API Settings',$u).'<div class="card">'.$flash.'<h3>Your API keys</h3>'.$items.'<form method="post"><input type="hidden" name="csrf" value="'.portal_h(portal_csrf()).'"><input type="hidden" name="action" value="create"><label>Key label</label><input name="label" value="My API key"><p><button class="btn">Generate API key</button></p></form><p class="muted">New key is shown only once after generation in this initial version; copy it from the response/confirmation before leaving.</p></div>';
        portal_page('API Settings',$body);
    }
}
portal_handle($path,$method);
