<?php
/** Link preview tests (F7). Run: php tests/link-preview-unit.php */
require __DIR__ . '/../src/link-preview.php';
$pass = $fail = 0;
function t($name, $ok) { global $pass, $fail; $ok ? $pass++ : $fail++; echo ($ok ? "  ok  " : "  FAIL ") . $name . "\n"; }
foreach (['facebookexternalhit/1.1', 'TelegramBot (like TwitterBot)', 'WhatsApp/2.23', 'Viber/22.0', 'Slackbot-LinkExpanding 1.0', 'Mozilla/5.0 (compatible; Discordbot/2.0)'] as $ua)
    t("bot: $ua", lp_is_preview_bot($ua));
foreach (['Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130', 'curl/8.14.1', 'Wget/1.21'] as $ua)
    t("not a bot: $ua", !lp_is_preview_bot($ua));
$_SERVER['HTTP_HOST'] = 'example.com"><script>'; $_SERVER['REQUEST_URI'] = '/f/abc';
$tags = lp_meta_tags('<b>"x"</b>', 'a & b');
t('title and description are escaped', strpos($tags, '&lt;b&gt;&quot;x&quot;&lt;/b&gt;') !== false && strpos($tags, 'a &amp; b') !== false);
t('host header cannot inject markup', strpos($tags, '<script>') === false);
t('size format', lp_size(5443059712) === '5.1 GB' && lp_size(512) === '512 B');
echo "\nResult: $pass passed, $fail failed\n";
exit($fail ? 1 : 0);
