<?php
/** Builds src/og-image.png (1200x630) for link previews (F7). Run once: php tools/make-og-image.php */
$w = 1200; $h = 630;
$im = imagecreatetruecolor($w, $h);
for ($y = 0; $y < $h; $y++) {   // indigo -> purple gradient (#4C51BF -> #764ba2)
    $t = $y / $h;
    $c = imagecolorallocate($im, (int)(0x4C + (0x76 - 0x4C) * $t), (int)(0x51 + (0x4b - 0x51) * $t), (int)(0xBF + (0xa2 - 0xBF) * $t));
    imageline($im, 0, $y, $w, $y, $c);
}
$white = imagecolorallocate($im, 255, 255, 255);
$soft = imagecolorallocatealpha($im, 255, 255, 255, 40);
$bold = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf';
$reg = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf';
// Folder/file glyph drawn with shapes (no emoji font needed)
imagefilledrectangle($im, 110, 225, 290, 375, $white);
imagefilledrectangle($im, 110, 205, 190, 230, $white);
imagettftext($im, 92, 0, 340, 330, $white, $bold, 'WebShare');
imagettftext($im, 34, 0, 345, 400, $soft, $reg, 'Споделени файлове и папки');
imagepng($im, __DIR__ . '/../src/og-image.png', 9);
echo "src/og-image.png written\n";
