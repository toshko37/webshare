<?php
/**
 * Simple SMTP Mailer Class
 * Sends emails via authenticated SMTP without external dependencies
 */

class SmtpMailer {
    private $host;
    private $port;
    private $username;
    private $password;
    private $encryption; // 'tls' or 'ssl'
    private $timeout = 30;
    private $socket;
    private $debug = false;
    private $lastError = '';

    public function __construct($host, $port, $username, $password, $encryption = 'tls') {
        $this->host = $host;
        $this->port = $port;
        $this->username = $username;
        $this->password = $password;
        $this->encryption = $encryption;
    }

    public function setDebug($debug) {
        $this->debug = $debug;
    }

    public function getLastError() {
        return $this->lastError;
    }

    /**
     * Send an email
     */
    public function send($to, $subject, $htmlBody, $fromName = 'WebShare', $replyTo = null) {
        $this->lastError = '';

        try {
            // Connect to SMTP server
            if (!$this->connect()) {
                return false;
            }

            // Say hello
            if (!$this->sendCommand("EHLO " . gethostname(), 250)) {
                // Try HELO if EHLO fails
                if (!$this->sendCommand("HELO " . gethostname(), 250)) {
                    $this->lastError = 'HELO/EHLO failed';
                    return false;
                }
            }

            // Start TLS if using TLS encryption
            if ($this->encryption === 'tls') {
                if (!$this->sendCommand("STARTTLS", 220)) {
                    $this->lastError = 'STARTTLS failed';
                    return false;
                }

                // Enable crypto on the socket
                if (!stream_socket_enable_crypto($this->socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                    $this->lastError = 'TLS encryption failed';
                    return false;
                }

                // Say hello again after TLS
                if (!$this->sendCommand("EHLO " . gethostname(), 250)) {
                    $this->lastError = 'EHLO after STARTTLS failed';
                    return false;
                }
            }

            // Authenticate
            if (!$this->sendCommand("AUTH LOGIN", 334)) {
                $this->lastError = 'AUTH LOGIN failed';
                return false;
            }

            if (!$this->sendCommand(base64_encode($this->username), 334)) {
                $this->lastError = 'Username authentication failed';
                return false;
            }

            if (!$this->sendCommand(base64_encode($this->password), 235)) {
                $this->lastError = 'Password authentication failed';
                return false;
            }

            // Set sender
            if (!$this->sendCommand("MAIL FROM:<{$this->username}>", 250)) {
                $this->lastError = 'MAIL FROM failed';
                return false;
            }

            // Set recipient
            if (!$this->sendCommand("RCPT TO:<{$to}>", 250)) {
                $this->lastError = 'RCPT TO failed';
                return false;
            }

            // Start data
            if (!$this->sendCommand("DATA", 354)) {
                $this->lastError = 'DATA command failed';
                return false;
            }

            // Build email headers and body
            $boundary = md5(uniqid(time()));
            $headers = $this->buildHeaders($to, $subject, $fromName, $replyTo, $boundary);
            $body = $this->buildBody($htmlBody, $boundary);

            // Send email content
            $emailData = $headers . "\r\n" . $body . "\r\n.";
            if (!$this->sendCommand($emailData, 250)) {
                $this->lastError = 'Sending email content failed';
                return false;
            }

            // Quit
            $this->sendCommand("QUIT", 221);

            $this->disconnect();
            return true;

        } catch (Exception $e) {
            $this->lastError = $e->getMessage();
            $this->disconnect();
            return false;
        }
    }

    private function connect() {
        $host = $this->host;

        // Use SSL wrapper for port 465
        if ($this->encryption === 'ssl' || $this->port == 465) {
            $host = 'ssl://' . $host;
        }

        $this->socket = @fsockopen($host, $this->port, $errno, $errstr, $this->timeout);

        if (!$this->socket) {
            $this->lastError = "Connection failed: $errstr ($errno)";
            return false;
        }

        // Read server greeting
        $response = $this->getResponse();
        if (substr($response, 0, 3) != '220') {
            $this->lastError = "Server greeting failed: $response";
            return false;
        }

        return true;
    }

    private function disconnect() {
        if ($this->socket) {
            fclose($this->socket);
            $this->socket = null;
        }
    }

    private function sendCommand($command, $expectedCode) {
        if ($this->debug) {
            echo "C: $command\n";
        }

        fwrite($this->socket, $command . "\r\n");
        $response = $this->getResponse();

        if ($this->debug) {
            echo "S: $response\n";
        }

        $code = (int)substr($response, 0, 3);
        return $code === $expectedCode;
    }

    private function getResponse() {
        $response = '';
        while ($line = fgets($this->socket, 515)) {
            $response .= $line;
            // Check if this is the last line (no continuation)
            if (substr($line, 3, 1) == ' ') {
                break;
            }
        }
        return trim($response);
    }

    private function buildHeaders($to, $subject, $fromName, $replyTo, $boundary) {
        $headers = [];
        $headers[] = "Date: " . date('r');
        $headers[] = "From: {$fromName} <{$this->username}>";
        $headers[] = "To: {$to}";
        $headers[] = "Subject: =?UTF-8?B?" . base64_encode($subject) . "?=";
        $headers[] = "MIME-Version: 1.0";
        $headers[] = "Content-Type: multipart/alternative; boundary=\"{$boundary}\"";
        $headers[] = "X-Mailer: WebShare Mailer";

        if ($replyTo) {
            $headers[] = "Reply-To: {$replyTo}";
        }

        return implode("\r\n", $headers);
    }

    private function buildBody($htmlBody, $boundary) {
        // Create plain text version from HTML
        $plainText = strip_tags(str_replace(['<br>', '<br/>', '<br />', '</p>', '</div>'], "\n", $htmlBody));
        $plainText = html_entity_decode($plainText, ENT_QUOTES, 'UTF-8');
        $plainText = preg_replace('/\n\s+/', "\n", $plainText);
        $plainText = trim($plainText);

        $body = [];
        $body[] = "--{$boundary}";
        $body[] = "Content-Type: text/plain; charset=UTF-8";
        $body[] = "Content-Transfer-Encoding: base64";
        $body[] = "";
        $body[] = chunk_split(base64_encode($plainText));

        $body[] = "--{$boundary}";
        $body[] = "Content-Type: text/html; charset=UTF-8";
        $body[] = "Content-Transfer-Encoding: base64";
        $body[] = "";
        $body[] = chunk_split(base64_encode($htmlBody));

        $body[] = "--{$boundary}--";

        return implode("\r\n", $body);
    }
}

/**
 * Get email template for file sharing
 */
function getShareEmailTemplate($downloadUrl, $filename, $senderName = null, $message = null) {
    $senderText = $senderName ? htmlspecialchars($senderName) : 'Someone';
    $filenameEscaped = htmlspecialchars($filename);
    $messageHtml = $message ? '<p style="background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #667eea; margin: 20px 0;">' . nl2br(htmlspecialchars($message)) . '</p>' : '';

    return <<<HTML
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f5f5f5; padding: 40px 20px;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); overflow: hidden;">
                    <!-- Header -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px; text-align: center;">
                            <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 600;">WebShare</h1>
                            <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0 0; font-size: 16px;">File Sharing Made Easy</p>
                        </td>
                    </tr>

                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px;">
                            <h2 style="color: #333; margin: 0 0 20px 0; font-size: 22px;">You've received a file!</h2>

                            <p style="color: #555; font-size: 16px; line-height: 1.6; margin: 0 0 20px 0;">
                                {$senderText} has shared a file with you via WebShare.
                            </p>

                            {$messageHtml}

                            <!-- File Info Box -->
                            <table width="100%" cellpadding="0" cellspacing="0" style="background: #f8f9fa; border-radius: 8px; margin: 25px 0;">
                                <tr>
                                    <td style="padding: 20px;">
                                        <table width="100%" cellpadding="0" cellspacing="0">
                                            <tr>
                                                <td width="50" valign="top">
                                                    <div style="width: 45px; height: 45px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 10px; text-align: center; line-height: 45px; font-size: 20px;">
                                                        📄
                                                    </div>
                                                </td>
                                                <td valign="middle" style="padding-left: 15px;">
                                                    <p style="margin: 0; color: #333; font-weight: 600; font-size: 16px;">{$filenameEscaped}</p>
                                                    <p style="margin: 5px 0 0 0; color: #888; font-size: 13px;">Click the button below to download</p>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>

                            <!-- Download Button -->
                            <table width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td align="center" style="padding: 10px 0 30px 0;">
                                        <a href="{$downloadUrl}" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #ffffff; text-decoration: none; padding: 16px 40px; border-radius: 8px; font-size: 16px; font-weight: 600; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);">
                                            Download File
                                        </a>
                                    </td>
                                </tr>
                            </table>

                            <!-- Alternative Link -->
                            <p style="color: #888; font-size: 13px; margin: 0; text-align: center;">
                                Or copy this link:<br>
                                <a href="{$downloadUrl}" style="color: #667eea; word-break: break-all;">{$downloadUrl}</a>
                            </p>
                        </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                        <td style="background: #f8f9fa; padding: 25px 40px; border-top: 1px solid #eee;">
                            <p style="color: #888; font-size: 13px; margin: 0; text-align: center;">
                                This email was sent via <strong>WebShare</strong> - Secure File Sharing<br>
                                <span style="color: #aaa;">Please do not reply to this email.</span>
                            </p>
                        </td>
                    </tr>
                </table>

                <!-- Footer Note -->
                <p style="color: #aaa; font-size: 12px; margin: 20px 0 0 0; text-align: center;">
                    If you didn't expect this email, you can safely ignore it.
                </p>
            </td>
        </tr>
    </table>
</body>
</html>
HTML;
}
