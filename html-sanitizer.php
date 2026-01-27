<?php
/**
 * HTML Sanitizer for WebShare
 * ===========================
 * Allows only safe HTML tags used by Quill.js editor.
 * Blocks all scripts, iframes, forms, and dangerous attributes.
 */

class HTMLSanitizer {
    // Allowed tags (Quill.js formatting only)
    private static $allowedTags = [
        'p', 'br', 'span', 'div',
        'strong', 'b', 'em', 'i', 'u', 's', 'strike',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li',
        'blockquote', 'pre', 'code',
        'a', 'img',
        'sub', 'sup'
    ];

    // Allowed attributes per tag
    private static $allowedAttributes = [
        '*' => ['class', 'style'],
        'a' => ['href', 'target', 'rel'],
        'img' => ['src', 'alt', 'width', 'height'],
        'span' => ['class', 'style']
    ];

    // Allowed CSS properties (for style attribute)
    private static $allowedCssProperties = [
        'color', 'background-color', 'background',
        'font-size', 'font-weight', 'font-style', 'font-family',
        'text-decoration', 'text-align',
        'margin', 'margin-left', 'margin-right',
        'padding', 'padding-left', 'padding-right'
    ];

    // Dangerous patterns to remove
    private static $dangerousPatterns = [
        // Script tags and content
        '/<script\b[^>]*>.*?<\/script>/is',
        // Event handlers
        '/\bon\w+\s*=\s*["\'][^"\']*["\']/i',
        '/\bon\w+\s*=\s*[^\s>]*/i',
        // JavaScript URLs
        '/javascript\s*:/i',
        '/vbscript\s*:/i',
        '/data\s*:[^,]*base64/i',
        // Expression (IE)
        '/expression\s*\(/i',
        // Import
        '/@import/i',
        // Behavior (IE)
        '/behavior\s*:/i',
        // Binding (Mozilla)
        '/-moz-binding\s*:/i'
    ];

    /**
     * Sanitize HTML content
     */
    public static function sanitize($html) {
        if (empty($html)) {
            return '';
        }

        // Remove null bytes
        $html = str_replace("\0", '', $html);

        // Remove dangerous patterns first
        foreach (self::$dangerousPatterns as $pattern) {
            $html = preg_replace($pattern, '', $html);
        }

        // Use DOMDocument for proper parsing
        $dom = new DOMDocument('1.0', 'UTF-8');

        // Suppress warnings for malformed HTML
        libxml_use_internal_errors(true);

        // Wrap in container to preserve structure
        $html = '<div id="sanitizer-root">' . $html . '</div>';
        $dom->loadHTML('<?xml encoding="UTF-8">' . $html, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);

        libxml_clear_errors();

        // Process all elements
        self::processNode($dom->documentElement);

        // Get sanitized HTML
        $result = '';
        $root = $dom->getElementById('sanitizer-root');
        if ($root) {
            foreach ($root->childNodes as $child) {
                $result .= $dom->saveHTML($child);
            }
        }

        return trim($result);
    }

    /**
     * Process a DOM node and its children
     */
    private static function processNode($node) {
        if (!$node) return;

        $nodesToRemove = [];

        foreach ($node->childNodes as $child) {
            if ($child->nodeType === XML_ELEMENT_NODE) {
                $tagName = strtolower($child->nodeName);

                // Check if tag is allowed
                if (!in_array($tagName, self::$allowedTags)) {
                    // Keep text content but remove the tag
                    $nodesToRemove[] = $child;
                    continue;
                }

                // Process attributes
                self::processAttributes($child);

                // Recursively process children
                self::processNode($child);
            }
        }

        // Remove disallowed nodes (replace with their text content)
        foreach ($nodesToRemove as $nodeToRemove) {
            $textContent = $nodeToRemove->textContent;
            if (!empty($textContent)) {
                $textNode = $nodeToRemove->ownerDocument->createTextNode($textContent);
                $nodeToRemove->parentNode->replaceChild($textNode, $nodeToRemove);
            } else {
                $nodeToRemove->parentNode->removeChild($nodeToRemove);
            }
        }
    }

    /**
     * Process and sanitize attributes
     */
    private static function processAttributes($element) {
        $tagName = strtolower($element->nodeName);
        $attributesToRemove = [];

        foreach ($element->attributes as $attr) {
            $attrName = strtolower($attr->name);
            $attrValue = $attr->value;

            // Get allowed attributes for this tag
            $allowed = self::$allowedAttributes['*'] ?? [];
            if (isset(self::$allowedAttributes[$tagName])) {
                $allowed = array_merge($allowed, self::$allowedAttributes[$tagName]);
            }

            // Check if attribute is allowed
            if (!in_array($attrName, $allowed)) {
                $attributesToRemove[] = $attr->name;
                continue;
            }

            // Special handling for specific attributes
            switch ($attrName) {
                case 'href':
                    // Only allow safe URLs
                    if (!self::isSafeUrl($attrValue)) {
                        $attributesToRemove[] = $attr->name;
                    }
                    break;

                case 'src':
                    // Only allow safe image URLs
                    if (!self::isSafeUrl($attrValue, true)) {
                        $attributesToRemove[] = $attr->name;
                    }
                    break;

                case 'style':
                    // Sanitize CSS
                    $safeStyle = self::sanitizeStyle($attrValue);
                    if (empty($safeStyle)) {
                        $attributesToRemove[] = $attr->name;
                    } else {
                        $element->setAttribute('style', $safeStyle);
                    }
                    break;

                case 'target':
                    // Force safe target values
                    if (!in_array($attrValue, ['_blank', '_self'])) {
                        $element->setAttribute('target', '_blank');
                    }
                    // Add rel="noopener" for security
                    $element->setAttribute('rel', 'noopener noreferrer');
                    break;
            }
        }

        // Remove disallowed attributes
        foreach ($attributesToRemove as $attrName) {
            $element->removeAttribute($attrName);
        }
    }

    /**
     * Check if URL is safe
     */
    private static function isSafeUrl($url, $imageOnly = false) {
        $url = trim($url);

        // Empty is not safe
        if (empty($url)) {
            return false;
        }

        // Check for dangerous protocols
        $dangerousProtocols = ['javascript:', 'vbscript:', 'data:', 'file:'];
        $urlLower = strtolower($url);
        foreach ($dangerousProtocols as $protocol) {
            if (strpos($urlLower, $protocol) === 0) {
                return false;
            }
        }

        // Allow relative URLs
        if ($url[0] === '/' || $url[0] === '.' || $url[0] === '#') {
            return true;
        }

        // Allow http and https
        if (preg_match('/^https?:\/\//i', $url)) {
            return true;
        }

        // Allow data URLs only for images (base64 images from Quill)
        if ($imageOnly && preg_match('/^data:image\/(png|jpeg|jpg|gif|webp);base64,/i', $url)) {
            return true;
        }

        return false;
    }

    /**
     * Sanitize CSS style attribute
     */
    private static function sanitizeStyle($style) {
        $safeStyles = [];

        // Parse CSS properties
        $properties = explode(';', $style);
        foreach ($properties as $property) {
            $property = trim($property);
            if (empty($property)) continue;

            $parts = explode(':', $property, 2);
            if (count($parts) !== 2) continue;

            $propName = strtolower(trim($parts[0]));
            $propValue = trim($parts[1]);

            // Check if property is allowed
            if (in_array($propName, self::$allowedCssProperties)) {
                // Remove any url() or expression() from value
                if (preg_match('/url\s*\(|expression\s*\(/i', $propValue)) {
                    continue;
                }
                $safeStyles[] = $propName . ': ' . $propValue;
            }
        }

        return implode('; ', $safeStyles);
    }

    /**
     * Quick check if content contains potential threats
     */
    public static function containsThreats($html) {
        $threats = [
            '/<script/i',
            '/javascript:/i',
            '/\bon\w+\s*=/i',
            '/<iframe/i',
            '/<frame/i',
            '/<object/i',
            '/<embed/i',
            '/<form/i',
            '/<input/i',
            '/<meta/i',
            '/<link/i',
            '/<style/i',
            '/expression\s*\(/i',
            '/@import/i'
        ];

        foreach ($threats as $pattern) {
            if (preg_match($pattern, $html)) {
                return true;
            }
        }

        return false;
    }
}

/**
 * Helper function
 */
function sanitizeHtml($html) {
    return HTMLSanitizer::sanitize($html);
}
