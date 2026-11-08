/*
 * WebShare UI kit: toasts, confirm/prompt dialogs, date formatting and an
 * accessibility safety net. Shared by all pages.
 * Docs: docs/ui-ux-plan.md (repository root, not served)
 */
(function () {
    'use strict';
    const WS = window.WS = window.WS || {};
    const FLASH_KEY = 'ws-flash';

    function el(tag, attrs, text) {
        const e = document.createElement(tag);
        if (attrs) Object.keys(attrs).forEach(k => e.setAttribute(k, attrs[k]));
        if (text !== undefined) e.textContent = text;
        return e;
    }

    function toastHost() {
        let host = document.getElementById('ws-toasts');
        if (!host) {
            host = el('div', { id: 'ws-toasts', role: 'status', 'aria-live': 'polite' });
            document.body.appendChild(host);
        }
        return host;
    }

    /**
     * Non-blocking notification.
     * @param {string} message
     * @param {'info'|'success'|'error'|'warning'} type
     * @param {number} timeout ms, 0 = stay until closed (errors default to 8 s)
     */
    WS.toast = function (message, type, timeout) {
        type = type || 'info';
        if (timeout === undefined) timeout = type === 'error' ? 8000 : 4000;
        const t = el('div', { class: 'ws-toast ' + type });
        if (type === 'error') t.setAttribute('role', 'alert');
        t.appendChild(document.createTextNode(String(message)));
        const close = el('button', { type: 'button', 'aria-label': 'Close' }, '×');
        close.addEventListener('click', () => t.remove());
        t.appendChild(close);
        toastHost().appendChild(t);
        if (timeout) setTimeout(() => t.remove(), timeout);
        return t;
    };

    /** Toast that survives a page reload (for actions followed by location.reload()) */
    WS.flash = function (message, type) {
        try {
            const list = JSON.parse(sessionStorage.getItem(FLASH_KEY) || '[]');
            list.push({ message: String(message), type: type || 'info' });
            sessionStorage.setItem(FLASH_KEY, JSON.stringify(list));
        } catch (e) { /* storage unavailable: message is lost, page still works */ }
    };

    function showFlashes() {
        try {
            const list = JSON.parse(sessionStorage.getItem(FLASH_KEY) || '[]');
            sessionStorage.removeItem(FLASH_KEY);
            list.forEach(f => WS.toast(f.message, f.type));
        } catch (e) { /* ignore */ }
    }

    /**
     * Modal confirmation built on <dialog> (native focus trap, Esc to cancel).
     * @param {{title:string, message?:string, items?:string[], confirmText?:string,
     *          cancelText?:string, danger?:boolean, input?:{label:string, value?:string}}} opts
     * @returns {Promise<boolean|string|null>} true/false, or the input value / null when opts.input is set
     */
    WS.confirm = function (opts) {
        opts = opts || {};
        return new Promise(resolve => {
            if (typeof HTMLDialogElement !== 'function') {
                // Very old browsers: fall back to the native dialogs
                if (opts.input) return resolve(window.prompt(opts.title, opts.input.value || ''));
                return resolve(window.confirm(opts.title + (opts.message ? '\n\n' + opts.message : '')));
            }
            const d = el('dialog', { class: 'ws-dialog', 'aria-labelledby': 'ws-dlg-title' });
            const body = el('div', { class: 'ws-dialog-body' });
            body.appendChild(el('h2', { id: 'ws-dlg-title' }, opts.title || 'Are you sure?'));
            if (opts.message) body.appendChild(el('p', null, opts.message));
            if (opts.items && opts.items.length) {
                const ul = el('ul');
                opts.items.slice(0, 200).forEach(i => ul.appendChild(el('li', null, i)));
                if (opts.items.length > 200) ul.appendChild(el('li', null, '… +' + (opts.items.length - 200)));
                body.appendChild(ul);
            }
            let input = null;
            if (opts.input) {
                const id = 'ws-dlg-input';
                body.appendChild(el('label', { for: id }, opts.input.label));
                input = el('input', { type: 'text', id: id });
                input.value = opts.input.value || '';
                body.appendChild(input);
            }
            const actions = el('div', { class: 'ws-dialog-actions' });
            const cancel = el('button', { type: 'button' }, opts.cancelText || 'Cancel');
            const ok = el('button', { type: 'button', class: opts.danger ? 'ws-danger' : 'ws-primary' }, opts.confirmText || 'OK');
            actions.appendChild(cancel);
            actions.appendChild(ok);
            d.appendChild(body);
            d.appendChild(actions);
            document.body.appendChild(d);

            let done = false;
            const finish = val => {
                if (done) return;
                done = true;
                d.close();
                d.remove();
                resolve(val);
            };
            cancel.addEventListener('click', () => finish(opts.input ? null : false));
            ok.addEventListener('click', () => finish(opts.input ? input.value : true));
            d.addEventListener('cancel', e => { e.preventDefault(); finish(opts.input ? null : false); });
            if (input) input.addEventListener('keydown', e => { if (e.key === 'Enter') finish(input.value); });
            d.showModal();
            // Destructive actions focus Cancel so Enter does not delete by accident
            (input || (opts.danger ? cancel : ok)).focus();
        });
    };

    /** dd.mm.yyyy HH:MM[:SS] from a unix timestamp (seconds) or Date */
    WS.formatDate = function (ts, withSeconds) {
        const d = ts instanceof Date ? ts : new Date(ts * 1000);
        if (isNaN(d)) return '';
        const p = n => String(n).padStart(2, '0');
        return p(d.getDate()) + '.' + p(d.getMonth() + 1) + '.' + d.getFullYear() + ' ' + p(d.getHours()) + ':' + p(d.getMinutes())
            + (withSeconds ? ':' + p(d.getSeconds()) : '');
    };

    /** Short, readable device name from a User-Agent string */
    WS.describeUA = function (ua) {
        ua = ua || '';
        if (/^curl\//i.test(ua)) return 'curl';
        if (/^wget/i.test(ua)) return 'wget';
        const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Firefox\//.test(ua) ? 'Firefox'
            : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
        const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS'
            : /Mac OS X/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : '';
        return os ? browser + ' · ' + os : browser;
    };

    /**
     * Accessibility safety net for markup that is not yet fixed at the source:
     * names for icon-only buttons and unlabeled fields, keyboard access to
     * scrollable code blocks. Runs on load and on DOM changes.
     */
    function nameOf(e) {
        return e.getAttribute('aria-label') || e.getAttribute('aria-labelledby') ||
            (e.id && document.querySelector('label[for="' + CSS.escape(e.id) + '"]')) || e.closest('label');
    }
    WS.enhanceA11y = function (root) {
        root = root || document;
        root.querySelectorAll('button, a[href], [role=button]').forEach(b => {
            if (b.getAttribute('aria-label')) return;
            const text = (b.textContent || '').replace(/[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE0F}\u{2190}-\u{21FF}]/gu, '').trim();
            if (!text && b.title) b.setAttribute('aria-label', b.title);
        });
        root.querySelectorAll('input:not([type=hidden]), select, textarea').forEach(i => {
            if (nameOf(i)) return;
            const n = i.getAttribute('placeholder') || i.title || (i.name ? i.name.replace(/[_-]+/g, ' ') : '');
            if (n) i.setAttribute('aria-label', n);
        });
        // Quill editor toolbar (chat): icon-only buttons and pickers
        const quillNames = { bold: 'Bold', italic: 'Italic', underline: 'Underline', strike: 'Strikethrough',
            blockquote: 'Quote', 'code-block': 'Code block', link: 'Link', clean: 'Clear formatting',
            color: 'Text colour', background: 'Highlight colour', header: 'Heading', list: 'List' };
        root.querySelectorAll('.ql-toolbar button, .ql-toolbar .ql-picker-label').forEach(b => {
            if (b.getAttribute('aria-label')) return;
            const host = b.classList.contains('ql-picker-label') ? b.closest('.ql-picker') : b;
            const m = host && [...host.classList].map(c => c.replace(/^ql-/, '')).find(c => quillNames[c]);
            if (!m) return;
            const v = b.getAttribute('value');
            b.setAttribute('aria-label', quillNames[m] + (v && v !== 'true' ? ' ' + v : ''));
        });
        root.querySelectorAll('pre, code, table').forEach(c => {
            if (c.scrollWidth > c.clientWidth + 1 && !c.hasAttribute('tabindex')) c.setAttribute('tabindex', '0');
        });
    };

    function init() {
        showFlashes();
        WS.enhanceA11y();
        let pending = false;
        new MutationObserver(() => {
            if (pending) return;
            pending = true;
            requestAnimationFrame(() => { pending = false; WS.enhanceA11y(); });
        }).observe(document.body, { childList: true, subtree: true });
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
