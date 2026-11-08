# Документация на WebShare

Тази папка е в корена на хранилището, извън DocumentRoot (`src/`), и не се сервира публично.

| Документ | Съдържание |
|---|---|
| [upload-guard.md](upload-guard.md) | Защита на анонимното качване: режими, проверка, пропуски, лимити, curl, админ панел, данни, тестове |
| [security-hardening.md](security-hardening.md) | Спешните точки U2–U11: поправки, защита от налучкване, fail2ban, права |
| [security-plan-2.md](security-plan-2.md) | Важните точки I1–I16 и група 4: план, статус, тестове |
| [backup.md](backup.md) | Архивиране: какво, къде, колко дълго, възстановяване |
| [decisions.md](decisions.md) | Дневник на решенията с контекст и причини |
| [audit-2026-11-08.md](audit-2026-11-08.md) | Технически одит и статус на всяка находка |
| [ui-ux-plan.md](ui-ux-plan.md) | План за UI/UX корекциите, фази и статус |
| [ui-ux-audit-2026-11-08.md](ui-ux-audit-2026-11-08.md) | UI/UX одит с измервания, достъпност и снимки, X1–X23 |
| [worklog.md](worklog.md) | Хронологичен дневник: променени файлове, намеси по сървъра, тестове |

## Тестове

```bash
php tests/upload-guard-unit.php                           # unit, без живи данни
tests/upload-guard-test.sh https://webshare.techbg.net    # end-to-end срещу сървър
node tests/ui-audit.js ...                                # UI/UX одит, виж заглавието на файла
php tests/security-unit.php                               # unit, защита от налучкване и пренасочване
tests/security-test.sh https://webshare.techbg.net        # end-to-end, като root на сървъра
php -d memory_limit=128M tests/encryption-unit.php --big  # криптиране v1/v2, 300 MB на поток
php tests/manifest-test.php                               # списъците на файловете са в синхрон
```

## Правила за документацията

1. Всяка функционалност получава документ в `docs/`.
2. Всяко нетривиално решение влиза в `decisions.md` с контекст, избор и причина.
3. Всяка сесия с промени влиза в `worklog.md`: файлове, намеси по сървъра, тестове с резултати, какво не е тествано.
4. Статусът в одита се обновява при всяка поправка.
5. `CHANGELOG.md` се попълва от `release.sh` при релийз.
