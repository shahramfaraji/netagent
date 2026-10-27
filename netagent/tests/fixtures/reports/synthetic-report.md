# ارزیابی امنیت پیکربندی Cisco IOS

- دستگاه: <bdi dir="ltr">synthetic-golden-sw1</bdi>
- مدل: <bdi dir="ltr">نامشخص</bdi>
- خانواده: <bdi dir="ltr">Catalyst 2960-X</bdi>
- نسخه کاتالوگ: <bdi dir="ltr">synthetic-golden-v1</bdi>

## حکم حداقل امنیت: حداقل امنیت برقرار نیست

قابل ارزیابی: 2 | ارزیابی‌شده: 2 | برقرار: 1 | ناموفق: 1 | داده ناقص: 0 | بازبینی دستی: 0 | استثنا: 0 | نامرتبط: 0

## مواردی که ابتدا باید اصلاح شوند
فهرست زیر فقط کنترل‌های ناموفق Standard را نشان می‌دهد.

| کنترل | شدت | Standard (حداقل): پاس‌شدن این ستون یعنی تنظیمات حداقلی در کانفیگ وجود دارد؛ نحوه اعمال روی پورت‌ها بررسی نشده است. | Pro (ارتقا) |
|---|---|---|---|
| <bdi dir="ltr">CTRL-FAIL</bdi> (<bdi dir="ltr">STIG-SYN-1</bdi>) | medium | ❌ ناموفق — missing mls qos | ✋ بازبینی دستی — Synthetic recommendation; Synthetic rationale; Pro detail |

## جزئیات کنترل‌ها

| کنترل | شدت | Standard (حداقل) | Pro (ارتقا) |
|---|---|---|---|
| <bdi dir="ltr">CTRL-FAIL</bdi> (<bdi dir="ltr">STIG-SYN-1</bdi>) | medium | ❌ ناموفق — missing mls qos | ✋ بازبینی دستی — Synthetic recommendation; Synthetic rationale; Pro detail |
| <bdi dir="ltr">CTRL-PASS</bdi> (<bdi dir="ltr">STIG-SYN-1</bdi>) | medium | ✅ برقرار — mls qos present | ✅ برقرار — Synthetic recommendation; Synthetic rationale; Pro detail |

## خلاصه وضعیت Pro

پوشش Pro (تعداد کنترل‌ها، نه درصد؛ قالب N of M): PASS: 1 of 2 | MANUAL: 1 of 2

Standard: «پاس‌شدن این ستون یعنی تنظیمات حداقلی در کانفیگ وجود دارد؛ نحوه اعمال روی پورت‌ها بررسی نشده است.»
