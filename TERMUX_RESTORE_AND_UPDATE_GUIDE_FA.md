# راهنمای قطعی بازیابی و به‌روزرسانی Termux — MIHOMO-4-CORE

**هدف:** پس از حذف Termux، تعویض گوشی، خرابی فایل‌ها یا نیاز به به‌روزرسانی Core/Geo، همان اسکریپت مبنا با همان قراردادها و مسیرها بازیابی شود. این سند دستور کار اجرایی است؛ جایگزین اسکریپت یا تست واقعی نیست.

## 0. قانون حفاظت از مبنا

- فایل اجرایی مرجع فقط `references/01_king_egress_final.py` با SHA-256 زیر است:

  `248357ff4a6f12b2785f1a6a11b529b291ee615436e97603674012918243c06b`

- نام کاری اسکریپت در بکاپ `01_king_egress_final.py` است؛ نامی که کاربر اجرا می‌کند می‌تواند `king_egress_final.py` باشد، ولی محتوا باید دقیقاً همین هش را داشته باشد.
- فایل تاریخی `king.py` مبنا نیست. از آن برای جایگزینی یا merge استفاده نکن.
- هیچ Core، موتور، MMDB، DAT یا DB را فقط به‌خاطر هم‌نام بودن جایگزین نکن.
- قبل از هر به‌روزرسانی، از اسکریپت، Core، پوشه Geo، ورودی و خروجی نسخهٔ پشتیبان بگیر.
- ابتدا نسخهٔ جدید را در پوشهٔ staging آزمایش کن؛ فقط بعد از موفقیت تست‌ها آن را به مسیر فعال منتقل کن.
- بستهٔ اصلی `03_MihomoIndustrial.zip` منبع بازیابی ساختار پروژه و فایل‌های Core/Geo فعلی است.

## 1. نقشهٔ مسیرها — این مسیرها بخشی از قرارداد فعلی‌اند

| جزء | مسیر فعال در Android/Termux | توضیح |
|---|---|---|
| پروژهٔ MihomoIndustrial | `$HOME/MihomoIndustrial/` | پوشهٔ اصلی پروژه؛ از ZIP شماره 03 بازیابی می‌شود |
| Core اجرایی | `$HOME/MihomoIndustrial/core/mihomo` | باینری Android ARM64؛ باید executable باشد |
| Core دوم/جایگزین قدیمی | `$HOME/MihomoIndustrial/core/mihomo2` | فقط candidate ثانویه در جست‌وجوی اسکریپت؛ تا زمان نیاز دست نزن |
| Geo assets پروژه | `$HOME/MihomoIndustrial/geo/` | فایل‌های MMDB و DAT/DB اصلی موجود در ZIP شماره 03 |
| ورودی و خروجی اسکریپت | `/storage/emulated/0/Download/Akbar98/` | `input.txt`، خروجی YAML، گزارش‌ها و audit |
| ورودی خام | `/storage/emulated/0/Download/Akbar98/input.txt` | اسکریپت هنگام اجرای workflow خودش آن را می‌خواند |
| گزارش Egress | `/storage/emulated/0/Download/Akbar98/egress_audit.json` | شواهد Egress؛ گزارش را با فایل ورودی/secretها اشتباه نگیر |
| GeoIP دستی/مشترک | `/storage/emulated/0/Download/almasi98/` | اسکریپت این مسیر را برای MMDBهای محلی جست‌وجو می‌کند |
| زیرپوشهٔ GeoIP | `/storage/emulated/0/Download/almasi98/geo/` | مسیر جایگزین برای همان نام‌های MMDB |
| سورس Go Mihomo | `$HOME/mihomo_source/mihomo-1.19.32/` | سورس جداگانه؛ Core اجرایی فعلی از این سورس به‌طور قطعی قابل بازتولید نیست |

**نکتهٔ مهم:** محل اجرای اسکریپت، مسیر ورودی/خروجی و محل Core سه چیز جدا هستند. جابه‌جایی فایل Python به‌تنهایی مسیر ثابت `Akbar98` را عوض نمی‌کند.

## 2. Core فعلی — هویت و سازگاری

از ZIP شماره 03، مسیر `core/mihomo` استخراج و بررسی شد:

- قالب: ELF 64-bit، ARM aarch64، Android، interpreter برابر `/system/bin/linker64`.
- build metadata قابل مشاهده در باینری: `v1.19.34-custom.8.828d64e`.
- SHA-256 فایل فعلی: `001aaba1fc07e18276b48552f8c0bd69096244e32334ac171976eb357800b13b`.
- اندازه: `64201176` بایت.
- باینری Android ARM64 است؛ باینری Linux x86_64 یا ARMv7 جایگزین آن نیست.
- سورس ZIP شماره 04 پوشهٔ `mihomo-1.19.32/` دارد. این نسخه با باینری `v1.19.34-custom.8.828d64e` یکی نیست. بنابراین ZIP سورس 1.19.32 را نباید به‌عنوان سورس دقیق build سفارشی فعلی معرفی یا برای بازتولید byte-identical آن استفاده کرد.

**مسیر جست‌وجوی Core در کد:** ابتدا `MIHOMO_BINARY` در محیط، سپس `$HOME/MihomoIndustrial/core/mihomo`، سپس `core/mihomo2`، سپس `Akbar98/core/mihomo`، مسیرهای Download و در پایان `PATH`.

## 3. GeoIP: دقیقاً کدام فایل برای کدام کار است؟

### 3.1 فایل‌هایی که اسکریپت Python برای تشخیص کشور Egress می‌خواند

کد `_open_local_mmdb()` فقط فایل MMDB قابل خواندن با `maxminddb` یا fallback `geoip2` را باز می‌کند. ترتیب اولویت فعلی:

1. مسیر صریح متغیر محیطی `MIHOMO_COUNTRY_MMDB`، اگر تعیین شده باشد.
2. `/storage/emulated/0/Download/almasi98/GeoLite2-City.mmdb`
3. همان مسیر با `City.mmdb`
4. `GeoLite2-Country.mmdb`
5. `Country-without-asn.mmdb`
6. `country.mmdb`
7. `country-lite.mmdb`
8. همین نام‌ها در زیرپوشهٔ `/storage/emulated/0/Download/almasi98/geo/`
9. همین نام‌های منتخب در `$HOME/MihomoIndustrial/geo/`
10. دو candidate در `$HOME/MihomoIndustrial/assets/`: `GeoLite2-Country.mmdb` و `Country-without-asn.mmdb`.

اولین MMDB قابل باز شدن استفاده می‌شود. بنابراین فایل قدیمی یا کم‌جزئیات‌تر که در مسیر با اولویت بالاتر باشد ممکن است قبل از فایل بهتر انتخاب شود. پس از تعویض دیتابیس، گزارش `[GEOIP-LOCAL] Loaded country MMDB:` را بررسی کن تا مسیر واقعی انتخاب‌شده مشخص شود.

### 3.2 تفاوت Country و City

- `GeoLite2-Country.mmdb` و `Country-without-asn.mmdb` برای کشور مناسب‌اند؛ الزاماً شهر نمی‌دهند.
- `GeoLite2-City.mmdb` یا `City.mmdb` فقط وقتی شهر قابل نمایش می‌کند که واقعاً دیتابیس City معتبر و قابل‌خواندن در مسیر اولویت‌دار باشد.
- در فایل‌های فعلی ZIP شماره 03، `GeoLite2-City.mmdb` ثبت نشده است. پس بستهٔ فعلی تضمین‌کنندهٔ تشخیص شهر نیست؛ برای شهر باید City MMDB مجاز و سازگار جداگانه تهیه و در مسیر اولویت‌دار قرار گیرد.
- موقعیت IP تخمینی است؛ شهر IP به معنی نشانی دقیق فیزیکی نیست.

### 3.3 فایل‌هایی که با MMDB جایگزین نمی‌شوند

| نوع فایل | نمونه | نقش عمومی | جایگزین MMDB در resolver اسکریپت؟ |
|---|---|---|---|
| MMDB | `GeoLite2-Country.mmdb`, `country.mmdb` | پایگاه MaxMind-style برای lookup آدرس IP | بله، اگر ساختار و reader سازگار باشد |
| DAT | `geoip.dat`, `geosite.dat`, `geoip-lite.dat` | دادهٔ GeoIP/GeoSite مورد استفادهٔ موتور Mihomo در حالت geodata | خیر |
| DB | `geoip.db`, `geoip.meta.db`, `geosite.db`, `ip_to_country.db` | دیتابیس‌های ابزار/فرمت‌های دیگر پروژه | خیر، مگر کد اختصاصی برای همان فرمت نوشته و تست شود |
| ASN MMDB | `ASN.mmdb`, `GeoLite2-ASN.mmdb` | اطلاعات Autonomous System | خیر؛ ASN مبنای کشور Egress نیست |

هیچ‌وقت پسوند را rename نکن تا یک فایل DAT/DB وانمود کند MMDB است. محتوا و format باید واقعی باشد.

## 4. بازیابی کامل پس از حذف Termux

1. آرشیو نهایی `MIHOMO-4-CORE_MASTER_20261116_EGRESS_FINAL.tar.gz` را از بکاپ خودت به Downloads برگردان.
2. SHA-256 آرشیو را با فایل `.sha256` کنار آن مقایسه کن؛ اگر متفاوت بود، استخراج و اجرا نکن.
3. آرشیو را در یک پوشهٔ موقت استخراج کن. داخل آن `MIHOMO-4-CORE_MASTER/` وجود دارد.
4. فایل‌های `references/`، `specifications/` و `indexes/` را به‌عنوان مرجع نگه دار.
5. از `references/03_MihomoIndustrial.zip` کل پروژه را در `$HOME/MihomoIndustrial/` استخراج کن؛ ساختار داخل ZIP از قبل با `core/mihomo` و `geo/` در ریشه ساخته شده است.
6. فایل `references/01_king_egress_final.py` را در محل نگهداری اسکریپت خودت کپی کن؛ هش آن باید دقیقاً `248357ff4a6f12b2785f1a6a11b529b291ee615436e97603674012918243c06b` باشد.
7. پوشهٔ `/storage/emulated/0/Download/Akbar98/` را بساز و ورودی `input.txt` را در همان‌جا قرار بده.
8. Geo MMDBهای مورد نیاز از پروژه در `$HOME/MihomoIndustrial/geo/` هستند؛ در صورت استفاده از مسیر مشترک، آن‌ها را در `/storage/emulated/0/Download/almasi98/` هم کپی کن. از کپی نسخهٔ ناشناخته روی فایل معتبر خودداری کن.
9. executable بودن Core را بررسی کن. در Termux: `chmod 700 "$HOME/MihomoIndustrial/core/mihomo"`.
10. بررسی معماری و نسخه: `file "$HOME/MihomoIndustrial/core/mihomo"` و `"$HOME/MihomoIndustrial/core/mihomo" -v`.
11. بررسی پیکربندی با Core: `"$HOME/MihomoIndustrial/core/mihomo" -t -d "$HOME/MihomoIndustrial/runtime" -f <config.yaml>`.
12. آزمون اسکریپت: `python <مسیر-اسکریپت>/king_egress_final.py --all-selftests`.
13. بعد از این مراحل، یک تست واقعی با چند نود در Termux انجام بده و لاگ Egress/GeoIP را بررسی کن. Self-test آفلاین به‌تنهایی اتصال واقعی را ثابت نمی‌کند.

## 5. به‌روزرسانی Core بدون تغییر اسکریپت

**منبع رسمی انتشار:** `https://github.com/MetaCubeX/mihomo/releases`

1. فقط asset مخصوص Android `arm64` را انتخاب کن؛ `armv7`، `amd64`، `linux` یا نسخهٔ سیستم‌عامل دیگر ممنوع است.
2. نسخه، تاریخ، checksum رسمی، نوع build و معماری را در changelog ثبت کن. اگر Core فعلی custom build است، نسخهٔ رسمی جدید ممکن است patchها/رفتار متفاوتی داشته باشد؛ آن را معادل ندان.
3. فایل فشرده را ابتدا به staging دانلود و استخراج کن؛ نام نهایی فایل اجرایی باید `mihomo` باشد.
4. فایل را از نظر ELF/ARM64 و `mihomo -v` بررسی کن. اگر دستور نسخه اجرا نشد یا معماری ناسازگار بود، به مسیر فعال منتقل نکن.
5. مسیر Core staging را با `MIHOMO_BINARY=/path/to/staging/mihomo` به اسکریپت معرفی کن و self-test و native config test را اجرا کن.
6. سپس تست واقعی Egress quorum، Health، dialer-proxy، GeoIP و YAML روی Termux انجام شود.
7. تنها پس از قبولی همهٔ آزمون‌ها، از Core قدیمی backup بگیر و فایل جدید را اتمیک به `$HOME/MihomoIndustrial/core/mihomo` منتقل کن.
8. اگر تستی شکست خورد، Core قبلی را برگردان. اسکریپت را برای سازگار کردن فوری با Core جدید دستکاری نکن؛ اول اختلاف schema/feature را مستند کن.

**ممنوع:** دانلود `latest` و overwrite مستقیم Core فعال، بدون checksum و staging.

## 6. به‌روزرسانی Geo files

### منابع رسمی

- GeoIP/GeoSite و MMDBهای سازگار با Mihomo: `https://github.com/MetaCubeX/meta-rules-dat/releases`
- فهرست نام فایل‌ها و شرح کاربرد: `https://github.com/MetaCubeX/meta-rules-dat`
- GeoLite2 Country/City: حساب و صفحهٔ رسمی دانلود MaxMind؛ دریافت دستی/خودکار تابع مجوز و شرایط MaxMind است: `https://support.maxmind.com/knowledge-base/articles/download-and-update-maxmind-databases`

### روند امن

1. ابتدا تعیین کن کدام نوع لازم است: Country MMDB برای کشور، City MMDB برای شهر، `geoip.dat` برای موتور در حالت DAT، `geosite.dat` برای دامنه‌ها، ASN MMDB فقط برای ASN.
2. فایل را در staging جداگانه دانلود کن؛ پسوند و نام واقعی را حفظ کن.
3. checksum رسمی را بررسی کن؛ اگر upstream checksum ارائه نکرد، SHA-256 محلی ثبت کن و منبع/تاریخ را یادداشت کن.
4. فایل MMDB را با reader واقعی باز کن و چند IP آزمایشی را lookup کن. فایل صفر بایت، HTML خطا یا archive فشردهٔ بازنشده قابل قبول نیست.
5. فایل جدید را در مسیر اصلی همان نوع قرار بده؛ برای resolver این اسکریپت مسیر `$HOME/MihomoIndustrial/geo/` یا `/storage/emulated/0/Download/almasi98/` است.
6. فایل قدیمی را تا پایان تست با نام backup نگه دار، ولی در candidateهای اولویت‌دار نگذار تا اشتباهاً انتخاب نشود.
7. اجرای آزمایشی باید نشان دهد دقیقاً کدام MMDB بار شده است. بعد چند Egress شناخته‌شده را بررسی کن.
8. DAT/DB را جداگانه و فقط در مسیر دادهٔ Mihomo جایگزین کن؛ تغییر آن‌ها را با `mihomo -t` و تست Rule GEOIP/GEOSITE بررسی کن.
9. اگر GeoIP جدید پاسخ نمی‌دهد، نسخهٔ قبلی را برگردان؛ نودها را به‌خاطر خطای Geo provider خراب اعلام نکن.

## 7. قراردادهای عملکردی که با به‌روزرسانی نباید تغییر کنند

- فقط Egress IP واقعی اندازه‌گیری‌شده از مسیر پروکسی مبنای کشور و یکتایی است.
- کشور از IP سرور، اسم نود، flag ورودی، protocol، ASN یا حدس استخراج نمی‌شود.
- Select: سالم + Egress عمومی تأییدشده + کشور معتبر.
- Fallback: سالم + Egress عمومی تأییدشده؛ کشور می‌تواند نامعلوم باشد.
- Unknown Country: سالم + Egress تأییدشده + کشور حل‌نشده.
- Direct: فقط `DIRECT`؛ هیچ proxy node عضو آن نیست.
- گروه‌ها از inventory خام و predicate مستقل خود ساخته می‌شوند؛ گروهی از گروه دیگر کپی نمی‌شود.
- یکتایی Egress داخل هر گروه جداگانه است؛ حذف از یک گروه inventory یا گروه‌های دیگر را حذف نمی‌کند.
- Egress Unverified با Unknown Country یکی نیست.
- خطای GeoIP، timeout یا rate limit به‌تنهایی خرابی نود نیست.
- ترتیب و نام چهار گروه، routing، dialer-proxy، quorum، health checks و invariants validation باید حفظ شوند.

## 8. آزمون پذیرش پس از هر تغییر

### سطح A — بدون شبکه

`python king_egress_final.py --all-selftests`

باید تمام موارد PASS شوند. خروجی کامل با تاریخ و hash اسکریپت ذخیره شود.

### سطح B — Core واقعی

- `mihomo -v` با نسخهٔ مورد انتظار تطبیق داشته باشد.
- `mihomo -t` برای config نمونه موفق باشد.
- معماری Android ARM64 باشد.

### سطح C — Termux واقعی

- لاگ نشان دهد Core صحیح پیدا شده است.
- حد نصاب Egress (در این baseline دو پاسخ از سه echo) رعایت شود.
- Egress IPv4/IPv6، Health و dialer-proxy مستقل تست شوند.
- MMDB واقعی و مسیر انتخاب‌شده در log مشخص باشد.
- کشور نامعلوم بدون حدس به Unknown برود؛ Egress نامشخص وارد گروه‌های نیازمند Egress verified نشود.
- هر گروه به‌صورت مستقل Egress duplicate نداشته باشد.
- خروجی YAML با همان Core تست شود.

قبولی سطح A هرگز جای سطح B و C را نمی‌گیرد.

## 9. پشتیبان‌گیری چندگانه

حداقل سه نسخهٔ مستقل نگه دار:

1. گوشی/حافظهٔ داخلی: آرشیو نهایی و checksum.
2. GitHub private یا مخزن خصوصی: اسکریپت، Markdownها، checksum و manifest؛ از قراردادن subscription، UUID، password، private key، token یا فایل‌های شخصی خودداری کن.
3. فضای ابری/پیام‌رسان شخصی: آرشیو رمزگذاری‌شده و checksum؛ قبل از ارسال، secrets و فایل‌های config حاوی credential را جدا کن.

پس از هر به‌روزرسانی پذیرفته‌شده، snapshot نسخه‌دار جدید بساز؛ آرشیو قبلی را حذف نکن.

## 10. اطلاعاتی که هنوز نباید فرض شوند

- باینری Core فعلی custom است و سورس موجود در ZIP شماره 04 نسخهٔ 1.19.32 است؛ commit دقیق سازندهٔ custom build از این چهار مرجع به‌تنهایی اثبات نشده.
- بستهٔ فعلی City MMDB ندارد؛ کشور قابل بازیابی است، اما شهر نیازمند City MMDB واقعی است.
- Self-testها offline هستند؛ کارکرد شبکهٔ واقعی، هر پروکسی و همهٔ نسخه‌های آیندهٔ Core تضمین نشده.
- اگر schema یا رفتار Core آینده تغییر کند، باید adapter/validation سازگار شود؛ هرگز فایل اجرایی اصلی را بدون تست بازنویسی نکن.

## 11. منابع رسمی

- Mihomo releases: https://github.com/MetaCubeX/mihomo/releases
- Meta rules data releases: https://github.com/MetaCubeX/meta-rules-dat/releases
- Meta rules data README: https://github.com/MetaCubeX/meta-rules-dat
- MaxMind database download/update guidance: https://support.maxmind.com/knowledge-base/articles/download-and-update-maxmind-databases
- Mihomo GEO settings documentation: https://github.com/MetaCubeX/Meta-Docs/blob/main/docs/config/general.en.md
