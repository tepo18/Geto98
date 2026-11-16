# پروندهٔ بازسازی کامل King / Mihomo Industrial

**شناسهٔ مرجع:** `MIHOMO-4-CORE`  
**نسخهٔ مبنا:** `king_egress_final.py`  
**وضعیت:** سند مهندسیِ همراهِ کد؛ برای بازیابی و ادامهٔ توسعه، نه جایگزین سورس اجرایی  
**تاریخ ثبت:** 2026-11-16

---

## 1) هدف این سند و قانون مرجع

این سند مشخصات قابل‌بازیابیِ اهداف، قراردادهای رفتاری، معماری، جریان داده، تصمیم‌های GeoIP/Egress، ساخت گروه‌ها، اعتبارسنجی، موتورهای کمکی، مسیرهای ورودی/خروجی و آزمون‌های اسکریپت `king_egress_final.py` را ثبت می‌کند تا اگر فایل اسکریپت، باینری Mihomo، بخشی از پروژه یا محیط اجرا حذف/خراب/به‌روزرسانی شد، بتوان نسخهٔ بعدی را از روی کد و این مشخصات مهندسی بازسازی کرد، بدون اینکه طراحی از صفر حدس زده شود.

**قانون پایه:** تنها کد اجراییِ مرجع در این بسته `references/01_king_egress_final.py` است. فایل تاریخی `king.py` دیگر پایهٔ توسعه نیست. سه مرجع دیگر (مستندات Meta، پروژهٔ MihomoIndustrial و سورس Mihomo) مستقل و بدون ادغام یا تغییر نگهداری می‌شوند.

این سند تضمین نمی‌کند که نسخهٔ بعدی بدون آزمایش روی Android/Termux یا با هر نسخهٔ جدید Mihomo صددرصد سازگار خواهد بود. سند، منطق و قرارداد را حفظ می‌کند؛ اجرای واقعی باید دوباره آزموده شود.

## 2) مأموریت عملکردی اسکریپت

اسکریپت یک سازندهٔ پیکربندی Mihomo برای Termux/Android است که:

1. ورودی‌های پروکسی را از متن، URI، Base64، JSON و YAML دریافت می‌کند.
2. انواع پروکسی شناخته‌شده را به ساختار داخلی نرمال‌شده تبدیل می‌کند.
3. نودها را از نظر فیلدهای ضروری و سازگاری پایه بررسی می‌کند.
4. برای هر نود، از طریق فرایند ایزولهٔ Mihomo تلاش می‌کند IP خروجی واقعی (Egress IP) را اندازه‌گیری کند.
5. سلامت اتصال و GeoIP را از شواهد جداگانه استخراج می‌کند؛ IP سرور، نام نود، پرچم منبع، ASN یا حدس، مبنای تعیین کشور نیست.
6. چهار گروه ثابت و مستقل می‌سازد: `Select ⚖️`، `🔁 Fallback`، `🌐 Unknown Country` و `⚡ Direct`.
7. درون هر گروه پروکسی، هر Egress IP را حداکثر یک بار می‌پذیرد؛ این محدودیت، حذف سراسری نود از موجودی نیست.
8. قوانین مسیریابی، DNS/TUN/Listener/Provider و بخش‌های شناخته‌شدهٔ پیکربندی را در صورت وجود دادهٔ منبع حفظ/نرمال می‌کند.
9. YAML و معنای پیکربندی را اعتبارسنجی می‌کند و خروجی را با نوشتن اتمیک ذخیره می‌کند.
10. گزارش ممیزی، سلامت، شواهد Egress و قابلیت‌های وب‌پنل/کنترلر محلی را فراهم می‌کند.

## 3) قرارداد قطعی چهار گروه

ترتیب خروجی ثابت است و کلید گروه نمی‌تواند این چهار گروه اجباری را حذف کند:

| ترتیب | نام | نوع Mihomo | شرط ورود |
|---|---|---|---|
| 1 | `Select ⚖️` | `select` | نود سالم + Egress IP عمومیِ اندازه‌گیری‌شده + کشور حل‌شده و معتبر |
| 2 | `🔁 Fallback` | `fallback` | نود سالم + Egress IP عمومیِ اندازه‌گیری‌شده؛ کشور می‌تواند معلوم یا نامعلوم باشد |
| 3 | `🌐 Unknown Country` | `select` | نود سالم + Egress IP اندازه‌گیری‌شده + کشور حل‌نشده/فاقد شواهد معتبر |
| 4 | `⚡ Direct` | `select` | فقط عضو داخلی `DIRECT`؛ بدون نود پروکسی |

### 3.1 استقلال گروه‌ها

- هر گروه از کل موجودی نودها و شرط مستقل خودش ساخته می‌شود.
- هیچ گروهی از اعضای گروه دیگر کپی یا مشتق نمی‌شود.
- اگر یک Egress IP در Select انتخاب شد، این موضوع به‌تنهایی مانع حضور همان Egress در Fallback نیست؛ هر گروه سیاست و مجموعهٔ `seen_egress` مستقل دارد.
- حذف یک نود از یک گروه، نود را از موجودی خام یا سایر گروه‌ها حذف نمی‌کند.
- `DIRECT` فقط در گروه Direct قرار می‌گیرد؛ گروه Direct دقیقاً `proxies: [DIRECT]` دارد.
- اگر گروه پروکسی عضو معتبر نداشته باشد، `REJECT` به‌عنوان عضو جایگزین امن قرار می‌گیرد؛ این placeholder نباید به‌عنوان پروکسی سالم گزارش شود.

### 3.2 یکتایی

کلید یکتایی عضویت گروه، **IP خروجی واقعی اندازه‌گیری‌شده** است؛ نه نام، پرچم، کشور نمایشی، IP سرور، پورت، پروتکل یا ASN. در هر گروه، اولین نود از بین نودهای رتبه‌بندی‌شده برای هر Egress IP نگه داشته می‌شود. در تابع انتخاب، تأخیر اندازه‌گیری‌شده اولویت دارد و ترتیب ورودی در تساوی نقش tie-breaker دارد.

اگر Egress IP اندازه‌گیری نشود، یکتایی قابل اثبات نیست؛ بنابراین چنین نودی نباید به Select/Fallback/Unknown راه یابد. این سیاست نباید با حذف نود از inventory اشتباه گرفته شود.

## 4) زنجیرهٔ اثبات Egress و سلامت

### 4.1 اندازه‌گیری از مسیر واقعی پروکسی

- برای هر نود، پیکربندی موقت Mihomo ساخته و با باینری محلی اجرا می‌شود.
- پیکربندی آزمایشی در صورت نیاز زنجیرهٔ `dialer-proxy` را بازسازی می‌کند تا نودهای وابسته از مسیر صحیح آزمایش شوند.
- یک فرایند Mihomo جداگانه و پورت محلی آزاد برای آزمایش استفاده می‌شود؛ چرخهٔ ایجاد، آماده‌سازی، درخواست و خاتمهٔ فرایند باید پاک‌سازی شود.
- درخواست IP عمومی از چند سرویس مستقل IPv4 یا IPv6 انجام می‌شود.
- حد نصاب فعلی `EGRESS_PROBE_QUORUM = 2` از سه سرویس echo است. تنها IP معتبر و مورد توافق به‌عنوان Egress ثبت می‌شود.
- پاسخ‌های IP باید با `ipaddress` تجزیه شوند و عمومی/Global باشند؛ IP خصوصی، رزروشده یا نامعتبر Egress عمومی محسوب نمی‌شود.
- آزمون سلامت از endpointهای Generate-204 مجزا از endpointهای تشخیص IP انجام می‌شود. دریافت IP به‌تنهایی معادل سالم بودن کامل مسیر نیست.

### 4.2 پارامترهای مهم فعلی

- `EGRESS_PROBE_ENABLED = True`
- `EGRESS_PROBE_WORKERS = 4`
- `EGRESS_PROBE_START_TIMEOUT = 12s`
- `EGRESS_PROBE_REQUEST_TIMEOUT = 6s`
- `EGRESS_PROBE_CONFIG_TEST_TIMEOUT = 20s`
- `EGRESS_PROBE_QUORUM = 2`
- IPv4 echo: `api4.ipify.org`, `ipv4.icanhazip.com`, `checkip.amazonaws.com`
- IPv6 echo: `api6.ipify.org`, `ipv6.icanhazip.com`, `v6.ident.me`
- Health: `gstatic generate_204`, `cp.cloudflare.com/generate_204`, `google.com/generate_204`

### 4.3 زنجیرهٔ شواهد و وضعیت‌ها

اطلاعات هر نود در رکورد Egress نگهداری می‌شود؛ از جمله IP خروجی، خانوادهٔ IP، منابع echo، زمان/تأخیر، وضعیت سلامت و اطلاعات GeoIP. رکوردها با fingerprint نود در حافظه نگاشت می‌شوند و برای جلوگیری از تداخل هم‌زمانی قفل دارند. گزارش ممیزی Egress در `egress_audit.json` نوشته می‌شود.

معنای وضعیت‌ها:
- **Egress verified:** IP عمومی واقعی از مسیر proxy و با حد نصاب پاسخ‌ها اندازه‌گیری شده است.
- **Healthy:** آزمون‌های سلامت مسیر موفق شده‌اند.
- **Country known:** کشور با دادهٔ GeoIP معتبر به IP خروجی اندازه‌گیری‌شده وصل شده است.
- **Unknown Country:** Egress معتبر وجود دارد، اما کشور از شواهد معتبر به دست نیامده است.
- **Egress unverified:** IP خروجی اندازه‌گیری نشده؛ این وضعیت نباید با Unknown Country یکی گرفته شود.

خطای سرویس GeoIP، timeout یا rate limit به‌تنهایی سلامت پروکسی را باطل نمی‌کند. GeoIP و Health دو محور مجزا هستند.

## 5) سیاست GeoIP

### 5.1 منبع معتبر

فقط Egress IP اندازه‌گیری‌شده به GeoIP داده می‌شود. اسکریپت ابتدا پایگاه محلی MMDB را بررسی می‌کند؛ مسیرهای اصلی شامل:

- `/storage/emulated/0/Download/almasi98/`
- زیرپوشهٔ `geo/` در همان مسیر
- `$HOME/MihomoIndustrial/geo/`
- `$HOME/MihomoIndustrial/assets/`
- مسیر صریح `MIHOMO_COUNTRY_MMDB` در صورت تنظیم

ترتیب پایگاه‌ها در کد مشخص شده و شامل `GeoLite2-City.mmdb`, `City.mmdb`, `GeoLite2-Country.mmdb`, `Country-without-asn.mmdb`, `country.mmdb`, `country-lite.mmdb` است.

**پسوندها قابل‌جایگزین نیستند:** `.mmdb` را نباید با `.db`، `.dat` یا `.csv` یکی فرض کرد. کد فقط reader سازگار MMDB را برای این مرحله باز می‌کند (`maxminddb` و در حالت جایگزین `geoip2`).

### 5.2 آنلاین به‌عنوان fallback اختیاری

اگر MMDB محلی نتیجه ندهد، دو سرویس آنلاین فعلی بررسی می‌شوند: `ipwho.is` و `ipapi.co`. کشور فقط وقتی پذیرفته می‌شود که کد ISO دوحرفی و نام کشور معتبر باشد و پاسخ‌های موجود دربارهٔ کد کشور اختلاف نداشته باشند. اگر دو سرویس کشور متفاوت بدهند، کشور Unknown می‌ماند.

Region و City سخت‌گیرانه‌ترند: در حالت چند پاسخ، تنها وقتی نگه داشته می‌شوند که پاسخ‌ها مقدار غیرخالی و یکسان داشته باشند. شهر/منطقه از یک پاسخ نامطمئن جعل نمی‌شود.

خطای 429، timeout، قطع اینترنت یا خطای یک provider به معنی خرابی نود نیست. Cache درون‌اجرایی بر اساس IP استفاده می‌شود؛ cache منبع حقیقت دائمی یا مجوز برچسب‌گذاری حدسی نیست.

### 5.3 نام و پرچم

پس از اندازه‌گیری و تصمیم GeoIP، نام نمایشی با کشور/منطقه/شهر و Egress IP تزئین می‌شود. اگر کشور معلوم نباشد، برچسب `🌐 Unknown Country | EGRESS <IP>` می‌آید؛ اگر خود Egress نامعلوم باشد، `🌐 Egress Unverified`. پرچم از کد معتبر کشور ISO ساخته می‌شود. برچسب کشور قبلیِ موجود در نام ورودی حذف/نادیده گرفته می‌شود و مبنای تصمیم نیست.

## 6) ورودی و نرمال‌سازی پروکسی

فرمت‌های ورودی: URI، Base64، JSON، YAML و متن ترکیبی/ساختاریافته. کد ابتدا ورودی را تشخیص/باز می‌کند، نودها را به مدل dict داخلی تبدیل می‌کند، فیلدهای مشترک را canonical می‌کند، fingerprint می‌سازد، سپس اعتبارسنجی و یکتاسازی نام را اجرا می‌کند.

Parserهای مشخص در فایل:
- `parse_vmess`, `parse_vless`, `parse_trojan`
- `parse_ss`, `parse_ssr`
- `parse_hysteria`, `parse_tuic`, `parse_http_socks`, `parse_anytls`
- `parse_uri`, `parse_node_dict`, `walk_structured`, `parse_structured`, `parse_all`

انواع پشتیبانی‌شدهٔ اعلام‌شده در `SUPPORTED_TYPES`: VLESS, VMess, Trojan, SS, SSR, Hysteria/Hysteria2/Hy2, TUIC, HTTP, SOCKS/SOCKS5, WireGuard, AnyTLS, Snell, Mieru, Sudoku, ShadowQUIC, TrustTunnel, EasyTier, Tailscale, SSH, MASQUE, ZeroTier و OpenVPN. پشتیبانی در سطح parser/ساختار باید از پشتیبانی runtime نسخهٔ باینری Mihomo تفکیک شود؛ هر نوع باید با نسخهٔ core واقعی اعتبارسنجی شود.

`validate_node()` نوع، server/port و فیلدهای ضروری شناخته‌شده را بررسی می‌کند؛ برای نمونه UUID در VLESS/VMess، password در Trojan، cipher/password در SS/SSR، token یا UUID+password در TUIC، auth در Hysteria، password در Hysteria2/AnyTLS و PSK در Snell.

## 7) ساخت پیکربندی و حفظ تنظیمات

سازندهٔ config از `build_config()` و نرمال‌سازهای مستقل برای DNS، TUN، listeners، experimental و providerها استفاده می‌کند. `PRESERVE_TOP_LEVEL` فهرست بزرگی از کلیدهای Mihomo را که دادهٔ منبع برایشان وجود دارد مشخص می‌کند. سیاست کلی این است که بخش غایب جعل نشود و بخش‌های موجودِ شناخته‌شده تا حد ممکن حفظ/نرمال شوند.

قواعد Direct فعلی برای دامنه‌های محلی/ایرانی و شبکه‌های private/local و GEOIP ایران به گروه `⚡ Direct` می‌روند. قاعدهٔ نهایی MATCH به Select یا در صورت خالی بودن Select به Fallback مستقل می‌رود؛ این fallback در انتخاب مقصد routing نباید باعث کپی اعضای Fallback به Select یا برعکس شود.

تنظیمات health group:
- URL: `https://www.gstatic.com/generate_204`
- interval: `300`
- timeout: `5000 ms`
- lazy: `true`

## 8) اعتبارسنجی و ایمنی نوشتن خروجی

اعتبارسنجی چندلایه است:
1. ساختار YAML و نوع داده‌ها.
2. بررسی فیلدهای semantic پروکسی.
3. بررسی ارجاع اعضای گروه و مقصد Ruleها.
4. بررسی DNS/TUN/listener/provider و بخش‌های اصلی.
5. `validate_config_ultimate()` برای invariants سخت‌گیرانه.
6. `enforce_manual_select_invariants()` برای قرارداد گروه‌ها و مسیر دستی.
7. در صورت وجود core، اجرای تست native Mihomo با فایل موقت.

خروجی نهایی با `atomic_write()` و commit تراکنشی نوشته می‌شود؛ در صورت شکست validation/commit، مسیر rollback برای جلوگیری از جایگزینی خروجی سالم با فایل ناقص وجود دارد. مسیرهای خروجی و نام امن از توابع `output_path()` و `output_path_ultimate()` گرفته می‌شوند. قابلیت backup/change-report/audit-log با پرچم‌ها قابل فعال‌سازی است و در تنظیمات فعلی برخی خاموش‌اند.

## 9) موتورهای نرم‌افزاری درون فایل

در بخش توسعهٔ تکمیلی فایل، کلاس‌های زیر وجود دارند:

- `GroupEngine`: فهرست، ایجاد و حذف گروه‌ها.
- `FilterEngine`: فیلتر موجودی بر اساس پروتکل/شرط‌ها.
- `RuleEngine`: ممیزی قواعد و مقصدهای ارجاع‌شده.
- `HealthEngine`: گزارش سلامت ساختاری و ذخیرهٔ گزارش.
- `ValidationEngine`: یافتن core و اعتبارسنجی فایل با Mihomo.
- `TransactionEngine`: commit اتمیک و اعتبارسنجی‌شدهٔ متن.
- `ConfigAuditEngine`: بررسی بخش‌ها و سازگاری ساختار پیکربندی.
- `EngineOrchestrator`: هماهنگ‌سازی auditها و تولید گزارش‌های بدون secret.

این کلاس‌ها در همان فایل واحد قرار دارند؛ این build یک بستهٔ 16 ماژول Python نیست. برای بازسازی دقیق این نسخه، فایل واحد کامل مهم‌ترین مرجع اجرایی است و سند حاضر نقش قرارداد/نقشهٔ معماری را دارد.

## 10) وب‌پنل و اتصال کنترلر

فایل شامل وب‌پنل محلی مبتنی بر `ThreadingHTTPServer` و مسیرهای کنترلر Mihomo محلی است. ادغام کنترلر به‌صورت اختیاری است و تنظیمات مهم آن با `ENABLE_CONTROLLER_PINNED_GROUP`, `ENABLE_CONTROLLER_LIVE_FILTER`, `CONTROLLER_API_URL`, secret و timeout کنترل می‌شود. حالت‌های live-filter و pinned-group در تنظیمات فعلی پیش‌فرض خاموش‌اند. فعال‌سازی آن‌ها باید با آدرس/secret واقعی کاربر و با توجه به سطح دسترسی کنترلر انجام شود؛ secret نباید وارد گزارش‌ها شود.

گزارش‌ها در مسیر پایهٔ برنامه و زیرپوشهٔ `reports/` قرار می‌گیرند. گزارش audit/health نباید حاوی UUID، password، private key یا controller secret باشد.

## 11) تنظیمات و مسیرهای فعلی مهم

- `BASE_DIR = /storage/emulated/0/Download/Akbar98`
- `INPUT_PATH = BASE_DIR / input.txt`
- `DOWNLOAD_DIR = /storage/emulated/0/Download`
- مسیر پایگاه محلی GeoIP: `/storage/emulated/0/Download/almasi98`
- گزارش Egress: `BASE_DIR / egress_audit.json`
- باینری قابل override با environment variable: `MIHOMO_BINARY`
- تعداد نود ورودی حداکثر: `MAX_NODES = 10000`
- حداکثر ورودی: `MAX_INPUT_BYTES = 25 MiB`
- حداکثر provider: `MAX_PROVIDER_SIZE = 100 MiB`

مسیرها و environment variableها در زمان انتقال به دستگاه دیگر باید بازبینی شوند؛ تغییر مسیر نباید سیاست Egress/GeoIP یا قرارداد گروه‌ها را تغییر دهد.

## 12) CLI و آزمون‌های داخلی

سوئیچ‌های آزمون/ممیزی که در انتهای فایل ثبت شده‌اند:
- `--all-selftests`
- `--endpoint-dedupe-selftest`
- `--egress-groups-selftest`
- `--egress-probe-selftest`
- `--engines-selftest`
- `--expansion-selftest`
- `--deep-expansion-selftest`
- `--egress-helpers-selftest`
- `--audit-config <path>`
- `--web-panel` / `web-panel` / `--panel`

فرمان آزمون جامع:

```bash
python king_egress_final.py --all-selftests
```

### نتیجهٔ آزمون ثبت‌شده هنگام ساخت این بسته

در محیط فعلی، فرمان بالا اجرا شد و موارد زیر PASS گزارش شدند:
- endpoint dedupe و برچسب endpoint
- قرارداد چهار گروه مستقل
- predicateهای Select/Fallback/Unknown
- یکتایی Egress در هر گروه و استقلال بین گروه‌ها
- Direct و routing محلی
- parsing IP عمومی و تولید پرچم
- رد spoof کشور در نام منبع و تزئین نام مبتنی بر Egress
- چرخهٔ آفلاین fake Mihomo، quorum، health، GeoIP و dialer chain
- شش موتور کمکی
- expansion، section audit، routing references، secret-free reports و transaction rollback

**حد آزمون:** این آزمون‌ها تست داخلی/آفلاین هستند. fake core در self-test، اتصال واقعی به سرورهای پروکسی یا موفقیت واقعی باینری Android را ثابت نمی‌کند. موفقیت واقعی Egress و GeoIP باید در Termux روی دستگاه و شبکهٔ کاربر آزمایش شود. باینری Android ARM64 را نباید با اجرای محیط Linux x86_64 یکی دانست.

## 13) نقشهٔ توابع و بخش‌های کلیدی

| محدوده | اجزای مهم | نقش |
|---|---|---|
| پارس/نرمال‌سازی | `parse_*`, `normalize_common`, `fingerprint`, `make_node` | تبدیل ورودی به نود استاندارد |
| یکتاسازی اولیه | `dedupe`, `unique_names`, `dedupe_by_resolved_endpoint_ip` | رفع تکرار ورودی/نام؛ این منطق جایگزین یکتایی Egress گروه نیست |
| اعتبارسنجی نود | `validate_node` | کنترل فیلدهای لازم |
| YAML | `yaml_dump`, `validate_yaml_text` | سریال‌سازی و صحت syntax |
| GeoIP | `_open_local_mmdb`, `_local_mmdb_lookup`, `_geoip_ip` | GeoIP محلی و سپس آنلاین |
| Core discovery | `_find_mihomo_binary`, `_free_local_port` | یافتن core و پورت آزمایش |
| Egress probe | `_collect_probe_chain`, `_make_probe_config`, `_request_via_local_mihomo`, `_public_ip_from_body`, `_probe_node_egress`, `_probe_all_nodes` | اندازه‌گیری Egress/سلامت |
| شواهد/نام | `_egress_result_for_node`, `_write_egress_audit`, `_decorate_node_names` | ثبت evidence و برچسب صحیح |
| گروه‌ها | `_unique_group_list`, `_build_groups_with_switches`, `build_groups`, `_active_default_group` | چهار گروه مستقل و fallback routing |
| Config | `build_config`, `validate_config`, `validate_config_ultimate` | تولید و کنترل پیکربندی |
| ذخیره | `atomic_write`, `_commit_validated_output` | نوشتن ایمن/rollback |
| اجرای برنامه | `main`, `start_web_panel` | CLI و پنل |
| موتورهای کمکی | کلاس‌های بخش 9 | فیلتر، گروه، rule، health، validation، transaction، audit |

## 14) روش بازسازی اگر اسکریپت یا Core از دست رفت

### حالت A — اسکریپت حذف یا خراب شده

1. از Library پوشهٔ `MIHOMO-4-CORE` را با همین نام پیدا کن.
2. `references/01_king_egress_final.py` را از نسخهٔ TAR یا فایل مستقل Library بازیابی کن.
3. SHA-256 آن را با `SHA256SUMS.txt` تطبیق بده.
4. `python -m py_compile king_egress_final.py` را اجرا کن.
5. `python king_egress_final.py --all-selftests` را اجرا کن.
6. قبل از هر اصلاح، این سند و گزارش تست‌های کاربر را بخوان؛ تنها تغییرات درخواستی را اعمال کن و نسخهٔ قبلی را نگه دار.

### حالت B — باینری Mihomo حذف یا به‌روزرسانی شده

1. نسخهٔ core را از مرجع مستقل `04_Mihomo_SOURCE_ENGINE_20261116_021146.zip` یا باینری همراه پروژهٔ اصلی بازیابی/ساخت کن.
2. معماری دستگاه را کنترل کن؛ Termux Android ARM64 به باینری سازگار Android ARM64 نیاز دارد.
3. `MIHOMO_BINARY` را برای مسیر جدید تنظیم کن یا core را در مسیرهای کشف‌شده قرار بده.
4. ابتدا `mihomo -v` و `mihomo -t -f <temporary-config>` را روی خود دستگاه بررسی کن.
5. سپس self-test داخلی و بعد تست عملی با نودهای نمونه را اجرا کن.
6. اگر نسخهٔ Mihomo تغییر کرده، تمام protocolها، گزینه‌های proxy، DNS/TUN/listeners/providers و قوانین را با مستندات نسخهٔ جدید تطبیق بده؛ فقط به موفقیت parser اکتفا نکن.

### حالت C — GeoIP database حذف/به‌روزرسانی شده

1. فقط MMDB معتبر و سازگار را در مسیرهای مستند قرار بده یا `MIHOMO_COUNTRY_MMDB` را تنظیم کن.
2. `.dat` و `.db` را به‌جای MMDB معرفی نکن.
3. نتیجهٔ Egress IP را جدا از نتیجهٔ GeoIP ثبت کن.
4. اگر GeoIP در دسترس نیست، کشور Unknown بماند؛ سلامت نود را به‌خاطر GeoIP ناموفق خراب نکن.

### حالت D — بازنویسی/توسعهٔ نسخهٔ جدید

1. ابتدا چهار گروه و قرارداد استقلال/یکتایی را به تست‌های واحد تبدیل کن.
2. بعد parser و normalizer را از ورودی‌های نمونه بازسازی کن.
3. Egress probe را مستقل از GeoIP بساز و تست کن.
4. GeoIP را فقط روی Egress تأییدشده سوار کن.
5. گروه‌ها را از inventory خام، با predicate مستقل بساز.
6. config/rules/validators/atomic transaction را اضافه کن.
7. گزارش‌های بدون secret و وب‌پنل/کنترلر را در مرحلهٔ بعد فعال کن.
8. هر مرحله باید قبل از ادغام مرحلهٔ بعد آزمون شود.

## 15) مواردی که نباید در بازسازی تغییر کنند مگر با درخواست صریح

- `king_egress_final.py` تنها مبنای فعلی است؛ `king.py` قدیمی فقط مرجع تاریخی/کمکی است.
- چهار گروه و ترتیب آن‌ها ثابت است.
- Egress واقعی، نه IP سرور، مبنای کشور و یکتایی است.
- گروه‌ها مستقل‌اند؛ dedupe سراسری ممنوع است.
- Unknown Country فقط برای Egress تأییدشده با کشور نامعلوم است؛ Egress نامعلوم وضعیت جداست.
- خطای GeoIP نباید به‌عنوان خرابی پروکسی تفسیر شود.
- منابع اصلی چهارگانه نباید ناخواسته merge یا بازنویسی شوند.
- تغییرات باید کوچک، قابل ممیزی و با حفظ منطق موجود باشند.

## 16) مرزهای دانسته‌ها و کارهای نیازمند تأیید

- self-test آفلاین جایگزین تست شبکهٔ واقعی نیست.
- GeoIP کشور/شهر تخمینیِ سطح IP است و موقعیت خیابان/آدرس دقیق را تعیین نمی‌کند.
- پشتیبانی parser برای یک پروتکل لزوماً به معنی پشتیبانی آن در باینری نصب‌شده نیست.
- برخی قابلیت‌های Controller/Web Panel اختیاری‌اند و در تنظیمات پیش‌فرض غیرفعال هستند.
- قبل از هر انتشار جدید، نام فایل، نسخه، SHA-256، py_compile، all-selftests، آزمون native core و تست Termux باید جداگانه ثبت شوند.

---

**اصل نهایی:** برای بازیابی سریع، همواره این سه مورد را کنار هم نگه دار: (1) سورس کامل `king_egress_final.py`، (2) همین پروندهٔ بازسازی، (3) سورس/باینری سازگار Mihomo به‌همراه مستندات نسخه. هیچ‌کدام به‌تنهایی جای دو مورد دیگر را نمی‌گیرد.
