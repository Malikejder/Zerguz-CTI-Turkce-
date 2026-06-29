# 🛡️ ZERGUZ CTI

**ZERGUZ CTI**, terminal üzerinden çalışan, çok kaynaklı bir **Cyber Threat Intelligence (Siber Tehdit İstihbaratı)** aracıdır. Dosya, IP/host ve hash değerlerini; **ThreatFox**, **MalwareBazaar**, **Shodan**, **AbuseIPDB**, **Feodo Tracker**, **FireHOL** ve **CINS Score** gibi güvenilir tehdit istihbaratı kaynaklarına karşı sorgulayarak risk skoru üretir.

```
███████╗███████╗██████╗  ██████╗ ██╗   ██╗███████╗     ██████╗████████╗██╗
╚══███╔╝██╔════╝██╔══██╗██╔════╝ ██║   ██║╚══███╔╝    ██╔════╝╚══██╔══╝██║
  ███╔╝ █████╗  ██████╔╝██║  ███╗██║   ██║  ███╔╝     ██║        ██║   ██║
 ███╔╝  ██╔══╝  ██╔══██╗██║   ██║██║   ██║ ███╔╝      ██║        ██║   ██║
███████╗███████╗██║  ██║╚██████╔╝╚██████╔╝███████╗    ╚██████╗   ██║   ██║
╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝     ╚═════╝   ╚═╝   ╚═╝
```

---

## ✨ Özellikler

- **📄 Dosya Tarama** — Dosyanın MD5 / SHA1 / SHA256 hash'ini hesaplar; ThreatFox ve MalwareBazaar veritabanlarına karşı sorgular, ayrıca yerel sezgisel (heuristic) analiz uygular (tehlikeli uzantılar, çift uzantı, şüpheli dosya isimleri, gömülü şüpheli komutlar vb.).
- **🌐 IP / Host Tarama** — Hedef IP'yi veya hostname'i; ThreatFox, Shodan, AbuseIPDB ile birlikte Feodo Tracker, FireHOL Level-1 ve CINS Score kara listeleriyle karşılaştırır. Açık portlar, CVE zafiyetleri, ters DNS ve şüpheli hostname desenleri de kontrol edilir.
- **📁 Dizin Tarama** — Belirtilen dizindeki tüm dosyaları topluca tarar ve özet bir tehdit raporu çıkarır.
- **🔎 Hash Sorgulama** — Elinizde sadece bir MD5/SHA256 hash'i varsa, dosyaya ihtiyaç duymadan doğrudan ThreatFox ve MalwareBazaar üzerinde arama yapar.
- **🔄 Feed Önbellek Yönetimi** — Feodo / FireHOL / CINS gibi büyük IP listeleri 1 saatlik önbellekle (cache) tutulur, istenildiğinde elle temizlenebilir.
- **🎯 0–10 Arası Tehdit Skoru** — Tüm sonuçlar; TEMİZ, DÜŞÜK RİSK, ŞÜPHELİ, ORTA TEHDİT, YÜKSEK TEHDİT ve KRİTİK TEHDİT seviyelerinden birine eşlenir.
- **⌨️ Hem Menü Hem CLI Desteği** — İnteraktif menüden kullanılabildiği gibi, doğrudan komut satırı argümanlarıyla script/otomasyon içinde de çalıştırılabilir.
- **🎨 Renkli Terminal Arayüzü** — ANSI renkleri ve ilerleme çubuklarıyla okunabilir, takip edilebilir çıktı.

---

## ⚙️ Gereksinimler

- Python **3.8+**
- [`requests`](https://pypi.org/project/requests/) kütüphanesi

```bash
pip install requests
```

> `requests` yüklü değilse program yine çalışır ancak ağ üzerinden yapılan tüm sorgular (API çağrıları) devre dışı kalır; sadece yerel hash/heuristic analizleri çalışmaya devam eder.

---

## 📥 Kurulum

```bash
git clone https://github.com/Malikejder/ZERGUZ-CTI.git
cd ZERGUZ-CTI
pip install -r requirements.txt   # veya: pip install requests
python3 Zerguz-CTI.py
```

> Repoda `requirements.txt` yoksa tek satırlık `requests` paketini eklemeniz yeterlidir.

---

## 🔑 API Anahtarları

Bazı kaynaklar (ThreatFox, MalwareBazaar, Shodan, AbuseIPDB) **isteğe bağlı** API anahtarı kullanır; anahtar girilmezse araç çalışmaya devam eder ama bu kaynaklardan daha sınırlı/limitli veri alınır. Feodo, FireHOL ve CINS herhangi bir anahtar gerektirmeden çalışır.

Anahtarları üç farklı şekilde tanımlayabilirsiniz:

**1) Program içinden (Menü 6 — API Anahtarlarını Ayarla)**
```text
6 → API Anahtarlarını Ayarla
```

**2) Komut satırı argümanlarıyla**
```bash
python3 Zerguz-CTI.py --shodan-key XXXX --abuseipdb-key XXXX \
                       --threatfox-key XXXX --malwarebazaar-key XXXX
```

**3) Doğrudan koda yapıştırarak**
`Zerguz-CTI.py` dosyasının başındaki `API_KEYS` sözlüğünü düzenleyin:
```python
API_KEYS = {
    "shodan": "BURAYA_SHODAN_KEYINIZ",
    "abuseipdb": "BURAYA_ABUSEIPDB_KEYINIZ",
    "threatfox": "BURAYA_THREATFOX_KEYINIZ",
    "malwarebazaar": "BURAYA_MALWAREBAZAAR_KEYINIZ"
}
```

> ⚠️ **Önemli:** Eğer anahtarlarınızı doğrudan koda yazdıysanız, bu dosyayı **asla** halka açık bir GitHub deposuna anahtarlarla birlikte yüklemeyin. `.gitignore` kullanın veya anahtarları ortam değişkeni/CLI argümanı olarak girin.

Anahtarları ücretsiz almak için:

| Kaynak | Bağlantı |
|---|---|
| ThreatFox | https://threatfox.abuse.ch/api/ |
| MalwareBazaar | https://bazaar.abuse.ch/api/ |
| Shodan | https://account.shodan.io |
| AbuseIPDB | https://www.abuseipdb.com/api |

---

## 🚀 Kullanım

### İnteraktif Menü

Hiçbir argüman vermeden çalıştırdığınızda menü açılır:

```bash
python3 Zerguz-CTI.py
```

```
┌──────────────────────────────────────────────────┐
│  1  Dosya Tara      (ThreatFox + MalwareBazaar)   │
│  2  IP / Host Tara  (TF + Shodan + AbuseIPDB)     │
│  3  Dizin Tara      (Toplu)                       │
│  4  Hash Sorgula    (MD5 / SHA256)                │
│  5  Feed Guncelle                                 │
│  6  API Anahtarlarini Ayarla                      │
│  0  Cikis                                         │
└──────────────────────────────────────────────────┘
```

### Komut Satırı (CLI) Modu

Otomasyon, script ve hızlı sorgular için doğrudan parametre verebilirsiniz:

| Parametre | Açıklama |
|---|---|
| `-f`, `--file <yol>` | Tek bir dosyayı tarar |
| `-i`, `--ip <ip/host>` | IP adresi veya hostname tarar |
| `-d`, `--dir <yol>` | Dizini topluca tarar |
| `-H`, `--hash <hash>` | MD5 veya SHA256 hash sorgular |
| `--shodan-key <key>` | Shodan API anahtarı tanımlar |
| `--abuseipdb-key <key>` | AbuseIPDB API anahtarı tanımlar |
| `--threatfox-key <key>` | ThreatFox API anahtarı tanımlar |
| `--malwarebazaar-key <key>` | MalwareBazaar API anahtarı tanımlar |
| `--no-banner` | Açılış banner'ını gizler |

#### Örnekler

**Bir dosyayı tara:**
```bash
python3 Zerguz-CTI.py -f /home/user/indirilenler/setup.exe
```

**Bir IP adresini tara:**
```bash
python3 Zerguz-CTI.py -i 185.220.101.1
```

**Bir hostname'i tara:**
```bash
python3 Zerguz-CTI.py -i example.com
```

**Bir dizini topluca tara:**
```bash
python3 Zerguz-CTI.py -d /home/user/indirilenler
```

**Sadece hash ile sorgula (dosyaya ihtiyaç duymadan):**
```bash
python3 Zerguz-CTI.py -H 44d88612fea8a8f36de82e1278abb02f
```

**API anahtarlarıyla birlikte, banner olmadan çalıştır:**
```bash
python3 Zerguz-CTI.py -i 8.8.8.8 --shodan-key XXXX --abuseipdb-key XXXX --no-banner
```

---

## 📊 Tehdit Skoru Nasıl Hesaplanır?

Her tarama sonunda **0–10** arası bir skor üretilir:

| Skor | Seviye |
|---|---|
| 0 | ✅ TEMİZ |
| 1–2 | 🔵 DÜŞÜK RİSK |
| 3–4 | 🟡 ŞÜPHELİ |
| 5–6 | 🟠 ORTA TEHDİT |
| 7–8 | 🔴 YÜKSEK TEHDİT |
| 9–10 | ☠ KRİTİK TEHDİT |

Skor; canlı tehdit istihbaratı sonuçları (ThreatFox/MalwareBazaar eşleşmesi, kara liste eşleşmesi vb.) ile yerel sezgisel analizin (heuristic) en yükseğine göre belirlenir.

---

## ⚠️ Sorumluluk Reddi

Bu araç yalnızca **savunma amaçlı** siber güvenlik analizleri (kendi sistemlerinizi/ağınızı kontrol etmek, şüpheli dosyaları incelemek vb.) için geliştirilmiştir. Üçüncü taraf sistemleri izinsiz taramak yasalara aykırı olabilir; aracı yalnızca **yetkiniz olan** sistemler ve dosyalar üzerinde kullanın. Geliştirici, aracın kötüye kullanımından doğacak herhangi bir zarardan sorumlu tutulamaz.

---

## 🤝 Katkı

Hata bildirimleri, öneriler ve pull request'ler memnuniyetle karşılanır. Bir issue açmadan önce mevcut issue'ları kontrol etmeniz rica olunur.

