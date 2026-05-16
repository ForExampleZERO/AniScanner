# AniScanner

اسکنر مدرن شبکه برای ترموکس و داشبورد وب

AniScanner یک ابزار سبک مبتنی بر Python برای اسکن TCP / TLS / SNI با رابط وب زنده و مدرن است که برای ترموکس و لینوکس طراحی شده.

---

## قابلیت‌ها

- اسکن اتصال TCP
- پشتیبانی از UDP Probe
- تشخیص نسخه TLS
- بررسی SNI
- تشخیص CDN و Provider
- نمایش اطلاعات ASN
- داشبورد زنده مبتنی بر SSE
- نمایش لحظه‌ای نتایج اسکن
- رابط کاربری Dark مدرن
- سازگار با Termux

---

## اسکرین‌شات

<p align="center">
  <img src="static/img/preview.png" width="100%">
</p>

---

## نصب روی ترموکس

```bash
pkg update -y
pkg install python git -y

git clone https://github.com/ForExampleZERO/AniScanner.git

cd AniScanner

pip install -r requirements.txt

python app.py
```

سپس داخل مرورگر باز کنید:

```txt
http://127.0.0.1:5000
```

---

## ساختار پروژه

```txt
AniScanner/
├── scanner/
├── static/
│   ├── css/
│   ├── js/
│   ├── icons/
│   ├── img/
│   └── logo/
├── templates/
└── logs/
```

---

## تکنولوژی‌ها

- Python
- Flask
- AsyncIO
- HTML/CSS/JS
- SSE Streaming

---

## توضیحات

این پروژه صرفاً برای اهداف آموزشی، تست شبکه و تحلیل اتصال طراحی شده است.

---

## کامیونیتی

گروه تلگرام:  
https://t.me/OnlyNightx

کانال تلگرام:  
https://t.me/aniartx
