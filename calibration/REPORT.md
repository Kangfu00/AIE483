# ผลการสอบเทียบ AIE483 ขั้นที่ 1 ถึง 3

วันที่: 2026-11-28

สถานะ: ผมยังไม่แก้โค้ดใน `app/` แม้แต่บรรทัดเดียว ของที่เพิ่มรอบนี้คือโฟลเดอร์ `calibration/`

## 1. เฉลยที่ใช้

**Observatory API:** `https://observatory-api.mdn.mozilla.net/api/v2/analyze?host=...`

Mozilla ย้าย Observatory ไป MDN แล้ว path เดิมที่ `observatory.mozilla.org` ตอบ 404 ทุกเส้นทาง

API ตอบ 200 พร้อม `scan.grade`, `scan.score` ช่วง 0 ถึง 115 และ `tests` 12 รายการ แต่ละ test มีค่า `pass` เป็น true, false หรือ null ค่า null หมายถึงทดสอบไม่ได้
**ชุด canary:** `calibration/canary.py` เสิร์ฟ 8 profile ที่กำหนด header เองได้ ผมเขียนคำตอบที่ถูกต้องไว้ใน `PROFILES[x]["expected"]` ก่อนรัน

## 2. ผล canary

เครื่องมือตรงกับเฉลย 9 จาก 12 ข้อ

```
[FAIL] missing_permissions_and_coop  security_headers  expected=warn  actual=pass  score=85
[FAIL] missing_coop_only             security_headers  expected=warn  actual=pass  score=95
[FAIL] clickjacking_via_csp          clickjacking_defense expected=pass actual=warn score=80
```

สองเคสแรกเป็นบั๊กจริง ขาด header สองตัวและหนึ่งตัวตามลำดับ แต่รายงานว่า pass

เคสที่สามผมเขียนเฉลยผิดเอง `_check_clickjacking_defense` ที่ `checks.py:232` บังคับให้ต้องมีทั้ง `X-Frame-Options` และ CSP `frame-ancestors` ถึงจะ pass ข้อกำหนดนี้เข้มกว่ามาตรฐานเพราะเบราว์เซอร์รุ่นใหม่ใช้ `frame-ancestors` อย่างเดียวพอ ผมจึงจัดเป็นนโยบายที่เข้มกว่ามาตรฐาน

## 3. ผลเทียบกับ Observatory บนเว็บจริง 14 แห่ง

| check | agreement | ตีความ |
|---|---|---|
| security_headers | 12/14 | ใช้ได้ |
| clickjacking_defense | 11/14 | ใช้ได้ |
| cors_info_disclosure | 11/14 | ใช้ได้ |
| https_transport | 10/14 | พอใช้ |
| cookie_hygiene | 1/9 | ใช้ไม่ได้ |
| mixed_content_sri | 0/6 | ใช้ไม่ได้ |

### cookie_hygiene ใช้เป็นเฉลยไม่ได้

test `cookies` ของ Observatory ตรวจทุก cookie ว่ามี flag ครบหรือไม่ และคืน `pass: true` เมื่อผ่าน `cookie_hygiene` ของโปรเจกต์นี้คืน `info` เมื่อไม่เจอ cookie และคืน `fail` เมื่อ flag ขาด

กรณี `vercel.com` Observatory คืน `pass: true` เพราะ cookie ที่มันเห็นมี flag ครบ โปรเจกต์นี้คืน `fail` ด้วยคะแนน 25 เพราะเห็น cookie คนละชุด Observatory อ่านจาก HTTP response เดียว โปรเจกต์นี้อ่านผ่าน Playwright จึงเห็น cookie ที่ถูกตั้งระหว่างโหลด

ตัวเลข 1 จาก 9 เกิดจากสองตัววัดคนละอย่าง ผมจึงไม่ใช้คู่นี้เป็นเฉลย

### mixed_content_sri ใช้เป็นเฉลยไม่ได้

Observatory ไม่มี test สำหรับ mixed content เลย มีแต่ `subresource-integrity` และคืน null เมื่อหน้าไม่มี script ภายนอก ซึ่งเกิด 6 ใน 14 เคส

ตัวเลข 0 จาก 6 เกิดจาก mapping ที่ไม่สมมูล ผมจึงไม่ใช้คู่นี้เป็นเฉลย

### คู่ที่ใช้เป็นเฉลยได้

`security_headers`, `clickjacking_defense`, `cors_info_disclosure`, `https_transport`

การเทียบกับผู้ตรวจภายนอกใช้ได้เฉพาะคู่ที่วัดสิ่งเดียวกันจริง

## 4. ผลการทดลอง 5 ข้อ

### EXP1 กรอง info/error ออกจากตัวหาร

```
zero-division cases : 0
max score delta     : 5
pages changing grade: 0/5
```

คะแนนขยับไม่เกิน 5 และไม่มีเกรดเปลี่ยนใน 5 เคส ความเสี่ยงต่อความเทียบได้กับรายงานเก่าน้อยกว่าที่ผมคาด

### EXP2 จุดตัดสถานะ

```
T=100  W=70..80  ->  5/5  false-pass=0
T=99             ->  5/5  false-pass=0
T=96             ->  5/5  false-pass=0
T=95             ->  4/5  false-pass=1
T<=91            ->  4/5  false-pass=1
```

ต้อง T ตั้งแต่ 96 ขึ้นไปจึงตัด false-pass ได้หมด และไม่เพิ่ม false-fail เพราะเคสที่เฉลยเป็น pass ทุกเคสได้คะแนน 100 พอดี

### EXP3 สัญญาณว่าสังเกตได้หรือไม่

```
false pass today         : True    (fallback ให้ pass/100)
fixed by reusing pw flag : True    (กลายเป็น info เมื่อไม่มี Playwright)
breaks genuine pass case : False   (Playwright เห็นว่าไม่มี mixed content จึงยัง pass)
```

ใช้ `snapshot.playwright_used` ที่มีอยู่ได้เลย ไม่ต้องเพิ่มฟิลด์ ผลถูกทั้งสามเคส

### EXP4 นโยบาย private IP

```
option A (block RFC1918, allow loopback): demo works=True, closes RFC1918=True
option B (block ทั้งหมด)                : demo works=False
```

ผลทดลองเหลือทางเดียวที่ใช้ได้คือ A เพราะ B ทำให้ demo พัง หน้าจอยิงไปที่ `127.0.0.1` ตาม `app.js:160`

### EXP5 เวลาของ hop-by-hop redirect

```
follow_redirects median : 656.4 ms
manual hop-by-hop       : 581.9 ms
```

แบบ hop-by-hop ใช้เวลา 581.9 ms ส่วนแบบเดิม 656.4 ms เคสนี้ไม่มี redirect hop ทั้งสองแบบจึงยิง request เท่ากัน

## 5. SSRF ยืนยันด้วย canary

```
guard verdict on PUBLIC redirector URL: ALLOWED
final_url after recon: http://127.0.0.1:8123/secret
redirect_chain: ['http://127.0.0.1:8124/go', 'http://127.0.0.1:8123/secret']
did we reach the internal service? True
```

ผมสร้าง redirector ที่ชี้ไป internal service แล้ว `run_passive_recon` ตามไปถึงและได้ 200 ยืนยันว่าเป็นช่องโหว่จริง

## 6. สถานะของข้อสังเกต 6 ข้อ

| # | ข้อสังเกต | สถานะ | หลักฐาน |
|---|---|---|---|
| 1 | สถานะขัดแย้งกับคะแนน ให้ pass ที่ 85 และ 95 | พิสูจน์แล้ว | canary ไม่ตรง 2 จาก 12 และการไล่จุดตัด |
| 2 | สถานะ info ถูกถ่วงน้ำหนัก | พิสูจน์แล้ว ผลกระทบน้อย | EXP1 คะแนนขยับ 5 เกรดไม่เปลี่ยน |
| 3 | fallback ให้คะแนนสูงเกินจริง | พิสูจน์แล้ว | fallback pass 100 เทียบกับ fail 55 |
| 4 | execute/stream ไม่แจ้ง error | พิสูจน์แล้ว | จำลองให้พัง ได้ event ไม่ครบ |
| 5 | API key ในโหมด auto ถูกทิ้ง | พิสูจน์แล้ว | `openai_key` ว่างขณะผู้ใช้พิมพ์ key |
| 6 | รับ private IP และตาม redirect โดยไม่ตรวจซ้ำ | พิสูจน์แล้ว | canary เข้าถึงบริการภายในได้ |

ทั้ง 6 ข้อเป็นปัญหาจริง ไม่มีข้อใดถูกหักล้างด้วยการทดลอง

## 7. ทางเลือกที่ผมเสนอ

| # | ทางเลือก | ที่มา |
|---|---|---|
| 1 | ตัดสินสถานะจากคะแนนด้วย T=96 | EXP2 |
| 2 | กรอง info ออกหรือคงไว้ ผลกระทบน้อยมาก | EXP1 |
| 3 | ใช้ `playwright_used` เป็นสัญญาณ | EXP3 |
| 4 | บล็อก RFC1918 แล้วยกเว้น loopback | EXP4 |
| 5 | เปลี่ยนเป็น hop-by-hop | EXP5 |
| 6 | เพิ่ม event `error` ใน execute/stream | รูปแบบเดียวกับ canary SSRF |

## 8. คำถามที่ยังไม่ได้คำตอบ

1. T=96 รับได้หรือไม่ ถ้าเลือก T=100 จะเข้มกว่าแต่กันได้เฉพาะกรณีที่ header ครบทุกตัว
2. `cookie_hygiene` และ `mixed_content_sri` เทียบ Observatory ไม่ได้ จะให้สร้าง canary เพิ่มเพื่อทดสอบสองข้อนี้เองหรือปล่อยไว้

ผมยังไม่แก้ `app/`
