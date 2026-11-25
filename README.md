# AI Web Security Posture Agent (Prototype)

โปรโตไทป์เว็บแอปพลิเคชันสำหรับ **ตรวจประเมินความปลอดภัยเว็บไซต์เชิงป้องกันแบบ Passive / Read-Only** ตามแนวทาง OWASP โดยใช้ **Playwright + HTTP Client** ร่วมกับ **AI Agent** เพื่อวิเคราะห์จุดที่มีการป้องกันดีอยู่แล้ว แนะนำรายการตรวจสอบ ให้ผู้ใช้ติ๊กเลือกพร้อมจัดลำดับ แล้วรันตรวจสอบทีละข้อพร้อมสรุปรายงาน

> **ขอบเขตความปลอดภัย (Scope & Safety):**
> เครื่องมือนี้ออกแบบเพื่อการตรวจสอบเชิงป้องกันแบบ **Passive / Read-Only เท่านั้น** (ตรวจ Header, TLS/HTTPS, Cookie Flags, Mixed Content, SRI, Form & Link Hygiene, CORS Header และ `security.txt`) **ไม่มีการส่ง Payload โจมตี, ไม่ยิง Fuzzing/Brute-force และไม่ทำการเจาะระบบ**

---

## Workflow การทำงาน

1. **กรอก URL เป้าหมาย** (หรือเลือกปุ่ม Demo Sandbox ในเครื่อง)
2. **AI สำรวจเบื้องต้น (Passive Recon):** ใช้ Playwright + `httpx` อ่านข้อมูลหน้าเว็บแบบ Read-Only แล้วสรุปแยกเป็น:
   - **ส่วนที่มีการป้องกันดีอยู่แล้ว**
   - **ส่วนที่แนะนำให้ตรวจสอบเพิ่มเติม** (พร้อมระดับ Priority)
3. **ผู้ใช้ติ๊กเลือก & จัดลำดับ:** เลือกหัวข้อที่ต้องการและเลื่อนขึ้น/ลง หรือลากจัดลำดับได้ตามต้องการ แล้วกดตกลง
4. **รันตรวจตามลำดับแบบ Real-time (SSE):** แสดงความคืบหน้าทีละข้อตามลำดับที่ผู้ใช้กำหนด
5. **รายงานสรุป (Security Posture Report):** แสดงคะแนน (0–100), เกรด (`A`–`F`), บทสรุปผู้บริหารจาก AI, หลักฐานที่ตรวจพบ, ตัวอย่างการตั้งค่าเชิงป้องกัน และดาวน์โหลดเป็น **Markdown / JSON / พิมพ์ PDF** ได้

---

## โครงสร้างโปรเจกต์

```text
d:\AIE483\
├── app/
│   ├── main.py          # FastAPI APIs, SSE Streaming และเสิร์ฟหน้า Web UI
│   ├── config.py        # Settings และ URL validation
│   ├── models.py        # Pydantic schemas
│   ├── recon.py         # Passive reconnaissance engine (httpx + Playwright)
│   ├── checks.py        # 8 modular passive OWASP posture checks
│   ├── agent.py         # AI Agent (Offline Rule-based + Gemini / OpenAI / Ollama)
│   ├── demo.py          # Local Demo Sandbox (/demo/vulnerable-config, /demo/hardened)
│   ├── report.py        # Scoring, grading และ Markdown exporter
│   └── static/          # Web UI (index.html, styles.css, app.js)
├── tests/
│   ├── test_checks.py
│   └── test_agent_and_api.py
├── requirements.txt
└── .env.example
```

---

## วิธีติดตั้งและรันใช้งาน

### 1. สร้าง Virtual Environment และติดตั้ง Dependencies
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
playwright install chromium
```
*(หมายเหตุ: บน Windows หากยังไม่ได้ติดตั้ง Playwright Chromium เพิ่มเติม ระบบมี Fallback ไปยังเบราว์เซอร์ Chromium ในเครื่อง / Chrome / Edge อัตโนมัติ)*

### 2. (ทางเลือก) ตั้งค่า AI Provider
โปรโตไทป์ทำงานได้ทันทีในโหมด **Offline Rule-Based Agent** โดยไม่ต้องใช้ API Key  
หากต้องการให้ LLM จริงช่วยวิเคราะห์และสรุปรายงาน สามารถคัดลอก `.env.example` เป็น `.env` หรือกรอกผ่านหน้าเว็บได้:
- **Google Gemini API** (`GEMINI_API_KEY`)
- **OpenAI / Compatible API** (`OPENAI_API_KEY`)
- **Local Ollama** (`OLLAMA_BASE_URL`, `OLLAMA_MODEL`)

### 3. รันเว็บแอปพลิเคชัน
```powershell
.\.venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8000
```
จากนั้นเปิดเบราว์เซอร์ไปที่ `http://127.0.0.1:8000`

### 4. รันชุดทดสอบ (Pytest)
```powershell
.\.venv\Scripts\pytest.exe -v
```
