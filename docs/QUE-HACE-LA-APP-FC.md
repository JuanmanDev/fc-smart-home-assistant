# Qué hace la app FC Smart Home (Crystal) — informe combinado

Fecha: 2026-09-07. Combina (a) pruebas EN VIVO ejecutadas esta noche contra
los hosts reales + BLE + LAN, y (b) mapa estático exhaustivo del código RE.
Detalle de pruebas en vivo: ver `LIVE-PROBE-2026-09-07.md`.

---

## 0. Resumen en una frase

La app controla cerraduras Fingerchip/Fingercrystal por **3 canales**: nube
(`www.fcsmartlock.com:443` + SaaS `iot.qspms.cn`), **BLE local** (offline), y
**WiFi/LAN local** (CoAP/Alink UDP 5683). Stack Alibaba IoT (OpenAccount,
LinkVisual, SecurityGuard, React Native), empaquetado SecNeo.

---

## 1. Pruebas EN VIVO de esta noche (qué respondió AHORA)

| Canal | Prueba | Resultado |
|---|---|---|
| Nube producción `www.fcsmartlock.com/api/` | GET | **502** nginx (backend Spring Boot caído, igual que época APK) |
| Nube raíz `/` | GET | 302 → http (nginx vivo, sin web) |
| SaaS `iot.qspms.cn/api/app/login` | GET+POST | **692** openresty (gate de firma Alibaba VIVO, body vacío, **sin filtrar pistas** de firma) |
| Canal AWS `18.219.242.80:443` | GET | **timeout** (host caído/filtrado) |
| Image base `:8060/images/` | GET | 404 (puerto vivo, dir vacío) |
| 96 hosts adivinados `fingercrystal.com/yilock` | GET | **0** responden (host real = fcsmartlock, no fingercrystal) |
| **BLE** `ble_scan_live` broad 12s | scan | **0 dispositivos** (sin adaptador BT activo o cerradura fuera de rango) |
| **LAN** `lan_recon` broadcast + gateway | discovery | **0 dispositivos FC** en la red 192.168.2.x; gateway `.2.1` resetó la sonda CoAP |

**Conclusión:** sin credenciales firmadas ni cerradura en rango no se extrae
más en vivo. Para volverlo "real" hace falta **captura mitmproxy del app**
(sub-rutas REST + esquema de firma + login real) y/o **HCI snoop BLE**
(UUIDs + framing). Ambos en HARVEST.md.

---

## 2. Canal NUBE — hosts, endpoints, crypto

### Hosts (confirmados del APK)
- Producción: `www.fcsmartlock.com:443` (gateway + appSystem).
- Regiones us/eu/cn/ru → **todas al mismo host** (el selector de región hoy no
  cambia el host). Canales distintos reales: `intl-aws` (18.219.242.80),
  `test`, `test2`.
- SaaS PMS: `iot.qspms.cn` (vivo, gate 692).
- Imágenes (fotos de cara/avatar): `http://www.fcsmartlock.com:8060/images/`.

### Endpoints REST (candidatos, sin confirmar sub-rutas — SecNeo bloqueó extracción estática)
| Ruta | Método | Función |
|---|---|---|
| `/api/app/login` | POST | Login `{email,password,platform,appVersion}`; password→AES-hex si crypto on |
| `/api/app/token/refresh` | POST | Refresh token |
| `/api/app/device/list` | GET | Lista dispositivos |
| `/api/app/device/{id}/status` | GET | Estado (`devStatus` int con bitmask) |
| `/api/app/device/{id}/unlock` \| `/lock` \| `/open` | POST | Abrir / cerrar / latch |
| `/api/app/device/{id}/bell` \| `/beep` | POST | Timbre / localizar |
| `/api/app/lock/{id}/child-lock` | POST | Bloqueo infantil |
| `/api/app/lock/{id}/user/list\|add\|delete\|update` | GET/POST | Gestión usuarios (huella/pass/tarjeta/NFC) |
| `/api/app/lock/{id}/fingerprint/enroll` | POST | Alta de huella |
| `/api/app/lock/{id}/log/list` | GET | Historial de accesos (quién/cómo/cuándo) |
| `/api/app/ws`, MQTT `fc/smarthome:1883` | WS/MQTT | Push (deshabilitado por defecto) |

### Auth + crypto — **ROTO/VERIFICADO EN VIVO 2026-09-09** (ver `PROTOCOL-VERIFIED.md`)
- ~~`687bbcd7f666...` web key~~ → la clave REAL es **negociada por sesión** vía
  `/v2/secure/getSecurityKey` (RSA-1024). Ver `docs/PROTOCOL-VERIFIED.md`.
- El flujo completo (handshake RSA → loginPassword → API con clave negociada)
  está implementado y probado en `api/crypto.py` + `api/client.py`.

---

## 3. Canal BLE local (offline) — TODO hipótesis, pendiente captura HCI

- **UUIDs GATT (candidatos):** servicio `0000fe00-…`, write `0000fe01-…`,
  notify `0000fe02-…`. Magic `"FCFC"`.
- **Match de scan:** prefijos de nombre `FC/Yi/EL/DX/K3/DZ/SL`; modo broad
  matchea por UUID de servicio o nombre con `lock/fc/yi/safe`.
- **Auto-negociación:** si `fe01/fe02` no están, elige la primera característica
  escribible + primera notificable → los UUIDs son punto de partida, no mapa fijo.
- **Framing (hipótesis):** `FCFC | len(body) | body | XOR-checksum`, con
  `body = [cmd, seq] + payload`.
- **Opcodes (hipótesis):** PAIR 0x01, STATUS 0x03, UNLOCK 0x10, LOCK 0x11,
  LATCH 0x12, BEEP 0x13, STATUS_NOTIFY 0x20, EVENT 0x21.
- **Pairing (hipótesis):** envía PAIR con pair code (`"000000"` por defecto);
  modelo real de auth (pair code vs key derivada de cuenta) desconocido.

## 4. Canal LAN/WiFi (CoAP/Alink) — el local MÁS confirmado

- **UDP 5683** (CoAP RFC 7252). Servidores CoAP FC verificados vivos (CON/ACK,
  token echo, 4.04 en ruta desconocida, 2.00 en `/`).
- **Codec CoAP + cliente Alink RPC = completo y con tests.** Solo falta
  confirmar **productKey/deviceName** y los nombres de servicio.
- **Descubrimiento:** broadcast UDP 5683 `{"method":"discover"}`, + mDNS
  (`_alink._udp`, `_fcsmart._tcp`, `_hap._tcp`).
- **Topic Alink:** `/sys/{productKey}/{deviceName}/thing/service/{leaf}`.
- **Métodos (candidatos):** `thing.deviceInfo.get`, `thing.service.property.get`,
  `thing.service.unlock {code}`, `.lock`, `.beep`, `.latch`.
- **pk/dn** se obtiene del cloud device list o `fcctl lan-register`. Sin ellos → 4.04.
- **Guarda anti-falso-positivo:** cualquier dispositivo CoAP hace ping-ACK a una
  sonda "FCFC" de 4 bytes (lee "FC" como message-id). Por eso solo marca
  verificado si responde un JSON Alink real con pk/dn.

## 5. Pipeline de eventos (quién abrió / manipulación / puerta)

- **Activo hoy:** polling de delta de historial cada 30s (min 15s): login →
  device list → por dispositivo status + history(30). Deduplica por
  `(timestamp,type,user_id,method,id)`, dispara `fc_smarthome_event` en el bus HA.
- **Método (quién/cómo)** del int `type`: 0 pass, 1 huella, 2 tarjeta, 3 nfc,
  4 remoto, 5 llave, 6 cara, 9 app.
- **Tipo de evento** del bitmask `devStatus`: tamper → puerta-abierta-larga →
  puerta-abierta → cerrado → si no, desbloqueado.
- **BLE push** (STATUS_NOTIFY/EVENT) implementado pero es la ruta hipótesis
  pendiente de captura.

---

## 6. ⚠️ Hallazgos de SEGURIDAD (revisar al despertar)

1. **Credenciales reales commiteadas en claro** en `tools/prod_login_test.py`
   y `tools/gate_test.py` (teléfono, código país, password). El README apunta a
   **repo GitHub público** (`github.com/JuanmanDev/fc-smart-home-hacs`). Si esos
   ficheros están en el repo público, **tu cuenta FC queda expuesta**.
   → Acción: quitar los ficheros del repo, rotar la password, `git filter-repo`
   o rehacer el historial si ya se pusheó.
2. **El connector cloud desactiva validación TLS** (`CERT_NONE`,
   `check_hostname=False`, `SECLEVEL=0`) para TODO el tráfico de producción, no
   solo el descubrimiento. Justificado porque el server tiene cadena rota, pero
   elimina protección MITM. Aceptable para RE personal; no dejarlo en producción.

## 7. Siguientes pasos para hacerlo real (cuando despiertes)

1. **mitmproxy del app FC** (HARVEST Path A, 30-60 min): saca sub-rutas REST
   exactas, esquema de firma (`sign`/`nonce`/`timestamp` + algoritmo) y login
   real. Es lo ÚNICO que desbloquea el canal cloud.
2. **HCI snoop BLE** (Path B): UUIDs + framing reales del canal local BLE.
3. **Captura pk/dn** (Path C) para el canal LAN CoAP (ya casi listo).
4. Reintentar `www.fcsmartlock.com/api/` — hoy 502, puede recuperarse.
5. Limpiar credenciales del repo (punto 6.1) ANTES de más pushes.
