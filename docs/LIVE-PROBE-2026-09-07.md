# FC SmartHome — resultados de pruebas EN VIVO (2026-09-07, madrugada)

Pruebas ejecutadas contra los hosts reales + BLE local, sin credenciales
(recon inofensivo, solo GET/HEAD/POST vacío). Complementa `tools/HARVEST.md`.

## Cloud (hosts confirmados del APK, estado AHORA)

| Host | Prueba | Resultado | Lectura |
|---|---|---|---|
| `www.fcsmartlock.com/api/` | GET | **HTTP 502**, `nginx/1.13.12` | Backend Spring Boot SIGUE caído (igual que en época del APK). El `/api/*` existe pero el upstream no responde. |
| `www.fcsmartlock.com/` | GET | **HTTP 302** → `http://www.fcsmartlock.com/` | nginx vivo; redirige HTTPS→HTTP raíz (loop de nginx por defecto, sin app web). |
| `iot.qspms.cn/api/app/login` | GET y POST | **HTTP 692**, `openresty/1.19.9.1`, body vacío, sin cabeceras extra | SaaS **VIVO**. Gate de firma (Alibaba SecurityGuard) confirmado. NO filtra ninguna pista (`sign`/`nonce`/`timestamp`) en la respuesta → el esquema de firma solo se saca con captura mitmproxy del app real. |
| `18.219.242.80:443` (canal AWS) | GET | **timeout (000)** tras 12s | Host AWS no responde / firewall. Canal AWS caído o filtrado ahora. |
| `www.fcsmartlock.com:8060/images/` | GET | **HTTP 404**, `nginx/1.13.12` | Puerto de imágenes vivo; listado vacío (404 en el dir, pero el puerto sirve). |
| 11 hosts `*.fingercrystal.com/.cn`, `yilock.com`, `fcsmarthome.com` (probe_endpoints, 96 combos) | GET | **0 respondieron** | Esos hostnames adivinados NO existen. El host real es `fcsmartlock.com`, no `fingercrystal.com`. |

**Conclusión cloud:** sin credenciales no se extrae más. Para saber las
sub-rutas REST exactas, el payload de login y el esquema de firma
(`sign`/`nonce`/`timestamp` + algoritmo) hace falta **captura mitmproxy del
app real** (HARVEST Path A). El gate 692 está vivo y silencioso.

## BLE local

- `tools/ble_scan_live.py` (scan broad 12s, cualquier dispositivo) → **0 dispositivos encontrados**.
- Causa: el PC no tiene adaptador BT activo, o ninguna cerradura FC en rango.
- **No hay dato BLE en vivo posible desde este PC ahora.** Para el canal BLE
  local hace falta: adaptador BT cerca de la cerradura + captura HCI snoop
  (HARVEST Path B) para confirmar UUIDs GATT, `CMD_*` y el framing.

## Qué SÍ quedó mapeado (estático, del código RE)

Ver el informe del mapa exhaustivo (URLs/llamadas/crypto/BLE/CoAP) generado
aparte. Lo confirmado del APK (no necesita captura): host producción
`www.fcsmartlock.com:443`, SaaS `iot.qspms.cn`, canal AWS `18.219.242.80`,
image base `:8060/images/`, auth `token:<hex>`, AES-128-ECB PKCS7 key
`687bbcd7f666afbcc1c44e6c9e86987c`[:16], envelope `{"result":1}`, HTTP 672
(rate limit) / 692 (gate de firma).

## Siguiente paso para hacerlo "real" (cuando despiertes)

1. **mitmproxy del app** (30-60 min, HARVEST Path A) → sub-rutas REST + firma + login real. Es lo único que desbloquea el canal cloud.
2. **HCI snoop BLE** (HARVEST Path B) → UUIDs + framing del canal local BLE (funciona offline).
3. Reintentar `www.fcsmartlock.com/api/` — hoy da 502, puede volver.
