"""
SOC MALWARE FORENSICS LAB
Laboratorio de capacitación en análisis de malware (Streamlit).

Módulo 1: Triaje inicial e identificación (el DNI del archivo)
Módulo 2: Análisis estático y extracción de cadenas (strings)
Módulo 3: Simulador de Sysinternals (procesos y persistencia)
Módulo 4: Sandbox, clasificación por familia y reporte forense

SEGURIDAD DEL LABORATORIO
- La "muestra" NightCrow Stealer es TEXTO INERTE escrito dentro de este archivo.
  No contiene lógica funcional, nunca se guarda en disco y nunca se ejecuta.
- El usuario NO puede subir archivos: no hay file_uploader en ninguna parte.
- El dominio y la IP del C2 son reservados para documentación (RFC 2606 y RFC 5737),
  no existen en internet.
- La consulta a inteligencia de amenazas, el árbol de procesos y la sandbox son simulados.

Estructura del repositorio para Streamlit Cloud:
    app.py
    requirements.txt
    .streamlit/config.toml
    assets/
        sound2.mp4          (música de ambiente; la app usa solo su audio)
"""
import base64
import hashlib
import html
import os
import re
import time
from datetime import datetime

import streamlit as st
import streamlit.components.v1 as components
from fpdf import FPDF

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Música de ambiente: se busca el video que subiste a assets/ (se usa solo su audio).
BGM_CANDIDATOS = ["assets/sound2.mp4", "assets/Sound2.mp4", "assets/sound 2.mp4", "assets/Sound 2.mp4",
                  "assets/sound2.mp3"]
BGM_VOLUMEN_INICIAL = 2  # escala de 0 a 10

MODULES = [
    "Módulo 1 · Triaje e identificación",
    "Módulo 2 · Análisis estático (strings)",
    "Módulo 3 · Procesos y persistencia",
    "Módulo 4 · Sandbox y reporte forense",
]

st.set_page_config(
    page_title="SOC Malware Forensics Lab",
    page_icon="🧬",
    layout="wide",
)

# =========================================================
# ESTILO (terminal sobrio: gris oscuro + verde apagado, sin resplandor)
# =========================================================
st.markdown("""
<style>
:root {
    --bg: #0d1117; --panel: #161b22; --borde: #30363d;
    --verde: #3fb950; --verde-osc: #238636; --texto: #c9d1d9; --tenue: #8b949e;
    --ambar: #d29922; --rojo: #f85149; --azul: #58a6ff;
}
.stApp { background-color: var(--bg); color: var(--texto); }
[data-testid="stSidebar"] { background-color: #010409; border-right: 1px solid var(--borde); }

h1, h2, h3 {
    color: var(--verde) !important;
    font-family: 'Consolas', 'Courier New', monospace !important;
    text-shadow: none !important;
    letter-spacing: 0.5px;
}
h1 { font-size: 2rem !important; }

/* Etiquetas y textos */
[data-testid="stWidgetLabel"] p, .stApp label p { color: var(--texto) !important; }
[data-testid="stCaptionContainer"] { color: var(--tenue) !important; }

/* Barra superior de Streamlit */
header[data-testid="stHeader"], [data-testid="stHeader"] {
    background-color: var(--bg) !important;
    border-bottom: 1px solid var(--borde);
}
[data-testid="stToolbar"] *, [data-testid="stAppDeployButton"] *, [data-testid="stMainMenu"] * {
    color: var(--verde) !important;
}

/* Avisos (success / error / info / warning) siempre oscuros */
[data-testid="stAlert"], [data-testid="stAlert"] > div, [data-testid="stAlertContainer"] {
    background-color: var(--panel) !important;
    border-radius: 6px !important;
}
.stAlert:has([data-testid="stAlertContentSuccess"]) { border-left: 4px solid var(--verde) !important; }
.stAlert:has([data-testid="stAlertContentError"])   { border-left: 4px solid var(--rojo) !important; }
.stAlert:has([data-testid="stAlertContentInfo"])    { border-left: 4px solid var(--azul) !important; }
.stAlert:has([data-testid="stAlertContentWarning"]) { border-left: 4px solid var(--ambar) !important; }
[data-testid="stAlert"] *, [data-testid="stAlertContainer"] * { color: var(--texto) !important; }
[data-testid="stAlert"] strong { color: #ffffff !important; }

/* Expanders */
[data-testid="stExpander"] {
    background-color: var(--panel) !important;
    border: 1px solid var(--borde) !important; border-radius: 6px;
}
[data-testid="stExpander"] summary, [data-testid="stExpander"] summary p,
[data-testid="stExpander"] summary span {
    color: var(--texto) !important; font-weight: bold !important; opacity: 1 !important;
}
[data-testid="stExpander"] summary svg { fill: var(--verde) !important; color: var(--verde) !important; }

/* Botones */
.stButton > button, .stDownloadButton > button {
    background-color: var(--panel); color: var(--verde);
    border: 1px solid var(--verde); border-radius: 4px;
    font-family: 'Consolas', 'Courier New', monospace; font-weight: bold;
    transition: all 0.2s ease;
}
.stButton > button:hover:not(:disabled), .stDownloadButton > button:hover {
    background-color: var(--verde-osc); color: #ffffff; border-color: var(--verde-osc);
}
.stButton > button:disabled { opacity: 0.35; }
[data-testid="stSidebar"] .stButton > button { width: 100%; text-align: left; justify-content: flex-start; }

/* Tarjetas */
.lab-card {
    background: var(--panel); border: 1px solid var(--borde); border-radius: 6px;
    padding: 14px 18px; margin-bottom: 14px;
}
.lab-card.verde { border-left: 4px solid var(--verde); }
.lab-card.rojo  { border-left: 4px solid var(--rojo); }
.lab-card.ambar { border-left: 4px solid var(--ambar); }
.badge {
    display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 0.75rem;
    font-weight: bold; font-family: 'Consolas', monospace; letter-spacing: 0.5px;
}
.badge.ok   { background: rgba(63,185,80,.15);  color: var(--verde); border: 1px solid var(--verde); }
.badge.pend { background: rgba(139,148,158,.12); color: var(--tenue); border: 1px solid var(--borde); }
.badge.mal  { background: rgba(248,81,73,.15);  color: var(--rojo);  border: 1px solid var(--rojo); }
.badge.mis  { background: rgba(210,153,34,.15); color: var(--ambar); border: 1px solid var(--ambar); }

/* Misión */
.mision .mision-sub { color: var(--verde); font: bold 0.95rem 'Consolas', monospace; margin: 12px 0 4px 0; }
.mision ul { margin: 4px 0 0 18px; }
.mision li { margin-bottom: 2px; }

/* Pasos */
.paso { background: var(--panel); border: 1px solid var(--borde); border-radius: 6px;
        padding: 10px 16px; margin: 18px 0 10px 0; }
.paso.done { border-left: 4px solid var(--verde); }
.paso-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.paso-num { color: var(--bg); background: var(--verde); padding: 1px 8px; border-radius: 4px;
            font: bold 0.8rem 'Consolas', monospace; }
.paso-head b { color: #e6edf3; font-size: 1.02rem; }
.paso-head .badge { margin-left: auto; }
.paso-body p { margin: 6px 0 0 0; }
.paso-body .porque { color: var(--tenue); font-size: 0.92rem; }

/* Títulos con hotspot */
.titulo { display: flex; align-items: center; gap: 8px; margin: 12px 0 6px 0; }
.titulo h3 { margin: 0; padding: 0; font-size: 1.15rem !important; }

/* Hotspot "?" */
.hint { position: relative; display: inline-block; }
.hint summary {
    list-style: none; cursor: pointer; width: 20px; height: 20px; border-radius: 50%;
    background: var(--verde-osc); color: #ffffff; font: bold 13px 'Consolas', monospace;
    display: flex; align-items: center; justify-content: center;
    animation: hint-pulse 2.2s infinite;
}
.hint summary::-webkit-details-marker { display: none; }
.hint[open] summary { animation: none; background: var(--verde); }
.hint .tip {
    position: absolute; z-index: 9999; top: 28px; left: 0; width: 320px;
    background: var(--panel); border: 1px solid var(--verde); border-radius: 6px;
    padding: 12px; font: normal 0.85rem sans-serif; color: var(--texto);
}
.hint.r .tip { left: auto; right: 0; }
.hint .tip b { color: var(--verde); }
@keyframes hint-pulse {
    0%   { box-shadow: 0 0 0 0 rgba(63,185,80,.5); }
    70%  { box-shadow: 0 0 0 8px rgba(63,185,80,0); }
    100% { box-shadow: 0 0 0 0 rgba(63,185,80,0); }
}

/* Tablas del laboratorio */
.lab-table { width: 100%; border-collapse: collapse; font-family: 'Consolas', 'Courier New', monospace;
             font-size: 0.83rem; }
.lab-table th { background: #21262d; color: var(--verde); text-align: left; padding: 6px 8px;
                border-bottom: 1px solid var(--borde); }
.lab-wrap { width: 100%; overflow-x: auto; margin-bottom: 8px; }
.lab-table td { padding: 5px 8px; border-bottom: 1px solid #21262d; color: var(--texto);
                vertical-align: top; overflow-wrap: break-word; }
.lab-table tr.sus td { background: rgba(248,81,73,.10); color: #ffa198; }
.lab-table tr.muerto td { color: #6e7681; text-decoration: line-through; }
.lab-table tr.ok td { background: rgba(63,185,80,.08); }

/* Visor de cadenas */
.strings-box { background: #010409; border: 1px solid var(--borde); border-radius: 6px;
               padding: 10px 12px; max-height: 420px; overflow-y: auto;
               font: 0.82rem 'Consolas', 'Courier New', monospace; line-height: 1.55; }
.strings-box .off { color: #6e7681; margin-right: 10px; }
.strings-box .enc { color: #6e7681; margin-right: 10px; }
.leyenda span { display: inline-block; margin: 0 14px 6px 0; font: 0.8rem 'Consolas', monospace; }

/* Barra lateral: módulos bloqueados legibles */
[data-testid="stSidebar"] .stButton > button:disabled {
    opacity: 1 !important; color: #6e7681 !important; border-color: #30363d !important;
    background-color: #0d1117 !important; cursor: not-allowed;
}
[data-testid="stSidebar"] .stButton > button:disabled p { color: #6e7681 !important; }

/* Barra de progreso: fondo oscuro y relleno verde */
[data-testid="stProgress"] [role="progressbar"] > div,
.stProgress > div > div > div { background-color: #21262d !important; }
[data-testid="stProgress"] [role="progressbar"] > div > div,
.stProgress > div > div > div > div { background-color: var(--verde) !important; }
[data-testid="stProgress"] p { color: var(--texto) !important; }

/* Oculta el iframe técnico que bloquea la traducción */
[data-testid="stElementContainer"]:has(iframe[height="0"]),
.element-container:has(iframe[height="0"]) { display: none; }

/* Reproductor de música de ambiente: suena, pero no se ve */
.st-key-bgm { position: fixed !important; left: -9999px !important; width: 1px !important;
              height: 1px !important; overflow: hidden !important; opacity: 0 !important;
              pointer-events: none !important; }

/* Monitor en vivo */
.feed { background: #010409; border: 1px solid var(--borde); border-radius: 6px; padding: 8px 12px;
        max-height: 330px; overflow-y: auto; font: 0.8rem 'Consolas', 'Courier New', monospace;
        line-height: 1.6; }
.feed .nuevo { background: rgba(63,185,80,.12); }
.feed .t { color: #6e7681; margin-right: 8px; }
.feed .tag { display: inline-block; min-width: 74px; font-weight: bold; margin-right: 8px; }
.live-dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; background: var(--rojo);
            margin-right: 6px; animation: live 1s infinite; }
@keyframes live { 0%,100% { opacity: 1; } 50% { opacity: .25; } }

/* Botón flotante para avanzar de módulo */
.st-key-next_mod { position: fixed; bottom: 26px; right: 30px; z-index: 1000; width: auto !important; }
.st-key-next_mod button { animation: hint-pulse 2.2s infinite; background: var(--verde-osc) !important;
                          color: #ffffff !important; }
</style>
""", unsafe_allow_html=True)

# Evita que el navegador traduzca la página automáticamente. El traductor de Chrome
# modifica el texto por debajo de Streamlit y provoca el error "removeChild" y
# pantallas que dejan de actualizarse. La app ya está en español.
components.html("""
<script>
  const d = window.parent.document;
  d.documentElement.lang = "es";
  d.documentElement.setAttribute("translate", "no");
  d.documentElement.classList.add("notranslate");
  if (!d.querySelector('meta[name="google"]')) {
    const m = d.createElement("meta");
    m.name = "google"; m.content = "notranslate";
    d.head.appendChild(m);
  }
</script>
""", height=0)


# =========================================================
# MUESTRAS DEL LABORATORIO (texto inerte, nunca se ejecuta)
# =========================================================
# Lo que "haría" la segunda etapa. Al decodificarla solo se ve este texto explicativo.
STAGE2_TEXT = ("Write-Host 'LAB NightCrow: en un ataque real, en este punto se descargaria "
               "el modulo de robo de credenciales desde nightcrow-c2.example. "
               "En este laboratorio no ocurre nada.'")
# PowerShell -enc usa Base64 sobre texto UTF-16LE; se replica ese formato.
STAGE2_B64 = base64.b64encode(STAGE2_TEXT.encode("utf-16-le")).decode()

SAMPLE_SCRIPT = r'''<#
  Factura_Noviembre_2026.pdf.ps1
  build: NC-2.4.1 | campaign: NC-LAB-0007
  LAB-NIGHTCROW :: muestra inerte de capacitacion (solo cadenas, sin logica)
#>
exit 0

# ---- config ----
$NC_C2_PRIMARY  = "hxxps://nightcrow-c2.example/gate.php"
$NC_C2_FALLBACK = "203.0.113.47:443"
$NC_EXFIL_NODE  = "198.51.100.23:443"
$NC_PROXY_PORT  = "8081/tcp"
$NC_USER_AGENT  = "Mozilla/5.0 (NightCrow)"
$NC_NOTE        = "Hola, soy malo"

# ---- targets ----
$NC_T1 = "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"
$NC_T2 = "%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json"
$NC_T3 = "%APPDATA%\Exodus\exodus.wallet"
$NC_T4 = "%APPDATA%\Telegram Desktop\tdata"
$NC_T5 = "%USERPROFILE%\Desktop\*.txt"

# ---- persistence ----
$NC_RUN  = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateHelper"
$NC_DROP = "%APPDATA%\Microsoft\wuhelper\wuhelper.ps1"
$NC_COPY1 = "%TEMP%\tmp4F2A.ps1"
$NC_COPY2 = "%PUBLIC%\Libraries\desktop.ps1"

# ---- stage 2 ----
$NC_STAGE2 = "powershell.exe -NoP -W Hidden -ExecutionPolicy Bypass -enc __B64__"

# ---- exfil ----
$NC_EXFIL = "POST /gate.php?id=NC-LAB-0007&type=creds"
'''.replace("__B64__", STAGE2_B64)

# Al final se agrega un "recurso" binario con una cadena en UTF-16, como en muestras reales.
SAMPLE_BYTES = (
    SAMPLE_SCRIPT.encode("ascii")
    + b"\r\n\x00\x00\x00\x13\x37\x00\x00\x00"
    + "NightCrow :: panel de operador v2.4".encode("utf-16-le")
    + b"\x00\x00\xff\xfe\x00\x00\x00\x00"
)

CLEAN_TEXT = """LINEAMIENTOS INTERNOS DE USO DEL EQUIPO DE CÓMPUTO
Versión 3.1 · Área de Tecnologías de la Información

1. El equipo asignado es para uso exclusivo de actividades institucionales.
2. No se deben instalar programas sin autorización del área de TI.
3. Las contraseñas son personales e intransferibles; nunca se comparten por teléfono o chat.
4. Cualquier correo o archivo sospechoso se reporta de inmediato a la mesa de ayuda.
5. Bloquea tu sesión cada vez que te levantes de tu lugar.
"""
CLEAN_BYTES = CLEAN_TEXT.encode("utf-8")

FILES = {
    "sospechoso": {
        "nombre": "Factura_Noviembre_2026.pdf.ps1",
        "visto_como": "Factura_Noviembre_2026.pdf",
        "ext_aparente": ".pdf",
        "ext_real": ".ps1",
        "origen": "Adjunto de un correo con asunto \"Factura pendiente de pago\"",
        "bytes": SAMPLE_BYTES,
    },
    "limpio": {
        "nombre": "Lineamientos_Internos.txt",
        "visto_como": "Lineamientos_Internos.txt",
        "ext_aparente": ".txt",
        "ext_real": ".txt",
        "origen": "Carpeta compartida oficial del área de TI",
        "bytes": CLEAN_BYTES,
    },
}


def hashes(data):
    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA-1": hashlib.sha1(data).hexdigest(),
        "SHA-256": hashlib.sha256(data).hexdigest(),
    }


SAMPLE_HASHES = hashes(SAMPLE_BYTES)
CLEAN_HASHES = hashes(CLEAN_BYTES)

# Base de inteligencia de amenazas SIMULADA (indexada por SHA-256).
INTEL_DB = {
    SAMPLE_HASHES["SHA-256"]: {
        "veredicto": "MALICIOSO",
        "familia": "NightCrow Stealer (infostealer)",
        "detecciones": "47 / 70 motores",
        "primera_vez": "28/10/2026",
        "etiquetas": "infostealer · powershell · doble-extensión · campaña NC-LAB-0007",
    },
    CLEAN_HASHES["SHA-256"]: {
        "veredicto": "LIMPIO",
        "familia": "Documento interno en lista blanca",
        "detecciones": "0 / 70 motores",
        "primera_vez": "02/03/2025",
        "etiquetas": "documento-oficial · lista-blanca",
    },
}


def firma_magica(data):
    """Interpreta los primeros bytes del archivo (firma mágica)."""
    head = data[:4]
    if head.startswith(b"%PDF"):
        return "Documento PDF"
    if head.startswith(b"MZ"):
        return "Ejecutable de Windows (PE)"
    if head.startswith(b"PK"):
        return "Archivo comprimido ZIP / Office"
    if head.startswith(b"<#") or b"powershell" in data[:4000].lower():
        return "Script de texto (PowerShell)"
    return "Texto plano"


# =========================================================
# ESTADO
# =========================================================
def estado_inicial():
    return {
        "mod": 0,
        "unlocked": 0,
        "learning": True,
        "qs": {},
        "m1": {"actual": None, "hash": [], "intel": []},
        "m2": {"extraido": False, "minlen": 6, "decodificado": False},
        "m3": {"proc_ok": False, "proc_int": 0, "proc_fail": None,
               "ar_ok": False, "ar_int": 0, "ar_fail": None,
               "aislado": False, "terminado": False, "persist": False,
               "mon_activo": False, "mon_idx": 0,
               "log": [], "errores": []},
        "m4": {"sandbox": False, "fam_ok": False, "fam_int": 0, "fam_fail": None},
        "bgm_on": True,
        "bgm_vol": BGM_VOLUMEN_INICIAL,
    }


for _k, _v in estado_inicial().items():
    st.session_state.setdefault(_k, _v)


def reiniciar_laboratorio():
    for k in list(st.session_state.keys()):
        del st.session_state[k]
    for k, v in estado_inicial().items():
        st.session_state[k] = v


def ir_a(i):
    st.session_state.mod = i


def avanzar(i):
    st.session_state.unlocked = max(st.session_state.unlocked, i + 1)
    st.session_state.mod = i + 1


# =========================================================
# AYUDANTES DE INTERFAZ
# =========================================================
def hint(title, text, align="left"):
    if not st.session_state.get("learning", True):
        return ""
    cls = "hint" + (" r" if align == "right" else "")
    return (f'<details class="{cls}"><summary>?</summary>'
            f'<div class="tip"><b>{title}</b><br>{text}</div></details>')


def titulo(texto, hint_html=""):
    st.markdown(f'<div class="titulo"><h3>{texto}</h3>{hint_html}</div>', unsafe_allow_html=True)


def encabezado(n, subtitulo):
    st.title(f"🧬 SOC MALWARE FORENSICS LAB // MÓDULO {n}")
    st.subheader(subtitulo)


def mision(objetivo, tiempo, lograras):
    items = "".join(f"<li>{x}</li>" for x in lograras)
    st.markdown(f"""
<div class="lab-card verde mision">
    <span class="badge ok">TU MISIÓN</span>
    <span class="badge pend" style="margin-left:8px;">⏱ {tiempo}</span>
    <p style="margin:10px 0 0 0;">{objetivo}</p>
    <div class="mision-sub">Al terminar este módulo sabrás:</div>
    <ul>{items}</ul>
</div>
""", unsafe_allow_html=True)


def paso(n, nombre, que_hacer, por_que, done):
    badge = '<span class="badge ok">✔ COMPLETADO</span>' if done else '<span class="badge pend">PENDIENTE</span>'
    st.markdown(f"""
<div class="paso {'done' if done else ''}">
  <div class="paso-head"><span class="paso-num">PASO {n}</span><b>{nombre}</b>{badge}</div>
  <div class="paso-body">
    <p><b>Qué hacer:</b> {que_hacer}</p>
    <p class="porque"><b>Por qué:</b> {por_que}</p>
  </div>
</div>
""", unsafe_allow_html=True)


def tabla(columnas, filas, clases=None):
    """Tabla HTML con estilo del laboratorio. 'filas' ya debe venir escapado si hace falta."""
    head = "".join(f"<th>{c}</th>" for c in columnas)
    body = ""
    for i, fila in enumerate(filas):
        cls = f' class="{clases[i]}"' if clases and clases[i] else ""
        body += f"<tr{cls}>" + "".join(f"<td>{c}</td>" for c in fila) + "</tr>"
    st.markdown(f'<div class="lab-wrap"><table class="lab-table"><thead><tr>{head}</tr></thead>'
                f'<tbody>{body}</tbody></table></div>', unsafe_allow_html=True)


def e(s):
    return html.escape(str(s))


def pregunta(qid, texto, opciones, correcta, explicacion_ok, explicaciones_fallo):
    """Pregunta de verificación. Devuelve True cuando se contestó bien."""
    Q = st.session_state.qs.setdefault(qid, {"ok": False, "intentos": 0, "fallo": None})
    titulo("❓ Pregunta de verificación", hint(
        "Para avanzar", "Contesta correctamente para desbloquear el siguiente módulo. "
        "Puedes intentarlo las veces que necesites."))
    st.markdown(f"**{texto}**")
    if Q["ok"]:
        st.success(f"Correcto: **{correcta}**. {explicacion_ok}")
        return True
    sel = st.radio("Elige tu respuesta:", opciones, index=None, key=f"q_{qid}")
    if st.button("Comprobar respuesta", key=f"qb_{qid}", disabled=sel is None):
        Q["intentos"] += 1
        if sel == correcta:
            Q["ok"] = True
            Q["fallo"] = None
        else:
            Q["fallo"] = sel
        st.rerun()
    if Q["fallo"]:
        st.error(f"**{Q['fallo']}** no es correcto. {explicaciones_fallo.get(Q['fallo'], '')} Intenta de nuevo.")
    return False


def boton_siguiente(i, done):
    if done and i < len(MODULES) - 1:
        st.button(f"➡️ IR AL MÓDULO {i + 2}", key="next_mod", on_click=avanzar, args=(i,))


# =========================================================
# MÓDULO 1 · TRIAJE E IDENTIFICACIÓN
# =========================================================
def m1_done():
    S = st.session_state.m1
    return (set(S["intel"]) >= {"sospechoso", "limpio"}
            and st.session_state.qs.get("m1", {}).get("ok", False))


def render_m1():
    S = st.session_state.m1
    encabezado(1, "Triaje Inicial e Identificación (El DNI del Archivo)")
    mision(
        "Llegó a la mesa de ayuda un archivo adjunto que un usuario reportó como sospechoso, junto con "
        "un documento interno de TI. Tu trabajo es <b>identificar ambos archivos sin abrirlos</b>: "
        "confirmar qué son en realidad, calcular su huella digital (hash) y consultarla en inteligencia "
        "de amenazas.",
        "10 minutos",
        ["Por qué nunca hay que confiar en el nombre ni en la extensión de un archivo.",
         "Qué es un hash y por qué funciona como el DNI de un archivo.",
         "Cómo se usa el hash para saber si un archivo ya es conocido como malicioso."],
    )

    # ---------- PASO 1 ----------
    paso(1, "Carga la evidencia",
         "Elige uno de los dos archivos de la lista y presiona <b>Cargar evidencia</b>. "
         "Empieza por el archivo sospechoso.",
         "En un SOC nunca se abre ni se ejecuta un archivo sospechoso. Se trabaja con una copia "
         "y solo se lee su contenido como datos.",
         S["actual"] is not None)
    opcion = st.radio("Archivo de evidencia:", list(FILES.keys()), horizontal=True,
                      format_func=lambda k: ("⚠️ " if k == "sospechoso" else "📄 ") + FILES[k]["nombre"],
                      key="m1_sel")
    if st.button("📂 Cargar evidencia", key="m1_cargar"):
        S["actual"] = opcion
        st.rerun()

    if S["actual"] is None:
        st.info("Todavía no has cargado ningún archivo.")
        return

    k = S["actual"]
    f = FILES[k]
    data = f["bytes"]
    firma = firma_magica(data)
    primeros = " ".join(f"{b:02X}" for b in data[:4])
    coincide = (f["ext_aparente"] == f["ext_real"])

    titulo(f"🗂️ Ficha de la evidencia: {e(f['nombre'])}", hint(
        "Firma mágica",
        "Los primeros bytes de un archivo indican su tipo real. Un PDF siempre empieza con "
        "<b>25 50 44 46</b> (\"%PDF\"). Si el archivo dice ser PDF pero empieza distinto, mintió."))
    tabla(["Campo", "Valor"], [
        ["Cómo lo ve el usuario en Windows", e(f["visto_como"])],
        ["Nombre real completo", e(f["nombre"])],
        ["Extensión aparente", e(f["ext_aparente"])],
        ["Extensión real", e(f["ext_real"])],
        ["Tamaño", f"{len(data):,} bytes"],
        ["Primeros 4 bytes (firma mágica)", primeros],
        ["Tipo real según la firma", e(firma)],
        ["Origen", e(f["origen"])],
    ], ["", "", "" if coincide else "sus", "" if coincide else "sus", "", "", "", ""])

    if not coincide:
        st.warning("**Doble extensión detectada.** Windows oculta la última extensión por defecto, así que "
                   "el usuario vio un \"PDF\". La firma mágica confirma que en realidad es un "
                   "**script de PowerShell**: un PDF real empezaría con `25 50 44 46`.")
    else:
        st.success("La extensión y la firma mágica coinciden: es un archivo de texto plano.")

    # ---------- PASO 2 ----------
    paso(2, "Calcula la huella digital (hash)",
         "Presiona <b>Calcular hashes</b>. La app lee los bytes del archivo y calcula MD5, SHA-1 y SHA-256 "
         "en tiempo real con Python.",
         "El hash es único para cada contenido. Si cambia un solo byte, el hash cambia por completo. "
         "Por eso el nombre puede mentir, pero el hash no.",
         k in S["hash"])
    if st.button("🔐 Calcular hashes", key=f"m1_hash_{k}"):
        if k not in S["hash"]:
            S["hash"].append(k)
        st.rerun()

    if k not in S["hash"]:
        return
    H = hashes(data)
    titulo("Resultado", hint(
        "¿Cuál uso?",
        "<b>MD5</b> y <b>SHA-1</b> son antiguos y ya se pueden forzar colisiones. "
        "Se siguen mostrando por compatibilidad, pero el estándar actual para identificar "
        "malware es <b>SHA-256</b>."))
    tabla(["Algoritmo", "Hash", "Uso recomendado"], [
        ["MD5", H["MD5"], "Solo referencia (obsoleto)"],
        ["SHA-1", H["SHA-1"], "Solo referencia (obsoleto)"],
        ["SHA-256", f"<b>{H['SHA-256']}</b>", "<b>Estándar para identificar malware</b>"],
    ], ["", "", "ok"])

    # ---------- PASO 3 ----------
    paso(3, "Consulta inteligencia de amenazas",
         "Presiona <b>Consultar inteligencia</b>. Se busca el SHA-256 en una base de datos de amenazas, "
         "como lo haría VirusTotal.",
         "Solo se envía el hash, nunca el archivo. Subir un archivo a un servicio público puede "
         "exponer información sensible de tu organización.",
         k in S["intel"])
    if st.button("🛰️ Consultar inteligencia (simulación)", key=f"m1_intel_{k}"):
        if k not in S["intel"]:
            S["intel"].append(k)
        st.rerun()

    if k in S["intel"]:
        I = INTEL_DB[H["SHA-256"]]
        malo = I["veredicto"] == "MALICIOSO"
        color, badge = ("rojo", "mal") if malo else ("verde", "ok")
        icono = "🚨" if malo else "✅"
        st.markdown(f"""
<div class="lab-card {color}">
  <span class="badge {badge}">{icono} VEREDICTO: {I['veredicto']}</span>
  <span class="badge pend" style="margin-left:8px;">CONSULTA SIMULADA</span>
  <table class="lab-table" style="margin-top:10px;">
    <tr><td><b>Familia / descripción</b></td><td>{e(I['familia'])}</td></tr>
    <tr><td><b>Detecciones</b></td><td>{e(I['detecciones'])}</td></tr>
    <tr><td><b>Primera vez visto</b></td><td>{e(I['primera_vez'])}</td></tr>
    <tr><td><b>Etiquetas</b></td><td>{e(I['etiquetas'])}</td></tr>
  </table>
</div>
""", unsafe_allow_html=True)
        if malo:
            st.error("Este hash ya está registrado como **NightCrow Stealer**, un ladrón de información. "
                     "En los siguientes módulos vas a confirmarlo con tus propios ojos.")

    # ---------- PASO 4 ----------
    pendiente = [x for x in FILES if x not in S["intel"]]
    paso(4, "Compara con el otro archivo",
         "Regresa al Paso 1, carga <b>el otro archivo</b> y repite los pasos 2 y 3.",
         "Comparar un archivo malicioso con uno legítimo te ayuda a ver que el hash distingue "
         "contenidos, sin importar cómo se llamen.",
         not pendiente)
    tabla(["Archivo", "Hash calculado", "Inteligencia consultada"],
          [[e(FILES[x]["nombre"]), "✔" if x in S["hash"] else "Pendiente",
            "✔" if x in S["intel"] else "Pendiente"] for x in FILES],
          ["ok" if x in S["intel"] else "" for x in FILES])
    if pendiente:
        st.info(f"Falta analizar: **{FILES[pendiente[0]]['nombre']}**")
        return

    # ---------- PREGUNTA ----------
    ok = pregunta(
        "m1",
        "El atacante renombra su archivo a \"Reporte_Anual.docx\". ¿Qué dato seguiría siendo exactamente el mismo?",
        ["El nombre del archivo", "La extensión", "El hash SHA-256", "El ícono que ve el usuario"],
        "El hash SHA-256",
        "Cambiar el nombre no cambia el contenido, así que la huella digital sigue igual. "
        "Por eso los equipos de seguridad bloquean por hash y no por nombre.",
        {"El nombre del archivo": "El nombre es justo lo que cambió.",
         "La extensión": "La extensión se puede cambiar libremente, como en la doble extensión.",
         "El ícono que ve el usuario": "El ícono depende de la extensión y se puede falsificar."},
    )
    boton_siguiente(0, ok and m1_done())


# =========================================================
# MÓDULO 2 · ANÁLISIS ESTÁTICO (STRINGS)
# =========================================================
CATEGORIAS = [
    ("mensaje", "Mensaje oculto", "#d29922", r"Hola, soy malo"),
    ("base64", "Carga codificada (Base64)", "#a371f7", r"[A-Za-z0-9+/]{40,}={0,2}"),
    ("comando", "Comando de consola", "#f85149",
     r"(?i)powershell(?:\.exe)?|-ExecutionPolicy|\bBypass\b|-W Hidden|-NoP\b|-enc\b"),
    ("registro", "Clave de registro", "#db6d28", r"HK(?:CU|LM)\\[^\"']+"),
    ("ip", "Dirección IP", "#ff7b72", r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"),
    ("puerto", "Puerto de red", "#ff7b72", r"\b\d{2,5}/(?:tcp|udp)\b"),
    ("url", "URL o dominio", "#e3b341", r"hxxps?://[^\s\"']+|\b[a-z0-9-]+\.example\b"),
    ("ruta", "Ruta local", "#58a6ff", r"%[A-Z]+%\\[^\"']+"),
]


def extraer_strings(data, minlen):
    """Equivalente a la herramienta 'strings': busca secuencias legibles ASCII y UTF-16LE."""
    res = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        res.append((m.start(), "ASCII", m.group().decode("ascii")))
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, data):
        res.append((m.start(), "UTF-16", m.group().decode("utf-16-le")))
    return sorted(res)


def categorias_de(texto):
    return [c[0] for c in CATEGORIAS if re.search(c[3], texto)]


def resaltar(texto):
    spans = []
    for _cid, _nom, color, rx in CATEGORIAS:
        for m in re.finditer(rx, texto):
            if any(not (m.end() <= s or m.start() >= f) for s, f, _ in spans):
                continue
            spans.append((m.start(), m.end(), color))
    spans.sort()
    out, pos = [], 0
    for s, f, color in spans:
        out.append(e(texto[pos:s]))
        out.append(f'<span style="color:{color};font-weight:bold;">{e(texto[s:f])}</span>')
        pos = f
    out.append(e(texto[pos:]))
    return "".join(out)


def hexdump(data, inicio=0, largo=256):
    lineas = []
    for off in range(inicio, min(len(data), inicio + largo), 16):
        chunk = data[off:off + 16]
        hx = " ".join(f"{b:02X}" for b in chunk).ljust(47)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lineas.append(f"{off:08X}  {hx}  {asc}")
    return "\n".join(lineas)


def m2_done():
    S = st.session_state.m2
    return S["extraido"] and S["decodificado"] and st.session_state.qs.get("m2", {}).get("ok", False)


def render_m2():
    S = st.session_state.m2
    data = SAMPLE_BYTES
    encabezado(2, "Análisis Estático y Extracción de Cadenas (Strings)")
    mision(
        "Ya sabes que <b>Factura_Noviembre_2026.pdf.ps1</b> es malicioso. Ahora vas a mirar "
        "<b>dentro</b> del archivo sin ejecutarlo, buscando pistas de texto que delaten qué hace: "
        "a dónde se conecta, qué busca en el equipo y cómo se esconde.",
        "15 minutos",
        ["Qué es el análisis estático y por qué es seguro.",
         "Cómo se extraen cadenas legibles de un archivo (como la herramienta strings).",
         "Qué son los indicadores de compromiso (IOC): IPs, dominios, rutas y claves de registro.",
         "Cómo los atacantes esconden comandos con Base64."],
    )

    # ---------- PASO 1 ----------
    paso(1, "Extrae las cadenas de texto",
         "Ajusta la <b>longitud mínima</b> (deja 6 si no estás seguro) y presiona <b>Extraer cadenas</b>.",
         "La app recorre los bytes del archivo y conserva solo las secuencias de caracteres legibles. "
         "Una longitud mínima evita que aparezca \"basura\" de 2 o 3 letras.",
         S["extraido"])
    S["minlen"] = st.slider("Longitud mínima de cadena:", 4, 12, S["minlen"], key="m2_minlen")
    if st.button("🔎 Extraer cadenas", key="m2_extraer"):
        S["extraido"] = True
        st.rerun()
    if not S["extraido"]:
        return

    cadenas = extraer_strings(data, S["minlen"])
    n_ascii = sum(1 for c in cadenas if c[1] == "ASCII")
    n_utf16 = len(cadenas) - n_ascii
    c1, c2, c3 = st.columns(3)
    c1.metric("Cadenas encontradas", len(cadenas))
    c2.metric("ASCII", n_ascii)
    c3.metric("UTF-16", n_utf16)

    # ---------- PASO 2 ----------
    paso(2, "Identifica los indicadores de compromiso (IOC)",
         "Revisa el visor. Los colores marcan cada tipo de hallazgo. Usa el filtro para quedarte solo "
         "con lo que te interesa y busca: la <b>IP</b>, el <b>dominio</b>, las <b>rutas</b> que el "
         "malware revisa y la <b>clave de registro</b>.",
         "Estos datos se llaman IOC. Con ellos el equipo de seguridad puede bloquear la amenaza en el "
         "firewall y buscarla en otros equipos de la organización.",
         S["extraido"])

    conteo = {c[0]: sum(1 for x in cadenas if c[0] in categorias_de(x[2])) for c in CATEGORIAS}
    st.markdown('<div class="leyenda">' + "".join(
        f'<span style="color:{col};">■ {nom} ({conteo[cid]})</span>' for cid, nom, col, _ in CATEGORIAS
    ) + "</div>", unsafe_allow_html=True)

    nombres = {c[0]: c[1] for c in CATEGORIAS}
    filtro = st.multiselect("Filtrar por tipo de hallazgo (vacío = mostrar todo):",
                            list(nombres.keys()), format_func=lambda x: nombres[x], key="m2_filtro",
                            placeholder="Elige uno o más tipos")
    solo_iocs = st.checkbox("Ocultar cadenas sin hallazgos", value=False, key="m2_solo")
    filas = []
    for off, enc, txt in cadenas:
        cats = categorias_de(txt)
        if filtro and not set(cats) & set(filtro):
            continue
        if solo_iocs and not cats:
            continue
        filas.append(f'<div><span class="off">0x{off:05X}</span><span class="enc">{enc:<6}</span>'
                     f'{resaltar(txt)}</div>')
    st.markdown('<div class="strings-box">' + ("".join(filas) or "Sin resultados para este filtro.")
                + "</div>", unsafe_allow_html=True)

    # ---------- PASO 3 ----------
    paso(3, "Observa la anatomía interna (vista hexadecimal)",
         "Revisa las dos vistas. A la izquierda está el inicio del archivo; a la derecha, el final, "
         "donde hay una cadena escondida en <b>UTF-16</b> (letras separadas por puntos).",
         "Así ven los analistas un archivo: offset, bytes en hexadecimal y su texto. Las cadenas UTF-16 "
         "no aparecen si solo buscas ASCII, por eso las herramientas buscan ambos formatos.",
         S["extraido"])
    a, b = st.columns(2)
    with a:
        st.caption("Inicio del archivo (primeros 128 bytes)")
        st.code(hexdump(data, 0, 128), language=None)
    with b:
        st.caption("Final del archivo (últimos 96 bytes)")
        inicio = (len(data) - 96) // 16 * 16
        st.code(hexdump(data, inicio, 112), language=None)

    # ---------- PASO 4 ----------
    paso(4, "Decodifica el comando oculto",
         "En el visor hay una cadena larga en color morado después de <code>-enc</code>. "
         "Presiona <b>Decodificar Base64</b> para ver qué esconde.",
         "PowerShell acepta comandos codificados en Base64 con <code>-enc</code>. Los atacantes lo usan "
         "para que el comando real no se lea a simple vista ni lo detecten filtros básicos.",
         S["decodificado"])
    st.code(f"-enc {STAGE2_B64[:60]}...", language=None)
    if st.button("🧩 Decodificar Base64", key="m2_decode"):
        S["decodificado"] = True
        st.rerun()
    if S["decodificado"]:
        decod = base64.b64decode(STAGE2_B64).decode("utf-16-le")
        st.markdown(f'<div class="lab-card ambar"><span class="badge mis">CONTENIDO DECODIFICADO</span>'
                    f'<pre style="white-space:pre-wrap;margin-top:10px;color:#e6edf3;">{e(decod)}</pre></div>',
                    unsafe_allow_html=True)
        st.info("En una muestra real, este comando descargaría la segunda etapa del malware desde el servidor "
                "de comando y control (C2). Aquí solo imprime un texto explicativo.")
    else:
        return

    # ---------- PREGUNTA ----------
    ok = pregunta(
        "m2",
        "Según las cadenas extraídas, ¿con qué dirección IP intentaría comunicarse la muestra si falla su dominio principal?",
        ["192.168.1.10", "203.0.113.47", "8.8.8.8", "127.0.0.1"],
        "203.0.113.47",
        "Aparece en la variable <code>$NC_C2_FALLBACK</code> con el puerto 443. Es el servidor de respaldo "
        "del C2 y es un IOC que se bloquearía de inmediato en el firewall.",
        {"192.168.1.10": "Esa es una IP privada de red local y no aparece en la muestra.",
         "8.8.8.8": "Ese es el DNS público de Google y no aparece en la muestra.",
         "127.0.0.1": "Esa es la dirección local del propio equipo (localhost)."},
    )
    boton_siguiente(1, ok and m2_done())


# =========================================================
# MÓDULO 3 · SYSINTERNALS (PROCESOS, ACTIVIDAD Y PERSISTENCIA)
# =========================================================
PROCESOS = [
    {"pid": 4, "ppid": 0, "nombre": "System", "nivel": 0, "usuario": "SYSTEM",
     "ventana": "No", "cmd": "", "red": ""},
    {"pid": 700, "ppid": 612, "nombre": "services.exe", "nivel": 0, "usuario": "SYSTEM",
     "ventana": "No", "cmd": r"C:\Windows\system32\services.exe", "red": ""},
    {"pid": 1024, "ppid": 700, "nombre": "svchost.exe", "nivel": 1, "usuario": "SYSTEM",
     "ventana": "No", "cmd": r"C:\Windows\system32\svchost.exe -k netsvcs -p", "red": ""},
    {"pid": 4120, "ppid": 3988, "nombre": "explorer.exe", "nivel": 0, "usuario": "usuario01",
     "ventana": "Sí", "cmd": r"C:\Windows\explorer.exe", "red": ""},
    {"pid": 5532, "ppid": 4120, "nombre": "OUTLOOK.EXE", "nivel": 1, "usuario": "usuario01",
     "ventana": "Sí", "cmd": r'"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"',
     "red": "Servidor de correo:443"},
    {"pid": 4388, "ppid": 4120, "nombre": "OneDrive.exe", "nivel": 1, "usuario": "usuario01",
     "ventana": "No", "cmd": r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background',
     "red": "Nube Microsoft:443"},
    {"pid": 7344, "ppid": 4120, "nombre": "powershell.exe", "nivel": 1, "usuario": "usuario01",
     "ventana": "Oculta",
     "cmd": f"powershell.exe -NoP -W Hidden -ExecutionPolicy Bypass -enc {STAGE2_B64[:28]}...",
     "red": "203.0.113.47:443 ESTABLISHED", "malo": True},
    {"pid": 7352, "ppid": 7344, "nombre": "conhost.exe", "nivel": 2, "usuario": "usuario01",
     "ventana": "No", "cmd": r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1",
     "red": "", "derivado": True},
    {"pid": 7390, "ppid": 7344, "nombre": "powershell.exe", "nivel": 2, "usuario": "usuario01",
     "ventana": "Oculta", "cmd": r"powershell.exe -NoP -W Hidden -File %TEMP%\tmp4F2A.ps1",
     "red": "0.0.0.0:8081 LISTENING · 198.51.100.23:443", "derivado": True},
]

FALLOS_PROC = {
    "System (PID 4)": "Es el núcleo del sistema operativo; siempre existe con PID 4.",
    "services.exe (PID 700)": "Es el administrador de servicios de Windows y está en su ruta correcta.",
    "svchost.exe (PID 1024)": "Es un anfitrión de servicios normal: es hijo de services.exe y está en System32.",
    "explorer.exe (PID 4120)": "Es el escritorio de Windows. Es legítimo, aunque fue quien lanzó al proceso anómalo.",
    "OUTLOOK.EXE (PID 5532)": "Es el cliente de correo, con una conexión normal a su servidor.",
    "OneDrive.exe (PID 4388)": "Es la sincronización de OneDrive, con conexión a la nube de Microsoft.",
    "conhost.exe (PID 7352)": "Casi: es la consola que acompaña a PowerShell, pero no es el origen. "
                              "Fíjate en su proceso padre (PPID).",
    "powershell.exe (PID 7390)": "Casi: también es malicioso, pero es una réplica que lanzó otro proceso. "
                                 "Fíjate en su PPID: busca al proceso que lo creó.",
}

# Actividad en segundo plano que se va revelando en el monitor en vivo.
# (tiempo, tipo, pid, detalle)
MONITOR_EVENTOS = [
    ("00:00.2", "PROCESO", 7344, "powershell.exe inicia con ventana oculta y -ExecutionPolicy Bypass"),
    ("00:00.6", "RÉPLICA", 7344, r"Se copia a sí mismo en %APPDATA%\Microsoft\wuhelper\wuhelper.ps1"),
    ("00:00.8", "RÉPLICA", 7344, r"Se copia a sí mismo en %TEMP%\tmp4F2A.ps1"),
    ("00:00.9", "PROCESO", 7344, r"Lanza una segunda instancia: powershell.exe (PID 7390) -File %TEMP%\tmp4F2A.ps1"),
    ("00:01.1", "REGISTRO", 7344, r"RegSetValue HKCU\...\CurrentVersion\Run\WindowsUpdateHelper"),
    ("00:01.3", "RED UDP", 7344, "10.0.7.25:53211 -> 10.0.0.53:53  Consulta DNS de nightcrow-c2.example"),
    ("00:01.6", "RED TCP", 7344, "10.0.7.25:49733 -> 203.0.113.47:443  Conexión establecida con el C2"),
    ("00:02.0", "ARCHIVO", 7344, r"ReadFile %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"),
    ("00:02.3", "ARCHIVO", 7344, r"ReadFile %APPDATA%\Exodus\exodus.wallet"),
    ("00:02.7", "PUERTO", 7390, "Abre 0.0.0.0:8081/TCP en escucha (proxy SOCKS para el atacante)"),
    ("00:03.0", "RÉPLICA", 7390, r"Se copia a sí mismo en %PUBLIC%\Libraries\desktop.ps1"),
    ("00:03.4", "RED TCP", 7390, "10.0.7.25:49741 -> 198.51.100.23:443  Intento de conexión a nodo alterno"),
    ("00:03.9", "EXFIL", 7344, "POST /gate.php hacia 203.0.113.47:443  (412 KB enviados)"),
]

COLOR_EVENTO = {
    "PROCESO": "#f85149", "RÉPLICA": "#a371f7", "REGISTRO": "#db6d28", "RED UDP": "#e3b341",
    "RED TCP": "#e3b341", "ARCHIVO": "#58a6ff", "PUERTO": "#ff7b72", "EXFIL": "#f85149",
}

# Conexiones estilo TCPView. "desde" = número de eventos revelados para que aparezca.
CONEXIONES = [
    {"pid": 7344, "proto": "UDP", "local": "10.0.7.25:53211", "remota": "10.0.0.53:53",
     "estado": "N/A (UDP)", "desde": 6, "externa": True},
    {"pid": 7344, "proto": "TCP", "local": "10.0.7.25:49733", "remota": "203.0.113.47:443",
     "estado": "ESTABLISHED", "desde": 7, "externa": True},
    {"pid": 7390, "proto": "TCP", "local": "0.0.0.0:8081", "remota": "0.0.0.0:0",
     "estado": "LISTENING", "desde": 10, "externa": False},
    {"pid": 7390, "proto": "TCP", "local": "10.0.7.25:49741", "remota": "198.51.100.23:443",
     "estado": "SYN_SENT", "desde": 12, "externa": True},
]

# Copias del archivo. "desde" = número de eventos revelados para que aparezca.
REPLICAS = [
    {"ruta": r"%USERPROFILE%\Downloads\Factura_Noviembre_2026.pdf.ps1", "origen": "Archivo original", "desde": 0},
    {"ruta": r"%APPDATA%\Microsoft\wuhelper\wuhelper.ps1", "origen": "Copia (persistencia)", "desde": 2},
    {"ruta": r"%TEMP%\tmp4F2A.ps1", "origen": "Copia (segunda instancia)", "desde": 3},
    {"ruta": r"%PUBLIC%\Libraries\desktop.ps1", "origen": "Copia (respaldo oculto)", "desde": 11},
]

AUTORUNS = [
    {"entrada": "SecurityHealth", "ubicacion": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
     "imagen": r"%windir%\system32\SecurityHealthSystray.exe", "editor": "Microsoft Corporation",
     "firmado": "✔ Firmado"},
    {"entrada": "OneDrive", "ubicacion": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
     "imagen": r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background', "editor": "Microsoft Corporation",
     "firmado": "✔ Firmado"},
    {"entrada": "WindowsUpdateHelper", "ubicacion": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
     "imagen": r"powershell.exe -W Hidden -File %APPDATA%\Microsoft\wuhelper\wuhelper.ps1",
     "editor": "(sin editor)", "firmado": "✘ No firmado", "malo": True},
    {"entrada": "ScheduledDefrag", "ubicacion": r"Task Scheduler\Microsoft\Windows\Defrag",
     "imagen": r"%windir%\system32\defrag.exe -c -h -o", "editor": "Microsoft Corporation",
     "firmado": "✔ Firmado"},
]

FALLOS_AR = {
    "SecurityHealth": "Es el ícono de Seguridad de Windows: firmado por Microsoft y en System32.",
    "OneDrive": "Es el arranque normal de OneDrive, firmado por Microsoft.",
    "ScheduledDefrag": "Es la desfragmentación programada de Windows, firmada por Microsoft.",
}


def m3_aislar():
    S = st.session_state.m3
    if S["aislado"]:
        return
    S["aislado"] = True
    S["log"].append("🔌 Equipo EQUIPO-07 aislado de la red desde la consola EDR. Conexiones externas bloqueadas.")


def m3_terminar():
    S = st.session_state.m3
    if S["terminado"]:
        return
    if not S["aislado"]:
        S["errores"].append("Terminaste los procesos antes de aislar el equipo. Mientras tanto las conexiones al "
                            "C2 siguieron abiertas y se perdió la evidencia que había en memoria.")
    S["terminado"] = True
    S["log"].append("⛔ Árbol de procesos terminado: powershell.exe (7344), conhost.exe (7352) y la réplica "
                    "powershell.exe (7390). Puerto 8081 cerrado.")


def m3_persistencia():
    S = st.session_state.m3
    if S["persist"]:
        return
    if not S["terminado"]:
        S["errores"].append("Eliminaste la persistencia con los procesos maliciosos todavía vivos: "
                            "el malware volvió a crear la clave y las copias segundos después.")
        S["log"].append("🗑️ Clave WindowsUpdateHelper eliminada... ⚠️ RECREADA por powershell.exe (PID 7344).")
        return
    S["persist"] = True
    S["log"].append("🗑️ Clave Run\\WindowsUpdateHelper eliminada y 3 copias del script (mismo SHA-256) "
                    "enviadas a cuarentena.")


def m3_monitor_iniciar():
    S = st.session_state.m3
    S["mon_activo"] = True
    S["mon_idx"] = max(S["mon_idx"], 1)


def m3_monitor_todo():
    S = st.session_state.m3
    S["mon_idx"] = len(MONITOR_EVENTOS)
    S["mon_activo"] = False


def m3_monitor_done():
    return st.session_state.m3["mon_idx"] >= len(MONITOR_EVENTOS)


def m3_done():
    S = st.session_state.m3
    return (S["proc_ok"] and m3_monitor_done() and st.session_state.qs.get("m3mon", {}).get("ok", False)
            and S["ar_ok"] and S["aislado"] and S["terminado"] and S["persist"])


def render_tabla_procesos():
    S = st.session_state.m3
    filas, clases = [], []
    for p in PROCESOS:
        sangria = "&nbsp;&nbsp;&nbsp;&nbsp;" * p["nivel"] + ("└─ " if p["nivel"] else "")
        maligno = p.get("malo") or p.get("derivado")
        muerto = S["terminado"] and maligno
        red = p["red"]
        if maligno and S["aislado"] and red and not muerto:
            red = red + " (BLOQUEADA)"
        if muerto:
            red = ""
        estado = "TERMINADO" if muerto else "En ejecución"
        filas.append([f'<span style="white-space:nowrap;">{sangria}<b>{e(p["nombre"])}</b></span>',
                      p["pid"], p["ppid"], e(p["usuario"]), e(p["ventana"]),
                      f'<span style="word-break:break-all;">{e(p["cmd"])}</span>', e(red),
                      f'<span style="white-space:nowrap;">{estado}</span>'])
        if muerto:
            clases.append("muerto")
        elif S["proc_ok"] and maligno:
            clases.append("sus")
        else:
            clases.append("")
    tabla(["Proceso", "PID", "PPID", "Usuario", "Ventana", "Línea de comandos", "Conexiones", "Estado"],
          filas, clases)


def render_monitor_contenido():
    """Dibuja el monitor (conexiones, actividad y réplicas) según cuántos eventos se han revelado."""
    S = st.session_state.m3
    n = S["mon_idx"]
    conexiones = [c for c in CONEXIONES if n >= c["desde"]]
    replicas = [r for r in REPLICAS if n >= r["desde"]]
    enviados = 412 if n >= 13 else (6 if n >= 7 else 0)
    abiertos = [c for c in conexiones if c["estado"] == "LISTENING" and not S["terminado"]]

    en_vivo = S["mon_activo"] and n < len(MONITOR_EVENTOS)
    if en_vivo:
        st.markdown('<span class="live-dot"></span><b>MONITOREANDO EN VIVO...</b> '
                    f'({n} de {len(MONITOR_EVENTOS)} eventos)', unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Conexiones de red", 0 if S["terminado"] else len(conexiones))
    c2.metric("Puertos en escucha", len(abiertos))
    c3.metric("Copias de sí mismo", max(0, len(replicas) - 1))
    c4.metric("Datos enviados", f"{enviados} KB")

    titulo("🧾 Actividad en segundo plano (Process Monitor)", hint(
        "Cómo leerlo", "Cada línea es algo que hizo el malware sin que el usuario lo viera. "
        "La más reciente aparece resaltada. Fíjate en las <b>RÉPLICAS</b>, el <b>PUERTO</b> abierto "
        "y las conexiones de <b>RED</b>."))
    lineas = []
    for i, (t, tipo, pid, det) in enumerate(MONITOR_EVENTOS[:n]):
        cls = ' class="nuevo"' if (i == n - 1 and en_vivo) else ""
        lineas.append(f'<div{cls}><span class="t">{t}</span>'
                      f'<span class="tag" style="color:{COLOR_EVENTO[tipo]};">{tipo}</span>'
                      f'<span class="t">PID {pid}</span>{e(det)}</div>')
    st.markdown('<div class="feed">' + ("".join(lineas) or "Esperando actividad...") + "</div>",
                unsafe_allow_html=True)
    titulo("📡 Conexiones de red (TCPView)", hint(
        "TCP vs. UDP", "<b>TCP</b> abre una conexión con confirmación (ESTABLISHED, SYN_SENT). "
        "<b>UDP</b> envía datos sin conexión, como una consulta DNS. <b>LISTENING</b> significa que el "
        "equipo dejó una puerta abierta esperando que alguien se conecte."))
    filas, clases = [], []
    for c in conexiones:
        estado = c["estado"]
        if S["terminado"]:
            estado, cls = "CERRADA", "muerto"
        elif S["aislado"] and c["externa"]:
            estado, cls = "BLOQUEADA (aislado)", "muerto"
        else:
            cls = "sus"
        filas.append([c["pid"], c["proto"], e(c["local"]), e(c["remota"]), e(estado)])
        clases.append(cls)
    if filas:
        tabla(["PID", "Proto", "Local", "Remota", "Estado"], filas, clases)
    else:
        st.caption("Sin conexiones todavía.")

    titulo("🧬 Réplicas del archivo", hint(
        "¿Cómo sé que son copias?", "Las cuatro rutas tienen <b>el mismo SHA-256</b> que la muestra del "
        "Módulo 1. Por eso los equipos de seguridad buscan por hash: aunque el archivo cambie de nombre y "
        "de lugar, su huella es la misma."))
    h = SAMPLE_HASHES["SHA-256"]
    filas_r, clases_r = [], []
    for r in replicas:
        en_cuarentena = S["persist"] and r["desde"] > 0
        filas_r.append([f'<span style="word-break:break-all;">{e(r["ruta"])}</span>', e(r["origen"]),
                        f"{h[:12]}... ✔ coincide",
                        "CUARENTENA" if en_cuarentena else "Presente"])
        clases_r.append("muerto" if en_cuarentena else ("sus" if r["desde"] > 0 else ""))
    tabla(["Ruta", "Origen", "SHA-256", "Estado"], filas_r, clases_r)


def render_monitor():
    """Monitor en vivo: revela un evento por segundo con st.fragment (si la versión lo permite)."""
    S = st.session_state.m3
    total = len(MONITOR_EVENTOS)
    vivo = S["mon_activo"] and S["mon_idx"] < total

    if hasattr(st, "fragment") and vivo:
        @st.fragment(run_every=1.0)
        def _monitor_vivo():
            if S["mon_activo"] and S["mon_idx"] < total:
                S["mon_idx"] += 1
            render_monitor_contenido()
            if S["mon_idx"] >= total:
                S["mon_activo"] = False
                st.rerun()
        _monitor_vivo()
    else:
        if vivo:  # Versión antigua de Streamlit sin fragmentos: se muestra todo de una vez
            S["mon_idx"], S["mon_activo"] = total, False
        render_monitor_contenido()


def render_m3():
    S = st.session_state.m3
    encabezado(3, "El Simulador de Sysinternals (Procesos, Actividad y Persistencia)")
    mision(
        "El usuario de <b>EQUIPO-07</b> abrió la \"factura\" antes de reportarla. Tienes acceso remoto al "
        "equipo con herramientas tipo <b>Process Explorer</b>, <b>Process Monitor</b>, <b>TCPView</b> y "
        "<b>Autoruns</b>. Encuentra el proceso malicioso, observa lo que hace en segundo plano, descubre cómo "
        "planea sobrevivir a un reinicio y contén la amenaza <b>en el orden correcto</b>.",
        "20 minutos",
        ["Cómo leer un árbol de procesos: quién es padre de quién.",
         "Qué señales delatan a un proceso anómalo (ventana oculta, comando codificado, conexión extraña).",
         "Cómo se ven en vivo las conexiones TCP y UDP, un puerto abierto y un malware que se copia a sí mismo.",
         "Qué es la persistencia y cómo la encuentra Autoruns.",
         "Por qué el orden de la respuesta a incidentes importa."],
    )

    # ---------- PASO 1 ----------
    paso(1, "Encuentra el proceso de origen (Process Explorer)",
         "Revisa el árbol de procesos. Fíjate en la columna <b>Ventana</b>, en la <b>línea de comandos</b>, en "
         "las <b>conexiones</b> y en el <b>PPID</b> (el proceso padre). Elige el proceso que <b>originó</b> la "
         "infección y presiona <b>Confirmar</b>.",
         "Muchos procesos legítimos pueden lanzar PowerShell, pero uno con ventana oculta, política de "
         "ejecución desactivada y un comando en Base64 que se conecta a una IP externa es una alerta clásica. "
         "Si hay varios sospechosos, el que importa es el padre de todos.",
         S["proc_ok"])
    titulo("🌳 Árbol de procesos · EQUIPO-07", hint(
        "Cómo leerlo",
        "La sangría indica jerarquía: un proceso con <b>└─</b> es hijo del que está arriba. "
        "<b>PPID</b> es el PID del proceso padre. Aquí, <b>explorer.exe</b> (el escritorio) lanzó un "
        "PowerShell porque el usuario dio doble clic en la \"factura\"."))
    render_tabla_procesos()

    opciones_proc = [f"{p['nombre']} (PID {p['pid']})" for p in PROCESOS]
    correcta_proc = "powershell.exe (PID 7344)"
    if not S["proc_ok"]:
        sel = st.radio("¿Cuál es el proceso que originó la infección?", opciones_proc, index=None,
                       key="m3_proc_sel")
        if st.button("Confirmar proceso", key="m3_proc_btn", disabled=sel is None):
            S["proc_int"] += 1
            if sel == correcta_proc:
                S["proc_ok"], S["proc_fail"] = True, None
            else:
                S["proc_fail"] = sel
            st.rerun()
        if S["proc_fail"]:
            st.error(f"**{S['proc_fail']}** no es. {FALLOS_PROC.get(S['proc_fail'], '')}")
        return
    st.success("Correcto: **powershell.exe (PID 7344)**. Ventana oculta, `-ExecutionPolicy Bypass`, comando en "
               "Base64 (el mismo que decodificaste en el Módulo 2) y conexión a **203.0.113.47:443**, la IP del C2. "
               "Además creó dos hijos: su consola y **una segunda instancia de sí mismo (PID 7390)**.")

    # ---------- PASO 2 ----------
    paso(2, "Observa la actividad en segundo plano (Process Monitor y TCPView)",
         "Presiona <b>Iniciar monitoreo en vivo</b> y observa durante unos segundos cómo aparecen los eventos. "
         "Busca tres cosas: <b>las copias que hace de sí mismo</b>, <b>las conexiones TCP y UDP</b> y <b>el "
         "puerto que deja abierto</b>.",
         "El usuario no ve nada de esto: todo ocurre en segundo plano. Un analista lo descubre con herramientas "
         "de monitoreo. Esta actividad confirma qué hace la muestra y qué tan urgente es contenerla.",
         m3_monitor_done())
    if S["mon_idx"] == 0:
        st.button("▶️ Iniciar monitoreo en vivo", key="m3_mon_ini", on_click=m3_monitor_iniciar)
        return
    if not m3_monitor_done():
        st.button("⏭️ Mostrar toda la actividad de una vez", key="m3_mon_todo", on_click=m3_monitor_todo)
    render_monitor()
    if not m3_monitor_done():
        return

    st.warning("**Resumen de lo observado:** la muestra se copió a sí misma en 3 ubicaciones (todas con el mismo "
               "SHA-256), lanzó una segunda instancia, hizo una consulta DNS por **UDP**, abrió conexiones **TCP** "
               "hacia dos servidores externos, dejó el **puerto 8081 en escucha** y envió **412 KB** de datos.")

    ok_mon = pregunta(
        "m3mon",
        "Según el monitor, ¿qué puerto dejó abierto en escucha (LISTENING) la segunda instancia del malware?",
        ["53/UDP", "443/TCP", "8081/TCP", "3389/TCP"],
        "8081/TCP",
        "La réplica PID 7390 abrió un proxy SOCKS en el puerto 8081 para que el atacante pueda usar el equipo "
        "como puente hacia la red interna. Es otro IOC que se debe bloquear y revisar en otros equipos.",
        {"53/UDP": "El 53/UDP es el de la consulta DNS, y es una conexión de salida, no un puerto en escucha.",
         "443/TCP": "El 443/TCP es el puerto remoto de los servidores C2, no uno abierto en el equipo.",
         "3389/TCP": "El 3389 es Escritorio Remoto y no aparece en el monitor."},
    )
    if not ok_mon:
        return

    # ---------- PASO 3 ----------
    paso(3, "Encuentra la persistencia (Autoruns)",
         "Revisa los programas que arrancan solos con Windows. Compara el <b>editor</b>, la <b>firma digital</b> "
         "y la <b>ruta</b> de cada uno. Elige la entrada maliciosa y presiona <b>Confirmar</b>.",
         "La persistencia es el truco que usa el malware para volver a ejecutarse cada vez que se reinicia el "
         "equipo. Si solo matas el proceso y no quitas la persistencia, regresa en el siguiente arranque.",
         S["ar_ok"])
    titulo("🚀 Autoruns · Inicio automático", hint(
        "Señales de alerta",
        "Desconfía de entradas <b>sin firma digital</b>, que viven en <b>AppData</b> o carpetas temporales, "
        "o que lanzan <b>PowerShell oculto</b>, sobre todo si su nombre imita algo de Windows."))
    filas_ar, clases_ar = [], []
    for a in AUTORUNS:
        estado = ""
        if a.get("malo"):
            estado = "ELIMINADA" if S["persist"] else ("Sospechosa" if S["ar_ok"] else "")
        filas_ar.append([f"<b>{e(a['entrada'])}</b>", e(a["ubicacion"]),
                         f'<span style="word-break:break-all;">{e(a["imagen"])}</span>', e(a["editor"]),
                         e(a["firmado"]), estado])
        if a.get("malo") and S["persist"]:
            clases_ar.append("muerto")
        elif a.get("malo") and S["ar_ok"]:
            clases_ar.append("sus")
        else:
            clases_ar.append("")
    tabla(["Entrada", "Ubicación", "Imagen / comando", "Editor", "Firma", "Estado"], filas_ar, clases_ar)

    if not S["ar_ok"]:
        sel = st.radio("¿Cuál entrada es la persistencia del malware?", [a["entrada"] for a in AUTORUNS],
                       index=None, key="m3_ar_sel")
        if st.button("Confirmar entrada", key="m3_ar_btn", disabled=sel is None):
            S["ar_int"] += 1
            if sel == "WindowsUpdateHelper":
                S["ar_ok"], S["ar_fail"] = True, None
            else:
                S["ar_fail"] = sel
            st.rerun()
        if S["ar_fail"]:
            st.error(f"**{S['ar_fail']}** es legítima. {FALLOS_AR.get(S['ar_fail'], '')}")
        return
    st.success("Correcto: **WindowsUpdateHelper**. Se hace pasar por Windows Update, pero no tiene firma, vive en "
               "**AppData** y lanza **PowerShell oculto** sobre una de las copias que viste en el monitor.")

    # ---------- PASO 4 ----------
    paso(4, "Contén la amenaza en el orden correcto",
         "Usa los tres botones de respuesta. <b>Piensa el orden antes de hacer clic</b>: cada decisión "
         "tiene consecuencias y se registra en la bitácora. Observa cómo cambian el árbol de procesos y el monitor.",
         "En respuesta a incidentes primero se <b>contiene</b> (aislar), luego se <b>erradica</b> "
         "(terminar los procesos y eliminar la persistencia y las copias). Un orden incorrecto puede dejar que el "
         "malware siga robando datos o que se reinstale solo.",
         m3_done())
    b1, b2, b3 = st.columns(3)
    with b1:
        st.button("🔌 Aislar equipo de la red", key="m3_aislar", on_click=m3_aislar, disabled=S["aislado"])
    with b2:
        st.button("⛔ Terminar árbol de procesos (PID 7344)", key="m3_terminar", on_click=m3_terminar,
                  disabled=S["terminado"])
    with b3:
        st.button("🗑️ Eliminar persistencia y copias", key="m3_persist", on_click=m3_persistencia,
                  disabled=S["persist"])

    if S["log"]:
        titulo("📜 Bitácora de respuesta")
        st.code("\n".join(f"[{i + 1}] {x}" for i, x in enumerate(S["log"])), language=None)
        titulo("📡 Estado actual del equipo")
        render_monitor_contenido()
    for err in S["errores"]:
        st.warning(f"**Lección:** {err}")

    if m3_done():
        if S["errores"]:
            st.info("Amenaza contenida, aunque el orden no fue el ideal. El orden recomendado es: "
                    "**1) aislar el equipo, 2) terminar los procesos, 3) eliminar la persistencia y las copias.**")
        else:
            st.success("Amenaza contenida en el orden ideal: aislaste, terminaste los procesos y eliminaste la "
                       "persistencia y las copias. Así trabaja un equipo de respuesta a incidentes.")
    boton_siguiente(2, m3_done())


# =========================================================
# MÓDULO 4 · SANDBOX, CLASIFICACIÓN Y REPORTE
# =========================================================
SANDBOX_EVENTOS = [
    ("00:00.2", "Proceso", "explorer.exe crea powershell.exe con ventana oculta y -ExecutionPolicy Bypass"),
    ("00:00.6", "Réplica", "Se copia a %APPDATA%\\Microsoft\\wuhelper\\wuhelper.ps1 y a %TEMP%\\tmp4F2A.ps1"),
    ("00:00.9", "Proceso", "Lanza una segunda instancia de sí mismo (powershell.exe -File %TEMP%\\tmp4F2A.ps1)"),
    ("00:01.1", "Registro", "Escribe HKCU\\...\\CurrentVersion\\Run\\WindowsUpdateHelper"),
    ("00:01.3", "Red", "UDP: consulta DNS de nightcrow-c2.example"),
    ("00:01.6", "Red", "TCP: conexión establecida con 203.0.113.47:443"),
    ("00:02.0", "Archivo", "Lee %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data"),
    ("00:02.2", "Archivo", "Lee %APPDATA%\\Mozilla\\Firefox\\Profiles\\*\\logins.json"),
    ("00:02.3", "Archivo", "Lee %APPDATA%\\Exodus\\exodus.wallet y %APPDATA%\\Telegram Desktop\\tdata"),
    ("00:02.7", "Red", "Abre el puerto 8081/TCP en escucha (proxy SOCKS)"),
    ("00:03.0", "Réplica", "Se copia a %PUBLIC%\\Libraries\\desktop.ps1"),
    ("00:03.4", "Red", "TCP: intento de conexión a 198.51.100.23:443 (nodo alterno)"),
    ("00:03.9", "Red", "POST /gate.php?id=NC-LAB-0007&type=creds hacia 203.0.113.47:443 (412 KB)"),
]

FAMILIAS = ["Troyano bancario", "Ransomware", "Gusano", "Infostealer"]
FALLOS_FAM = {
    "Troyano bancario": "No hay inyección en páginas de bancos ni ventanas falsas de banca en línea. "
                        "Roba credenciales en general, no solo bancarias.",
    "Ransomware": "No cifra archivos, no cambia extensiones y no deja nota de rescate.",
    "Gusano": "Ojo con esta confusión: la muestra sí se copió a sí misma, pero solo dentro del mismo equipo "
              "(para esconderse y persistir). Un gusano se propaga a OTROS equipos por la red, USB o carpetas "
              "compartidas, y aquí no hay escaneo de red ni intentos de infectar otras máquinas.",
}

IOCS = [
    ("Hash SHA-256", SAMPLE_HASHES["SHA-256"]),
    ("Hash MD5", SAMPLE_HASHES["MD5"]),
    ("Nombre de archivo", "Factura_Noviembre_2026.pdf.ps1"),
    ("Dominio C2", "nightcrow-c2.example"),
    ("URL C2", "hxxps://nightcrow-c2.example/gate.php"),
    ("IP C2 (respaldo)", "203.0.113.47:443"),
    ("IP nodo de exfiltración", "198.51.100.23:443"),
    ("Puerto en escucha", "8081/TCP (proxy SOCKS)"),
    ("Clave de registro", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateHelper"),
    ("Archivo de persistencia", r"%APPDATA%\Microsoft\wuhelper\wuhelper.ps1"),
    ("Copia del script", r"%TEMP%\tmp4F2A.ps1"),
    ("Copia del script", r"%PUBLIC%\Libraries\desktop.ps1"),
    ("User-Agent", "Mozilla/5.0 (NightCrow)"),
]

ATTACK = [
    ("T1036.007", "Enmascaramiento: doble extensión", "Factura...pdf.ps1"),
    ("T1059.001", "Intérprete de comandos: PowerShell", "powershell.exe -NoP -W Hidden"),
    ("T1027", "Ofuscación de archivos o información", "Comando en Base64 con -enc"),
    ("T1555.003", "Credenciales de navegadores web", "Login Data de Chrome, logins.json de Firefox"),
    ("T1547.001", "Persistencia: claves Run del registro", "Run\\WindowsUpdateHelper"),
    ("T1090", "Proxy", "Puerto 8081/TCP en escucha (SOCKS)"),
    ("T1041", "Exfiltración por el canal de C2", "POST de 412 KB a /gate.php"),
]

RECOMENDACIONES = [
    "Mantener aislado EQUIPO-07 hasta completar el análisis y, de preferencia, reinstalar el sistema.",
    "Restablecer todas las contraseñas guardadas en los navegadores del usuario y activar doble factor.",
    "Cerrar todas las sesiones activas de mensajería (Telegram) y correo del usuario.",
    "Si había carteras de criptomonedas, mover los fondos a una cartera nueva desde un equipo limpio.",
    "Bloquear el dominio, la URL y las IP 203.0.113.47 y 198.51.100.23 en firewall, proxy y DNS.",
    "Revisar en toda la red si algún equipo tiene el puerto 8081/TCP en escucha.",
    "Buscar el hash SHA-256, sus copias y la clave de registro en todos los equipos de la organización.",
    "Bloquear la ejecución de scripts .ps1 descargados de correo y mostrar extensiones en Windows.",
    "Reforzar la concientización sobre adjuntos con doble extensión.",
]


def m4_desempeno():
    """Calcula el desempeño del analista con base en los primeros intentos y la respuesta."""
    qs = st.session_state.qs
    S3, S4 = st.session_state.m3, st.session_state.m4
    items = [
        ("Módulo 1 · Pregunta de verificación", qs.get("m1", {}).get("intentos", 0) == 1),
        ("Módulo 2 · Pregunta de verificación", qs.get("m2", {}).get("intentos", 0) == 1),
        ("Módulo 3 · Proceso malicioso", S3["proc_int"] == 1),
        ("Módulo 3 · Puerto en escucha", qs.get("m3mon", {}).get("intentos", 0) == 1),
        ("Módulo 3 · Persistencia", S3["ar_int"] == 1),
        ("Módulo 4 · Clasificación de familia", S4["fam_int"] == 1),
    ]
    puntos = sum(12 for _, ok in items if ok)
    errores = len(S3["errores"])
    respuesta = 28 if errores == 0 else (14 if errores == 1 else 0)
    return items, respuesta, errores, puntos + respuesta


def _t(s):
    """Texto seguro para las fuentes base del PDF (latin-1)."""
    reemplazos = {"✔": "OK", "✘": "X", "→": "->", "└─": "", "·": "-", "⚠️": "!", "…": "..."}
    s = str(s)
    for a, b in reemplazos.items():
        s = s.replace(a, b)
    return s.encode("latin-1", "replace").decode("latin-1")


class ReportePDF(FPDF):
    def footer(self):
        self.set_y(-13)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(130, 130, 130)
        self.cell(0, 8, _t(f"SOC Malware Forensics Lab - Laboratorio de capacitación con datos simulados - "
                           f"Página {self.page_no()}"), align="C")


def generar_pdf():
    items, respuesta, errores, total = m4_desempeno()
    S3 = st.session_state.m3
    pdf = ReportePDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(16, 16, 16)
    pdf.add_page()
    NAVY = (13, 42, 74)

    def h2(texto):
        # Evita que un título quede solo al final de la página
        if pdf.get_y() > pdf.h - 45:
            pdf.add_page()
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(*NAVY)
        pdf.cell(0, 8, _t(texto), new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(200, 205, 212)
        pdf.set_line_width(0.3)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(2)

    def parrafo(texto, size=10, color=(40, 40, 40), estilo=""):
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", estilo, size)
        pdf.set_text_color(*color)
        pdf.multi_cell(0, 5, _t(texto), new_x="LMARGIN", new_y="NEXT")

    def fila(clave, valor, mono=False, ancho=48):
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(ancho, 5.5, _t(clave))
        pdf.set_font("Courier" if mono else "Helvetica", "", 8.5 if mono else 9)
        pdf.set_text_color(30, 30, 30)
        pdf.multi_cell(0, 5.5, _t(valor), new_x="LMARGIN", new_y="NEXT")

    # Encabezado
    pdf.set_font("Helvetica", "B", 17)
    pdf.set_text_color(*NAVY)
    pdf.cell(0, 10, _t("Reporte de Triaje Forense"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(90, 90, 90)
    pdf.cell(0, 6, _t(f"Incidente: NightCrow Stealer en EQUIPO-07  |  Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M')}"),
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "I", 8.5)
    pdf.set_text_color(120, 120, 120)
    pdf.multi_cell(0, 4.5, _t("Documento generado en un laboratorio de capacitación. Todos los datos son "
                              "simulados y no corresponden a un incidente real."), new_x="LMARGIN", new_y="NEXT")

    h2("1. Resumen ejecutivo")
    parrafo("Un usuario abrió un adjunto de correo llamado Factura_Noviembre_2026.pdf.ps1, que se hacía pasar "
            "por un PDF mediante doble extensión. El archivo es un script de PowerShell de la familia "
            "NightCrow Stealer (infostealer), diseñado para robar contraseñas de navegadores, carteras de "
            "criptomonedas y sesiones de mensajería, y enviarlas a un servidor de comando y control. "
            "Se copió a sí mismo en 3 ubicaciones, abrió el puerto 8081/TCP como proxy y envió 412 KB de datos. "
            "El equipo fue aislado, el proceso terminado y la persistencia eliminada.")
    fila("Severidad", "ALTA")
    fila("Puntuación de riesgo", "9.5 / 10")
    fila("Familia", "Infostealer - NightCrow Stealer")
    fila("Equipo afectado", "EQUIPO-07 (usuario01)")
    fila("Estado", "Contenido")

    h2("2. Identificación del archivo")
    fila("Nombre", "Factura_Noviembre_2026.pdf.ps1")
    fila("Tipo real", "Script de PowerShell (extensión aparente .pdf)")
    fila("Tamaño", f"{len(SAMPLE_BYTES):,} bytes")
    fila("MD5", SAMPLE_HASHES["MD5"], mono=True)
    fila("SHA-1", SAMPLE_HASHES["SHA-1"], mono=True)
    fila("SHA-256", SAMPLE_HASHES["SHA-256"], mono=True)
    fila("Inteligencia", "47 / 70 motores lo detectan (consulta simulada)")

    h2("3. Indicadores de compromiso (IOC)")
    for k, v in IOCS:
        fila(k, v, mono=True)

    h2("4. Técnicas MITRE ATT&CK observadas")
    for tid, nombre, evidencia in ATTACK:
        fila(tid, f"{nombre}. Evidencia: {evidencia}")

    h2("5. Acciones de contención realizadas")
    for i, x in enumerate(S3["log"], 1):
        parrafo(f"{i}. {x}", size=9)
    if S3["errores"]:
        parrafo("Observaciones sobre el orden de respuesta:", size=9, estilo="B")
        for err in S3["errores"]:
            parrafo(f"- {err}", size=9)

    h2("6. Recomendaciones")
    for r in RECOMENDACIONES:
        parrafo(f"- {r}", size=9.5)

    h2("7. Desempeño del analista en el laboratorio")
    for nombre, ok in items:
        fila(nombre, "Acierto al primer intento" if ok else "Requirió más de un intento", ancho=78)
    fila("Respuesta a incidentes", f"{respuesta} / 28 puntos ({errores} error(es) de orden)", ancho=78)
    fila("Puntuación total", f"{total} / 100", ancho=78)

    return bytes(pdf.output())


def render_m4():
    S = st.session_state.m4
    encabezado(4, "Sandboxing y Clasificación por Familias (El Reporte Forense)")
    mision(
        "La amenaza está contenida. Ahora vas a <b>detonar la muestra en una sandbox</b> para confirmar su "
        "comportamiento, <b>clasificarla</b> en una familia de malware con base en toda la evidencia y "
        "<b>entregar el reporte</b> al equipo de respuesta a incidentes.",
        "10 minutos",
        ["Qué es una sandbox y por qué se usa.",
         "Cómo se distinguen las familias de malware por su comportamiento.",
         "Qué contiene un reporte de triaje: severidad, IOC, técnicas ATT&CK y recomendaciones."],
    )

    # ---------- PASO 1 ----------
    paso(1, "Detona la muestra en la sandbox",
         "Presiona <b>Detonar en sandbox</b> y revisa la línea de tiempo de lo que hizo la muestra.",
         "Una sandbox es un equipo virtual aislado y desechable donde se ejecuta el malware a propósito para "
         "observarlo sin poner en riesgo la red real. Es el complemento del análisis estático.",
         S["sandbox"])
    if not S["sandbox"]:
        if st.button("🧪 Detonar en sandbox (simulación)", key="m4_sandbox"):
            barra = st.progress(0, text="Preparando máquina virtual aislada...")
            textos = ["Preparando máquina virtual aislada...", "Copiando la muestra...",
                      "Ejecutando y monitoreando procesos, archivos, registro y red...", "Generando reporte..."]
            for i in range(20):
                time.sleep(0.12)
                barra.progress((i + 1) / 20, text=textos[min(i // 5, 3)])
            S["sandbox"] = True
            st.rerun()
        return

    titulo("🧫 Comportamiento observado en la sandbox", hint(
        "Cómo leerlo", "Cada fila es una acción de la muestra, con el tiempo desde que inició. "
        "Fíjate en <b>qué archivos lee</b>: son la clave para saber a qué familia pertenece."))
    colores = {"Proceso": "#f85149", "Archivo": "#58a6ff", "Registro": "#db6d28", "Red": "#e3b341",
               "Réplica": "#a371f7"}
    tabla(["Tiempo", "Tipo", "Acción"],
          [[t, f'<span style="color:{colores[tipo]};font-weight:bold;">{tipo}</span>', e(acc)]
           for t, tipo, acc in SANDBOX_EVENTOS])

    # ---------- PASO 2 ----------
    paso(2, "Clasifica la familia de malware",
         "Con todo lo que encontraste (cadenas, procesos, persistencia y sandbox), elige a qué familia pertenece "
         "la muestra y presiona <b>Confirmar clasificación</b>.",
         "Clasificar bien define la respuesta: un ransomware exige restaurar respaldos, mientras que un "
         "infostealer exige cambiar contraseñas y cerrar sesiones de inmediato.",
         S["fam_ok"])
    titulo("📚 Guía rápida de familias", hint(
        "Pista", "Pregúntate: ¿qué <b>busca</b> el malware en el equipo y qué <b>hace</b> con eso?"))
    tabla(["Familia", "Qué hace", "Señal típica"], [
        ["Troyano bancario", "Roba acceso a banca en línea", "Ventanas falsas sobre páginas de bancos"],
        ["Ransomware", "Cifra archivos y pide rescate", "Extensiones cambiadas y nota de rescate"],
        ["Gusano", "Se copia solo a otros equipos", "Escaneo de red, carpetas compartidas, USB"],
        ["Infostealer", "Roba información guardada y la envía", "Lee contraseñas, carteras y sesiones; las sube al C2"],
    ])
    if not S["fam_ok"]:
        sel = st.radio("¿A qué familia pertenece NightCrow?", FAMILIAS, index=None, key="m4_fam_sel",
                       horizontal=True)
        if st.button("Confirmar clasificación", key="m4_fam_btn", disabled=sel is None):
            S["fam_int"] += 1
            if sel == "Infostealer":
                S["fam_ok"], S["fam_fail"] = True, None
            else:
                S["fam_fail"] = sel
            st.rerun()
        if S["fam_fail"]:
            st.error(f"**{S['fam_fail']}** no es. {FALLOS_FAM.get(S['fam_fail'], '')}")
        return
    st.success("Correcto: **Infostealer**. Lee contraseñas de navegadores, carteras de criptomonedas y sesiones "
               "de Telegram, y las envía al C2 con un POST. No cifra, no se propaga y no ataca solo a bancos.")

    # ---------- PASO 3 ----------
    paso(3, "Revisa el reporte de triaje ejecutivo",
         "Lee el reporte completo: severidad, indicadores, técnicas ATT&CK y recomendaciones.",
         "Este es el entregable que recibe el equipo de respuesta a incidentes y la dirección. Debe poder "
         "leerse rápido y servir para actuar.",
         True)
    st.markdown("""
<div class="lab-card rojo">
  <span class="badge mal">SEVERIDAD ALTA</span>
  <span class="badge pend" style="margin-left:8px;">ESTADO: CONTENIDO</span>
  <p style="margin:10px 0 0 0;">Infostealer <b>NightCrow Stealer</b> ejecutado en <b>EQUIPO-07</b> desde un
  adjunto con doble extensión. Robo potencial de credenciales de navegador, carteras de criptomonedas y
  sesiones de mensajería. Se replicó en 3 ubicaciones del equipo, abrió el puerto 8081/TCP como proxy y
  exfiltró 412 KB hacia un servidor de comando y control.</p>
</div>
""", unsafe_allow_html=True)
    items, respuesta, errores, total = m4_desempeno()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Severidad", "ALTA")
    c2.metric("Riesgo", "9.5 / 10")
    c3.metric("IOC identificados", len(IOCS))
    c4.metric("Tu puntuación", f"{total} / 100")

    titulo("🎯 Indicadores de compromiso (IOC)")
    tabla(["Tipo", "Valor"], [[e(k), e(v)] for k, v in IOCS])
    titulo("🧭 Técnicas MITRE ATT&CK", hint(
        "¿Qué es ATT&CK?", "Es un catálogo público de técnicas de ataque. Usar sus códigos permite que "
        "cualquier equipo de seguridad entienda el reporte con el mismo lenguaje."))
    tabla(["ID", "Técnica", "Evidencia"], [[e(a), e(b), e(c)] for a, b, c in ATTACK])
    titulo("🛠️ Recomendaciones")
    st.markdown("\n".join(f"- {r}" for r in RECOMENDACIONES))
    titulo("📈 Tu desempeño")
    tabla(["Actividad", "Resultado"],
          [[e(n), "✔ Al primer intento" if ok else "Requirió más de un intento"] for n, ok in items]
          + [["Respuesta a incidentes (orden)", f"{respuesta} / 28 ({errores} error(es))"]],
          ["ok" if ok else "" for _, ok in items] + ["ok" if errores == 0 else ""])

    # ---------- PASO 4 ----------
    paso(4, "Exporta el reporte",
         "Presiona <b>Descargar reporte (PDF)</b>. El documento tiene formato sobrio, listo para compartirse "
         "con el equipo de respuesta a incidentes.",
         "Un hallazgo que no se documenta no existe para la organización. El reporte deja constancia de lo "
         "que pasó, lo que se hizo y lo que falta por hacer.",
         st.session_state.get("m4_descargado", False))
    st.download_button(
        "⬇️ Descargar reporte (PDF)",
        data=generar_pdf(),
        file_name="reporte_triaje_nightcrow.pdf",
        mime="application/pdf",
        key="m4_pdf",
        on_click=lambda: st.session_state.update(m4_descargado=True),
    )
    st.success("🎓 **Laboratorio completado.** Recorriste el ciclo completo de un analista: identificar, "
               "analizar, contener, clasificar y reportar.")


# =========================================================
# MÚSICA DE AMBIENTE
# =========================================================
BGM_JS = """
<script>
  const P = window.parent, d = P.document;
  P.__bgm = {on: __ON__, vol: __VOL__};
  function aplicar(intentarPlay) {
    const a = d.querySelector('.st-key-bgm audio');
    if (!a) return false;
    a.loop = true;
    a.volume = P.__bgm.vol;
    a.muted = !P.__bgm.on;
    if (!P.__bgm.on) { a.pause(); }
    else if (intentarPlay && a.paused) { a.play().catch(() => {}); }
    return true;
  }
  // Los navegadores no dejan reproducir audio hasta que el usuario interactúa con la página:
  // la música arranca con el primer clic o tecla en cualquier parte de la app.
  if (!P.__bgmListener) {
    P.__bgmListener = true;
    d.addEventListener('click', () => aplicar(true), true);
    d.addEventListener('keydown', () => aplicar(true), true);
  }
  let n = 0;
  const iv = setInterval(() => { if (aplicar(true) || ++n > 40) clearInterval(iv); }, 250);
</script>
"""


def render_musica():
    """Reproductor oculto en bucle + controles de silencio y volumen en la barra lateral."""
    ruta = next((os.path.join(BASE_DIR, c) for c in BGM_CANDIDATOS
                 if os.path.exists(os.path.join(BASE_DIR, c))), None)
    if ruta is None:
        st.markdown("**🎵 Música de ambiente**")
        st.caption("No se encontró `assets/sound2.mp4`.")
        return
    # El reproductor va primero y siempre en el mismo lugar, para que la canción no se reinicie
    # al cambiar de módulo ni al mover los controles. Silencio y volumen se aplican con JavaScript.
    with st.container(key="bgm"):
        mime = "audio/mpeg" if ruta.lower().endswith(".mp3") else "audio/mp4"
        st.audio(ruta, format=mime, loop=True)
    st.markdown("**🎵 Música de ambiente**")
    st.toggle("Reproducir música", key="bgm_on", help="Apágalo para silenciar la música.")
    st.slider("Volumen", 0, 10, key="bgm_vol", disabled=not st.session_state.bgm_on)
    st.caption("La música inicia con tu primer clic en la página.")
    on = "true" if st.session_state.bgm_on else "false"
    vol = round(st.session_state.bgm_vol / 10, 2)
    components.html(BGM_JS.replace("__ON__", on).replace("__VOL__", str(vol)), height=0)


# =========================================================
# BARRA LATERAL Y ENRUTADO
# =========================================================
DONE_FNS = [m1_done, m2_done, m3_done, lambda: st.session_state.m4["fam_ok"]]

with st.sidebar:
    st.markdown("## 🧬 SOC // Malware Forensics")
    completados = sum(1 for f in DONE_FNS if f())
    st.progress(completados / len(MODULES), text=f"Progreso: {completados} de {len(MODULES)} módulos")
    for i, nombre in enumerate(MODULES):
        bloqueado = i > st.session_state.unlocked
        icono = "✅" if DONE_FNS[i]() else ("🔒" if bloqueado else ("▶️" if i == st.session_state.mod else "○"))
        st.button(f"{icono} {nombre}", key=f"nav_{i}", disabled=bloqueado, on_click=ir_a, args=(i,))
    st.caption("Los módulos se desbloquean al completar el anterior.")
    st.toggle("Modo aprendizaje (pistas ?)", key="learning")
    render_musica()
    with st.expander("📖 Glosario"):
        st.markdown("""
- **Hash:** huella digital única del contenido de un archivo.
- **SHA-256:** algoritmo de hash estándar actual para identificar malware.
- **Firma mágica:** primeros bytes que indican el tipo real de archivo.
- **Strings:** cadenas de texto legibles dentro de un archivo.
- **IOC:** indicador de compromiso (IP, dominio, hash, clave de registro).
- **C2:** servidor de comando y control del atacante.
- **Base64:** codificación que convierte datos en texto; se usa para esconder comandos.
- **Persistencia:** técnica para volver a ejecutarse tras un reinicio.
- **Sandbox:** entorno aislado y desechable para ejecutar malware sin riesgo.
- **Infostealer:** malware que roba información guardada y la envía al atacante.
- **MITRE ATT&CK:** catálogo público de técnicas de ataque.
""")
    with st.expander("Herramientas del presentador"):
        st.button("Reiniciar laboratorio", on_click=reiniciar_laboratorio, key="reset_lab")
        if st.button("Desbloquear todos los módulos", key="unlock_all"):
            st.session_state.unlocked = len(MODULES) - 1
            st.rerun()
    st.caption("Todos los datos de este laboratorio son simulados. Ningún archivo se ejecuta "
               "y no se permite subir archivos.")

RENDERS = [render_m1, render_m2, render_m3, render_m4]
RENDERS[st.session_state.mod]()