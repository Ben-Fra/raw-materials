from pathlib import Path
import base64, hashlib, hmac, json, os, time, sqlite3
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo


import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

# ─── CONFIG ───────────────────────────────────────────────────────────────────

BASE_DIR      = Path(__file__).parent
DATABASE_URL  = os.environ.get("DATABASE_URL", "")
APP_TZ        = ZoneInfo("Asia/Jerusalem")
UTC_TZ        = ZoneInfo("UTC")
AUTH_DAYS     = 30
STATIC_BASE   = "/app/static"
PRODUCTS_PATH = BASE_DIR / "products.csv"

def _load_materials():
    import csv
    path = BASE_DIR / "materials.csv"
    mapping = {}
    if path.exists():
        with open(path, encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                heb = row.get("hebrew", "").strip()
                rus = row.get("russian", "").strip()
                if heb:
                    mapping[heb] = rus
    return mapping

MATERIALS_MAP = _load_materials()   # {hebrew: russian}
RAW_MATERIALS = sorted(MATERIALS_MAP.keys()) if MATERIALS_MAP else []

def material_display(heb):
    """Показывает русское название + иврит в скобках."""
    rus = MATERIALS_MAP.get(heb, "")
    return f"{rus}  |  {heb}" if rus else heb


def _load_packaging_items():
    import csv
    path = BASE_DIR / "packaging_items.csv"
    items = []
    if path.exists():
        with open(path, encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get("name", "").strip()
                unit = row.get("unit", "шт").strip()
                article = row.get("article", "").strip()
                if name:
                    items.append({"name": name, "unit": unit, "article": article})
    return items

PACKAGING_ITEMS      = _load_packaging_items()
PACKAGING_ITEMS_NAMES = [x["name"] for x in PACKAGING_ITEMS]
# unit lookup by name
PACKAGING_ITEMS_UNIT  = {x["name"]: x["unit"] for x in PACKAGING_ITEMS}

SUPPLIERS = ["גו פיש", "לנדוי", "צ'ירינה"]

FG_PRODUCT_COLUMNS = ["id", "hebrew_name", "unit_weight", "tare_weight", "russian_name"]

def _to_number(series):
    return pd.to_numeric(
        series.astype(str).str.replace(",", ".", regex=False).str.strip(),
        errors="coerce",
    )

def _normalize_products(df):
    if df.empty or len(df.columns) < 5:
        return pd.DataFrame(columns=FG_PRODUCT_COLUMNS)
    products = df.iloc[:, :5].copy()
    products.columns = FG_PRODUCT_COLUMNS
    products = products.dropna(how="all")
    products["id"] = products["id"].astype(str).str.strip().str.replace(r"\.0$", "", regex=True)
    products["hebrew_name"]  = products["hebrew_name"].astype(str).str.strip()
    products["russian_name"] = products["russian_name"].astype(str).str.strip()
    products["unit_weight"]  = _to_number(products["unit_weight"]).fillna(0)
    products["tare_weight"]  = _to_number(products["tare_weight"]).fillna(0)
    header_like = products["id"].str.lower().isin(["id", "id номер", "номер"])
    products = products[~header_like]
    products = products[
        (products["id"] != "") & (products["id"].str.lower() != "nan") &
        (products["hebrew_name"] != "") & (products["hebrew_name"].str.lower() != "nan") &
        (products["russian_name"] != "") & (products["russian_name"].str.lower() != "nan")
    ]
    return products.reset_index(drop=True)

def load_products_from_csv():
    if not PRODUCTS_PATH.exists():
        PRODUCTS_PATH.write_text("id,hebrew_name,unit_weight,tare_weight,russian_name\n", encoding="utf-8")
    try:
        df = pd.read_csv(PRODUCTS_PATH, header=None, encoding="utf-8-sig")
    except pd.errors.EmptyDataError:
        return pd.DataFrame(columns=FG_PRODUCT_COLUMNS)
    return _normalize_products(df)

def sync_products_to_db(products):
    for product in products.to_dict("records"):
        db_run(
            """INSERT INTO fg_products (id, hebrew_name, unit_weight, tare_weight, russian_name)
               VALUES (?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                   hebrew_name=excluded.hebrew_name,
                   unit_weight=excluded.unit_weight,
                   tare_weight=excluded.tare_weight,
                   russian_name=excluded.russian_name""",
            (product["id"], product["hebrew_name"],
             float(product["unit_weight"]), float(product["tare_weight"]),
             product["russian_name"]),
        )

PACKAGING_UNITS = ["шт", "кг", "упаковка", "л", "литр", "пакет", "рулон", "коробка", "мешок", "м"]

# ─── AUTH ─────────────────────────────────────────────────────────────────────

def load_users():
    env = os.environ.get("APP_USERS_JSON")
    if env:
        return json.loads(env)
    try:
        s = st.secrets.get("users", {})
        if s:
            return dict(s)
    except Exception:
        pass
    return {"Alexander": "", "Oleg": "", "Admin": ""}


USERS = load_users()
_SECRET = (
    os.environ.get("APP_AUTH_SECRET")
    or os.environ.get("APP_USERS_JSON")
    or json.dumps(USERS, sort_keys=True)
)


def _b64enc(payload):
    return base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ).decode().rstrip("=")


def _b64dec(text):
    pad = "=" * (-len(text) % 4)
    return json.loads(base64.urlsafe_b64decode((text + pad).encode()))


def _sign(text):
    return hmac.new(_SECRET.encode(), text.encode(), hashlib.sha256).hexdigest()


def make_token(username):
    p = _b64enc({"username": username, "expires_at": int(time.time()) + AUTH_DAYS * 86400})
    return f"{p}.{_sign(p)}"


def check_token(token):
    if not token or "." not in token:
        return None
    text, sig = token.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(text)):
        return None
    try:
        p = _b64dec(text)
    except Exception:
        return None
    u = p.get("username")
    if u not in USERS or p.get("expires_at", 0) < int(time.time()):
        return None
    return u

# ─── DATABASE ─────────────────────────────────────────────────────────────────

def _conn():
    if DATABASE_URL:
        import psycopg2
        return psycopg2.connect(DATABASE_URL), True
    c = sqlite3.connect(str(BASE_DIR / "raw_materials.db"), check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c, False


def db_query(sql, params=()):
    conn, is_pg = _conn()
    if is_pg:
        sql = sql.replace("?", "%s")
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        if cur.description is None:
            return []
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        conn.close()


def db_run(sql, params=()):
    conn, is_pg = _conn()
    if is_pg:
        sql = sql.replace("?", "%s")
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def init_db():
    conn, is_pg = _conn()
    pk  = "SERIAL PRIMARY KEY" if is_pg else "INTEGER PRIMARY KEY AUTOINCREMENT"
    now = "NOW()" if is_pg else "datetime('now')"
    stmts = [
        f"""CREATE TABLE IF NOT EXISTS raw_receipts (
            id {pk},
            receipt_date TEXT NOT NULL,
            order_number TEXT NOT NULL,
            supplier TEXT NOT NULL,
            material TEXT NOT NULL,
            quantity_kg REAL NOT NULL,
            price_per_kg REAL,
            total_price REAL,
            production_date TEXT,
            expiry_date TEXT,
            created_at TEXT DEFAULT ({now}),
            created_by TEXT NOT NULL DEFAULT 'unknown'
        )""",
        f"""CREATE TABLE IF NOT EXISTS production_writeoffs (
            id {pk},
            receipt_id INTEGER NOT NULL,
            material TEXT NOT NULL,
            supplier TEXT NOT NULL,
            quantity_kg REAL NOT NULL,
            writeoff_date TEXT NOT NULL,
            batch_number TEXT,
            notes TEXT,
            created_at TEXT DEFAULT ({now}),
            created_by TEXT NOT NULL DEFAULT 'unknown'
        )""",
        f"""CREATE TABLE IF NOT EXISTS packaging_receipts (
            id {pk},
            receipt_date TEXT NOT NULL,
            item_name TEXT NOT NULL,
            quantity REAL NOT NULL,
            unit TEXT NOT NULL,
            price_per_unit REAL,
            total_price REAL,
            supplier TEXT,
            notes TEXT,
            created_at TEXT DEFAULT ({now}),
            created_by TEXT NOT NULL DEFAULT 'unknown'
        )""",
        f"""CREATE TABLE IF NOT EXISTS production_finished_transfers (
            id {pk},
            production_writeoff_id INTEGER NOT NULL,
            material TEXT NOT NULL,
            supplier TEXT NOT NULL,
            quantity_kg REAL NOT NULL,
            transfer_date TEXT NOT NULL,
            finished_goods_receipt_id INTEGER,
            notes TEXT,
            created_at TEXT DEFAULT ({now}),
            created_by TEXT NOT NULL DEFAULT 'unknown'
        )""",
        f"""CREATE TABLE IF NOT EXISTS fg_products (
            id TEXT PRIMARY KEY,
            hebrew_name TEXT NOT NULL,
            unit_weight REAL NOT NULL DEFAULT 0,
            tare_weight REAL NOT NULL DEFAULT 0,
            russian_name TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS fg_receipts (
            id {pk},
            product_id TEXT NOT NULL,
            hebrew_name TEXT NOT NULL,
            russian_name TEXT NOT NULL,
            unit_weight REAL NOT NULL DEFAULT 0,
            tare_weight REAL NOT NULL DEFAULT 0,
            calculation_method TEXT NOT NULL DEFAULT 'tare',
            units_count INTEGER NOT NULL DEFAULT 0,
            cartons_count INTEGER NOT NULL DEFAULT 0,
            gross_weight REAL NOT NULL DEFAULT 0,
            net_weight REAL NOT NULL,
            receipt_date TEXT NOT NULL,
            created_at TEXT DEFAULT ({now}),
            created_by TEXT NOT NULL DEFAULT 'unknown'
        )""",
        f"""CREATE TABLE IF NOT EXISTS access_logs (
            id {pk},
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            created_at TEXT DEFAULT ({now})
        )""",
    ]
    try:
        cur = conn.cursor()
        for s in stmts:
            cur.execute(s)
        conn.commit()
        # Migration: add batch_number if column doesn't exist yet
        try:
            cur.execute("ALTER TABLE production_writeoffs ADD COLUMN batch_number TEXT")
            conn.commit()
        except Exception:
            pass  # column already exists
        # Migration: add delivery_code if column doesn't exist yet
        try:
            cur.execute("ALTER TABLE raw_receipts ADD COLUMN delivery_code TEXT")
            conn.commit()
        except Exception:
            pass  # column already exists
    finally:
        conn.close()

# ─── FINISHED GOODS HELPERS ───────────────────────────────────────────────────

def fg_calculation_method(product):
    if float(product["unit_weight"]) > 0:
        return "unit"
    if float(product["tare_weight"]) > 0:
        return "tare"
    return "missing"

def fg_product_label(product):
    method = fg_calculation_method(product)
    if method == "unit":
        detail = f'штука {float(product["unit_weight"]):.3f}'
    elif method == "tare":
        detail = f'тара {float(product["tare_weight"]):.3f}'
    else:
        detail = "нет веса"
    return f'{product["russian_name"]} | ID {product["id"]} | {detail}'

def get_fg_stock_summary():
    return db_query("""
        SELECT
            product_id AS id,
            russian_name,
            hebrew_name,
            SUM(units_count)  AS units_total,
            SUM(cartons_count) AS cartons_total,
            ROUND(CAST(SUM(gross_weight) AS NUMERIC) * 1000) / 1000 AS gross_total,
            ROUND(CAST(SUM(net_weight)   AS NUMERIC) * 1000) / 1000 AS net_total,
            MIN(receipt_date) AS first_date,
            MAX(receipt_date) AS last_date
        FROM fg_receipts
        GROUP BY product_id, russian_name, hebrew_name
        ORDER BY russian_name
    """)

def get_fg_receipts(limit=200):
    return db_query(f"""
        SELECT id, receipt_date, created_by, product_id,
               russian_name, hebrew_name, calculation_method,
               unit_weight, units_count, tare_weight, gross_weight,
               cartons_count, net_weight
        FROM fg_receipts
        ORDER BY receipt_date DESC, id DESC
        LIMIT {limit}
    """)

def save_fg_receipt(product, method, gross_weight, units_count, cartons_count,
                    net_weight, receipt_date, created_by):
    if is_pg := DATABASE_URL:
        sql = """INSERT INTO fg_receipts
                    (product_id, hebrew_name, russian_name, unit_weight, tare_weight,
                     calculation_method, units_count, cartons_count, gross_weight,
                     net_weight, receipt_date, created_by)
                 VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id"""
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        try:
            cur = conn.cursor()
            cur.execute(sql, (
                product["id"], product["hebrew_name"], product["russian_name"],
                float(product["unit_weight"]), float(product["tare_weight"]),
                method, int(units_count), int(cartons_count),
                float(gross_weight), float(net_weight),
                str(receipt_date), created_by,
            ))
            receipt_id = cur.fetchone()[0]
            conn.commit()
        finally:
            conn.close()
    else:
        conn = sqlite3.connect(str(BASE_DIR / "raw_materials.db"), check_same_thread=False)
        try:
            cur = conn.cursor()
            cur.execute("""INSERT INTO fg_receipts
                    (product_id, hebrew_name, russian_name, unit_weight, tare_weight,
                     calculation_method, units_count, cartons_count, gross_weight,
                     net_weight, receipt_date, created_by)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (
                product["id"], product["hebrew_name"], product["russian_name"],
                float(product["unit_weight"]), float(product["tare_weight"]),
                method, int(units_count), int(cartons_count),
                float(gross_weight), float(net_weight),
                str(receipt_date), created_by,
            ))
            receipt_id = cur.lastrowid
            conn.commit()
        finally:
            conn.close()
    return receipt_id

def get_production_stock():
    """Партии сырья, ещё не полностью переданные на склад ГП."""
    return db_query("""
        SELECT
            pw.id,
            pw.batch_number,
            pw.writeoff_date,
            pw.material,
            pw.supplier,
            rr.expiry_date,
            pw.quantity_kg - COALESCE(SUM(pft.quantity_kg), 0) AS available_kg
        FROM production_writeoffs pw
        JOIN raw_receipts rr ON rr.id = pw.receipt_id
        LEFT JOIN production_finished_transfers pft ON pft.production_writeoff_id = pw.id
        GROUP BY pw.id, pw.batch_number, pw.writeoff_date,
                 pw.material, pw.supplier, rr.expiry_date, pw.quantity_kg
        HAVING pw.quantity_kg - COALESCE(SUM(pft.quantity_kg), 0) > 0.001
        ORDER BY pw.writeoff_date ASC
    """)

def save_production_transfer(writeoff_id, material, supplier, quantity_kg,
                              transfer_date, fg_receipt_id, created_by):
    db_run(
        """INSERT INTO production_finished_transfers
            (production_writeoff_id, material, supplier, quantity_kg,
             transfer_date, finished_goods_receipt_id, created_by)
           VALUES (?,?,?,?,?,?,?)""",
        (writeoff_id, material, supplier, quantity_kg,
         transfer_date, fg_receipt_id, created_by),
    )

def log_access(username, action):
    db_run(
        "INSERT INTO access_logs (username, action) VALUES (?,?)",
        (username, action),
    )

# ─── PAGE CONFIG (must be first st call) ──────────────────────────────────────

st.set_page_config(
    page_title="Склад сырья",
    page_icon="🏭",
    layout="wide",
)


def inject_pwa():
    st.html("""
    <script>
    (() => {
        const doc = window.parent.document;
        const head = doc.head || doc.getElementsByTagName("head")[0];
        const base = "/app/static";

        function ensureLink(rel, href) {
            if (!doc.querySelector(`link[rel="${rel}"]`)) {
                const l = doc.createElement("link");
                l.rel = href.endsWith(".json") ? rel : rel;
                l.rel = rel; l.href = href;
                head.appendChild(l);
            }
        }
        function ensureMeta(name, content) {
            if (!doc.querySelector(`meta[name="${name}"]`)) {
                const m = doc.createElement("meta");
                m.name = name; m.content = content;
                head.appendChild(m);
            }
        }

        ensureLink("manifest", `${base}/manifest.json`);
        ensureLink("apple-touch-icon", `${base}/icon-192.png`);
        ensureMeta("theme-color", "#1565C0");
        ensureMeta("mobile-web-app-capable", "yes");
        ensureMeta("apple-mobile-web-app-capable", "yes");
        ensureMeta("apple-mobile-web-app-title", "Склад сырья");
        ensureMeta("apple-mobile-web-app-status-bar-style", "black-translucent");

        if ("serviceWorker" in window.parent.navigator) {
            window.parent.navigator.serviceWorker
                .register(`${base}/service-worker.js`, { scope: `${base}/` })
                .catch(() => {});
        }
    })();
    </script>
    """)

# ─── UI HELPERS ───────────────────────────────────────────────────────────────

def inject_css():
    st.markdown("""
    <style>
    #MainMenu, header, footer {visibility: hidden;}
    .block-container {padding: 1rem 1.5rem; max-width: 1300px;}

    .stButton > button {
        min-height: 3rem; font-size: 1.05rem; width: 100%;
        border-radius: 8px; font-weight: 600;
    }
    .page-title {
        font-size: 1.7rem; font-weight: 700; color: #1565C0;
        margin-bottom: 1.2rem; border-bottom: 2px solid #1565C0;
        padding-bottom: 0.4rem;
    }
    .page-title-fg {
        font-size: 1.7rem; font-weight: 700; color: #c62828;
        margin-bottom: 1.2rem; border-bottom: 2px solid #c62828;
        padding-bottom: 0.4rem;
    }
    .metric-card {
        background: #E3F2FD; border-radius: 10px;
        padding: 0.9rem; text-align: center; margin: 0.4rem 0;
    }
    .metric-card h2 {font-size: 1.8rem; margin: 0; color: #1565C0;}
    .metric-card p  {font-size: 0.85rem; margin: 0; color: #555;}
    .metric-card-fg {
        background: #FFEBEE; border-radius: 10px;
        padding: 0.9rem; text-align: center; margin: 0.4rem 0;
    }
    .metric-card-fg h2 {font-size: 1.8rem; margin: 0; color: #c62828;}
    .metric-card-fg p  {font-size: 0.85rem; margin: 0; color: #555;}

    div[data-testid="stTextInput"] input,
    div[data-testid="stNumberInput"] input,
    div[data-testid="stDateInput"] input {
        min-height: 2.8rem; font-size: 1.05rem;
    }
    div[data-baseweb="select"] > div {
        min-height: 2.8rem; font-size: 1.02rem;
    }
    @media (max-width: 1100px) {
        .block-container { padding-left: 0.8rem; padding-right: 0.8rem; }
        .stButton > button { min-height: 3.5rem; font-size: 1.1rem; }
        div[data-testid="stTextInput"] input,
        div[data-testid="stNumberInput"] input { min-height: 3.2rem; }
    }
    </style>
    """, unsafe_allow_html=True)


_COOKIE_KEY     = "wh_auth_token"
_COOKIE_MAX_AGE = AUTH_DAYS * 86400  # секунды


def read_auth_cookie() -> str | None:
    """Читает cookie мгновенно на сервере — без лишних round-trip."""
    try:
        return st.context.cookies.get(_COOKIE_KEY)
    except Exception:
        return None


def save_auth_cookie(token: str):
    """Записывает cookie через лёгкий JS (fire-and-forget)."""
    st.html(
        f"<script>document.cookie = "
        f"'{_COOKIE_KEY}={token}; path=/; max-age={_COOKIE_MAX_AGE}; SameSite=Lax';"
        f"</script>"
    )


def clear_auth_cookie():
    """Удаляет cookie через JS."""
    st.html(
        f"<script>document.cookie = "
        f"'{_COOKIE_KEY}=; path=/; max-age=0; SameSite=Lax';"
        f"</script>"
    )


def back_btn(dest="home", label="← Назад"):
    if st.button(label, key=f"back_{dest}"):
        st.session_state.page = dest
        st.rerun()

# ─── LOGIN ────────────────────────────────────────────────────────────────────

def page_login():
    st.markdown('<div class="page-title">🏭 Управление складом</div>', unsafe_allow_html=True)
    st.markdown("### Вход в систему")
    _, col, _ = st.columns([1, 2, 1])
    with col:
        username = st.selectbox("Пользователь", [""] + list(USERS.keys()))
        password = st.text_input("Пароль", type="password")
        if st.button("Войти", type="primary"):
            if username and USERS.get(username) == password:
                token = make_token(username)
                save_auth_cookie(token)
                st.session_state.current_user = username
                log_access(username, "вход")
                st.rerun()
            else:
                st.error("Неверный логин или пароль")

# ─── HOME ─────────────────────────────────────────────────────────────────────

def page_home():
    user = st.session_state.current_user
    st.markdown('<div class="page-title">🏭 Управление складом</div>', unsafe_allow_html=True)
    st.markdown(f"Добро пожаловать, **{user}**")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### 📦 Сырьё и производство")
        if st.button("📥 Приём сырья (склад №2)", key="nav_recv"):
            st.session_state.page = "receive"; st.rerun()
        if st.button("📊 Остатки сырья (склад №2)", key="nav_stock"):
            st.session_state.page = "stock"; st.rerun()
        if st.button("🏭 Списать в производство", key="nav_wo"):
            st.session_state.page = "writeoff"; st.rerun()
        if st.button("🔄 Сырьё в производстве (склад №3)", key="nav_prod"):
            st.session_state.page = "production"; st.rerun()
        if st.button("📦 Упаковка и материалы (склад №5)", key="nav_pack"):
            st.session_state.page = "packaging"; st.rerun()
        if st.button("📅 Журнал остатков", key="nav_journal"):
            st.session_state.page = "journal"; st.rerun()
    with col2:
        st.markdown("#### 🏪 Готовая продукция")
        if st.button("📊 Склад готовой продукции", key="nav_fg_stock"):
            st.session_state.page = "fg_stock"; st.rerun()
        if st.button("➕ Внесение готовой продукции", key="nav_fg_recv"):
            st.session_state.page = "fg_receipt"; st.rerun()

    st.divider()

    raw_kg  = (db_query("SELECT COALESCE(SUM(quantity_kg),0) AS v FROM raw_receipts") or [{"v":0}])[0]["v"]
    wo_kg   = (db_query("SELECT COALESCE(SUM(quantity_kg),0) AS v FROM production_writeoffs") or [{"v":0}])[0]["v"]
    fg_kg   = (db_query("SELECT COALESCE(SUM(net_weight),0) AS v FROM fg_receipts") or [{"v":0}])[0]["v"]
    remain  = raw_kg - wo_kg

    c1, c2, c3 = st.columns(3)
    c1.markdown(f'<div class="metric-card"><h2>{remain:,.0f} кг</h2><p>Остаток сырья (склад №2)</p></div>'.replace(",", " "), unsafe_allow_html=True)
    c2.markdown(f'<div class="metric-card"><h2>{wo_kg:,.0f} кг</h2><p>В производстве (склад №3)</p></div>'.replace(",", " "), unsafe_allow_html=True)
    c3.markdown(f'<div class="metric-card-fg"><h2>{fg_kg:,.0f} кг</h2><p>Готовая продукция (нетто)</p></div>'.replace(",", " "), unsafe_allow_html=True)

    st.divider()
    if st.button("Выйти", key="logout"):
        log_access(user, "выход")
        clear_auth_cookie()
        del st.session_state.current_user
        st.query_params.clear()
        st.rerun()

# ─── RECEIVE ──────────────────────────────────────────────────────────────────

def page_receive():
    st.markdown('<div class="page-title">📥 Приём сырья — Склад №2</div>', unsafe_allow_html=True)
    back_btn()

    user   = st.session_state.current_user
    MANUAL = "✏️ Ввести вручную..."

    if "recv_buffer" not in st.session_state:
        st.session_state.recv_buffer = []
    if "recv_header" not in st.session_state:
        st.session_state.recv_header = None

    buf    = st.session_state.recv_buffer
    header = st.session_state.recv_header

    # ══════════════════════════════════════════════════════════════════════════
    # ШАГ 1 — Шапка накладной (вводится один раз)
    # ══════════════════════════════════════════════════════════════════════════
    if header is None:
        st.markdown("#### 📋 Шаг 1 — Данные накладной")
        st.info("Введите общие данные для всей накладной. Позиции будут добавляться на следующем шаге.")

        with st.form("recv_header_form"):
            hc1, hc2 = st.columns(2)
            with hc1:
                h_date         = st.date_input("Дата получения", value=date.today())
                h_order        = st.text_input("Номер документа / накладной")
                h_delivery     = st.text_input("Код поставки")
            with hc2:
                h_supplier_sel = st.selectbox("Поставщик (ספק)", [""] + SUPPLIERS + [MANUAL])
                h_supplier_man = st.text_input("Поставщик — вручную", placeholder="Введите название")

            if st.form_submit_button("→ Перейти к вводу позиций", type="primary", use_container_width=True):
                supplier = h_supplier_man.strip() if h_supplier_sel == MANUAL else h_supplier_sel
                errors = []
                if not h_order.strip(): errors.append("Укажите номер документа / накладной")
                if not supplier:        errors.append("Выберите или введите поставщика")
                if errors:
                    for e in errors: st.error(e)
                else:
                    st.session_state.recv_header = {
                        "recv_date":     h_date.isoformat(),
                        "order_no":      h_order.strip(),
                        "delivery_code": h_delivery.strip() or None,
                        "supplier":      supplier,
                    }
                    st.rerun()
        return   # не показываем остальное пока шапка не заполнена

    # ══════════════════════════════════════════════════════════════════════════
    # ШАГ 2 — Шапка зафиксирована, вводим позиции
    # ══════════════════════════════════════════════════════════════════════════

    # Карточка шапки
    delivery_str = f" · Код: {header['delivery_code']}" if header.get("delivery_code") else ""
    st.markdown(
        f"<div style='background:#E3F2FD;border-radius:8px;padding:0.7rem 1rem;margin-bottom:1rem;'>"
        f"📋 <b>{header['order_no']}</b>{delivery_str} &nbsp;|&nbsp; "
        f"📅 {header['recv_date']} &nbsp;|&nbsp; "
        f"🏢 {header['supplier']}"
        f"</div>",
        unsafe_allow_html=True,
    )
    if st.button("✏️ Изменить данные накладной", key="edit_header_btn"):
        st.session_state.recv_header = None
        st.rerun()

    # ── Форма добавления позиции ──────────────────────────────────────────────
    st.markdown("#### Добавить позицию")
    with st.form("recv_item_form", clear_on_submit=True):
        ic1, ic2 = st.columns(2)
        with ic1:
            material_sel    = st.selectbox("Товар (סחורה)", [""] + RAW_MATERIALS + [MANUAL],
                                format_func=lambda x: material_display(x) if x and x != MANUAL else x)
            material_manual = st.text_input("Товар — вручную", placeholder="Введите название") if material_sel == MANUAL else ""
            qty_kg          = st.number_input("Количество кг", min_value=0.0, step=0.001, format="%.3f")
        with ic2:
            price_kg  = st.number_input("Цена за кг", min_value=0.0, step=0.01, format="%.3f")
            prod_date = st.date_input("Дата производства (תוצרת)", value=None)
            exp_date  = st.date_input("Годен до (תוקף)", value=None)

        material = material_manual.strip() if material_sel == MANUAL else material_sel
        total    = round(qty_kg * price_kg, 3) if qty_kg and price_kg else 0.0
        st.markdown(f"**Сумма позиции: {total:,.3f}**")

        if st.form_submit_button("➕ Добавить позицию", type="primary", use_container_width=True):
            errors = []
            if not material: errors.append("Выберите или введите название товара")
            if qty_kg <= 0:  errors.append("Количество должно быть больше 0")
            if errors:
                for e in errors: st.error(e)
            else:
                buf.append({
                    "recv_date":     header["recv_date"],
                    "order_no":      header["order_no"],
                    "delivery_code": header.get("delivery_code"),
                    "supplier":      header["supplier"],
                    "material":      material,
                    "qty_kg":        qty_kg,
                    "price_kg":      price_kg or None,
                    "total":         total or None,
                    "prod_date":     prod_date.isoformat() if prod_date else None,
                    "exp_date":      exp_date.isoformat()  if exp_date  else None,
                })
                mat_display = MATERIALS_MAP.get(material, material)
                st.success(f"Добавлено: {mat_display} — {qty_kg:,.3f} кг")

    # ── Буфер ─────────────────────────────────────────────────────────────────
    st.divider()
    st.markdown(f"#### Позиции накладной — {len(buf)} шт. (проверьте перед сохранением)")

    if not buf:
        st.info("Позиций пока нет. Добавьте позиции выше, затем сохраните на склад.")
    else:
        df_buf = pd.DataFrame([{
            "№": i + 1,
            "Товар (рус)": MATERIALS_MAP.get(r["material"], r["material"]),
            "Товар (иврит)": r["material"],
            "Кг": r["qty_kg"],
            "Цена/кг": r["price_kg"] or "",
            "Сумма": r["total"] or "",
            "Дата произв.": r["prod_date"] or "",
            "Годен до": r["exp_date"] or "",
        } for i, r in enumerate(buf)])
        st.dataframe(df_buf, use_container_width=True, hide_index=True)

        # Итого по позициям
        total_kg  = sum(r["qty_kg"] for r in buf)
        total_sum = sum(r["total"] or 0 for r in buf)
        tc1, tc2 = st.columns(2)
        tc1.metric("Итого кг",  f"{total_kg:,.3f}".replace(",", " "))
        tc2.metric("Итого сумма", f"{total_sum:,.2f}".replace(",", " "))

        # ── Редактирование выбранной позиции ──
        idx = st.selectbox(
            "Выберите позицию для редактирования / удаления",
            range(len(buf)),
            format_func=lambda i: (
                f"#{i+1}  {MATERIALS_MAP.get(buf[i]['material'], buf[i]['material'])} "
                f"| {buf[i]['qty_kg']:,.3f} кг"
            ),
            key="recv_edit_idx",
        )
        item = buf[idx]

        with st.form(f"edit_recv_{idx}"):
            st.markdown(f"**Редактирование позиции #{idx + 1}**")
            ec1, ec2 = st.columns(2)
            with ec1:
                e_material = st.text_input("Товар (иврит)",  value=item["material"])
                e_qty      = st.number_input("Кг",           value=float(item["qty_kg"]), min_value=0.001, step=0.001, format="%.3f")
                e_price    = st.number_input("Цена/кг",      value=float(item["price_kg"] or 0), min_value=0.0, step=0.01, format="%.3f")
            with ec2:
                e_prod = st.date_input("Дата произв.", value=date.fromisoformat(item["prod_date"]) if item["prod_date"] else None)
                e_exp  = st.date_input("Годен до",     value=date.fromisoformat(item["exp_date"])  if item["exp_date"]  else None)
                st.markdown("*Дата, №, код, поставщик берутся из шапки накладной.*  \nЧтобы изменить — нажмите «Изменить данные накладной» выше.")

            if st.form_submit_button("💾 Сохранить изменения", use_container_width=True):
                buf[idx] = {
                    **{k: item[k] for k in ("recv_date","order_no","delivery_code","supplier")},
                    "material":  e_material.strip(),
                    "qty_kg":    e_qty,
                    "price_kg":  e_price or None,
                    "total":     round(e_qty * e_price, 3) if e_price else None,
                    "prod_date": e_prod.isoformat() if e_prod else None,
                    "exp_date":  e_exp.isoformat()  if e_exp  else None,
                }
                st.success("Позиция обновлена")
                st.rerun()

        c1, c2, c3 = st.columns(3)
        with c1:
            if st.button(f"🗑 Удалить позицию #{idx + 1}", use_container_width=True):
                buf.pop(idx)
                st.rerun()
        with c2:
            if st.button("🗑 Очистить буфер и начать заново", use_container_width=True):
                buf.clear()
                st.session_state.recv_header = None
                st.rerun()
        with c3:
            if st.button(f"✅ Сохранить на склад ({len(buf)} поз.)", type="primary", use_container_width=True):
                for r in buf:
                    db_run(
                        """INSERT INTO raw_receipts
                            (receipt_date, order_number, delivery_code, supplier, material,
                             quantity_kg, price_per_kg, total_price,
                             production_date, expiry_date, created_by)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        (r["recv_date"], r["order_no"], r.get("delivery_code"), r["supplier"], r["material"],
                         r["qty_kg"], r["price_kg"], r["total"],
                         r["prod_date"], r["exp_date"], user),
                    )
                n = len(buf)
                buf.clear()
                st.session_state.recv_header = None
                st.success(f"✅ Сохранено на склад: {n} позиций")
                st.rerun()

    st.divider()
    st.markdown("#### Последние поступления на складе")
    rows = db_query(
        "SELECT receipt_date,order_number,supplier,material,"
        "quantity_kg,price_per_kg,total_price,expiry_date "
        "FROM raw_receipts ORDER BY id DESC LIMIT 20"
    )
    if rows:
        df = pd.DataFrame(rows)
        df.columns = ["Дата", "№ документа", "Поставщик", "Товар", "Кг", "Цена/кг", "Сумма", "Годен до"]
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("Нет поступлений")

# ─── STOCK ────────────────────────────────────────────────────────────────────

def page_stock():
    st.markdown('<div class="page-title">📊 Остатки сырья — Склад №2</div>', unsafe_allow_html=True)
    back_btn()

    rows = db_query("""
        SELECT
            rr.id,
            rr.receipt_date,
            rr.order_number,
            rr.delivery_code,
            rr.supplier,
            rr.material,
            rr.quantity_kg,
            rr.price_per_kg,
            rr.production_date,
            rr.expiry_date,
            COALESCE(SUM(pw.quantity_kg), 0) AS written_off,
            rr.quantity_kg - COALESCE(SUM(pw.quantity_kg), 0) AS remaining_kg
        FROM raw_receipts rr
        LEFT JOIN production_writeoffs pw ON pw.receipt_id = rr.id
        GROUP BY rr.id
        HAVING rr.quantity_kg - COALESCE(SUM(pw.quantity_kg), 0) > 0.001
        ORDER BY
            CASE WHEN rr.expiry_date IS NULL THEN 1 ELSE 0 END,
            rr.expiry_date ASC
    """)

    if not rows:
        st.info("Склад пуст")
        return

    df = pd.DataFrame(rows)
    total_remain = df["remaining_kg"].sum()
    total_value  = (df["remaining_kg"] * df["price_per_kg"].fillna(0)).sum()

    c1, c2 = st.columns(2)
    c1.markdown(f'<div class="metric-card"><h2>{total_remain:,.0f} кг</h2><p>Общий остаток</p></div>'.replace(",", " "), unsafe_allow_html=True)
    c2.markdown(f'<div class="metric-card"><h2>{total_value:,.0f}</h2><p>Стоимость остатка</p></div>'.replace(",", " "), unsafe_allow_html=True)

    today = date.today().isoformat()
    soon  = (date.today() + timedelta(days=30)).isoformat()

    display = df[[
        "receipt_date", "material", "remaining_kg", "quantity_kg", "written_off",
        "price_per_kg", "supplier", "order_number", "delivery_code", "expiry_date",
    ]].copy()
    display.columns = [
        "Дата прихода", "Товар (иврит)", "Остаток кг", "Принято кг", "Списано кг",
        "Цена/кг", "Поставщик", "№ документа", "Код поставки", "Годен до",
    ]
    display.insert(1, "Товар", display["Товар (иврит)"].map(lambda h: MATERIALS_MAP.get(h, h)))
    display["Стоимость остатка"] = (
        display["Остаток кг"] * display["Цена/кг"].fillna(0)
    ).round(2)
    display = display[[
        "Дата прихода", "Товар", "Товар (иврит)", "Остаток кг", "Принято кг", "Списано кг",
        "Стоимость остатка", "Поставщик", "Цена/кг", "№ документа", "Код поставки", "Годен до",
    ]]

    st.dataframe(display, use_container_width=True, hide_index=True)

    st.divider()
    st.markdown("#### По видам сырья")
    summary = (
        df.groupby("material")["remaining_kg"]
        .sum()
        .reset_index()
        .sort_values("remaining_kg", ascending=False)
    )
    summary.columns = ["Товар", "Остаток кг"]
    st.dataframe(summary, use_container_width=True, hide_index=True)

    if st.button("📥 Скачать Excel", key="dl_stock"):
        from io import BytesIO
        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as w:
            display.to_excel(w, index=False, sheet_name="Остатки")
            summary.to_excel(w, index=False, sheet_name="По товарам")
        st.download_button("⬇ Скачать файл", buf.getvalue(), "остатки_сырья.xlsx")

    # ── Редактирование и удаление (только Admin) ──
    if st.session_state.get("current_user") == "Admin":
        st.divider()
        st.markdown("#### ✏️ Редактировать / удалить запись прихода (Admin)")
        all_receipts = db_query(
            "SELECT id, receipt_date, order_number, delivery_code, supplier, material, "
            "quantity_kg, price_per_kg, production_date, expiry_date "
            "FROM raw_receipts ORDER BY id DESC LIMIT 200"
        )
        if all_receipts:
            id_map = {
                r["id"]: f'{r["receipt_date"]} | №{r["order_number"]} | {r["supplier"]} | {r["material"]} | {r["quantity_kg"]:,.3f} кг'
                for r in all_receipts
            }
            selected_edit_id = st.selectbox(
                "Выберите запись",
                list(id_map.keys()),
                format_func=lambda i: id_map[i],
                key="admin_stock_edit_select",
            )
            rec = next(r for r in all_receipts if r["id"] == selected_edit_id)

            tab_edit, tab_del = st.tabs(["✏️ Редактировать", "🗑 Удалить"])

            with tab_edit:
                with st.form("admin_edit_receipt_form"):
                    ec1, ec2 = st.columns(2)
                    with ec1:
                        e_date     = st.date_input("Дата прихода",    value=date.fromisoformat(rec["receipt_date"]))
                        e_order    = st.text_input("№ документа",     value=rec["order_number"] or "")
                        e_delivery = st.text_input("Код поставки",    value=rec["delivery_code"] or "")
                        e_supplier = st.text_input("Поставщик",       value=rec["supplier"] or "")
                        e_material = st.text_input("Товар (иврит)",   value=rec["material"] or "")
                    with ec2:
                        e_qty   = st.number_input("Количество кг",  value=float(rec["quantity_kg"]),        min_value=0.001, step=0.001, format="%.3f")
                        e_price = st.number_input("Цена/кг",         value=float(rec["price_per_kg"] or 0), min_value=0.0,   step=0.01,  format="%.3f")
                        e_prod  = st.date_input("Дата производства", value=date.fromisoformat(rec["production_date"]) if rec["production_date"] else None)
                        e_exp   = st.date_input("Годен до",          value=date.fromisoformat(rec["expiry_date"])     if rec["expiry_date"]     else None)
                    if st.form_submit_button("💾 Сохранить изменения", type="primary", use_container_width=True):
                        db_run(
                            """UPDATE raw_receipts SET
                                receipt_date=?, order_number=?, delivery_code=?, supplier=?, material=?,
                                quantity_kg=?, price_per_kg=?, total_price=?, production_date=?, expiry_date=?
                               WHERE id=?""",
                            (e_date.isoformat(), e_order.strip(), e_delivery.strip() or None,
                             e_supplier.strip(), e_material.strip(),
                             e_qty, e_price or None, round(e_qty * e_price, 3) if e_price else None,
                             e_prod.isoformat() if e_prod else None,
                             e_exp.isoformat()  if e_exp  else None,
                             selected_edit_id),
                        )
                        st.success(f"✅ Запись #{selected_edit_id} обновлена")
                        st.rerun()

            with tab_del:
                st.warning(f"Будет удалена запись: **{id_map[selected_edit_id]}**")
                with st.form("delete_receipt_form"):
                    confirmed = st.checkbox("Подтверждаю удаление выбранной записи")
                    if st.form_submit_button("🗑 Удалить запись", type="primary"):
                        if not confirmed:
                            st.error("Поставьте галочку подтверждения")
                        else:
                            db_run("DELETE FROM production_writeoffs WHERE receipt_id = ?", (selected_edit_id,))
                            db_run("DELETE FROM raw_receipts WHERE id = ?", (selected_edit_id,))
                            st.success(f"✅ Запись удалена: {id_map[selected_edit_id]}")
                            st.rerun()

# ─── WRITE-OFF ────────────────────────────────────────────────────────────────

def page_writeoff():
    st.markdown('<div class="page-title">🏭 Списание в производство — Склад №2 → №3</div>', unsafe_allow_html=True)
    back_btn()

    user = st.session_state.current_user

    if "wo_buffer" not in st.session_state:
        st.session_state.wo_buffer = []
    buf = st.session_state.wo_buffer

    # Загружаем остатки из БД
    stock = db_query("""
        SELECT
            rr.id, rr.material, rr.supplier, rr.order_number,
            rr.expiry_date, rr.receipt_date,
            rr.quantity_kg - COALESCE(SUM(pw.quantity_kg), 0) AS remaining_kg
        FROM raw_receipts rr
        LEFT JOIN production_writeoffs pw ON pw.receipt_id = rr.id
        GROUP BY rr.id
        HAVING rr.quantity_kg - COALESCE(SUM(pw.quantity_kg), 0) > 0.001
        ORDER BY
            CASE WHEN rr.expiry_date IS NULL THEN 1 ELSE 0 END,
            rr.expiry_date ASC
    """)

    if not stock:
        st.info("Склад пуст — нет сырья для списания")
        return

    # Считаем, сколько уже добавлено в буфер по каждому receipt_id
    buffered = {}
    for b in buf:
        buffered[b["receipt_id"]] = buffered.get(b["receipt_id"], 0) + b["qty_kg"]

    # Доступный остаток = остаток в БД − уже в буфере
    available = {r["id"]: r["remaining_kg"] - buffered.get(r["id"], 0) for r in stock}
    stock_avail = [r for r in stock if available[r["id"]] > 0.001]

    # ── Форма добавления в буфер ──
    st.markdown("#### Добавить позицию в буфер")
    if not stock_avail:
        st.warning("Всё доступное сырьё уже добавлено в буфер.")
    else:
        search = st.text_input("🔍 Поиск по названию (на русском)", placeholder="Например: скумб")
        filtered = [
            r for r in stock_avail
            if not search.strip() or search.strip().lower() in MATERIALS_MAP.get(r["material"], r["material"]).lower()
        ]
        if not filtered:
            st.warning("Ничего не найдено. Попробуйте другой запрос.")
        else:
            options = [r["id"] for r in filtered]
            def wo_label(rid):
                r = next(x for x in filtered if x["id"] == rid)
                rus = MATERIALS_MAP.get(r["material"], r["material"])
                return (f"{rus} | {r['supplier']} | доступно: {available[rid]:,.3f} кг"
                        f" | до: {r['expiry_date'] or '—'}")
        with st.form("wo_form", clear_on_submit=True):
            selected_id = st.selectbox("Выберите позицию со склада №2", options if filtered else [None],
                                       format_func=wo_label if filtered else lambda x: "—")
            selected = f"#{selected_id}" if selected_id else None
            wo_qty   = st.number_input("Количество для списания (кг)", min_value=0.001, step=0.001, format="%.3f")
            wo_date  = st.date_input("Дата списания", value=date.today())
            notes    = st.text_input("Примечание (необязательно)")

            if st.form_submit_button("➕ Добавить в буфер", type="primary", use_container_width=True):
                rid = selected_id
                row = next(r for r in stock if r["id"] == rid)
                avail = available[rid]
                if wo_qty > avail + 0.001:
                    st.error(f"Нельзя добавить {wo_qty:,.3f} кг — доступно только {avail:,.3f} кг")
                else:
                    rus = MATERIALS_MAP.get(row["material"], row["material"])
                    batch = f"{rus} {wo_date.strftime('%d/%m/%y')}"
                    buf.append({
                        "receipt_id":   rid,
                        "material":     row["material"],
                        "supplier":     row["supplier"],
                        "qty_kg":       wo_qty,
                        "wo_date":      wo_date.isoformat(),
                        "batch_number": batch,
                        "notes":        notes.strip() or None,
                    })
                    st.success(f"Добавлено в буфер: {rus} — {wo_qty:,.3f} кг | Партия: {batch}")

    # ── Буфер ──
    st.divider()
    st.markdown(f"#### Буфер — {len(buf)} поз. (проверьте перед списанием)")

    if not buf:
        st.info("Буфер пуст. Добавьте позиции выше, проверьте и подтвердите списание.")
    else:
        df_buf = pd.DataFrame([{
            "№": i + 1, "Партия": b["batch_number"], "Дата": b["wo_date"],
            "Товар": b["material"], "Поставщик": b["supplier"],
            "Кг": b["qty_kg"], "Примечание": b["notes"] or "",
        } for i, b in enumerate(buf)])
        st.dataframe(df_buf, use_container_width=True, hide_index=True)

        idx = st.selectbox(
            "Выберите позицию для редактирования / удаления",
            range(len(buf)),
            format_func=lambda i: f"#{i+1}  {buf[i]['batch_number']} | {buf[i]['qty_kg']:,.3f} кг",
            key="wo_edit_idx",
        )
        item = buf[idx]
        # Максимум для редактирования = остаток в БД − буфер без этой позиции
        rid_item = item["receipt_id"]
        other_buffered = sum(b["qty_kg"] for j, b in enumerate(buf) if j != idx and b["receipt_id"] == rid_item)
        db_remaining = next((r["remaining_kg"] for r in stock if r["id"] == rid_item), 0)
        max_qty = db_remaining - other_buffered

        with st.form(f"edit_wo_{idx}"):
            st.markdown(f"**Редактирование #{idx + 1} — партия: {item['batch_number']}**")
            e_qty   = st.number_input("Кг", value=float(item["qty_kg"]), min_value=0.001, max_value=float(max_qty), step=0.001, format="%.3f")
            e_date  = st.date_input("Дата списания", value=date.fromisoformat(item["wo_date"]))
            e_notes = st.text_input("Примечание", value=item["notes"] or "")

            if st.form_submit_button("💾 Сохранить изменения", use_container_width=True):
                new_date = e_date.isoformat()
                buf[idx]["qty_kg"]       = e_qty
                buf[idx]["wo_date"]      = new_date
                buf[idx]["notes"]        = e_notes.strip() or None
                buf[idx]["batch_number"] = f"{item['material']} {e_date.strftime('%d/%m/%y')}"
                st.success("Позиция обновлена")
                st.rerun()

        c1, c2, c3 = st.columns(3)
        with c1:
            if st.button(f"🗑 Удалить позицию #{idx + 1}", use_container_width=True):
                buf.pop(idx)
                st.rerun()
        with c2:
            if st.button("🗑 Очистить весь буфер", use_container_width=True):
                buf.clear()
                st.rerun()
        with c3:
            if st.button(f"✅ Списать в производство ({len(buf)} поз.)", type="primary", use_container_width=True):
                for b in buf:
                    db_run(
                        """INSERT INTO production_writeoffs
                            (receipt_id, material, supplier, quantity_kg,
                             writeoff_date, batch_number, notes, created_by)
                           VALUES (?,?,?,?,?,?,?,?)""",
                        (b["receipt_id"], b["material"], b["supplier"],
                         b["qty_kg"], b["wo_date"], b["batch_number"], b["notes"], user),
                    )
                n = len(buf)
                buf.clear()
                st.success(f"✅ Списано в производство: {n} позиций")
                st.rerun()

    st.divider()
    st.markdown("#### История списаний")
    hist = db_query(
        "SELECT id,batch_number,writeoff_date,material,supplier,quantity_kg,notes,created_by "
        "FROM production_writeoffs ORDER BY id DESC LIMIT 30"
    )
    if hist:
        df = pd.DataFrame(hist)
        df.columns = ["id", "Партия", "Дата", "Товар", "Поставщик", "Кг", "Примечание", "Оператор"]
        st.dataframe(df.drop(columns=["id"]), use_container_width=True, hide_index=True)
    else:
        st.info("Нет списаний")

    # ── Удаление записи (только Admin) ──
    if st.session_state.current_user == "Admin" and hist:
        st.divider()
        st.markdown("#### 🗑 Удалить запись списания (Admin)")
        rows_for_del = db_query(
            "SELECT id,batch_number,writeoff_date,material,supplier,quantity_kg "
            "FROM production_writeoffs ORDER BY id DESC LIMIT 100"
        )
        id_map = {
            r["id"]: f'{r["writeoff_date"]} | {r["batch_number"]} | {r["material"]} | {r["supplier"]} | {r["quantity_kg"]:,.3f} кг'
            for r in rows_for_del
        }
        with st.form("delete_writeoff_form"):
            del_id = st.selectbox(
                "Выберите запись для удаления",
                list(id_map.keys()),
                format_func=lambda i: id_map[i],
            )
            confirmed = st.checkbox("Подтверждаю удаление выбранной записи")
            if st.form_submit_button("🗑 Удалить запись", type="primary"):
                if not confirmed:
                    st.error("Поставьте галочку подтверждения")
                else:
                    db_run("DELETE FROM production_writeoffs WHERE id = ?", (del_id,))
                    st.success(f"✅ Запись удалена: {id_map[del_id]}")
                    st.rerun()

# ─── PRODUCTION ───────────────────────────────────────────────────────────────

def page_production():
    st.markdown('<div class="page-title">🔄 Сырьё в производстве — Склад №3</div>', unsafe_allow_html=True)
    back_btn()

    rows = db_query("""
        SELECT
            pw.id,
            pw.batch_number,
            pw.writeoff_date,
            pw.material,
            pw.supplier,
            pw.quantity_kg,
            pw.notes,
            rr.order_number,
            rr.delivery_code,
            rr.expiry_date,
            COALESCE(SUM(pft.quantity_kg), 0) AS transferred_kg
        FROM production_writeoffs pw
        JOIN raw_receipts rr ON rr.id = pw.receipt_id
        LEFT JOIN production_finished_transfers pft ON pft.production_writeoff_id = pw.id
        GROUP BY pw.id, pw.batch_number, pw.writeoff_date, pw.material, pw.supplier,
                 pw.quantity_kg, pw.notes, rr.order_number, rr.delivery_code, rr.expiry_date
        ORDER BY pw.writeoff_date DESC, pw.id DESC
    """)

    if not rows:
        st.info("Нет данных о списаниях в производство")
        return

    df = pd.DataFrame(rows)
    df["remaining_kg"] = df["quantity_kg"] - df["transferred_kg"]

    total_kg       = df["quantity_kg"].sum()
    transferred_kg = df["transferred_kg"].sum()
    remaining_kg   = df["remaining_kg"].sum()

    c1, c2, c3 = st.columns(3)
    c1.markdown(f'<div class="metric-card"><h2>{total_kg:,.0f} кг</h2><p>Отправлено в производство</p></div>'.replace(",", " "), unsafe_allow_html=True)
    c2.markdown(f'<div class="metric-card"><h2>{transferred_kg:,.0f} кг</h2><p>Передано на склад ГП</p></div>'.replace(",", " "), unsafe_allow_html=True)
    c3.markdown(f'<div class="metric-card"><h2>{remaining_kg:,.0f} кг</h2><p>Остаток в производстве</p></div>'.replace(",", " "), unsafe_allow_html=True)

    display = df[["batch_number", "writeoff_date", "material", "supplier",
                  "quantity_kg", "transferred_kg", "remaining_kg",
                  "notes", "order_number", "delivery_code", "expiry_date"]].copy()
    display.columns = ["Партия", "Дата списания", "Товар (иврит)", "Поставщик",
                       "Отправлено кг", "Передано ГП кг", "Остаток кг",
                       "Примечание", "№ документа", "Код поставки", "Годен до"]
    display.insert(2, "Товар", display["Товар (иврит)"].map(lambda h: MATERIALS_MAP.get(h, h)))
    st.dataframe(display, use_container_width=True, hide_index=True)

    st.divider()
    st.markdown("#### Остатки в производстве по видам сырья")
    summary = (
        df.assign(Товар=df["material"].map(lambda h: MATERIALS_MAP.get(h, h)))
        .groupby("Товар")[["quantity_kg", "transferred_kg", "remaining_kg"]]
        .sum()
        .reset_index()
        .sort_values("remaining_kg", ascending=False)
    )
    summary.columns = ["Товар", "Отправлено кг", "Передано ГП кг", "Остаток кг"]
    st.dataframe(summary, use_container_width=True, hide_index=True)

# ─── PACKAGING ────────────────────────────────────────────────────────────────

def page_packaging():
    st.markdown('<div class="page-title">📦 Упаковка и материалы — Склад №5</div>', unsafe_allow_html=True)
    back_btn()

    user = st.session_state.current_user

    if "pack_buffer" not in st.session_state:
        st.session_state.pack_buffer = []
    buf = st.session_state.pack_buffer

    # ── Форма добавления в буфер ──
    st.markdown("#### Добавить позицию в буфер")
    MANUAL = "✏️ Ввести вручную..."
    with st.form("pack_form", clear_on_submit=True):
        col1, col2 = st.columns(2)
        with col1:
            recv_date = st.date_input("Дата получения", value=date.today())
            item_sel  = st.selectbox(
                "Наименование",
                [""] + PACKAGING_ITEMS_NAMES + [MANUAL],
            )
            if item_sel == MANUAL:
                item_manual = st.text_input("Наименование — вручную", placeholder="Введите наименование")
            else:
                item_manual = ""
            # Определяем единицу измерения по выбранной позиции
            auto_unit = PACKAGING_ITEMS_UNIT.get(item_sel, "шт")
            unit_idx  = PACKAGING_UNITS.index(auto_unit) if auto_unit in PACKAGING_UNITS else 0
            unit = st.selectbox("Единица измерения", PACKAGING_UNITS, index=unit_idx)
            qty  = st.number_input("Количество", min_value=0.0, step=0.01, format="%.3f")
        with col2:
            price_unit = st.number_input("Цена за единицу", min_value=0.0, step=0.01, format="%.3f")
            supplier   = st.text_input("Поставщик")
            notes      = st.text_input("Примечание")

        item_name = item_manual.strip() if item_sel == MANUAL else item_sel
        total = round(qty * price_unit, 3) if qty and price_unit else 0.0
        st.markdown(f"**Общая сумма: {total:,.3f}**")

        if st.form_submit_button("➕ Добавить в буфер", type="primary", use_container_width=True):
            if not item_name:
                st.error("Выберите наименование из списка или введите вручную")
            elif qty <= 0:
                st.error("Количество должно быть больше 0")
            else:
                buf.append({
                    "recv_date":  recv_date.isoformat(),
                    "item_name":  item_name,
                    "qty":        qty,
                    "unit":       unit,
                    "price_unit": price_unit or None,
                    "total":      total or None,
                    "supplier":   supplier.strip() or None,
                    "notes":      notes.strip() or None,
                })
                st.success(f"Добавлено в буфер: {item_name} — {qty:,.3f} {unit}")

    # ── Буфер ──
    st.divider()
    st.markdown(f"#### Буфер — {len(buf)} поз. (проверьте перед сохранением на склад)")

    if not buf:
        st.info("Буфер пуст. Добавьте позиции выше, проверьте и сохраните на склад.")
    else:
        df_buf = pd.DataFrame([{
            "№": i + 1, "Дата": r["recv_date"], "Наименование": r["item_name"],
            "Кол-во": r["qty"], "Ед.": r["unit"],
            "Цена/ед.": r["price_unit"] or "", "Сумма": r["total"] or "",
            "Поставщик": r["supplier"] or "", "Примечание": r["notes"] or "",
        } for i, r in enumerate(buf)])
        st.dataframe(df_buf, use_container_width=True, hide_index=True)

        idx = st.selectbox(
            "Выберите позицию для редактирования / удаления",
            range(len(buf)),
            format_func=lambda i: f"#{i+1}  {buf[i]['item_name']} | {buf[i]['qty']:,.3f} {buf[i]['unit']}",
            key="pack_edit_idx",
        )
        item = buf[idx]

        with st.form(f"edit_pack_{idx}"):
            st.markdown(f"**Редактирование позиции #{idx + 1}**")
            ec1, ec2 = st.columns(2)
            with ec1:
                e_date  = st.date_input("Дата",         value=date.fromisoformat(item["recv_date"]))
                e_name  = st.text_input("Наименование", value=item["item_name"])
                e_qty   = st.number_input("Количество", value=float(item["qty"]),  min_value=0.001, step=0.01, format="%.3f")
                e_unit  = st.selectbox("Ед.", PACKAGING_UNITS, index=PACKAGING_UNITS.index(item["unit"]) if item["unit"] in PACKAGING_UNITS else 0)
            with ec2:
                e_price = st.number_input("Цена/ед.",   value=float(item["price_unit"] or 0), min_value=0.0, step=0.01, format="%.3f")
                e_supp  = st.text_input("Поставщик",   value=item["supplier"] or "")
                e_notes = st.text_input("Примечание",  value=item["notes"] or "")

            if st.form_submit_button("💾 Сохранить изменения", use_container_width=True):
                buf[idx] = {
                    "recv_date":  e_date.isoformat(),
                    "item_name":  e_name.strip(),
                    "qty":        e_qty,
                    "unit":       e_unit,
                    "price_unit": e_price or None,
                    "total":      round(e_qty * e_price, 3) if e_price else None,
                    "supplier":   e_supp.strip() or None,
                    "notes":      e_notes.strip() or None,
                }
                st.success("Позиция обновлена")
                st.rerun()

        c1, c2, c3 = st.columns(3)
        with c1:
            if st.button(f"🗑 Удалить позицию #{idx + 1}", use_container_width=True):
                buf.pop(idx)
                st.rerun()
        with c2:
            if st.button("🗑 Очистить весь буфер", use_container_width=True):
                buf.clear()
                st.rerun()
        with c3:
            if st.button(f"✅ Сохранить на склад ({len(buf)} поз.)", type="primary", use_container_width=True):
                for r in buf:
                    db_run(
                        """INSERT INTO packaging_receipts
                            (receipt_date, item_name, quantity, unit,
                             price_per_unit, total_price, supplier, notes, created_by)
                           VALUES (?,?,?,?,?,?,?,?,?)""",
                        (r["recv_date"], r["item_name"], r["qty"], r["unit"],
                         r["price_unit"], r["total"], r["supplier"], r["notes"], user),
                    )
                n = len(buf)
                buf.clear()
                st.success(f"✅ Сохранено на склад: {n} позиций")
                st.rerun()

    st.divider()
    st.markdown("#### Записи упаковки и материалов")
    rows = db_query(
        "SELECT id,receipt_date,item_name,quantity,unit,price_per_unit,total_price,supplier,notes "
        "FROM packaging_receipts ORDER BY id DESC LIMIT 50"
    )
    if rows:
        df_view = pd.DataFrame(rows)
        df_view_disp = df_view.drop(columns=["id"])
        df_view_disp.columns = ["Дата", "Наименование", "Кол-во", "Ед.", "Цена/ед.", "Сумма", "Поставщик", "Примечание"]
        st.dataframe(df_view_disp, use_container_width=True, hide_index=True)
    else:
        st.info("Нет записей")

    # ── Редактирование и удаление упаковки (только Admin) ──
    if st.session_state.get("current_user") == "Admin":
        st.divider()
        st.markdown("#### ✏️ Редактировать / удалить запись упаковки (Admin)")
        pack_all = db_query(
            "SELECT id,receipt_date,item_name,quantity,unit,price_per_unit,supplier,notes "
            "FROM packaging_receipts ORDER BY id DESC LIMIT 200"
        )
        if pack_all:
            pack_id_map = {
                r["id"]: f'{r["receipt_date"]} | {r["item_name"]} | {r["quantity"]:,.3f} {r["unit"]}'
                for r in pack_all
            }
            sel_pack_id = st.selectbox(
                "Выберите запись",
                list(pack_id_map.keys()),
                format_func=lambda i: pack_id_map[i],
                key="admin_pack_edit_select",
            )
            prec = next(r for r in pack_all if r["id"] == sel_pack_id)

            ptab_edit, ptab_del = st.tabs(["✏️ Редактировать", "🗑 Удалить"])

            with ptab_edit:
                MANUAL = "✏️ Ввести вручную..."
                with st.form("admin_edit_pack_form"):
                    pc1, pc2 = st.columns(2)
                    with pc1:
                        pe_date  = st.date_input("Дата получения", value=date.fromisoformat(prec["receipt_date"]))
                        # Определяем начальный индекс в списке, если есть
                        cur_name = prec["item_name"]
                        name_options = [""] + PACKAGING_ITEMS_NAMES + [MANUAL]
                        name_idx = name_options.index(cur_name) if cur_name in name_options else len(name_options) - 1
                        pe_item_sel = st.selectbox("Наименование", name_options, index=name_idx)
                        if pe_item_sel == MANUAL or pe_item_sel == "":
                            pe_item_manual = st.text_input("Наименование — вручную", value=cur_name if cur_name not in name_options else "")
                        else:
                            pe_item_manual = ""
                        auto_unit   = PACKAGING_ITEMS_UNIT.get(pe_item_sel, prec["unit"] or "шт")
                        unit_idx_e  = PACKAGING_UNITS.index(auto_unit) if auto_unit in PACKAGING_UNITS else 0
                        # Если текущая единица не совпадает с авто — используем текущую
                        if prec["unit"] in PACKAGING_UNITS and pe_item_sel not in PACKAGING_ITEMS_NAMES:
                            unit_idx_e = PACKAGING_UNITS.index(prec["unit"])
                        pe_unit = st.selectbox("Единица измерения", PACKAGING_UNITS, index=unit_idx_e)
                        pe_qty  = st.number_input("Количество", value=float(prec["quantity"]), min_value=0.001, step=0.01, format="%.3f")
                    with pc2:
                        pe_price = st.number_input("Цена/ед.", value=float(prec["price_per_unit"] or 0), min_value=0.0, step=0.01, format="%.3f")
                        pe_supp  = st.text_input("Поставщик",  value=prec["supplier"] or "")
                        pe_notes = st.text_input("Примечание", value=prec["notes"] or "")

                    if st.form_submit_button("💾 Сохранить изменения", type="primary", use_container_width=True):
                        pe_name = pe_item_manual.strip() if (pe_item_sel == MANUAL or pe_item_sel == "") else pe_item_sel
                        if not pe_name:
                            st.error("Укажите наименование")
                        else:
                            db_run(
                                """UPDATE packaging_receipts SET
                                    receipt_date=?, item_name=?, quantity=?, unit=?,
                                    price_per_unit=?, total_price=?, supplier=?, notes=?
                                   WHERE id=?""",
                                (pe_date.isoformat(), pe_name, pe_qty, pe_unit,
                                 pe_price or None, round(pe_qty * pe_price, 3) if pe_price else None,
                                 pe_supp.strip() or None, pe_notes.strip() or None,
                                 sel_pack_id),
                            )
                            st.success(f"✅ Запись #{sel_pack_id} обновлена")
                            st.rerun()

            with ptab_del:
                st.warning(f"Будет удалена запись: **{pack_id_map[sel_pack_id]}**")
                with st.form("delete_pack_form"):
                    p_confirmed = st.checkbox("Подтверждаю удаление")
                    if st.form_submit_button("🗑 Удалить запись", type="primary"):
                        if not p_confirmed:
                            st.error("Поставьте галочку подтверждения")
                        else:
                            db_run("DELETE FROM packaging_receipts WHERE id = ?", (sel_pack_id,))
                            st.success(f"✅ Запись удалена: {pack_id_map[sel_pack_id]}")
                            st.rerun()

# ─── JOURNAL ─────────────────────────────────────────────────────────────────

def page_journal():
    st.markdown('<div class="page-title">📅 Журнал остатков</div>', unsafe_allow_html=True)
    back_btn()

    sel_date = st.date_input("Выберите дату", value=date.today(), max_value=date.today())
    date_str = sel_date.isoformat()

    st.markdown(f"### Склад №2 — Сырьё на {sel_date.strftime('%d.%m.%Y')}")

    stock_rows = db_query(f"""
        SELECT
            rr.material,
            rr.supplier,
            rr.order_number,
            rr.quantity_kg,
            rr.price_per_kg,
            rr.expiry_date,
            COALESCE(SUM(pw.quantity_kg), 0) AS written_off,
            rr.quantity_kg - COALESCE(SUM(pw.quantity_kg), 0) AS remaining_kg
        FROM raw_receipts rr
        LEFT JOIN production_writeoffs pw
            ON pw.receipt_id = rr.id
            AND pw.writeoff_date <= ?
        WHERE rr.receipt_date <= ?
        GROUP BY rr.id
        HAVING rr.quantity_kg - COALESCE(SUM(pw.quantity_kg), 0) > 0.001
        ORDER BY rr.expiry_date ASC
    """, (date_str, date_str))

    if stock_rows:
        df_stock = pd.DataFrame(stock_rows)
        df_stock.insert(0, "Товар", df_stock["material"].map(lambda h: MATERIALS_MAP.get(h, h)))
        total_remain = df_stock["remaining_kg"].sum()
        total_value  = (df_stock["remaining_kg"] * df_stock["price_per_kg"].fillna(0)).sum()
        c1, c2 = st.columns(2)
        c1.markdown(f'<div class="metric-card"><h2>{total_remain:,.0f} кг</h2><p>Остаток сырья</p></div>'.replace(",", " "), unsafe_allow_html=True)
        c2.markdown(f'<div class="metric-card"><h2>{total_value:,.0f}</h2><p>Стоимость остатка</p></div>'.replace(",", " "), unsafe_allow_html=True)
        df_stock["Стоимость"] = (df_stock["remaining_kg"] * df_stock["price_per_kg"].fillna(0)).round(2)
        display = df_stock[["Товар", "material", "supplier", "order_number",
                             "quantity_kg", "written_off", "remaining_kg",
                             "price_per_kg", "Стоимость", "expiry_date"]].copy()
        display.columns = ["Товар", "Товар (иврит)", "Поставщик", "№ документа",
                            "Принято кг", "Списано кг", "Остаток кг",
                            "Цена/кг", "Стоимость", "Годен до"]
        st.dataframe(display, use_container_width=True, hide_index=True)

        if st.button("📥 Скачать Excel (склад №2)", key="dl_journal_stock"):
            from io import BytesIO
            buf = BytesIO()
            with pd.ExcelWriter(buf, engine="openpyxl") as w:
                display.to_excel(w, index=False, sheet_name="Склад №2")
            st.download_button("⬇ Скачать", buf.getvalue(),
                               f"склад2_{date_str}.xlsx")
    else:
        st.info("На эту дату данных нет")

    st.divider()
    st.markdown(f"### Склад №3 — Сырьё в производстве на {sel_date.strftime('%d.%m.%Y')}")

    prod_rows = db_query("""
        SELECT
            pw.writeoff_date,
            pw.material,
            pw.supplier,
            pw.quantity_kg,
            pw.batch_number,
            rr.expiry_date,
            COALESCE(SUM(pft.quantity_kg), 0) AS transferred_kg,
            pw.quantity_kg - COALESCE(SUM(pft.quantity_kg), 0) AS remaining_kg
        FROM production_writeoffs pw
        JOIN raw_receipts rr ON rr.id = pw.receipt_id
        LEFT JOIN production_finished_transfers pft
            ON pft.production_writeoff_id = pw.id
            AND pft.transfer_date <= ?
        WHERE pw.writeoff_date <= ?
        GROUP BY pw.id, pw.writeoff_date, pw.material, pw.supplier,
                 pw.quantity_kg, pw.batch_number, rr.expiry_date
        HAVING pw.quantity_kg - COALESCE(SUM(pft.quantity_kg), 0) > 0.001
        ORDER BY pw.writeoff_date DESC
    """, (date_str, date_str))

    if prod_rows:
        df_prod = pd.DataFrame(prod_rows)
        df_prod.insert(1, "Товар", df_prod["material"].map(lambda h: MATERIALS_MAP.get(h, h)))
        total_prod     = df_prod["quantity_kg"].sum()
        remaining_prod = df_prod["remaining_kg"].sum()
        c1, c2 = st.columns(2)
        c1.markdown(f'<div class="metric-card"><h2>{total_prod:,.0f} кг</h2><p>Отправлено в производство</p></div>'.replace(",", " "), unsafe_allow_html=True)
        c2.markdown(f'<div class="metric-card"><h2>{remaining_prod:,.0f} кг</h2><p>Остаток в производстве</p></div>'.replace(",", " "), unsafe_allow_html=True)
        display_prod = df_prod[["writeoff_date", "Товар", "material", "supplier",
                                 "quantity_kg", "transferred_kg", "remaining_kg",
                                 "batch_number", "expiry_date"]].copy()
        display_prod.columns = ["Дата списания", "Товар", "Товар (иврит)",
                                 "Поставщик", "Отправлено кг", "Передано ГП кг",
                                 "Остаток кг", "Партия", "Годен до"]
        st.dataframe(display_prod, use_container_width=True, hide_index=True)
    else:
        st.info("На эту дату данных нет")

    st.divider()
    st.markdown(f"### Склад №5 — Упаковка и материалы на {sel_date.strftime('%d.%m.%Y')}")

    pack_rows = db_query("""
        SELECT
            item_name,
            unit,
            COUNT(*)          AS записей,
            SUM(quantity)     AS total_qty,
            SUM(COALESCE(total_price, 0)) AS total_cost,
            MAX(receipt_date) AS last_receipt
        FROM packaging_receipts
        WHERE receipt_date <= ?
        GROUP BY item_name, unit
        ORDER BY item_name
    """, (date_str,))

    if pack_rows:
        df_pack = pd.DataFrame(pack_rows)
        total_pack_cost = df_pack["total_cost"].sum()
        st.markdown(
            f'<div class="metric-card"><h2>{total_pack_cost:,.0f}</h2>'
            f'<p>Общая стоимость поступлений упаковки</p></div>'.replace(",", " "),
            unsafe_allow_html=True,
        )
        df_pack.columns = ["Наименование", "Ед.", "Кол-во записей",
                           "Итого кол-во", "Сумма", "Последний приход"]
        st.dataframe(df_pack, use_container_width=True, hide_index=True)

        st.markdown("##### Детализация приходов склада №5")
        pack_detail = db_query("""
            SELECT receipt_date, item_name, quantity, unit,
                   price_per_unit, total_price, supplier, notes
            FROM packaging_receipts
            WHERE receipt_date <= ?
            ORDER BY receipt_date DESC, id DESC
        """, (date_str,))
        if pack_detail:
            df_det = pd.DataFrame(pack_detail)
            df_det.columns = ["Дата", "Наименование", "Кол-во", "Ед.",
                              "Цена/ед.", "Сумма", "Поставщик", "Примечание"]
            st.dataframe(df_det, use_container_width=True, hide_index=True)

        if st.button("📥 Скачать Excel (склад №5)", key="dl_journal_pack"):
            from io import BytesIO
            buf_xl = BytesIO()
            with pd.ExcelWriter(buf_xl, engine="openpyxl") as w:
                df_pack.to_excel(w, index=False, sheet_name="Итого по позициям")
                pd.DataFrame(pack_detail).to_excel(w, index=False, sheet_name="Детализация")
            st.download_button("⬇ Скачать", buf_xl.getvalue(),
                               f"склад5_{date_str}.xlsx")
    else:
        st.info("На эту дату данных нет")

# ─── FG STOCK ────────────────────────────────────────────────────────────────

def page_fg_stock():
    st.markdown('<div class="page-title-fg">🏪 Склад готовой продукции</div>', unsafe_allow_html=True)
    back_btn()

    summary = get_fg_stock_summary()
    if not summary:
        st.info("На складе готовой продукции пока нет записей.")
        return

    df_sum = pd.DataFrame(summary)
    total_net = df_sum["net_total"].sum()
    st.markdown(f'<div class="metric-card-fg"><h2>{total_net:,.3f} кг</h2><p>Общий вес нетто на складе ГП</p></div>'.replace(",", " "), unsafe_allow_html=True)

    # Мультиселект для суммирования
    id_options = df_sum["id"].astype(str).tolist()
    label_by_id = {str(r["id"]): f'{r["id"]} — {r["russian_name"]}' for r in summary}
    selected_ids = st.multiselect("Выберите ID для суммирования", id_options,
                                  format_func=lambda i: label_by_id.get(i, i))
    if selected_ids:
        sel = df_sum[df_sum["id"].astype(str).isin(selected_ids)]
        st.markdown("**Сумма по выбранным:**")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Нетто кг",    f'{sel["net_total"].sum():.3f}')
        c2.metric("Брутто кг",   f'{sel["gross_total"].sum():.3f}')
        c3.metric("Штуки",       f'{int(sel["units_total"].sum())}')
        c4.metric("Картоны",     f'{int(sel["cartons_total"].sum())}')
        st.dataframe(sel.rename(columns={
            "id":"ID","russian_name":"Продукт","hebrew_name":"Иврит",
            "units_total":"Штуки","cartons_total":"Картоны",
            "gross_total":"Брутто кг","net_total":"Нетто кг",
            "first_date":"Первый приход","last_date":"Последний приход",
        }), use_container_width=True, hide_index=True)

    st.subheader("Вся готовая продукция на складе")
    display_sum = df_sum.rename(columns={
        "id":"ID","russian_name":"Продукт","hebrew_name":"Иврит",
        "units_total":"Штуки","cartons_total":"Картоны",
        "gross_total":"Брутто кг","net_total":"Нетто кг",
        "first_date":"Первый приход","last_date":"Последний приход",
    })
    st.dataframe(display_sum, use_container_width=True, hide_index=True)

    receipts = get_fg_receipts()
    st.subheader("История внесения")
    if receipts:
        df_r = pd.DataFrame(receipts)
        for rdate, grp in df_r.groupby("receipt_date", sort=False):
            st.markdown(f"**{rdate}**")
            g = grp.drop(columns=["id","receipt_date"]).rename(columns={
                "created_by":"Оператор","product_id":"ID",
                "russian_name":"Продукт","hebrew_name":"Иврит",
                "calculation_method":"Метод",
                "unit_weight":"Вес шт","units_count":"Штуки",
                "tare_weight":"Вес тары","gross_weight":"Брутто","cartons_count":"Картоны",
                "net_weight":"Нетто кг",
            })
            st.dataframe(g, use_container_width=True, hide_index=True)

    # Excel
    if st.button("📥 Скачать Excel", key="fg_dl"):
        from io import BytesIO
        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as w:
            display_sum.to_excel(w, index=False, sheet_name="Склад ГП")
            if receipts:
                pd.DataFrame(receipts).to_excel(w, index=False, sheet_name="История")
        st.download_button("⬇ Скачать", buf.getvalue(), f"склад_гп_{date.today()}.xlsx")

    # Удаление (Admin)
    if st.session_state.get("current_user") == "Admin" and receipts:
        st.divider()
        st.markdown("#### 🗑 Удалить запись ГП (Admin)")
        df_del = pd.DataFrame(receipts)
        id_map = {
            int(r["id"]): f'{r["receipt_date"]} | ID {r["product_id"]} | {r["russian_name"]} | {r["net_weight"]:.3f} кг'
            for r in receipts
        }
        with st.form("fg_delete_form"):
            del_id = st.selectbox("Выберите запись", list(id_map.keys()), format_func=lambda i: id_map[i])
            confirmed = st.checkbox("Подтверждаю удаление")
            if st.form_submit_button("🗑 Удалить", type="primary"):
                if not confirmed:
                    st.error("Поставьте галочку")
                else:
                    db_run("DELETE FROM fg_receipts WHERE id = ?", (del_id,))
                    st.success(f"✅ Удалено: {id_map[del_id]}")
                    st.rerun()

# ─── FG RECEIPT ──────────────────────────────────────────────────────────────

def page_fg_receipt():
    st.markdown('<div class="page-title-fg">➕ Внесение готовой продукции</div>', unsafe_allow_html=True)
    back_btn()

    user = st.session_state.current_user
    products = st.session_state.get("_fg_products", pd.DataFrame())

    if products.empty:
        st.warning("Справочник продуктов пуст. Загрузите products.csv.")
        return

    if "fg_buffer" not in st.session_state:
        st.session_state.fg_buffer = []
    if "fg_prod_transfers" not in st.session_state:
        st.session_state.fg_prod_transfers = []

    buf       = st.session_state.fg_buffer
    transfers = st.session_state.fg_prod_transfers

    # ── Поиск и выбор продукта ──
    product_records = products.reset_index(names="row_idx").sort_values(["russian_name","id"]).to_dict("records")
    for p in product_records:
        p["pkey"] = f'{p["id"]}__{p["row_idx"]}'
    by_key = {p["pkey"]: p for p in product_records}
    by_id  = {}
    for p in product_records:
        by_id.setdefault(p["id"], []).append(p)

    if "fg_search" not in st.session_state:
        st.session_state.fg_search = ""
    if "fg_id_input" not in st.session_state:
        st.session_state.fg_id_input = ""
    if "fg_sel_key" not in st.session_state:
        st.session_state.fg_sel_key = product_records[0]["pkey"] if product_records else ""

    search = st.text_input("🔍 Поиск продукта (ID или название)", key="fg_search",
                           placeholder="Введите ID или часть названия")
    norm   = search.strip().lower()
    filtered = [p for p in product_records if not norm or
                norm in p["id"].lower() or norm in p["russian_name"].lower() or
                norm in p["hebrew_name"].lower()]
    if not filtered:
        st.error("Продукт не найден")
        return

    pkeys = [p["pkey"] for p in filtered]
    if st.session_state.fg_sel_key not in pkeys:
        st.session_state.fg_sel_key = pkeys[0]

    def _sync_id_from_product():
        st.session_state.fg_id_input = by_key[st.session_state.fg_sel_key]["id"]

    def _sync_product_from_id():
        eid = st.session_state.fg_id_input.strip()
        if eid in by_id:
            st.session_state.fg_sel_key = by_id[eid][0]["pkey"]

    id_col, prod_col = st.columns([1, 5])
    with id_col:
        st.text_input("ID", max_chars=4, key="fg_id_input", on_change=_sync_product_from_id)
    with prod_col:
        st.selectbox("Продукт", pkeys,
                     format_func=lambda k: fg_product_label(by_key[k]),
                     key="fg_sel_key", on_change=_sync_id_from_product)

    sel = by_key[st.session_state.fg_sel_key]
    method     = fg_calculation_method(sel)
    unit_w     = float(sel["unit_weight"])
    tare_w     = float(sel["tare_weight"])

    m1, m2, m3 = st.columns([0.6, 0.9, 4])
    m1.metric("ID", sel["id"])
    m2.metric("Вес шт" if unit_w > 0 else "Вес тары",
              f'{unit_w:.3f}' if unit_w > 0 else f'{tare_w:.3f}')
    m3.write(f"**{sel['russian_name']}**  \n{sel['hebrew_name']}")

    if method == "missing":
        st.error("Для продукта не заполнен ни вес штуки, ни вес тары. Проверьте products.csv.")
        return

    with st.form("fg_receipt_form"):
        recv_date = st.date_input("Дата внесения", value=date.today(), format="DD.MM.YYYY")
        if method == "unit":
            f1, f2 = st.columns(2)
            with f1:
                units_count = st.number_input("Количество штук", min_value=0, step=1)
            with f2:
                gross_weight  = 0.0
                cartons_count = 0
                net_weight    = units_count * unit_w
                st.metric("Вес нетто", f"{net_weight:.3f}")
        else:
            f1, f2, f3 = st.columns(3)
            with f1:
                gross_weight = st.number_input("Вес брутто", min_value=0.0, step=0.001, format="%.3f")
            with f2:
                cartons_count = st.number_input("Количество картонов", min_value=0, step=1)
            with f3:
                units_count = 0
                net_weight  = gross_weight - cartons_count * tare_w
                st.metric("Вес нетто", f"{net_weight:.3f}")

        add_clicked = st.form_submit_button("➕ Добавить в буфер", type="primary", use_container_width=True)

    if add_clicked:
        errors = []
        if method == "unit" and units_count <= 0:
            errors.append("Количество штук должно быть больше 0")
        if method == "tare" and gross_weight <= 0:
            errors.append("Вес брутто должен быть больше 0")
        if net_weight < 0:
            errors.append("Вес нетто отрицательный — проверьте данные")
        if errors:
            for e in errors: st.error(e)
        else:
            buf.append({
                "product":        dict(sel),
                "product_id":     sel["id"],
                "russian_name":   sel["russian_name"],
                "hebrew_name":    sel["hebrew_name"],
                "unit_weight":    unit_w,
                "tare_weight":    tare_w,
                "method":         method,
                "gross_weight":   float(gross_weight),
                "units_count":    int(units_count),
                "cartons_count":  int(cartons_count),
                "net_weight":     float(net_weight),
                "receipt_date":   recv_date.isoformat(),
                "prod_transfers": list(transfers),
            })
            transfers.clear()
            t_info = f" | {len(buf[-1]['prod_transfers'])} парт. из пр-ва" if buf[-1]["prod_transfers"] else ""
            st.success(f"Добавлено в буфер: {sel['russian_name']} — {net_weight:.3f} кг{t_info}")

    # ── Сырьё из производства ──────────────────────────────────────────────────
    st.divider()
    st.subheader("🏭 Сырьё из производства (необязательно)")
    prod_stock = get_production_stock()

    if not prod_stock:
        st.info("В производстве (Склад №3) нет сырья.")
    else:
        already_used = {}
        for t in transfers:
            already_used[t["writeoff_id"]] = already_used.get(t["writeoff_id"], 0) + t["qty_kg"]

        if transfers:
            st.markdown("**Добавлено к текущей позиции:**")
            for i, t in enumerate(transfers):
                c1, c2 = st.columns([5, 1])
                c1.write(f"📦 {t['batch_number']} — **{t['qty_kg']:.3f} кг**")
                if c2.button("✕", key=f"tr_del_{i}"):
                    transfers.pop(i); st.rerun()

        avail = [p for p in prod_stock
                 if p["available_kg"] - already_used.get(p["id"], 0) > 0.001]

        if avail:
            with st.form("fg_prod_transfer_form", clear_on_submit=True):
                def _ps_label(pid):
                    p = next(x for x in avail if x["id"] == pid)
                    av = p["available_kg"] - already_used.get(p["id"], 0)
                    return f"{p['batch_number']} | {p['supplier']} | доступно: {av:.3f} кг | до: {p.get('expiry_date') or '—'}"
                sel_ps = st.selectbox("Партия из производства",
                                      [p["id"] for p in avail], format_func=_ps_label)
                ps_row   = next(x for x in avail if x["id"] == sel_ps)
                max_avail = float(ps_row["available_kg"]) - already_used.get(sel_ps, 0)
                tr_qty   = st.number_input("Количество кг", min_value=0.001,
                                           max_value=round(max_avail, 3),
                                           step=0.001, format="%.3f")
                if st.form_submit_button("➕ Добавить сырьё из производства", use_container_width=True):
                    transfers.append({
                        "writeoff_id":  sel_ps,
                        "batch_number": ps_row["batch_number"],
                        "material":     ps_row["material"],
                        "supplier":     ps_row["supplier"],
                        "qty_kg":       tr_qty,
                    })
                    st.rerun()

    # ── Буфер ──────────────────────────────────────────────────────────────────
    st.divider()
    st.subheader(f"Буфер — {len(buf)} поз.")

    if not buf:
        st.info("Буфер пуст. Добавьте позиции выше.")
        return

    buf_rows = []
    for i, item in enumerate(buf, 1):
        tr_str = "; ".join(f"{t['batch_number']} {t['qty_kg']:.3f}кг"
                           for t in item.get("prod_transfers", [])) or "—"
        buf_rows.append({
            "№": i, "Дата": item["receipt_date"],
            "ID": item["product_id"], "Продукт": item["russian_name"],
            "Нетто кг": f'{item["net_weight"]:.3f}',
            "Брутто": f'{item["gross_weight"]:.3f}',
            "Картоны": item["cartons_count"],
            "Сырьё из пр-ва": tr_str,
        })
    st.dataframe(buf_rows, use_container_width=True, hide_index=True)

    idx = st.selectbox("Позиция для удаления из буфера", range(len(buf)),
                       format_func=lambda i: f"#{i+1} {buf[i]['russian_name']} {buf[i]['net_weight']:.3f} кг",
                       key="fg_buf_idx")

    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button(f"🗑 Удалить #{idx+1}", use_container_width=True):
            buf.pop(idx); st.rerun()
    with c2:
        if st.button("🗑 Очистить буфер", use_container_width=True):
            buf.clear(); st.rerun()
    with c3:
        if st.button(f"✅ Сохранить на склад ({len(buf)} поз.)", type="primary", use_container_width=True):
            tr_count = 0
            for item in buf:
                rid = save_fg_receipt(
                    item["product"], item["method"],
                    item["gross_weight"], item["units_count"], item["cartons_count"],
                    item["net_weight"], item["receipt_date"], user,
                )
                for t in item.get("prod_transfers", []):
                    save_production_transfer(
                        t["writeoff_id"], t["material"], t["supplier"],
                        t["qty_kg"], item["receipt_date"], rid, user,
                    )
                    tr_count += 1
            n = len(buf)
            buf.clear()
            tr_msg = f" Списано из пр-ва: {tr_count} парт." if tr_count else ""
            st.success(f"✅ Сохранено на склад ГП: {n} поз.{tr_msg}")
            st.rerun()

# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    init_db()
    inject_pwa()
    inject_css()

    # Инициализация session state
    if "page" not in st.session_state:
        st.session_state.page = "home"
    if "fg_buffer" not in st.session_state:
        st.session_state.fg_buffer = []
    if "fg_prod_transfers" not in st.session_state:
        st.session_state.fg_prod_transfers = []

    # Загружаем справочник продуктов ГП один раз за сессию
    if "_fg_products" not in st.session_state:
        products = load_products_from_csv()
        sync_products_to_db(products)
        st.session_state["_fg_products"] = products

    # ── Авторизация через cookie ──────────────────────────────────────────────
    # CookieController рендерится один раз и читает cookie из браузера
    if "current_user" not in st.session_state:
        saved_token = read_auth_cookie()
        if saved_token:
            username = check_token(saved_token)
            if username:
                st.session_state.current_user = username

    if "current_user" not in st.session_state:
        page_login()
        return

    pages = {
        "home":       page_home,
        "receive":    page_receive,
        "stock":      page_stock,
        "writeoff":   page_writeoff,
        "production": page_production,
        "packaging":  page_packaging,
        "journal":    page_journal,
        "fg_stock":   page_fg_stock,
        "fg_receipt": page_fg_receipt,
    }
    fn = pages.get(st.session_state.page)
    if fn:
        fn()
    else:
        st.session_state.page = "home"
        st.rerun()


if __name__ == "__main__":
    main()
