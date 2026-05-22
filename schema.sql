-- Warehouse #2: Incoming raw materials
CREATE TABLE IF NOT EXISTS raw_receipts (
    id              SERIAL PRIMARY KEY,
    receipt_date    TEXT NOT NULL,
    order_number    TEXT NOT NULL,
    supplier        TEXT NOT NULL,
    material        TEXT NOT NULL,
    quantity_kg     REAL NOT NULL,
    price_per_kg    REAL,
    total_price     REAL,
    production_date TEXT,
    expiry_date     TEXT,
    created_at      TEXT DEFAULT (NOW()),
    created_by      TEXT NOT NULL DEFAULT 'unknown'
);

CREATE INDEX IF NOT EXISTS idx_raw_receipts_material     ON raw_receipts(material);
CREATE INDEX IF NOT EXISTS idx_raw_receipts_receipt_date ON raw_receipts(receipt_date);

-- Warehouse #2 → #3: Write-offs to production
CREATE TABLE IF NOT EXISTS production_writeoffs (
    id            SERIAL PRIMARY KEY,
    receipt_id    INTEGER NOT NULL REFERENCES raw_receipts(id),
    material      TEXT NOT NULL,
    supplier      TEXT NOT NULL,
    quantity_kg   REAL NOT NULL,
    writeoff_date TEXT NOT NULL,
    notes         TEXT,
    created_at    TEXT DEFAULT (NOW()),
    created_by    TEXT NOT NULL DEFAULT 'unknown'
);

CREATE INDEX IF NOT EXISTS idx_writeoffs_receipt_id    ON production_writeoffs(receipt_id);
CREATE INDEX IF NOT EXISTS idx_writeoffs_writeoff_date ON production_writeoffs(writeoff_date);

-- Warehouse #5: Packaging and auxiliary materials
CREATE TABLE IF NOT EXISTS packaging_receipts (
    id             SERIAL PRIMARY KEY,
    receipt_date   TEXT NOT NULL,
    item_name      TEXT NOT NULL,
    quantity       REAL NOT NULL,
    unit           TEXT NOT NULL,
    price_per_unit REAL,
    total_price    REAL,
    supplier       TEXT,
    notes          TEXT,
    created_at     TEXT DEFAULT (NOW()),
    created_by     TEXT NOT NULL DEFAULT 'unknown'
);

CREATE INDEX IF NOT EXISTS idx_packaging_receipt_date ON packaging_receipts(receipt_date);
