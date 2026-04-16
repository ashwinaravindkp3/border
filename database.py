import psycopg2
import psycopg2.extras
from pymongo import MongoClient
from dotenv import load_dotenv
import os
import secrets

load_dotenv()

def get_pg():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST"),
        dbname=os.getenv("POSTGRES_DB"),
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD")
    )

def get_mongo():
    client = MongoClient(
        os.getenv("MONGO_URI"),
        serverSelectionTimeoutMS=1000,
        connectTimeoutMS=1000,
    )
    return client[os.getenv("MONGO_DB")]

def init_db():
    conn = get_pg()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nodes (
            node_id     VARCHAR(50) PRIMARY KEY,
            lat         DOUBLE PRECISION NOT NULL,
            lng         DOUBLE PRECISION NOT NULL,
            zone        VARCHAR(50),
            secret_key  VARCHAR(128) NOT NULL,
            last_seen   TIMESTAMP,
            status      VARCHAR(20) DEFAULT 'unknown'
        );

        CREATE TABLE IF NOT EXISTS events (
            id          SERIAL PRIMARY KEY,
            node_id     VARCHAR(50) REFERENCES nodes(node_id),
            event_type  VARCHAR(50),
            alert_level INTEGER DEFAULT 0,
            timestamp   TIMESTAMP DEFAULT NOW(),
            seq_no      INTEGER,
            image_ref   VARCHAR(128),
            lat         DOUBLE PRECISION,
            lng         DOUBLE PRECISION,
            verified    BOOLEAN DEFAULT FALSE,
            notes       TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id            SERIAL PRIMARY KEY,
            event_id      INTEGER REFERENCES events(id),
            level         INTEGER,
            triggered_at  TIMESTAMP DEFAULT NOW(),
            confirmed_by  VARCHAR(50),
            confirmed_at  TIMESTAMP,
            resolved      BOOLEAN DEFAULT FALSE
        );

        CREATE TABLE IF NOT EXISTS heartbeats (
            id        SERIAL PRIMARY KEY,
            node_id   VARCHAR(50) REFERENCES nodes(node_id),
            received  TIMESTAMP DEFAULT NOW(),
            seq_no    INTEGER,
            rssi      INTEGER
        );

        CREATE TABLE IF NOT EXISTS security_log (
            id          SERIAL PRIMARY KEY,
            node_id     VARCHAR(50),
            attack_type VARCHAR(50),
            detail      TEXT,
            logged_at   TIMESTAMP DEFAULT NOW(),
            blocked     BOOLEAN DEFAULT FALSE
        );
    """)

    cur.execute(
        """
        ALTER TABLE nodes
        ADD COLUMN IF NOT EXISTS aes_key VARCHAR(64)
        """
    )
    cur.execute(
        """
        ALTER TABLE nodes
        ADD COLUMN IF NOT EXISTS crypto_mode VARCHAR(10) DEFAULT 'hmac'
        """
    )
    cur.execute(
        """
        ALTER TABLE events
        ALTER COLUMN seq_no TYPE BIGINT
        USING seq_no::BIGINT
        """
    )
    cur.execute(
        """
        ALTER TABLE heartbeats
        ALTER COLUMN seq_no TYPE BIGINT
        USING seq_no::BIGINT
        """
    )

    cur.execute("SELECT node_id FROM nodes WHERE aes_key IS NULL")
    for (node_id,) in cur.fetchall():
        cur.execute(
            """
            UPDATE nodes
            SET aes_key = %s,
                crypto_mode = %s
            WHERE node_id = %s
            """,
            (secrets.token_hex(32), "aes_gcm", node_id),
        )

    conn.commit()
    cur.close()
    conn.close()
    print("PostgreSQL tables created and node registry seeded.")
