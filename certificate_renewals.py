import sqlite3


def ensure_certificate_renewal_schema(conn: sqlite3.Connection):
    columns = {row[1] for row in conn.execute("PRAGMA table_info(certificates)")}
    if "renewed_from_serial" not in columns:
        conn.execute("ALTER TABLE certificates ADD COLUMN renewed_from_serial TEXT")
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'").fetchone():
            conn.execute("""
                UPDATE certificates
                SET renewed_from_serial = (
                    SELECT json_extract(e.details, '$.previous_serial')
                    FROM events e
                    WHERE e.resource_type = 'certificate'
                      AND e.resource_name = certificates.serial
                      AND e.event_type IN ('create', 'renew')
                      AND json_valid(e.details)
                      AND CASE WHEN json_valid(e.details) THEN json_extract(e.details, '$.renewal') END = 1
                    ORDER BY e.event_id DESC LIMIT 1
                )
                WHERE issued_via = 'scep'
            """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_certificates_renewed_from_serial ON certificates(renewed_from_serial)"
    )


def get_certificate_renewal_links(conn: sqlite3.Connection, rows, user_id=None):
    if not rows:
        return {}
    serials = {row["serial"] for row in rows}
    serials.update(row["renewed_from_serial"] for row in rows if row["renewed_from_serial"])
    serials = sorted(serials)
    placeholders = ",".join("?" for _ in serials)
    query = f"""
        SELECT id, serial, renewed_from_serial FROM certificates
        WHERE (serial IN ({placeholders}) OR renewed_from_serial IN ({placeholders}))
    """
    params = [*serials, *serials]
    if user_id is not None:
        query += " AND user_id = ?"
        params.append(user_id)
    related = conn.execute(query + " ORDER BY id", params).fetchall()
    by_serial = {row["serial"]: row["id"] for row in related}
    links = {}
    for row in rows:
        previous_serial = row["renewed_from_serial"]
        links[row["id"]] = {
            "previous": {
                "serial": previous_serial,
                "id": by_serial.get(previous_serial),
            } if previous_serial else None,
            "successors": [
                {"id": other["id"], "serial": other["serial"]}
                for other in related if other["renewed_from_serial"] == row["serial"]
            ],
        }
    return links
