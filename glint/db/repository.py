import json
import sqlite3
from dataclasses import dataclass


@dataclass
class ScanRow:
    id: str
    created_at: str
    ip_address: str
    user_agent: str
    composite_score: float
    risk_level: str
    raw_payload: dict
    result_json: dict


class ScanRepository:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path

    def save(self, scan_id: str, created_at: str, ip_address: str,
             user_agent: str, composite_score: float, risk_level: str,
             raw_payload: dict, result: dict) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """INSERT INTO scans
                   (id, created_at, ip_address, user_agent,
                    composite_score, risk_level, raw_payload, result_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    created_at,
                    ip_address,
                    user_agent,
                    composite_score,
                    risk_level,
                    json.dumps(raw_payload),
                    json.dumps(result),
                ),
            )
            for finding in result.get("findings", []):
                conn.execute(
                    """INSERT INTO findings
                       (id, scan_id, dimension, severity, finding_key,
                        title, description, evidence)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding["id"],
                        scan_id,
                        finding["dimension"],
                        finding["severity"],
                        finding["finding_key"],
                        finding["title"],
                        finding["description"],
                        json.dumps(finding.get("evidence", {})),
                    ),
                )

    def get(self, scan_id: str) -> ScanRow | None:
        with sqlite3.connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT id, created_at, ip_address, user_agent, "
                "composite_score, risk_level, raw_payload, result_json "
                "FROM scans WHERE id = ?",
                (scan_id,),
            ).fetchone()

        if row is None:
            return None

        return ScanRow(
            id=row[0],
            created_at=row[1],
            ip_address=row[2],
            user_agent=row[3],
            composite_score=row[4],
            risk_level=row[5],
            raw_payload=json.loads(row[6]),
            result_json=json.loads(row[7]),
        )

    def list_all(self) -> list[ScanRow]:
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                "SELECT id, created_at, ip_address, user_agent, "
                "composite_score, risk_level, raw_payload, result_json "
                "FROM scans ORDER BY created_at DESC"
            ).fetchall()

        return [
            ScanRow(
                id=r[0],
                created_at=r[1],
                ip_address=r[2],
                user_agent=r[3],
                composite_score=r[4],
                risk_level=r[5],
                raw_payload=json.loads(r[6]),
                result_json=json.loads(r[7]),
            )
            for r in rows
        ]
