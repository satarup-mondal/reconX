from backend.queue import redis_client, QUEUE_NAME
from backend.database import SessionLocal
from backend.models import Scan, Target
from backend.result_service import save_result

from backend.recon.http_probe import probe_http
from backend.recon.dns_probe import probe_dns
from backend.recon.port_probe import probe_ports


def run_worker():
    print("[WORKER] Waiting for jobs...")

    while True:
        job = redis_client.blpop(QUEUE_NAME)

        if not job:
            continue

        _, scan_id = job
        scan_id = int(scan_id)

        db = SessionLocal()
        scan = None

        try:
            # ----------------------------------------
            # Get scan
            # ----------------------------------------

            scan = db.query(Scan).filter(
                Scan.id == scan_id
            ).first()

            if not scan:
                print(f"[WORKER] Scan {scan_id} not found")
                continue

            # ----------------------------------------
            # Get target
            # ----------------------------------------

            target = db.query(Target).filter(
                Target.id == scan.target_id
            ).first()

            if not target:
                scan.status = "failed"
                db.commit()

                print(
                    f"[WORKER] Target {scan.target_id} not found"
                )
                continue

            scan.status = "running"
            db.commit()

            print(f"[WORKER] Scan {scan.id} started")
            print(f"[WORKER] Target: {target.domain}")

            # Host without port
            host = target.domain.split(":", 1)[0]

            # ----------------------------------------
            # 1. HTTP PROBE
            # ----------------------------------------

            http_result = probe_http(target.domain)

            if http_result["status"] == "success":

                save_result(
                    db=db,
                    scan_id=scan.id,
                    result_type="http_status",
                    value=str(http_result["status_code"])
                )

                if http_result.get("content_type"):
                    save_result(
                        db=db,
                        scan_id=scan.id,
                        result_type="content_type",
                        value=http_result["content_type"]
                    )

                if http_result.get("server"):
                    save_result(
                        db=db,
                        scan_id=scan.id,
                        result_type="server",
                        value=http_result["server"]
                    )

                save_result(
                    db=db,
                    scan_id=scan.id,
                    result_type="final_url",
                    value=http_result["final_url"]
                )

            else:
                save_result(
                    db=db,
                    scan_id=scan.id,
                    result_type=http_result["status"],
                    value=str(
                        http_result.get(
                            "error",
                            http_result
                        )
                    )
                )

            # ----------------------------------------
            # 2. DNS PROBE
            # ----------------------------------------

            dns_result = probe_dns(host)

            if dns_result["status"] == "success":

                for address in dns_result["addresses"]:
                    save_result(
                        db=db,
                        scan_id=scan.id,
                        result_type="dns",
                        value=address
                    )

            else:
                save_result(
                    db=db,
                    scan_id=scan.id,
                    result_type="dns_error",
                    value=dns_result["error"]
                )

            # ----------------------------------------
            # 3. PORT PROBE
            # ----------------------------------------

            port_result = probe_ports(host)

            if port_result["status"] == "success":

                for port in port_result["open_ports"]:
                    save_result(
                        db=db,
                        scan_id=scan.id,
                        result_type="open_port",
                        value=str(port)
                    )

            else:
                save_result(
                    db=db,
                    scan_id=scan.id,
                    result_type="port_error",
                    value=str(port_result)
                )

            # ----------------------------------------
            # COMPLETE
            # ----------------------------------------

            scan.status = "completed"
            db.commit()

            print(
                f"[WORKER] Scan {scan.id} completed"
            )

        except Exception as error:

            if scan:
                scan.status = "failed"
                db.commit()

            print(
                f"[WORKER] Scan {scan_id} failed: {error}"
            )

        finally:
            db.close()