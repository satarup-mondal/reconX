from backend.queue import redis_client, QUEUE_NAME
from backend.database import SessionLocal
from backend.models import Scan, Target
from backend.result_service import save_result

from backend.recon.registry import RECON_MODULES, SCAN_PROFILES


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

            # ----------------------------------------
            # Validate profile
            # ----------------------------------------

            profile = scan.profile

            if profile not in SCAN_PROFILES:
                scan.status = "failed"
                db.commit()

                print(
                    f"[WORKER] Invalid profile: {profile}"
                )
                continue

            modules = SCAN_PROFILES[profile]

            # ----------------------------------------
            # Target info
            # ----------------------------------------

            domain = target.domain
            port = target.port

            if port:
                target_url = f"{domain}:{port}"
            else:
                target_url = domain

            print(f"[WORKER] Scan {scan.id} started")
            print(f"[WORKER] Target: {target_url}")
            print(f"[WORKER] Profile: {profile}")
            print(f"[WORKER] Modules: {modules}")

            scan.status = "running"
            db.commit()

            # ----------------------------------------
            # Execute modules
            # ----------------------------------------

            for module_name in modules:

                module_config = RECON_MODULES.get(
                    module_name
                )

                if not module_config:
                    print(
                        f"[WORKER] Unknown module: {module_name}"
                    )
                    continue

                module_function = module_config["function"]
                module_handler = module_config["handler"]
                target_type = module_config["target"]

                # ----------------------------------------
                # Decide module target
                # ----------------------------------------

                if target_type == "host":
                    module_target = domain

                elif target_type == "domain":
                    module_target = target_url

                else:
                    module_target = domain

                print(
                    f"[WORKER] Running module: {module_name}"
                )

                module_handler(
                    module_function,
                    module_target,
                    save_result,
                    db,
                    scan.id
                )

            # ----------------------------------------
            # Complete
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