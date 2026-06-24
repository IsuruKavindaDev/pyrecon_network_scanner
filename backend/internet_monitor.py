import subprocess
import time

# =========================================
# INTERNET STATUS MONITOR
# =========================================

def check_internet():

    try:

        # =====================================
        # PING GOOGLE DNS
        # =====================================

        start = time.time()

        result = subprocess.run(

            ["ping", "-n", "1", "8.8.8.8"],

            capture_output=True,
            text=True

        )

        end = time.time()

        latency = round((end - start) * 1000)

        # =====================================
        # INTERNET STATUS
        # =====================================

        if result.returncode == 0:

            status = "ONLINE"

        else:

            status = "OFFLINE"

        # =====================================
        # ROUTE QUALITY
        # =====================================

        if latency < 50:

            quality = "EXCELLENT"

        elif latency < 120:

            quality = "GOOD"

        else:

            quality = "POOR"

        return {

            "internet_status": status,
            "latency_ms": latency,
            "route_quality": quality,
            "target": "8.8.8.8"

        }

    except Exception as e:

        return {

            "internet_status": "OFFLINE",
            "latency_ms": 0,
            "route_quality": "UNKNOWN",
            "error": str(e)

        }