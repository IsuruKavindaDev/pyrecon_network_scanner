import requests

def get_public_ip_info():

    try:

        # Get Public IP
        ip_response = requests.get(
            "https://api.ipify.org?format=json"
        ).json()

        public_ip = ip_response["ip"]

        # Get Geo Information
        geo_response = requests.get(
            f"http://ip-api.com/json/{public_ip}"
        ).json()

        return {

            "public_ip": public_ip,
            "country": geo_response.get("country"),
            "city": geo_response.get("city"),
            "isp": geo_response.get("isp"),
            "org": geo_response.get("org"),
            "asn": geo_response.get("as"),
            "latitude": geo_response.get("lat"),
            "longitude": geo_response.get("lon"),
            "timezone": geo_response.get("timezone")

        }

    except Exception as e:

        return {
            "error": str(e)
        }