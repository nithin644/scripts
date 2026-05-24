
import requests
import re
import sys
import json
import argparse
import os
import signal
from urllib.parse import urlparse
from typing import Tuple, Dict, List
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import os
os.environ['FORCE_COLOR'] = '1'

_STOP = False

_OUT_FILE = None

def _write_url(url: str):
    if _OUT_FILE:
        _OUT_FILE.write(url + "\n")
        _OUT_FILE.flush()

class C:
    RED = '\033[91m'
    GRN = '\033[92m'
    YEL = '\033[93m'
    BLU = '\033[94m'
    CYN = '\033[96m'
    BLD = '\033[1m'
    END = '\033[0m'

import sys as _sys
if hasattr(_sys.stdout, 'reconfigure'):
    try:
        _sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

def _handle_sigint(sig, frame):
    global _STOP
    _STOP = True
    print(f"\n{C.YEL}[!] Ctrl+C — stopping cleanly...{C.END}\n")

signal.signal(signal.SIGINT, _handle_sigint)

def banner():
    print(f"""{C.CYN}{C.BLD}
                                              
                                              
██ ▄█▀ ▄▄▄▄▄ ▄▄ ▄▄ ██  ██ ▄▄ ▄▄ ▄▄  ▄▄ ▄▄▄▄▄▄ 
████   ██▄▄  ▀███▀ ██████ ██ ██ ███▄██   ██   
██ ▀█▄ ██▄▄▄   █   ██  ██ ▀███▀ ██ ▀██   ██
{C.END}
{C.BLD}Lostsec - Google Maps API Vulnerability Checker{C.END}
""")

def validate_api(api: str) -> bool:
    return bool(re.match(r'^AIza[0-9A-Za-z\-_]{35}$', api) and len(api) == 39)

def validate_proxy(proxy: str) -> bool:
    try:
        result = urlparse(proxy)
        return bool(result.scheme and result.netloc)
    except:
        return False

def load_apis_from_file(filename: str) -> List[str]:
    if not os.path.exists(filename):
        print(f"{C.RED}[ERROR] File not found: {filename}{C.END}")
        return []
    
    try:
        valid_keys = []
        with open(filename, 'r') as f:
            for line in f:
                api = line.strip()
                if api and validate_api(api):
                    valid_keys.append(api)
        return valid_keys
    except Exception as e:
        print(f"{C.RED}[ERROR] Failed to read file: {e}{C.END}")
        return []

def make_req(url: str, method: str = "GET", proxy: str = None, 
            headers: Dict = None, data: str = None) -> Tuple[int, str]:
    if _STOP:
        return -1, ""
    try:
        if headers is None:
            headers = {}
        
        headers["User-Agent"] = "COFFIN - Google Maps API Checker (Owner: lostsec)"
        proxies = {"http": proxy, "https": proxy} if proxy else None
        
        if method == "GET":
            resp = requests.get(url, headers=headers, proxies=proxies, 
                              timeout=20, verify=False, allow_redirects=True)
        elif method == "POST":
            resp = requests.post(url, headers=headers, proxies=proxies,
                               data=data if data else None, timeout=20, verify=False,
                               allow_redirects=True)
        
        return resp.status_code, resp.text
    except:
        return -1, ""

def get_json(resp: str, path: str) -> str:
    try:
        data = json.loads(resp)
        for key in path.split('.'):
            if isinstance(data, dict):
                data = data.get(key, "")
            else:
                return ""
        return str(data) if data else ""
    except:
        return ""


def check_custom_search(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://www.googleapis.com/customsearch/v1?cx=017576662512468239146:omuauf_lfve&q=lectures&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    err = get_json(resp, 'error.status')
    
    if (code == 403 and err == "PERMISSION_DENIED") or (code == 400 and err == "INVALID_ARGUMENT"):
        if not quiet:
            print(f"{C.GRN}[+] CustomSearchAPI{C.END}")
    else:
        print(f"{C.RED}[VULN] CustomSearchAPI{C.END}")
        _write_url(url)
        if poc:
            print(f"       Endpoint: {url}")

def check_static_map(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    is_error = any(x in resp for x in ["API key", "keyInvalid", "PERMISSION_DENIED", "not authorized"])
    if code == 200 and not is_error:
        print(f"{C.RED}[VULN] StaticMapAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    elif not quiet:
        print(f"{C.GRN}[+] StaticMapAPI{C.END}")

def check_street_view(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    is_error = any(x in resp for x in ["API key", "keyInvalid", "PERMISSION_DENIED", "not authorized"])
    if code == 200 and not is_error:
        print(f"{C.RED}[VULN] StreetViewAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    elif not quiet:
        print(f"{C.GRN}[+] StreetViewAPI{C.END}")

def check_directions(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    status = get_json(resp, 'status')
    err = get_json(resp, 'error.status')
    safe = (code == 403 and err == "PERMISSION_DENIED") or (code == 400 and err == "INVALID_ARGUMENT") or status == "REQUEST_DENIED"
    if safe:
        if not quiet: print(f"{C.GRN}[+] DirectionsAPI{C.END}")
    elif code == 200 and status in ("OK", "ZERO_RESULTS", "NOT_FOUND"):
        print(f"{C.RED}[VULN] DirectionsAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    else:
        print(f"{C.RED}[VULN] DirectionsAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")

def check_geocode(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    status = get_json(resp, 'status')
    err = get_json(resp, 'error.status')
    safe = (code == 403 and err == "PERMISSION_DENIED") or (code == 400 and err == "INVALID_ARGUMENT") or status == "REQUEST_DENIED"
    if safe:
        if not quiet: print(f"{C.GRN}[+] GeocodeAPI{C.END}")
    elif code == 200 and status in ("OK", "ZERO_RESULTS"):
        print(f"{C.RED}[VULN] GeocodeAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    else:
        print(f"{C.RED}[VULN] GeocodeAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")

def check_distance_matrix(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    status = get_json(resp, 'status')
    err = get_json(resp, 'error.status')
    safe = (code == 403 and err == "PERMISSION_DENIED") or (code == 400 and err == "INVALID_ARGUMENT") or status == "REQUEST_DENIED"
    if safe:
        if not quiet: print(f"{C.GRN}[+] DistanceMatrixAPI{C.END}")
    elif code == 200 and status in ("OK", "ZERO_RESULTS"):
        print(f"{C.RED}[VULN] DistanceMatrixAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    else:
        print(f"{C.RED}[VULN] DistanceMatrixAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")

def check_find_place_text(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    status = get_json(resp, 'status')
    err = get_json(resp, 'error.status')
    safe = (code == 403 and err == "PERMISSION_DENIED") or (code == 400 and err == "INVALID_ARGUMENT") or status == "REQUEST_DENIED"
    if safe:
        if not quiet: print(f"{C.GRN}[+] FindPlaceFromTextAPI{C.END}")
    elif code == 200 and status in ("OK", "ZERO_RESULTS"):
        print(f"{C.RED}[VULN] FindPlaceFromTextAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    else:
        print(f"{C.RED}[VULN] FindPlaceFromTextAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")

def check_autocomplete(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    status = get_json(resp, 'status')
    err = get_json(resp, 'error.status')
    safe = (code == 403 and err == "PERMISSION_DENIED") or (code == 400 and err == "INVALID_ARGUMENT") or status == "REQUEST_DENIED"
    if safe:
        if not quiet: print(f"{C.GRN}[+] AutocompleteAPI{C.END}")
    elif code == 200 and status in ("OK", "ZERO_RESULTS"):
        print(f"{C.RED}[VULN] AutocompleteAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    else:
        print(f"{C.RED}[VULN] AutocompleteAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")

def check_elevation(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    status = get_json(resp, 'status')
    err = get_json(resp, 'error.status')
    safe = (code == 403 and err == "PERMISSION_DENIED") or (code == 400 and err == "INVALID_ARGUMENT") or status == "REQUEST_DENIED"
    if safe:
        if not quiet: print(f"{C.GRN}[+] ElevationAPI{C.END}")
    elif code == 200 and status in ("OK", "ZERO_RESULTS"):
        print(f"{C.RED}[VULN] ElevationAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    else:
        print(f"{C.RED}[VULN] ElevationAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")

def check_timezone(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    status = get_json(resp, 'status')
    err = get_json(resp, 'error.status')
    safe = (code == 403 and err == "PERMISSION_DENIED") or (code == 400 and err == "INVALID_ARGUMENT") or status == "REQUEST_DENIED"
    if safe:
        if not quiet: print(f"{C.GRN}[+] TimezoneAPI{C.END}")
    elif code == 200 and status in ("OK", "ZERO_RESULTS"):
        print(f"{C.RED}[VULN] TimezoneAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    else:
        print(f"{C.RED}[VULN] TimezoneAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")

def check_nearest_roads(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    err = get_json(resp, 'error.status')
    if (code == 403 and err == "PERMISSION_DENIED") or (code == 400 and err == "INVALID_ARGUMENT"):
        if not quiet: print(f"{C.GRN}[+] NearestRoadsAPI{C.END}")
    elif code == 200:
        print(f"{C.RED}[VULN] NearestRoadsAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    else:
        print(f"{C.RED}[VULN] NearestRoadsAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")

def check_geolocation(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://www.googleapis.com/geolocation/v1/geolocate?key={api}'
    h = {"Authorization": f"key={api}", "Content-Type": "application/json"}
    code, resp = make_req(url, "POST", proxy, h, '{"considerIp": true}')
    if code == -1: return
    msg = get_json(resp, 'error.message')
    st = get_json(resp, 'error.status')
    if ((code == 403 and "PERMISSION_DENIED" in msg) or (code == 403 and st == "PERMISSION_DENIED") or 
        (code == 400 and st == "INVALID_ARGUMENT") or (code == 400 and msg == "INVALID_ARGUMENT") or
        (code == 403 and "Geolocation API has not been used" in msg)):
        if not quiet: print(f"{C.GRN}[+] GeolocationAPI{C.END}")
    else:
        print(f"{C.RED}[VULN] GeolocationAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")

def check_snap_to_roads(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    err = get_json(resp, 'error.status')
    if (code == 403 and err == "PERMISSION_DENIED") or (code == 400 and err == "INVALID_ARGUMENT"):
        if not quiet: print(f"{C.GRN}[+] RouteToTraveledAPI{C.END}")
    elif code == 200:
        print(f"{C.RED}[VULN] RouteToTraveledAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    else:
        print(f"{C.RED}[VULN] RouteToTraveledAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")

def check_speed_limit(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    err = get_json(resp, 'error.status')
    if (code == 403 and err == "PERMISSION_DENIED") or (code == 400 and err == "INVALID_ARGUMENT"):
        if not quiet: print(f"{C.GRN}[+] SpeedLimitRoadsAPI{C.END}")
    elif code == 200:
        print(f"{C.RED}[VULN] SpeedLimitRoadsAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    else:
        print(f"{C.RED}[VULN] SpeedLimitRoadsAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")

def check_place_details(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    status = get_json(resp, 'status')
    err = get_json(resp, 'error.status')
    safe = (code == 403 and err == "PERMISSION_DENIED") or (code == 400 and err == "INVALID_ARGUMENT") or status == "REQUEST_DENIED"
    if safe:
        if not quiet: print(f"{C.GRN}[+] PlaceDetailsAPI{C.END}")
    elif code == 200 and status in ("OK", "ZERO_RESULTS"):
        print(f"{C.RED}[VULN] PlaceDetailsAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    else:
        print(f"{C.RED}[VULN] PlaceDetailsAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")

def check_nearby_search(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    status = get_json(resp, 'status')
    err = get_json(resp, 'error.status')
    safe = (code == 403 and err == "PERMISSION_DENIED") or (code == 400 and err == "INVALID_ARGUMENT") or status == "REQUEST_DENIED"
    if safe:
        if not quiet: print(f"{C.GRN}[+] NearbySearchPlacesAPI{C.END}")
    elif code == 200 and status in ("OK", "ZERO_RESULTS"):
        print(f"{C.RED}[VULN] NearbySearchPlacesAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    else:
        print(f"{C.RED}[VULN] NearbySearchPlacesAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")

def check_text_search(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    status = get_json(resp, 'status')
    err = get_json(resp, 'error.status')
    safe = (code == 403 and err == "PERMISSION_DENIED") or (code == 400 and err == "INVALID_ARGUMENT") or status == "REQUEST_DENIED"
    if safe:
        if not quiet: print(f"{C.GRN}[+] TextSearchPlacesAPI{C.END}")
    elif code == 200 and status in ("OK", "ZERO_RESULTS"):
        print(f"{C.RED}[VULN] TextSearchPlacesAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    else:
        print(f"{C.RED}[VULN] TextSearchPlacesAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")

def check_place_photo(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    if code == 200:
        print(f"{C.RED}[VULN] PlacesPhotoAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    elif not quiet:
        print(f"{C.GRN}[+] PlacesPhotoAPI{C.END}")

def check_fcm(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://fcm.googleapis.com/fcm/send'
    h = {"Authorization": f"key={api}", "Content-Type": "application/json"}
    code, resp = make_req(url, "POST", proxy, h, '{"registration_ids":["ABC"]}')
    if code == -1: return
    if code != 200:
        if not quiet: print(f"{C.GRN}[+] FCMAPI{C.END}")
    else:
        print(f"{C.RED}[VULN] FCMAPI{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")

def check_query_autocomplete(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://maps.googleapis.com/maps/api/place/queryautocomplete/json?input=pizza+near%20par&key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    status = get_json(resp, 'status')
    err = get_json(resp, 'error.status')
    safe = (code == 403 and err == "PERMISSION_DENIED") or (code == 400 and err == "INVALID_ARGUMENT") or status == "REQUEST_DENIED"
    if safe:
        if not quiet: print(f"{C.GRN}[+] QueryAutocompletePlaces{C.END}")
    elif code == 200 and status in ("OK", "ZERO_RESULTS"):
        print(f"{C.RED}[VULN] QueryAutocompletePlaces{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    else:
        print(f"{C.RED}[VULN] QueryAutocompletePlaces{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")

def check_generative(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    url = f'https://generativelanguage.googleapis.com/v1beta/files?key={api}'
    code, resp = make_req(url, proxy=proxy)
    if code == -1: return
    if code == 200:
        print(f"{C.RED}[VULN] GenerativeLanguage{C.END}")
        _write_url(url)
        if poc: print(f"       Endpoint: {url}")
    elif not quiet:
        print(f"{C.GRN}[+] GenerativeLanguage{C.END}")

def run_all_checks(api: str, proxy: str = None, poc: bool = False, quiet: bool = False):
    checks = [
        check_custom_search,
        check_static_map,
        check_street_view,
        check_directions,
        check_geocode,
        check_distance_matrix,
        check_find_place_text,
        check_autocomplete,
        check_elevation,
        check_timezone,
        check_nearest_roads,
        check_geolocation,
        check_snap_to_roads,
        check_speed_limit,
        check_place_details,
        check_nearby_search,
        check_text_search,
        check_place_photo,
        check_fcm,
        check_query_autocomplete,
        check_generative,
    ]
    
    for func in checks:
        if _STOP:
            break
        try:
            func(api, proxy=proxy, poc=poc, quiet=quiet)
        except KeyboardInterrupt:
            break
    
    if not _STOP:
        print(f"\n{C.CYN}[*] All {len(checks)} checks completed for: {api}{C.END}\n")
    else:
        print(f"{C.YEL}[!] Scan stopped.{C.END}\n")

def main():
    parser = argparse.ArgumentParser(
        usage=argparse.SUPPRESS,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
USAGE:
  python3 keyhunt.py -k <api_key> --poc 
  python3 keyhunt.py -kf api_keys.txt --poc
        """
    )
    
    parser.add_argument('-k', '--key', help='Single Google Maps API Key to test')
    parser.add_argument('-kf', '--file', help='File with API keys (one per line)')
    parser.add_argument('-p', '--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--poc', action='store_true', help='Show PoC endpoints with vulnerabilities')
    parser.add_argument('-q', '--quiet', action='store_true', help='Only show vulnerable APIs')
    parser.add_argument('-o', '--output', help='Save vulnerable URLs to file (one per line, clean format)')
    
    args = parser.parse_args()
    
    apis = []
    
    if args.key:
        if not validate_api(args.key):
            banner()
            print(f"{C.RED}[ERROR] Invalid API key format{C.END}")
            print("Expected: AIza[0-9A-Za-z-_]{35}")
            sys.exit(1)
        apis = [args.key]
    
    elif args.file:
        apis = load_apis_from_file(args.file)
        if not apis:
            sys.exit(1)
    
    else:
        banner()
        parser.print_help()
        sys.exit(1)
    
    if args.proxy and not validate_proxy(args.proxy):
        print(f"{C.RED}[ERROR] Invalid proxy URL{C.END}")
        sys.exit(1)
    
    global _OUT_FILE
    if args.output:
        try:
            _OUT_FILE = open(args.output, 'w', encoding='utf-8')
            print(f"{C.CYN}[*] Saving vulnerable URLs to: {args.output}{C.END}")
        except Exception as e:
            print(f"{C.RED}[ERROR] Cannot open output file: {e}{C.END}")
            sys.exit(1)
    
    banner()
    
    for i, api in enumerate(apis, 1):
        if _STOP:
            break
        if len(apis) > 1:
            print(f"{C.BLU}[*] Testing API {i}/{len(apis)}: {api[:20]}...{C.END}\n")
        
        run_all_checks(api, proxy=args.proxy, poc=args.poc, quiet=args.quiet)
        
        if len(apis) > 1:
            print("")

    if _STOP:
        sys.exit(0)
    
    if _OUT_FILE:
        _OUT_FILE.close()
        print(f"{C.GRN}[✓] Results saved to: {args.output}{C.END}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YEL}[!] Exiting...{C.END}\n")
        sys.exit(0)
    except Exception as e:
        print(f"{C.RED}[ERROR] {e}{C.END}\n")
        sys.exit(1)
