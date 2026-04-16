import requests
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize colors
init(autoreset=True)

# Banner
print(Fore.CYAN + """
========================================
   Heroku API Key Validator 
   Author: Nithin
========================================
""")

# Function to check key
def check_api_key(api_key):
    url = "https://api.heroku.com/account"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/vnd.heroku+json; version=3"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return (api_key, "VALID", response.status_code)
        elif response.status_code == 429:
            return (api_key, "RATE_LIMITED", response.status_code)
        else:
            return (api_key, "INVALID", response.status_code)
    except requests.exceptions.ConnectionError:
        return (api_key, "ERROR", 0)
    except requests.exceptions.Timeout:
        return (api_key, "ERROR", 0)
    except requests.exceptions.RequestException as e:
        return (api_key, "ERROR", 0)


def main():
    file_path = input(Fore.YELLOW + "Enter file path: ").strip()

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            keys = [line.strip() for line in f if line.strip()]

        if not keys:
            print(Fore.RED + "No keys found in file!")
            return

        print(Fore.BLUE + f"\nLoaded {len(keys)} keys\n")

        valid_keys = []
        invalid_count = 0
        error_count = 0
        rate_limited_count = 0

        # Thread pool (5 workers to avoid rate limiting)
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(check_api_key, key) for key in keys]

            for future in as_completed(futures):
                key, status, code = future.result()
                code_str = f"[{code}]" if code != 0 else "[ERR]"

                if status == "VALID":
                    print(Fore.GREEN + f"[VALID]        {code_str}  {key}")
                    valid_keys.append(key)

                elif status == "INVALID":
                    print(Fore.RED + f"[INVALID]      {code_str}  {key}")
                    invalid_count += 1

                elif status == "RATE_LIMITED":
                    print(Fore.YELLOW + f"[RATE LIMITED] {code_str}  {key}")
                    rate_limited_count += 1

                else:
                    print(Fore.MAGENTA + f"[ERROR]        {code_str}  {key}")
                    error_count += 1

        # Save valid keys
        with open("valid_keys.txt", "w", encoding="utf-8") as f:
            for key in valid_keys:
                f.write(key + "\n")

        print(Fore.CYAN + "\n========== SUMMARY ==========")
        print(Fore.GREEN  + f"Valid Keys    : {len(valid_keys)}")
        print(Fore.RED    + f"Invalid Keys  : {invalid_count}")
        print(Fore.YELLOW + f"Rate Limited  : {rate_limited_count}")
        print(Fore.MAGENTA+ f"Errors        : {error_count}")
        print(Fore.YELLOW + "Saved valid keys to valid_keys.txt")

    except FileNotFoundError:
        print(Fore.RED + "File not found!")
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\nStopped by user.")


if __name__ == "__main__":
    main()
