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
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            return (api_key, "VALID")
        else:
            return (api_key, "INVALID")
    except:
        return (api_key, "ERROR")


def main():
    file_path = input(Fore.YELLOW + "Enter file path: ")

    try:
        with open(file_path, "r") as f:
            keys = [line.strip() for line in f if line.strip()]

        print(Fore.BLUE + f"\nLoaded {len(keys)} keys\n")

        valid_keys = []
        invalid_count = 0

        # Thread pool (adjust workers if needed)
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_api_key, key) for key in keys]

            for future in as_completed(futures):
                key, status = future.result()

                if status == "VALID":
                    print(Fore.GREEN + f"[VALID]   {key}")
                    valid_keys.append(key)

                elif status == "INVALID":
                    print(Fore.RED + f"[INVALID] {key}")
                    invalid_count += 1

                else:
                    print(Fore.MAGENTA + f"[ERROR]   {key}")

        # Save valid keys
        with open("valid_keys.txt", "w") as f:
            for key in valid_keys:
                f.write(key + "\n")

        print(Fore.CYAN + "\n========== SUMMARY ==========")
        print(Fore.GREEN + f"Valid Keys   : {len(valid_keys)}")
        print(Fore.RED + f"Invalid Keys : {invalid_count}")
        print(Fore.YELLOW + "Saved valid keys to valid_keys.txt")

    except FileNotFoundError:
        print(Fore.RED + "File not found!")


if __name__ == "__main__":
    main()
