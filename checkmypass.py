import requests
import hashlib
import sys


def request_api_data(query_char):
    """Send the first five characters of the hash to be checked"""
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    """Check all the returned hashes to see if any match the full hash string"""
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    """Convert to SHA1 hash, which is required by api"""
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char = sha1password[:5]
    tail = sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times. You should change your password')
        else:
            print(f'{password} was not found')
    return 'done'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
