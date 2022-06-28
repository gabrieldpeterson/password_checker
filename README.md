This command line program checks to see if your password has been found in any compromised sites.

It uses the API from pwnedpasswords.com, and the full SHA1 hash of the password is never sent, it is checked locally on your machine.

Run the program from the terminal followed by the password or passwords you want checked.

Example:
python3 checkmypass.py password123 password456