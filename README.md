# EvilSMTP
This scripts provides a quick and easy way to start an SMTP Honeypot. Currently, EvilSMTP supports PLAIN and STARTTLS authentication methods. EvilSMTP will simply accept a connection, record the supplied credentials into a file, but never allow the client to send any additional data.

```console
foo@bar:~$ git clone https://github.com/abrsecuritygroup/EvilSMTP && cd EvilSMTP
```
After cloning the repository, generate a self signed TLS certificate
```console
foo@bar:~$ openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout key.pem
```

Now run the python script
```console
foo@bar:~$ sudo python3 EvilSMTP.py
```
And it's that simple! You can test your SMTP server by using swaks
```console
foo@bar:~$ swaks --to test@example.com --server {server IP} --port 587 --tls --auth {LOGIN or PLAIN} --auth-user testuser --auth-password testpass
```
A successful credential capture will show something similar to below
```console
2025-03-12 20:39:08,326 - INFO - Captured credentials from ('X.X.X.X', 18123): username=testuser, password=testpass
```
