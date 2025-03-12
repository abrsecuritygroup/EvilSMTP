#!/usr/bin/python3

import asyncio
import ssl
import logging
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, SMTP, LoginPassword

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("smtp_honeypot")

class SMTPHoneypotAuthenticator:
    """
    Class to handle SMTP authentication
    """
    def __call__(self, server, session, envelope, mechanism, auth_data=None):
        """
        This __call__ function allows this class to be called like a function. It checks to make sure
        a supported authentication mechanism is in use, checks if the authentication data is of the
        expected format, logs any captured credentials, an returns an auth results as if it failed
        """
        peer = session.peer
        logger.info("Authenticator called: mechanism=%s, auth_data=%s, peer=%s", mechanism, auth_data, peer)

        supported_mechanisms = ["LOGIN", "PLAIN"]

        #Check if the auth mechanism is supported
        if mechanism.upper() not in supported_mechanisms:
            logger.info("Unsupported mechanism: %s", mechanism)
            return AuthResult(success=False, handled=True)

        #Check if the auth data is of type LoginPassword
        if not isinstance(auth_data, LoginPassword):
            logger.error("Unexpected auth_data type: %s", type(auth_data))
            return AuthResult(success=False, handled=True)

        try:
            #Checks if auth data needs to be decoded and log the creds to your credentials file
            username = auth_data.login.decode('utf-8', errors='ignore') if isinstance(auth_data.login, bytes) else auth_data.login
            password = auth_data.password.decode('utf-8', errors='ignore') if isinstance(auth_data.password, bytes) else auth_data.password
            logger.info("Captured credentials from %s: username=%s, password=%s", peer, username, password)
            with open("credentials.log", "a") as f:
                f.write(f"Peer: {peer}, Username: {username}, Password: {password}\n")
            return AuthResult(success=False, handled=True)  # Fake success
        except Exception as e:
            logger.error("Error processing credentials from %s: %s", peer, e)
            return AuthResult(success=False, handled=True)

class SMTPHoneypotHandler:
    """
    Handle any data sent if you wish to actually handle data
    """
    async def handle_DATA(self, server, session, envelope):
        logger.info("Received DATA from %s", envelope.mail_from)
        return '250 Message accepted for delivery'

def run_smtp_starttls_honeypot():
    """
    Start the honeypot
    """
    #Define the tls context for client auth purposes. Creates a server side socket
    tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        #Load the TLS certs you created
        tls_context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
    except FileNotFoundError as e:
        logger.error("Certificate files not found: %s", e)
        return

    #Create a controller using your authentication and data handlers
    controller = Controller(
        handler=SMTPHoneypotHandler(),
        authenticator=SMTPHoneypotAuthenticator(),
        hostname='0.0.0.0',
        port=587,
        tls_context=tls_context
    )
    controller.start()
    logger.info("SMTP honeypot is running on port 587...")

    #Create a new asyncio event loop and set it to the current one.
    #This isolates the honeypot's asynchronous operations from any existing loops
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    #Run indefinitely until a KeyboardInterrupt is caught
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down honeypot.")
        controller.stop()
        loop.close()

if __name__ == '__main__':
    print("""
                   =====
                ===------=-=
            ===---------------=
           ==--------===-------=
           -----=-=-    =------=
           ---=-   =----   -==-=
          ++-     -------     -++
       +++++      -------      +++++
    ++++++++      -------      ++++++++
 +++++++++++      -------      +++++++++++
 ++++++++++       -------       ++++++++++
 +++++++          -------          +++++++
 ++++++           ---=---           ++++++
 ++++++           =+++++=           ++++++
 ++++++        +++++++++++++        ++++++
 ++++++     +++++++++++++++++++*    ++++++
 ++++++ *++++++++++++=+++++++++++++ ++++++
 +++++++++++++++++=-----=+++++++++++++++++
 +++++++++++++++  -------  +++++++++++++++
 ++++++++++++     -------     ++++++++++++
 +++++++++        -------         ++++++++
 ++**#####        -------         ####**++
 *###########     -------     ###########*
   #############   ==--=   #############
      #############     #############
         #########################
            ###################
                ############
                   ######

╦═╗┌─┐┬ ┬  ╦ ╦┬┬  ┬  ┬┌─┐┌┬┐┌─┐
╠╦╝│ │└┬┘  ║║║││  │  │├─┤│││└─┐
╩╚═└─┘ ┴   ╚╩╝┴┴─┘┴─┘┴┴ ┴┴ ┴└─┘
╔═╗┌┬┐┬  ┬┌─┐┌┐┌┌─┐┌─┐┌┬┐  ╔╗ ┬ ┬┌─┐┬┌┐┌┌─┐┌─┐┌─┐  ╦═╗┌─┐┌─┐┌─┐┬ ┬┬─┐┌─┐┌─┐┌─┐
╠═╣ ││└┐┌┘├─┤││││  ├┤  ││  ╠╩╗│ │└─┐││││├┤ └─┐└─┐  ╠╦╝├┤ └─┐│ ││ │├┬┘│  ├┤ └─┐
╩ ╩─┴┘ └┘ ┴ ┴┘└┘└─┘└─┘─┴┘  ╚═╝└─┘└─┘┴┘└┘└─┘└─┘└─┘  ╩╚═└─┘└─┘└─┘└─┘┴└─└─┘└─┘└─┘

          """)
    run_smtp_starttls_honeypot()
