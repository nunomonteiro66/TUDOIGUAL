import hashlib, binascii

from .sqlhelper import *
from .tui.cli import crt

MYSQL = mysql.connector

class UsernameNotFound(Exception):
    """Exception UsernameNotFound."""
    def __init__(self, message="Username not found"):
        self.message = message
        super().__init__(self.message)


class WrongPassword(Exception):
    """Exception WrongPassword."""
    def __init__(self, message="Wrong password"):
        self.message = message
        super().__init__(self.message)


class DBControl(object):
    def __init__(self) -> None:
        """Initializes DBControl"""
        self._helper = MySQLDBHelper()
        self._helper.bindErrorCallback(crt.writeError)

    def start(self):
        """
        Starts DBControl.

        Raises:
            ConnectionNotEstablished: raised when MySQLDBHelper isn't connected
        """
        self._helper.connect()
        if not self._helper.isConnected():
            raise ConnectionNotEstablished()


    def stop(self):
        """Stops DBControl."""        
        if self._helper.isConnected():
            self._helper.disconnect()
            
    
    def fetchAppId(self, appId):
        """
        Fetchs App ID.
        WHERE THE HELL IS THIS CALLED???

        Args:
            appId (int): Application ID

        Returns:
            [type]: [description] 
        """        
        self.start()
        self._helper                    \
            .Select([("`key`", None)])  \
            .From("apps")               \
            .Where("appid=?")           \
            .execute((appId,))

        self._helper.resetQuery()

        try:
            record = self._helper.getCursor().next()[0]
            #for (r,) in self._helper.getCursor():
            #    record = r
            self.stop()
            return record
        except (StopIteration, Exception, MYSQL.Error):
            self.stop()
            return None
        
        
    def getHMACKey(self):
        """
        Gets HMAC Key from the config.

        Returns:
            str: HMAC key
        """        
        return self._helper.config['VALIDATION']['hmac']
    
    
    def valueExists(self, table, field, value):
        """
        Checks if value exists.

        Args:
            table (str): Table
            field (str): Field
            value (str): Value

        Returns:
            bool: True IF exists ELSE False
        """        
        self.start()
        self._helper                    \
            .Select([(field, None)])    \
            .From(table)                \
            .Where(f"{field}=?")        \
            .execute((value,))
        self._helper.resetQuery()
        ok = False
        for (c,) in self._helper.getCursor():
            ok = True
        self.stop()
        return ok
    
    
    def userExists(self, username):
        """
        Checks if user exists.

        Args:
            username (str): Username

        Returns:
            bool: True IF exists ELSE False
        """
        return self.valueExists(
            table = "utilizadores",
            field = "username",
            value = username
        )
        
        
    def emailExists(self, email):
        """
        Checks if an email already exists.

        Args:
            email (str): email

        Returns:
            bool: True IF exists ELSE False
        """
        return self.valueExists(
            table = "utilizadores",
            field = "email",
            value = email
        )


    def loginUser(self, username, password):
        """
        Logs the user in.

        Args:
            username (str): Username
            password (str): Password

        Raises:
            Exception:        Generic Exception
            UsernameNotFound: Could not find username
            WrongPassword:    Wrong Password

        Returns:
            (bool, int): (Success, User ID)
        """
        self.start()
        key, salt = "", ""
        self._helper \
            .Select([("id_user", None), ("password", None), ("salt", None)]) \
            .From("utilizadores") \
            .Where("username=?") \
            .execute((username,))
        
        self._helper.resetQuery()

        try:
            for (x, y, z) in self._helper.getCursor():
                (id_user, key, salt) = (x, y, z)
            if (password == "" or salt == ""):
                raise Exception()
        except (Exception, MYSQL.Error) as ex:
            raise UsernameNotFound(f"User '{username}' does not exist.")
        self.stop()
        new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), binascii.unhexlify(salt), 100000)
        if new_key == binascii.unhexlify(key):
            return (True, id_user)
        else:
            raise WrongPassword(f"Wrong password for user '{username}'.")


    def registerUser(self, username, password, email):
        """
        Registers User.
        Generates salt, calculates sha256 (10000x)

        Args:
            username (str): Username
            password (str): Password
            email (str): Email

        Returns:
            bool: True IF successful ELSE False
        """
        self.start()
        salt = os.urandom(32)   # A new salt for this user
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        try:
            self._helper \
                .InsertInto("utilizadores", ["username", "email", "password", "salt"]) \
                .execute((username, email, binascii.hexlify(key), binascii.hexlify(salt),))
            self._helper.commit()
        except (Exception, MYSQL.Error) as ex:
            crt.writeError(f"Error at database: {ex}")
            self._helper.resetQuery()
            self.stop()
            return False
        self._helper.resetQuery()
        self.stop()
        return True
    
    
    def getEmail(self, id_user):
        """
        Gets Email.

        Args:
            id_user (str): User ID

        Returns:
            str: User's Email
            None: When fails
        """        
        self.start()
        try:
            self._helper                    \
                .Select([("email", None)])  \
                .From("utilizadores")       \
                .Where("id_user = ?")       \
                .execute((id_user,))
            self._helper.resetQuery()
            for (email,) in self._helper.getCursor():
                useremail = email
            self.stop()
            return useremail
        except (Exception, MYSQL.Error) as ex:
            crt.writeError(f"Error at database: {ex}")
            self._helper.resetQuery()
        self.stop()
        return None