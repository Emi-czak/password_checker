"""Password validators"""
from abc import ABC, abstractmethod
from functools import lru_cache
from hashlib import sha1
from requests import get

class ValidationError(Exception):
    """Validation error exception"""

class Validator(ABC):
    """Interface for validators"""
    @abstractmethod
    def __init__(self, password):
        """Forcing the implemention of the __init__ method"""

    @abstractmethod
    def is_valid(self):
        """Forcing the implemention of the is_valid method"""

class LenghtValidator(Validator):
    """Validator to check password length"""
    def __init__(self, password, req_lenght = 8):
        self.password = password
        self.req_lenght = req_lenght

    def is_valid(self):
        """Checks if password is valid

        Raises:
            ValidationError: password is not valid because it is too short

        Returns:
            bool: password is long enough
        """
        if len(self.password) >= self.req_lenght:
            return True
        raise ValidationError('Password is too short!')

class NumberValidator(Validator):
    """Validator that check if a password contains at least one digit"""
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        """Checks if password is valid

        Raises:
            ValidationError: password is not valid because it does not contain at least one digit

        Returns:
            bool: password has at least one digit
        """
        if any(char.isdigit() for char in self.password):
            return True
        raise ValidationError('Password must contain at least one digit!')

class LowerUpperLettersValidator(Validator):
    """Validator that check if a password contains lower and upper case letters"""
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        """Checks if password is valid

        Raises:
            ValidationError: password is not valid because it does not have lower or upper character

        Returns:
            bool: password has lower and upper characters
        """
        if any(char.isupper() for char in self.password) \
            and any(char.islower() for char in self.password):
            return True
        raise ValidationError('Password must contain lower and upper case letters!')

class SpecialCharactersValidator(Validator):
    """Validator that check if a password contains at least special character"""
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        """Checks if password is valid

        Raises:
            ValidationError: password is not valid
                because it does not contain at least special character

        Returns:
            bool: password has at least special character
        """
        if any(not char.isalnum() for char in self.password):
            return True
        raise ValidationError('Password must contain at least one special character!')

class HaveIbeenPwnedValidator(Validator):
    """Validator that check if a password is not in leaked password database"""
    def __init__(self, password):
        self.password = password
        self.password_hash = self.hash_making()

    def hash_making(self):
        """Converts password into hash code

        Returns:
            str: hash code of the password
        """
        password_hash = sha1(self.password.encode('utf-8'))
        return password_hash.hexdigest().upper()

    @lru_cache(maxsize = None)
    def is_valid(self):
        """Checks if password is leaked

        Raises:
            ValidationError: password is not valid because it is in leaked password database

        Returns:
            bool: password is safe
        """
        url = 'https://api.pwnedpasswords.com/range/' + self.password_hash[:5]
        with get(url) as answ:
            for line in answ.text.splitlines():
                if self.password_hash[5:] == line.split(':')[0]:
                    raise ValidationError('Password is in the leaked passwords database!')
        return True

class PasswordValidator(Validator):
    """Validator that check if password is safe"""
    def __init__(self, password):
        self.password = password
        self.validators = [
        LenghtValidator,
        NumberValidator,
        LowerUpperLettersValidator,
        SpecialCharactersValidator,
        HaveIbeenPwnedValidator
    ]

    def is_valid(self):
        """Checks if password is safe

        Returns:
            str: password safety information
        """
        validators_check = []
        for class_name in self.validators:
            validator = class_name(self.password)
            validators_check.append(validator.is_valid())
            if all(validators_check) is False:
                print(validators_check)
                return 'unsafe'
        return 'safe'
