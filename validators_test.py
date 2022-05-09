"""Collection of validator tests"""
import pytest
from validators import (
    LenghtValidator,
    NumberValidator,
    LowerUpperLettersValidator,
    SpecialCharactersValidator,
    HaveIbeenPwnedValidator,
    PasswordValidator,
    ValidationError
)

def test_password_lenght_is_enought():
    validator = LenghtValidator('12345678')
    result = validator.is_valid()
    assert result is True

    validator_2 = LenghtValidator('123', 3)
    result_2 = validator_2.is_valid()
    assert result_2 is True

def test_password_lenght_is_not_enought():
    validator = LenghtValidator('1234567')

    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password is too short' in str(error.value)

    validator_2 = LenghtValidator('1234', 5)
    with pytest.raises(ValidationError) as error:
        validator_2.is_valid()
        assert 'Password is too short' in str(error.value)

def test_number_in_password_is_positive():
    validator = NumberValidator('Password1')
    result = validator.is_valid()
    assert result is True

def test_number_in_password_is_negative():
    validator = NumberValidator('Password')
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password must contain at least one digit!' in str(error.value)

def test_lower_upper_case_letters_in_password_is_positive():
    validator = LowerUpperLettersValidator('passWord')
    result = validator.is_valid()
    assert result is True

    validator_2 = LowerUpperLettersValidator('PASSwORD')
    result_2 = validator_2.is_valid()
    assert result_2 is True

def test_lower_upper_case_letters_in_password_is_negative():
    validator = LowerUpperLettersValidator('password')
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password must contain lower and upper case letters!' in str(error.value)

    validator_2 = LowerUpperLettersValidator('PASSWORD')
    with pytest.raises(ValidationError) as error:
        validator_2.is_valid()
        assert 'Password must contain lower and upper case letters!' in str(error.value)

def test_special_characters_in_password_is_positive():
    validator = SpecialCharactersValidator('p@ssword')
    result = validator.is_valid()
    assert result is True

def test_special_characters_in_password_is_negative():
    validator = LowerUpperLettersValidator('password')
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password must contain at least one special character!' in str(error.value)

def test_password_is_not_leaked(requests_mock):
    #password: P4s$wORd_13
    #hash: AAB6D9F554EA847B6309CFE5419DC406E5178712
    data = '0123A5B3069D0CA31210A184BB79927B9C9:64\n\r \
    AD6F6EB8508DD6A14CFA704BAD7F05F6FB1:5\n\r \
    012A94FB50CFC1267DEC3EE8C3826AA2405:1\n\r'

    requests_mock.get('https://api.pwnedpasswords.com/range/AAB6D', text = data)
    validator = HaveIbeenPwnedValidator('P4s$wORd_13')
    result = validator.is_valid()
    assert result is True

def test_password_is_leaked(requests_mock):
    #password: Password123
    #hash: B2E98AD6F6EB8508DD6A14CFA704BAD7F05F6FB1
    data = '0123A5B3069D0CA31210A184BB79927B9C9:64\n\rAD6F6EB8508DD6A14CFA704BAD7F05F6FB1:5\n\r\
    012A94FB50CFC1267DEC3EE8C3826AA2405:1\n\r'

    requests_mock.get('https://api.pwnedpasswords.com/range/B2E98', text = data)
    validator = HaveIbeenPwnedValidator('Password123')
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password is in the leaked passwords database!' in str(error.value)

def test_password_is_safe(requests_mock):
    #password: s1Mpl3_P@$sw0rd
    #hash: 1E3C9414EEE7C0FF56214399178D4E84DCFB5179
    data = '0123A5B3069D0CA31210A184BB79927B9C9:64\n\rAD6F6EB8508DD6A14CFA704BAD7F05F6FB1:5\n\r\
    012A94FB50CFC1267DEC3EE8C3826AA2405:1\n\r'

    requests_mock.get('https://api.pwnedpasswords.com/range/1E3C9', text = data)
    validator = PasswordValidator('s1Mpl3_P@$sw0rd')
    result = validator.is_valid()
    assert result == 'safe'

def test_password_is_unsafe():
    validator = PasswordValidator('s1mpl3_p@s$w0rd')
    with pytest.raises(ValidationError) as error:
        validator.is_valid()
        assert 'Password must contain lower and upper case letters!' in str(error.value)
