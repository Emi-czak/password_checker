"""
    Checks passwords in *.txt file
    using collections of password validators
    and file handling methods
"""
from file import File
from validators import HaveIbeenPwnedValidator, PasswordValidator

if __name__ == '__main__':
    # hash_password_file = File('password_file_number_2')
    # hash_password_file.add_new_password()
    # hash_password_file.check_file()
    haszysz = HaveIbeenPwnedValidator('ZAQ!2wsxCDE#')
    print(haszysz.hash_making())
