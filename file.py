"""Handling file with passwords to be checked"""
from validators import PasswordValidator, ValidationError

class File:
    """Checks passwords in file and safe results in another one"""
    def __init__(self,filename):
        self.input_file = filename + '.txt'
        self.output_file = filename + '_results.txt'

    @staticmethod
    def mini_menu():
        """Print simple user interface on console"""
        print('Avelible options:')
        print('1 - add new password')
        print('0 - check passwords')

    def read_file(self):
        """Print passwords in file"""
        with open(self.input_file, mode = 'r', encoding='utf-8') as file:
            for line in file:
                print(line.strip())

    def add_new_password(self):
        """Adding new passwords to existing file"""
        with open(self.input_file, mode = 'a', encoding='utf-8') as file:
            while True:
                self.mini_menu()
                choose = input('Choose option: ')
                if choose == '1':
                    password = input('Type new password to check: ')
                    file.write(password + '\n')
                elif choose == '0':
                    return False

    def how_many_unsafe_passwords(self):
        """Print number of unsafe password in checked file"""
        with open(self.output_file, 'r', encoding='utf-8') as output_file:
            unsafe_pswrd = [line.split('\t')[0] for line in output_file \
                if line.split('\t')[1].strip() == 'unsafe']
            return len(unsafe_pswrd)

    def check_file(self):
        """Checks if passwords in file are safe and saves results in new file"""
        with open(self.input_file, 'r', encoding='utf-8') as input_file, \
            open(self.output_file, 'w', encoding='utf-8') as output_file:
            for line in input_file:
                try:
                    strip_password = line.strip()
                    check = PasswordValidator(strip_password)
                    check.is_valid()
                    output_file.write(strip_password + '\t' + 'safe' + '\n')
                except ValidationError as error:
                    output_file.write(strip_password + '\t' + 'unsafe' + '\t' + str(error) + '\n')
                    print(strip_password, error)
        print(f'You have {len(self.how_many_unsafe_passwords())} unsafe passwords')
