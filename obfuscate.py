__name__ = "rose_obfuscator"
__author__ = "gumbobr0t"
__version__ = "1.0.3"

from logging import INFO, DEBUG, getLogger, Formatter, FileHandler
from ast import (
    parse,
    unparse,
    walk,
    Name,
    Assign,
    ClassDef,
    FunctionDef,
    AsyncFunctionDef,
)
from random import choice
from string import ascii_letters, ascii_uppercase, digits, punctuation
from os import path, getcwd
from re import sub
from lzma import compress, decompress
from argparse import ArgumentParser
from colorlog import StreamHandler, ColoredFormatter
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode

log_format = "%(asctime)s [%(levelname)s] [%(module)s.%(funcName)s] %(message)s"
handler = StreamHandler()
handler.setFormatter(ColoredFormatter(log_format))
handler.setLevel(INFO)
file_handler = FileHandler("rose-obf.log", encoding="utf-8")
file_handler.setLevel(DEBUG)
file_formatter = Formatter(log_format)
file_handler.setFormatter(file_formatter)
root_logger = getLogger()
root_logger.addHandler(handler)
root_logger.addHandler(file_handler)
root_logger.setLevel(DEBUG)


def generate_key(length=16):
    characters = ascii_letters + punctuation
    key = "".join(choice(characters) for _ in range(length))
    return key


def generate_random_string(length):
    characters = ascii_uppercase + digits
    return "".join(choice(characters) for _ in range(length))


def getCustom():
    dec = choice([1, 2, 3])

    if dec == 1:
        return generate_pattern1()
    elif dec == 2:
        return generate_pattern2()
    elif dec == 3:
        return generate_pattern3()


def generate_pattern1():
    return "__" + "".join(choice("O0") for _ in range(10))


def generate_pattern2():
    return "__" + "".join(choice("0123456789") for _ in range(10)) + "__"


def generate_pattern3():
    return "".join(choice("Il") for _ in range(15)) + "I"


def encryptData(text, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return urlsafe_b64encode(ciphertext).decode()


def decryptData(ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = (
        decryptor.update(urlsafe_b64decode(ciphertext)) + decryptor.finalize()
    )

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data.decode()


def process_node(node, name_dict):
    if isinstance(node, Name) and node.id in name_dict:
        node.id = name_dict[node.id]


def obfuscate_code(input_file):
    with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    content = sub(r"\n\s*\n", "\n", content)

    tree = parse(content)

    name_dict = {}

    root_logger.info(
        "Renaming Classes, Functions, Arguments, Keyword Arguments and Variables..."
    )
    for node in walk(tree):
        if isinstance(node, (FunctionDef, AsyncFunctionDef)):
            old_name = node.name
            new_name = getCustom()
            root_logger.debug(
                f"Function Name: {old_name} ---> New Function Name: {new_name}"
            )
            name_dict[old_name] = new_name
            node.name = new_name

            for arg in node.args.args:
                old_arg_name = arg.arg
                new_arg_name = getCustom()
                root_logger.debug(
                    f"Argument Name: {old_arg_name} ---> New Argument Name: {new_arg_name}"
                )
                name_dict[old_arg_name] = new_arg_name
                arg.arg = new_arg_name

            for keyword in node.args.kwonlyargs:
                old_kwarg_name = keyword.arg
                new_kwarg_name = getCustom()
                root_logger.debug(
                    f"Keyword Argument Name: {old_kwarg_name} ---> New Keyword Argument Name: {new_kwarg_name}"
                )
                name_dict[old_kwarg_name] = new_kwarg_name
                keyword.arg = new_kwarg_name

        elif isinstance(node, ClassDef):
            old_name = node.name
            new_name = getCustom()
            root_logger.debug(f"Class Name: {old_name} ---> New Class Name: {new_name}")
            name_dict[old_name] = new_name
            node.name = new_name

    for node in walk(tree):
        if isinstance(node, Assign):
            for target in node.targets:
                if isinstance(target, Name):
                    old_var_name = target.id
                    new_var_name = getCustom()
                    root_logger.debug(
                        f"Variable Name: {old_var_name} ---> New Variable Name: {new_var_name}"
                    )
                    name_dict[old_var_name] = new_var_name
                    target.id = new_var_name

        process_node(node, name_dict)
    root_logger.info(
        "Renaming of classes, functions, arguments, keyword arguments and variables done."
    )

    return unparse(tree)


key = [ord(char) for char in generate_key()]
decryptionFun = getCustom()
ciphertextParam = getCustom()
base64decodeVar = getCustom()
lzmadecompressVar = getCustom()
keyVar = getCustom()
cipherVar = getCustom()
decryptorVar = getCustom()
decrypted_textVar = getCustom()
unpadderVar = getCustom()
unpadded_dataVar = getCustom()


def replace_string(match):
    s = match.group(1)
    encrypted_string = encryptData(s, bytes(key))
    encrypted_string = encrypted_string.replace("'", r"\'")
    chr_format = "+".join([f"chr({ord(char)})" for char in repr(encrypted_string)])
    b_format = [ord(char) for char in encrypted_string]
    stage_1 = f"{decryptionFun}(eval({base64decodeVar}({urlsafe_b64encode(f'bytes({b_format})'.encode('utf-8'))})).decode(\"utf-8\"))"
    stringified_stage_1 = str(urlsafe_b64encode(stage_1.encode("utf-8")))
    stage_2 = f'eval({base64decodeVar}({stringified_stage_1}).decode("utf-8"))[1:-1]'
    decrypted_string = decryptData(encrypted_string, bytes(key))
    root_logger.debug(
        f"String: {s} ---> Encrypted String: {encrypted_string} ---> Char Encrypted String: {chr_format} ---> Bytes Encrypted String: {b_format} ---> Evalized encoded string: {stage_2} ---> Aes Decrypted String: {decrypted_string}"
    )
    return stage_2


def obfuscate_strings(content):
    root_logger.info("Encrypting strings...")
    data = sub(r"(\'[^\']*\'|\"[^\"]*\")", replace_string, content)
    root_logger.info("Encryption of strings done.")
    return data


def main(input_file, output_file):
    root_logger.debug("Entered main function.")
    content = obfuscate_code(input_file)

    with open(output_file, "w") as f:
        data = "".join(
            [
                "from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes\n",
                "from cryptography.hazmat.primitives import padding\n",
                "from cryptography.hazmat.backends import default_backend\n",
                f"def {decryptionFun}({ciphertextParam}):\n",
                f"   {keyVar}=bytes({key})\n"
                f"   {cipherVar}=Cipher(algorithms.AES({keyVar}),modes.ECB(),backend=default_backend())\n",
                f"   {decryptorVar}={cipherVar}.decryptor()\n",
                f"   {decrypted_textVar}={decryptorVar}.update({base64decodeVar}({ciphertextParam}))+{decryptorVar}.finalize()\n",
                f"   {unpadderVar}=padding.PKCS7(128).unpadder()\n",
                f"   {unpadded_dataVar}={unpadderVar}.update({decrypted_textVar}) + {unpadderVar}.finalize()\n",
                f"   return {unpadded_dataVar}.decode()\n\n",
                obfuscate_strings(content),
            ]
        )

        compressed_data = compress(
            f'str({base64decodeVar}({urlsafe_b64encode(str(data).encode("utf-8"))}).decode("utf-8"))'.encode(
                "utf-8"
            )
        )
        data = f"from base64 import urlsafe_b64decode as {base64decodeVar};from lzma import decompress as {lzmadecompressVar};exec(eval({lzmadecompressVar}({compressed_data})))"
        data = (
            """# Obfuscated with Rose\n# github.com/rose-dll\n\n# ^..^      /\n# /_/\_____/\n#    /\   /\\\n#   /  \ /  \\\n\n"""
            + data
        )
        f.write(data)


if __name__ == "rose_obfuscator":
    parser = ArgumentParser(
        description="Obfuscate Python code efficiently with Rose-obf."
    )
    parser.add_argument(
        "-i",
        "--input",
        help="Input file name (required, .py)",
        dest="in_file",
        metavar="<input_file>",
        required=True,
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file name",
        dest="out_file",
        metavar="<output_file>",
        required=False,
    )
    args = parser.parse_args()

    input_file = args.in_file
    output_file = (
        path.join(getcwd(), f"obf-{generate_random_string(10)}.py")
        if args.out_file is None
        else args.out_file
    )

    if input_file.endswith(".py"):
        try:
            root_logger.info(f"{input_file} ---> {output_file}...")
            root_logger.debug("Entering main function.")
            main(input_file, output_file)
            root_logger.info(f"Done. {input_file} ---> {output_file}")
        except Exception as e:
            root_logger.error(f"Error: {e}")
    else:
        root_logger.error(
            "Invalid Python file entered. Please make sure the file has a .py extension."
        )
