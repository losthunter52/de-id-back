from anonymizer.utils.data_processing import convert_to_string, check_columns, check_nan_fields
from Crypto.Cipher import AES, ChaCha20, Salsa20
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

def encrypt_chacha20(df, columns, semaphore, **configuration):
    """
    Encrypts the values in the specified columns of the DataFrame using the ChaCha20 cipher.

    Args:
        df (pandas.DataFrame): The input DataFrame containing the data to be encrypted.
        columns (list): The list of column names whose values will be encrypted.
        semaphore (threading.Semaphore): A semaphore used to synchronize access to the DataFrame.
        configuration (dict): A dictionary containing the encryption configuration parameters.
            - 'key' (str): The encryption key used for ChaCha20 cipher.
            - 'parameter_id' (int, optional): An identifier to associate the nonce with the encryption.

    Returns:
        None
    """
    parameter_id = configuration.get('parameter_id', 0)
    key = configuration.get('key')
    if not key:
        raise ValueError("Encryption key not provided in the configuration.")
    elif not isinstance(key, str):
        raise ValueError("Encryption key should be an string.")
    
    check_columns(df, columns, semaphore)
    convert_to_string(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    key_derived = hashlib.sha256(key.encode()).digest()[:32]

    nonce = get_random_bytes(8)

    cipher = ChaCha20.new(key=key_derived, nonce=nonce)

    def encrypt_value(value):
        return cipher.encrypt(value.encode())

    semaphore.acquire()
    try:
        for column in columns:
            df[column] = df[column].apply(encrypt_value)
            df[f'{column}[{parameter_id}]_nonce'] = nonce
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()

    return None

def encrypt_aes(df, columns, semaphore, **configuration):
    """
    Encrypts the values in the specified columns of the DataFrame using the AES cipher.

    Args:
        df (pandas.DataFrame): The input DataFrame containing the data to be encrypted.
        columns (list): The list of column names whose values will be encrypted.
        semaphore (threading.Semaphore): A semaphore used to synchronize access to the DataFrame.
        configuration (dict): A dictionary containing the encryption configuration parameters.
            - 'key' (str): The encryption key used for AES cipher.

    Returns:
        None
    """
    key = configuration.get('key')
    if not key:
        raise ValueError("Encryption key not provided in the configuration.")
    elif not isinstance(key, str):
        raise ValueError("Encryption key should be an string.")
    
    check_columns(df, columns, semaphore)
    convert_to_string(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    key_derived = hashlib.sha256(key.encode()).digest()

    cipher = AES.new(key_derived, AES.MODE_ECB)

    def encrypt_value(value):
        value_padded = pad(value.encode(), AES.block_size)
        return cipher.encrypt(value_padded)

    semaphore.acquire()
    try:
        for column in columns:
            df[column] = df[column].apply(encrypt_value)
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()

    return None

def encrypt_salsa20(df, columns, semaphore, **configuration):
    """
    Encrypts the values in the specified columns of the DataFrame using the Salsa20 cipher.

    Args:
        df (pandas.DataFrame): The input DataFrame containing the data to be encrypted.
        columns (list): The list of column names whose values will be encrypted.
        semaphore (threading.Semaphore): A semaphore used to synchronize access to the DataFrame.
        configuration (dict): A dictionary containing the encryption configuration parameters.
            - 'key' (str): The encryption key used for Salsa20 cipher.
            - 'parameter_id' (int, optional): An identifier to associate the nonce with the encryption.

    Returns:
        None
    """

    parameter_id = configuration.get('parameter_id', 0)
    key = configuration.get('key')
    if not key:
        raise ValueError("Encryption key not provided in the configuration.")
    elif not isinstance(key, str):
        raise ValueError("Encryption key should be an string.")
    
    check_columns(df, columns, semaphore)
    convert_to_string(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    key_derived = hashlib.sha256(key.encode()).digest()[:32]

    nonce = get_random_bytes(8)

    cipher = Salsa20.new(key=key_derived, nonce=nonce)

    def encrypt_value(value):
        return cipher.encrypt(value.encode())

    semaphore.acquire()
    try:
        for column in columns:
            df[column] = df[column].apply(encrypt_value)
            df[f'{column}[{parameter_id}]_nonce'] = nonce
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()

    return None
