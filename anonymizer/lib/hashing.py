from anonymizer.utils.data_processing import convert_to_string, check_nan_fields, check_columns
import hashlib

def apply_md5(df, columns, semaphore, **configuration):
    """
    Applies the MD5 hash function to the specified columns of a DataFrame.

    Args:
        df (pd.DataFrame): DataFrame containing the data.
        columns (list): Name of the column(s) to apply the MD5 hash.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.

    Returns:
        None
    """

    check_columns(df, columns, semaphore)
    convert_to_string(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    semaphore.acquire() 
    try:
        for column in columns:
            df[column] = df[column].apply(lambda x: hashlib.md5(x.encode()).hexdigest())
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()  

    return None

def apply_sha1(df, columns, semaphore, **configuration):
    """
    Applies the SHA1 hash function to the specified columns of a DataFrame.

    Args:
        df (pd.DataFrame): DataFrame containing the data.
        columns (list): Name of the column(s) to apply the SHA1 hash.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.

    Returns:
        None
    """

    check_columns(df, columns, semaphore)
    convert_to_string(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    semaphore.acquire()  
    try:
        for column in columns:
            df[column] = df[column].apply(lambda x: hashlib.sha1(x.encode()).hexdigest())
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()  

    return None

def apply_sha256(df, columns, semaphore, **configuration):
    """
    Applies the SHA256 hash function to the specified columns of a DataFrame.

    Args:
        df (pd.DataFrame): DataFrame containing the data.
        columns (list): Name of the column(s) to apply the SHA256 hash.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.

    Returns:
        None
    """

    check_columns(df, columns, semaphore)
    convert_to_string(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    semaphore.acquire()  
    try:
        for column in columns:
            df[column] = df[column].apply(lambda x: hashlib.sha256(x.encode()).hexdigest())
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()  

    return None
