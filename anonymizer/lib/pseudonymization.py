from anonymizer.utils.data_processing import convert_to_string, check_nan_fields, check_columns
import hashlib
import pandas as pd

def pseudonymize_columns(df, columns, semaphore, **configuration):
    """
    Pseudonymizes the values in the specified columns of a DataFrame.

    Args:
        df: pandas DataFrame.
        columns: List of columns to be pseudonymized.
        semaphore: threading.Semaphore to synchronize access to the DataFrame.

    Returns:
        None
    """

    check_columns(df, columns, semaphore)
    convert_to_string(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    semaphore.acquire()  
    try:
        for column in columns:
            df[column] = df[column].apply(lambda x: f'{column}_{hashlib.md5(x.encode()).hexdigest()}' if pd.notnull(x) else x)
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:   
        semaphore.release()  

    return None

def pseudonymize_rows(df, columns, semaphore, **configuration):
    """
    Pseudonymizes the rows of the DataFrame based on the specified columns.

    Args:
        df: pandas DataFrame.
        columns: List of columns to be used for pseudonymization.
        semaphore: threading.Semaphore to synchronize access to the DataFrame.

    Returns:
        None
    """

    check_columns(df, columns, semaphore)
    convert_to_string(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    semaphore.acquire()  
    try:
        df['Object'] = df[columns].agg(''.join, axis=1)
        df.drop(columns, axis=1, inplace=True)
    
        df['Object'] = df['Object'].apply(lambda x: f'Object_{hashlib.md5(x.encode()).hexdigest()}' if pd.notnull(x) else x)
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()

    return None