import pandas as pd

def value_to_dataframe(values):
    """
    Converts values into a DataFrame.

    Args:
        values (value): The values to be converted.

    Returns:
        pandas.DataFrame: The converted DataFrame.
    """
    df = pd.DataFrame(values)
    return df

def csv_to_dataframe(csv_file):
    """
    Converts a CSV file into a DataFrame.

    Args:
        csv_file (str): The path to the CSV file.

    Returns:
        pandas.DataFrame: The converted DataFrame.
    """
    df = pd.read_csv(csv_file)
    return df

def convert_to_string(df, columns, semaphore):
    """
    Converts the specified columns to string type.

    Args:
        df (pandas.DataFrame): The DataFrame to be converted.
        columns (str or list): Name of the column(s) to be converted.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.

    Returns:
        None
    """
    semaphore.acquire()  
    try:
        df[columns] = df[columns].applymap(lambda x: str(x) if pd.notna(x) else x)
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release() 

    return None


def convert_to_numeric(df, columns, semaphore):
    """
    Converts the specified columns to numeric type.

    Args:
        df (pandas.DataFrame): The DataFrame to be converted.
        columns (str or list): Name of the column(s) to be converted.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.
    
    Returns:
        None
    """
    semaphore.acquire()  
    try:
        df[columns] = df[columns].apply(pd.to_numeric, errors='coerce')
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()  

    return None

def convert_to_datetime(df, columns, semaphore):
    """
    Converts the specified columns to datetime type.

    Args:
        df (pandas.DataFrame): The DataFrame to be converted.
        columns (str or list): Name of the column(s) to be converted.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.
    
    Returns:
        None
    """
    semaphore.acquire()  
    try:
        df[columns] = df[columns].apply(pd.to_datetime, errors='coerce', format='mixed')
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release() 

    return None

def convert_to_bool(df, columns, semaphore):
    """
    Converts the specified columns to boolean type.

    Args:
        df (pandas.DataFrame): The DataFrame to be converted.
        columns (str or list): Name of the column(s) to be converted.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.
    
    Returns:
        None
    """

    semaphore.acquire()  
    try:
        df[columns] = df[columns].apply(pd.to_bool, errors='coerce')
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release() 

    return None

def check_columns(df, columns, semaphore):
    """
    Checks if any columns are duplicated in the list and if specified columns are present in the DataFrame.

    Args:
        df (pandas.DataFrame): The DataFrame to be checked.
        columns (list): List of column names to be checked.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.

    Raises:
        ValueError: If any columns are duplicated in the list, if
                    any of the specified columns are missing in the DataFrame,
                    or if any column in columns is not of type string.
    """
    seen_columns = set()
    duplicate_columns = []

    for col in columns:
        if not isinstance(col, str):
            raise ValueError(f"Invalid column type. Column name must be a string: {col}")

        if col in seen_columns:
            duplicate_columns.append(col)
        else:
            seen_columns.add(col)

    if duplicate_columns:
        raise ValueError(f"The following columns are duplicated in the list: {duplicate_columns}")

    semaphore.acquire()  
    try:
        missing_columns = [col for col in columns if col not in df.columns]
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release() 

    if missing_columns:
        raise ValueError(f"The following columns are missing in the DataFrame: {missing_columns}")


def check_nan_fields(df, columns, semaphore):
    """
    Checks if there are any specified columns in the DataFrame where all fields are NaN or NaT.
    Fills NaN values with the last valid value in forward and reverse order before performing the check.

    Args:
        df (pandas.DataFrame): The DataFrame to be checked.
        columns (list): List of column names to be checked.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.

    Raises:
        ValueError: If there are any specified columns where all fields are NaN or NaT.
    """
    semaphore.acquire()  
    try:
        df[columns] = df[columns].fillna(method='ffill').fillna(method='bfill')
        nan_columns = df[columns].columns[df[columns].isnull().all()]
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()  

    if len(nan_columns) > 0:
        raise ValueError(f"There are columns in the specified columns where all fields are NaN or NaT: {nan_columns.tolist()}")