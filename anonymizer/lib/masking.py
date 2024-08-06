from anonymizer.utils.data_processing import convert_to_string, check_nan_fields, check_columns
import re

def mask_full(df, columns, semaphore, **configuration):
    """
    Applies the '*' mask to all specified columns.

    Args:
        df (pandas.DataFrame): The input DataFrame.
        columns (list): A list of column names to apply the mask to.
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
            df[column] = '*'
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()

    return None


def mask_range(df, columns, semaphore, **configuration): 
    """
    Applies the '*' mask to a range of characters in each specified column.

    Args:
        df (pandas.DataFrame): The input DataFrame.
        columns (list): A list of column names to apply the mask to.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.
        configuration (dict): A dictionary containing the mask configuration parameters.
            - 'start_index' (int): The starting index of the range.
            - 'end_index' (int): The ending index of the range.

    Returns:
        None
    """
    start_index = configuration.get('start_index')
    if not start_index:
        raise ValueError("Start Index not provided in the configuration.")
    elif not isinstance(start_index, int):
        raise ValueError("Start Index should be an integer.")
    
    end_index = configuration.get('end_index')
    if not end_index:
        raise ValueError("End Index not provided in the configuration.")
    elif not isinstance(end_index, int):
        raise ValueError("End Index should be an integer.")
    
    if start_index < 1:
        raise ValueError("Start_index must be higher than zero.")
    if start_index >= end_index:
        raise ValueError("Invalid range.")  
    
    start_index -= 1
    end_index -= 1
    
    check_columns(df, columns, semaphore)
    convert_to_string(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    semaphore.acquire()
    try:
        for column in columns:
            df[column] = apply_range_mask(df[column], start_index, end_index)
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()

    return None


def apply_range_mask(column, start_index, end_index):        
    start_index = min(start_index, len(str(column.iloc[0])))
    column = column.apply(
        lambda val: val[:start_index] + '*' * (min(end_index, len(val)) - start_index) + val[min(end_index, len(val)):]
    )
    
    return column


def mask_last_n_characters(df, columns, semaphore, **configuration): 
    """
    Applies the '*' mask to the last N characters of each specified column.

    Args:
        df (pandas.DataFrame): The input DataFrame.
        columns (list): A list of column names to apply the mask to.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.
        configuration (dict): A dictionary containing the mask configuration parameters.
            - 'n' (int): The number of characters to mask from the end of each value.

    Returns:
        None
    """
    n = configuration.get('n')
    if not n:
        raise ValueError("N Value not provided in the configuration.")
    elif not isinstance(n, int):
        raise ValueError("N should be an integer.")
    elif n < 1:
        raise ValueError("Start_index must be higher than zero.")
    
    check_columns(df, columns, semaphore)
    convert_to_string(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)
    
    semaphore.acquire()
    try:
        for column in columns:
            df[column] = apply_last_n_character_mask(df[column], n)
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()

    return None


def apply_last_n_character_mask(column, n):
    masked_column = column.apply(lambda val: str(val)[:-min(n, len(str(val)))] + '*' * min(n, len(str(val))))
    return masked_column


def mask_first_n_characters(df, columns, semaphore, **configuration): 
    """
    Applies the '*' mask to the first N characters of each specified column.

    Args:
        df (pandas.DataFrame): The input DataFrame.
        columns (list): A list of column names to apply the mask to.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.
        configuration (dict): A dictionary containing the mask configuration parameters.
            - 'n' (int): The number of characters to mask from the beginning of each value.

    Returns:
        None
    """
    n = configuration.get('n')
    if not n:
        raise ValueError("N Value not provided in the configuration.")
    elif not isinstance(n, int):
        raise ValueError("N should be an integer.")
    elif n < 1:
        raise ValueError("Start_index must be higher than zero.")
    
    check_columns(df, columns, semaphore)
    convert_to_string(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    semaphore.acquire()
    try:
        for column in columns:
            df[column] = apply_first_n_character_mask(df[column], n)
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()

    return None


def apply_first_n_character_mask(column, n):
    masked_column = column.apply(lambda val: '*' * min(n, len(str(val))) + str(val)[min(n, len(str(val))):])
    return masked_column


def mask_email(df, columns, semaphore, **configuration): 
    """
    Extracts the email domain from each specified column and replaces invalid values with 'email.com'.

    Args:
        df (pandas.DataFrame): The input DataFrame.
        columns (list): A list of column names to apply the mask to.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.

    Returns:
        None
    """
    check_columns(df, columns, semaphore)
    convert_to_string(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    pattern = re.compile(r"@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")

    semaphore.acquire()
    try:
        for column in columns:
            df[column] = df[column].str.extract(pattern).fillna("email.com")
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()

    return None


def mask_cpf(df, columns, semaphore, **configuration): 
    """
    Applies the mask to CPFs, keeping only the first 3 digits and the last 2 digits visible.

    Args:
        df (pandas.DataFrame): The input DataFrame.
        columns (list): A list of column names to apply the mask to.
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
            df[column] = apply_mask_cpf(df[column])
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:    
        semaphore.release()

    return None


def apply_mask_cpf(column):
    column = column.astype(str)
    mask_11 = column.str.len() == 11
    mask_14 = column.str.len() == 14

    column[mask_11] = column[mask_11].str[:3] + '*' * 6 + column[mask_11].str[-2:]
    column[mask_14] = column[mask_14].str[:3] + '.' + '*' * 3 + '.' + '*' * 3 + column[mask_14].str[-2:]
    column[~(mask_11 | mask_14)] = '***.***.***-**'

    return column