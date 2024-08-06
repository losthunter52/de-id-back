from anonymizer.utils.data_processing import  convert_to_datetime, convert_to_numeric, check_nan_fields, check_columns
import pandas as pd
import numpy as np
import random

def perturb_date(df, columns, semaphore, **configuration):
    """
    Applies a date perturbation technique to specific columns of the DataFrame.

    Args:
        df (pandas.DataFrame): The input DataFrame.
        columns (list): A list of column names to apply the perturbation to.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.
        configuration (dict): A dictionary containing the perturbation configuration parameters.
            - unit (string): Unit of time to be added/subtracted (e.g., 'days', 'hours', 'minutes').
            - min_value (int): Minimum number of units to be added/subtracted.
            - max_value (int): Maximum number of units to be added/subtracted.

    Returns:
        None
    """
    unit = configuration.get('unit')
    if not unit:
        raise ValueError("Unit of Time not provided in the configuration.")
    elif not isinstance(unit, str):
        raise ValueError("Unit of Time should be an string.")
    
    min_value = configuration.get('min_value')
    if not min_value:
        raise ValueError("Minimum number of units not provided in the configuration.")
    elif not isinstance(min_value, int):
        raise ValueError("Minimum number of units should be an integer.")
    
    max_value = configuration.get('max_value')
    if not max_value:
        raise ValueError("Maximum number of units not provided in the configuration.")
    elif not isinstance(max_value, int):
        raise ValueError("Maximum number of units should be an integer.")


    supported_units = [
        'days',
        'hours',
        'minutes',
        'seconds',
        'milliseconds',
        'microseconds',
        'nanoseconds'
    ]

    if unit not in supported_units:
        raise ValueError(f"Unsupported unit: {unit}")
    
    check_columns(df, columns, semaphore)
    convert_to_datetime(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    semaphore.acquire()  
    try:
        for column in columns:
            df[column] = df[column].apply(lambda x: x + pd.Timedelta(**{unit: random.randint(min_value, max_value)}))
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()  

    return None


def perturb_numeric_range(df, columns, semaphore, **configuration): 
    """
    Applies a numeric perturbation technique to specific columns of the DataFrame.

    Args:
        df (pandas.DataFrame): The input DataFrame.
        columns (list): A list of column names to apply the perturbation to.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.
        configuration (dict): A dictionary containing the perturbation configuration parameters.
            - min_value: Minimum of the range of the perturbation.
            - max_value: Maximum of the range of the perturbation.
    
    Returns:
        None
    """

    min_value = configuration.get('min_value')
    if not min_value:
        raise ValueError("Minimum of the range not provided in the configuration.")
    elif not isinstance(min_value, int):
        raise ValueError("Minimum of the range should be an integer.")
    
    max_value = configuration.get('max_value')
    if not max_value:
        raise ValueError("Maximum of the range not provided in the configuration.")
    elif not isinstance(max_value, int):
        raise ValueError("Maximum of the range should be an integer.")
    
    if min_value >= max_value:
        raise ValueError("Invalid range.")  

    perturbation_range = (min_value, max_value)

    check_columns(df, columns, semaphore)
    convert_to_numeric(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    semaphore.acquire()  
    try:
        for column in columns:
            if np.issubdtype(df[column].dtype, np.integer):
                df[column] += np.random.randint(*perturbation_range, size=len(df[column]))
            elif np.issubdtype(df[column].dtype, np.floating):
                df[column] += np.random.uniform(*perturbation_range, size=len(df[column]))
            else:
                raise ValueError(f"Column '{column}' is not of type int or float.")
    except ValueError as ve:
            raise ValueError("" + ve)
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release() 

    return None


def perturb_numeric_gaussian(df, columns, semaphore, **configuration): 
    """
    Applies a Gaussian perturbation technique to specific columns of the DataFrame.

    Args:
        df (pandas.DataFrame): The input DataFrame.
        columns (list): A list of column names to apply the perturbation to.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.
        configuration (dict): A dictionary containing the perturbation configuration parameters.
            - std: Standard deviation of the Gaussian perturbation.
    
    Returns:
        None
    """

    std = configuration.get('std')
    if not std:
        raise ValueError("Perturbation std not provided in the configuration.")
    elif not isinstance(std, float):
        raise ValueError("Perturbation std should be an float.")

    check_columns(df, columns, semaphore)
    convert_to_numeric(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    semaphore.acquire()  
    try:
        for column in columns:
            if np.issubdtype(df[column].dtype, np.integer):
                df[column] += np.random.normal(scale=std, size=len(df[column])).astype(int)
            elif np.issubdtype(df[column].dtype, np.floating):
                df[column] += np.random.normal(scale=std, size=len(df[column]))
            else:
                raise ValueError(f"Column '{column}' is not of type int or float.")
    except ValueError as ve:
            raise ValueError("" + ve)
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()  

    return None

def perturb_numeric_laplacian(df, columns, semaphore, **configuration): 
    """
    Applies a Laplacian perturbation technique to specific columns of the DataFrame.

    Args:
        df (pandas.DataFrame): The input DataFrame.
        columns (list): A list of column names to apply the perturbation to.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.
        configuration (dict): A dictionary containing the perturbation configuration parameters.
            - value: Perturbation value.
    
    Returns:
        None
    """

    value = configuration.get('value')
    if not value:
        raise ValueError("Perturbation value not provided in the configuration.")
    elif not isinstance(value, int):
        raise ValueError("Perturbation value should be an integer.")

    check_columns(df, columns, semaphore)
    convert_to_numeric(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    semaphore.acquire() 
    try:
        for column in columns:
            if np.issubdtype(df[column].dtype, np.integer):
                df[column] += np.random.laplace(scale=value/np.sqrt(2), size=len(df[column]))
            elif np.issubdtype(df[column].dtype, np.floating):
                df[column] += np.random.laplace(scale=value/np.sqrt(2), size=len(df[column]))
            else:
                raise ValueError(f"Column '{column}' is not of type int or float.")
    except ValueError as ve:
            raise ValueError("" + ve)
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()  

    return None