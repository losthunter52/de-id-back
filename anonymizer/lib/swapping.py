from anonymizer.utils.data_processing import check_nan_fields, check_columns
import pandas as pd
import numpy as np

def swap_columns(df, columns, semaphore, **configuration):
    """
    Swaps the values in the specified columns of the DataFrame.

    Args:
        df (pandas.DataFrame): The DataFrame to be modified.
        columns (str or list): Name of the column(s) to be swapped.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.

    Returns: 
        None
    """

    
    check_columns(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    semaphore.acquire()  
    try:
        for column in columns:
            df[column] = np.random.permutation(df[column])
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()  

    return None

def swap_rows(df, columns, semaphore, **configuration):
    """
    Swaps the rows of the DataFrame based on the values in the specified columns.

    Args:
        df (pandas.DataFrame): The DataFrame to be modified.
        columns (str or list): Name of the column(s) to be used for row swapping.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.
    
    Returns: 
        None
    """

    check_columns(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    combined_column = '_combined_'

    semaphore.acquire() 
    try:
        df[combined_column] = df[columns].apply(tuple, axis=1)
        df[combined_column] = np.random.permutation(df[combined_column])
        df[columns] = pd.DataFrame(df[combined_column].tolist(), index=df.index)
        df.drop(columns=[combined_column], inplace=True)
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()

    return None