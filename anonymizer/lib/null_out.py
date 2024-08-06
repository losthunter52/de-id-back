from anonymizer.utils.data_processing import check_columns

def drop_columns(df, columns, semaphore, **configuration):
    """
    Drops the specified columns from a DataFrame.

    Args:
        df (pd.DataFrame): DataFrame containing the data.
        columns (str or list): Name of the column(s) to be dropped.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.

    Returns:
        None
    """

    check_columns(df, columns, semaphore)

    semaphore.acquire()  
    try:
        df.drop(columns, axis=1, inplace=True)
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()  

    return None