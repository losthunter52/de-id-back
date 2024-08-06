from anonymizer.utils.data_processing import convert_to_numeric, check_nan_fields, check_columns

def percent_generalization(df, columns, semaphore, **configuration):
    """
    Applies a percent based generalization technique to one or more columns of a DataFrame.
    
    Args:
        df (pd.DataFrame): DataFrame containing the data.
        columns (list): Name of the column(s) to be generalized.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.
    
    Returns:
        None
    """

    check_columns(df, columns, semaphore)
    convert_to_numeric(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    semaphore.acquire()
    try:
        df[columns] = df[columns].applymap(percent_generalize_func)
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()

    return None

def age_generalization(df, columns, semaphore, **configuration):
    """
    Applies a age based generalization technique to one or more columns of a DataFrame.
    
    Args:
        df (pd.DataFrame): DataFrame containing the data.
        columns (list): Name of the column(s) to be generalized.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.
    
    Returns:
        None
    """

    check_columns(df, columns, semaphore)
    convert_to_numeric(df, columns, semaphore)
    check_nan_fields(df, columns, semaphore)

    semaphore.acquire()
    try:
        df[columns] = df[columns].applymap(age_generalize_func)
    except Exception as e:
        raise Exception("Unespected Error: " + str(e))
    finally:
        semaphore.release()

    return None

def age_generalize_func(value):
    if value >= 18:
        return 'Adult'
    else:
        return 'Young'

def percent_generalize_func(value):
    if value >= 75:
        return 'High'
    elif value >= 50:
        return 'Medium'
    else:
        return 'Low'
