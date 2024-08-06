import pandas as pd
from anonymizer.utils.data_processing import check_columns

def calculate_k_anonymity(df, sensitive_columns, semaphore):
    """
    Calculate the k-anonymity of a dataset.

    Args:
        df (pd.DataFrame): The dataset to analyze.
        sensitive_columns (list): List of columns containing sensitive attributes.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.

    Returns:
        str: Minimum count among the grouped sensitive attribute combinations.
    """
    check_columns(df, sensitive_columns, semaphore)

    group_counts = df.groupby(sensitive_columns).size().reset_index(name='count')
    min_count = str(group_counts['count'].min())
    return min_count

def calculate_l_diversity(df, sensitive_columns, diversity_columns, semaphore):
    """
    Calculate the l-diversity of a dataset.

    Args:
        df (pd.DataFrame): The dataset to analyze.
        sensitive_columns (list): List of columns containing sensitive attributes.
        diversity_columns (list): List of columns containing attributes for diversity measurement.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.

    Returns:
        str: Average diversity among the unique sensitive attribute combinations.
    """

    check_columns(df, sensitive_columns, semaphore)
    check_columns(df, diversity_columns, semaphore)

    unique_combinations = df[sensitive_columns].drop_duplicates()
    min_diversities = []

    for _, group in unique_combinations.iterrows():
        group_filter = None
        for col in sensitive_columns:
            if group_filter is None:
                group_filter = (df[col] == group[col])
            else:
                group_filter &= (df[col] == group[col])

        group_df = df[group_filter]
        group_diversity = group_df[diversity_columns].nunique().min()
        min_diversities.append(group_diversity)

    average_diversity = str(sum(min_diversities) / len(min_diversities))
    return average_diversity

def calculate_t_closeness(df, sensitive_columns, closeness_columns, semaphore):
    """
    Calculate the t-closeness of a dataset.

    Args:
        df (pd.DataFrame): The dataset to analyze.
        sensitive_columns (list): List of columns containing sensitive attributes.
        closeness_columns (list): List of columns for t-closeness measurement.
        semaphore (threading.Semaphore): Semaphore to synchronize access to the DataFrame.

    Returns:
        str: Average distance of attribute means or an error message.
    """
    check_columns(df, sensitive_columns, semaphore)
    check_columns(df, closeness_columns, semaphore)

    non_numeric_attributes = [attr for attr in closeness_columns if not pd.api.types.is_numeric_dtype(df[attr])]
    if non_numeric_attributes:
        return(f"NaN")

    overall_attribute_means = df[closeness_columns].mean()
    group_distances = df.groupby(sensitive_columns)[closeness_columns].apply(lambda x: (x - overall_attribute_means).abs().mean())
    average_group_distance = str(group_distances.mean())
    return average_group_distance
