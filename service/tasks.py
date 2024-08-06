import json
from celery import shared_task, current_task
from concurrent.futures import ThreadPoolExecutor, wait
from threading import Semaphore
from anonymizer.utils.data_processing import value_to_dataframe
from anonymizer.utils.data_analysis import calculate_k_anonymity, calculate_l_diversity, calculate_t_closeness
from anonymizer.lib.encryption import encrypt_aes, encrypt_chacha20, encrypt_salsa20
from anonymizer.lib.generalization import age_generalization, percent_generalization
from anonymizer.lib.hashing import apply_md5, apply_sha1, apply_sha256
from anonymizer.lib.masking import mask_cpf, mask_email, mask_first_n_characters, mask_full, mask_last_n_characters, mask_range
from anonymizer.lib.null_out import drop_columns
from anonymizer.lib.perturbation import perturb_date, perturb_numeric_gaussian, perturb_numeric_laplacian, perturb_numeric_range
from anonymizer.lib.pseudonymization import pseudonymize_columns, pseudonymize_rows
from anonymizer.lib.swapping import swap_columns, swap_rows
from secstor.shamir.lib import shamir_reconstruct, shamir_split
from secstor.pyvss.lib import pvss_combine, pvss_split
from .models import Task

SECSTOR_ALGORITHM_FUNCTIONS = {
    'reconstruct.pvss': pvss_combine,
    'split.pvss': pvss_split,
    'reconstruct.shamir': shamir_reconstruct,
    'split.shamir': shamir_split
}

ANONYMIZER_ALGORITHM_FUNCTIONS = {
    'encrypt.chacha20': encrypt_chacha20,
    'encrypt.aes': encrypt_aes,
    'encrypt.salsa20': encrypt_salsa20,
    'generalize.percent': percent_generalization,
    'generalize.age': age_generalization,
    'hash.md5': apply_md5,
    'hash.sha1': apply_sha1,
    'hash.sha256': apply_sha256,
    'mask.full': mask_full,
    'mask.range': mask_range,
    'mask.first_n_characters': mask_first_n_characters,
    'mask.last_n_characters': mask_last_n_characters,
    'mask.email': mask_email,
    'mask.cpf': mask_cpf,
    'null_out.columns': drop_columns,
    'perturb.date': perturb_date,
    'perturb.numeric_range': perturb_numeric_range,
    'perturb.numeric_gaussian': perturb_numeric_gaussian,
    'perturb.numeric_laplacian': perturb_numeric_laplacian,
    'pseudonymize.columns': pseudonymize_columns,
    'pseudonymize.rows': pseudonymize_rows,
    'swap.columns': swap_columns,
    'swap.rows': swap_rows
}

@shared_task
def assync_process_data(payload, user_pk):
    """
    Process the provided data using the specified algorithms and parameters. When processing starts, a Task object is created, and when processing ends, this object is updated according to the results obtained.

    Args:
        payload (dict): A dictionary containing 'data' and 'execution_parameters'.
                     'data' (list): List of dictionaries representing the input data.
                     'sensitive_columns' (list): List of columns containing sensitive attributes.
                     'diversity_columns' (list): List of columns containing attributes for diversity measurement.
                     'closeness_columns' (list): List of columns for t[-]closeness measurement.
                     'execution_parameters' (list): List of dictionaries containing the processing parameters.
                        Each dictionary contains the following keys:
                            - 'algorithm' (str): Name of the algorithm to apply.
                            - 'configuration' (dict): Algorithm-specific configuration parameters.
                            - 'columns' (dict): Column-specific configuration parameters.
        user_pk (int): The primary key of the user associated with this task.

    Return:
        None
    """
    task_id = current_task.request.id
    errors = [] 

    semaphore = Semaphore()

    df = value_to_dataframe(payload.get('data', []))
    description = payload.get('description', 'Object')
    sensitive_columns = payload.get('sensitive_columns', [])
    closeness_columns = payload.get('closeness_columns', [])
    diversity_columns = payload.get('diversity_columns', [])
    real_data_k_anonymity = ""
    real_data_t_closeness = ""
    real_data_l_diversity = ""
    a_error_message = False


    try:
        real_data_k_anonymity = calculate_k_anonymity(df, sensitive_columns, semaphore)
        real_data_t_closeness = calculate_t_closeness(df, sensitive_columns, closeness_columns, semaphore)
        real_data_l_diversity = calculate_l_diversity(df, sensitive_columns, diversity_columns, semaphore)
    except ValueError as ve:
        a_error_message = str(ve)
    except Exception as e:
        a_error_message = "Unespected Error: " + str(e)

    if a_error_message:
        error_info = {
            "parameter_id": 0,
            "algorithm": "real_data_analysis",
            "error_message": a_error_message
        }
        errors.append(error_info)
        task = Task.objects.create(task_id=task_id, description=description, user_id=user_pk, status='ERROR', errors = errors,  real_data_k_anonymity=real_data_k_anonymity, real_data_l_diversity= real_data_l_diversity, real_data_t_closeness=real_data_t_closeness)
        task.save()

    else:
        task = Task.objects.create(task_id=task_id, description=description, user_id=user_pk, status='PENDING', real_data_k_anonymity=real_data_k_anonymity, real_data_l_diversity= real_data_l_diversity, real_data_t_closeness=real_data_t_closeness)
        task.save()

        execution_parameters = payload.get('execution_parameters', {})

        futures = []

        with ThreadPoolExecutor() as executor:
            for parameter_id, parameter in enumerate(execution_parameters, start=1):
                algorithm = parameter.get('algorithm', {})
                configuration = parameter.get('configuration', {})
                configuration.update({"parameter_id": parameter_id})
                columns = parameter.get('columns', {})
                future = executor.submit(
                    apply_algorithm, algorithm, configuration, columns, df, semaphore, parameter_id, errors
                )
                futures.append(future)

        wait(futures)

        for column in df.columns:
            df[column] = df[column].apply(lambda x: x.decode('utf-8', errors='replace') if isinstance(x, bytes) else x)

        decoded_data = df.to_dict(orient='records')
        processed_data = json.dumps(decoded_data)

        anonymized_data_k_anonymity = ""
        anonymized_data_t_closeness = ""
        anonymized_data_l_diversity = ""


        try:
            anonymized_data_k_anonymity = calculate_k_anonymity(df, sensitive_columns, semaphore)
            anonymized_data_t_closeness = calculate_t_closeness(df, sensitive_columns, closeness_columns, semaphore)
            anonymized_data_l_diversity = calculate_l_diversity(df, sensitive_columns, diversity_columns, semaphore)
        except ValueError as ve:
            a_error_message = str(ve)
        except Exception as e:
            a_error_message = "Unespected Error: " + str(e)

        if a_error_message:
            error_info = {
                "parameter_id": 0,
                "algorithm": "anonymized_data_analysis",
                "error_message": a_error_message
            }
            errors.append(error_info)

        if errors:
            task.status = 'COMPLETED_WITH_ERRORS'
            task.result = processed_data
            task.errors = errors
            task.anonymized_data_k_anonymity = anonymized_data_k_anonymity
            task.anonymized_data_l_diversity = anonymized_data_l_diversity
            task.anonymized_data_t_closeness = anonymized_data_t_closeness
            task.save()
        else:
            task.status = 'COMPLETED'
            task.result = task.result = processed_data
            task.anonymized_data_k_anonymity = anonymized_data_k_anonymity
            task.anonymized_data_l_diversity = anonymized_data_l_diversity
            task.anonymized_data_t_closeness = anonymized_data_t_closeness
            task.save()
    
    return None

def sync_process_data(payload):
    """
    Process the provided data using the specified algorithms and parameters. 

    Args:
        payload (dict): A dictionary containing 'data' and 'execution_parameters'.
                     'data' (list): List of dictionaries representing the input data.
                     'execution_parameters' (list): List of dictionaries containing the processing parameters.
                        Each dictionary contains the following keys:
                            - 'algorithm' (str): Name of the algorithm to apply.
                            - 'configuration' (dict): Algorithm-specific configuration parameters.
                            - 'columns' (dict): Column-specific configuration parameters.
    Return:
        None
    """
    errors = [] 

    df = value_to_dataframe(payload.get('data', []))

    semaphore = Semaphore()

    execution_parameters = payload.get('execution_parameters', {})

    for parameter_id, parameter in enumerate(execution_parameters, start=1):
        algorithm = parameter.get('algorithm', {})
        configuration = parameter.get('configuration', {})
        configuration.update({"parameter_id": parameter_id})
        columns = parameter.get('columns', {})
        apply_algorithm(algorithm, configuration, columns, df, semaphore, parameter_id, errors)

    for column in df.columns:
            df[column] = df[column].apply(lambda x: x.decode('utf-8', errors='replace') if isinstance(x, bytes) else x)

    decoded_data = df.to_dict(orient='records')
    processed_data = json.dumps(decoded_data)

    return processed_data

def apply_algorithm(algorithm, configuration, columns, df, semaphore, parameter_id, errors):
    """
    Apply the specified algorithm to the DataFrame using the provided configuration and columns.

    Args:
        algorithm (str): Name of the algorithm to apply.
        configuration (dict): Algorithm-specific configuration parameters.
        columns (dict): Column-specific configuration parameters.
        df (pd.DataFrame): DataFrame containing the data to be processed.
        parameter_id (int): ID of the current processing parameter.

    Return:
        None
    """

    algorithm_function = ANONYMIZER_ALGORITHM_FUNCTIONS.get(algorithm)
    error_message = False


    if algorithm_function:
        try:
            algorithm_function(df, columns, semaphore, **configuration)
        except ValueError as ve:
            error_message = str(ve)
        except Exception as e:
            error_message = "Unespected Error: " + str(e)
    else:
        error_message = "Invalid algorithm name:" + str(algorithm)

    if error_message:
        error_info = {
            "parameter_id": parameter_id,
            "algorithm": algorithm,
            "error_message": error_message
        }
        errors.append(error_info)

    return None

def split_data(payload):
    errors = [] 

    data = payload.get('data', [])
    execution_parameters = payload.get('execution_parameters', {})

    n = execution_parameters.get('n', 2)
    k = execution_parameters.get('k', 2)
    algorithm = execution_parameters.get('algorithm', "")

    algorithm_function = SECSTOR_ALGORITHM_FUNCTIONS.get(algorithm)

    secret_share = {}    

    if algorithm_function:
        try:
            secret_share = algorithm_function(n, k, data)
        except Exception as e:
            errors.append("Unespected Error: " + str(e))
    else:
        errors.append("Invalid algorithm name:" + str(algorithm))

    if len(errors) > 0:
        return json.dumps({"error":errors})
    else:
        return secret_share

def reconstruct_data(payload):
    errors = [] 

    secret_share = payload.get('data', {})
    execution_parameters = payload.get('execution_parameters', {})

    n = execution_parameters.get('n', 2)
    k = execution_parameters.get('k', 2)
    algorithm = execution_parameters.get('algorithm', "")

    algorithm_function = SECSTOR_ALGORITHM_FUNCTIONS.get(algorithm)

    secret = ""    

    if algorithm_function:
        try:
            secret = algorithm_function(n, k, secret_share)
        except Exception as e:
            errors.append("Unespected Error: " + str(e))
    else:
        errors.append("Invalid algorithm name:" + str(algorithm))

    if len(errors) > 0:
        return  json.dumps({"error":errors})
    else:
        return secret
