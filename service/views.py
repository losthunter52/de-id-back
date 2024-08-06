from rest_framework.decorators import api_view, parser_classes, authentication_classes, permission_classes
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from .tasks import assync_process_data, sync_process_data
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from .models import Task
import json

@api_view(['POST'])
@parser_classes([JSONParser])
def register(request):
    """
    Endpoint to register a new user and return an authentication token.

    Args:
        request (rest_framework.request.Request): The HTTP request object.

    Return:
        rest_framework.response.Response: The HTTP response object containing the token or error message.
    """
    data = request.data
    username = data.get('username')
    password = data.get('password')

    if not check_required_fields(data, ['username', 'password']):
        return Response({"error": "Username and password are required."}, status=400)

    if User.objects.filter(username=username).exists():
        return Response({"error": "Username already exists."}, status=400)

    user = User.objects.create_user(username=username, password=password)
    token = Token.objects.create(user=user)

    return Response({"token": token.key}, status=201)


@api_view(['POST'])
@parser_classes([JSONParser])
def login(request):
    """
    Endpoint to perform login and return an authentication token.

    Args:
        request (rest_framework.request.Request): The HTTP request object.

    Return:
        rest_framework.response.Response: The HTTP response object containing the token or error message.
    """
    data = request.data
    username = data.get('username')
    password = data.get('password')

    if not check_required_fields(data, ['username', 'password']):
        return Response({"error": "Username and password are required."}, status=400)

    user = authenticate(username=username, password=password)

    if not user:
        return Response({"error": "Invalid username or password."}, status=401)

    token, _ = Token.objects.get_or_create(user=user)

    return Response({"token": token.key}, status=200)

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def results(request):
    """
    Endpoint to retrieve the result of an anonymization task.

    Args:
        request (rest_framework.request.Request): The HTTP request object.
        task_id (str): The ID of the anonymization task.

    Return:
        rest_framework.response.Response: The HTTP response object containing the task result or status.
    """

    results = []

    user = request.user
    tasks = Task.objects.filter(user=user).order_by('-creation_date')

    for task in tasks:
        results.append({"created_at": str(task.creation_date), "status": str(task.status), "description": str(task.description), "task_id": str(task.task_id)})

    return Response(results)

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def result_detail(request, task_id):
    """
    Endpoint to retrieve a specific task by its ID.

    Args:
        request (rest_framework.request.Request): The HTTP request object.
        task_id (str): The ID of the task to retrieve.

    Return:
        rest_framework.response.Response: The HTTP response object containing the task details.
    """
    user = request.user

    try:
        task = Task.objects.get(task_id=task_id, user=user)
        task_details = {
            "id": str(task.task_id),
            "description": str(task.description),
            "created_at": str(task.creation_date),
            "status": str(task.status),
            "results": str(task.result),
            "errors": str(task.errors),
            "real_data_k_anonymity": str(task.real_data_k_anonymity),
            "real_data_t_closeness": str(task.real_data_t_closeness),
            "real_data_l_diversity": str(task.real_data_l_diversity),
            "anonymized_data_k_anonymity": str(task.anonymized_data_k_anonymity),
            "anonymized_data_t_closeness": str(task.anonymized_data_t_closeness),
            "anonymized_data_l_diversity": str(task.anonymized_data_l_diversity)
        }
        return Response(task_details)
    except Task.DoesNotExist:
        return Response({"message": "Task not found."}, status=404)
    

def check_required_fields(data, fields):
    for field in fields:
        if not data.get(field):
            return False
    return True


@api_view(['POST'])
@parser_classes([JSONParser])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def anonymize_async(request):
    """
    Endpoint to initiate an asynchronous anonymization task.

    Args:
        request (rest_framework.request.Request): The HTTP request object.

    Return:
        rest_framework.response.Response: The HTTP response object containing the task status and ID.
    """
    data = request.data
    
    if not check_required_fields(data, ['execution_parameters', 'sensitive_columns', 'diversity_columns','closeness_columns', 'data']):
        return Response({"message": "Missing required attributes in the JSON data."}, status=400)

    task = assync_process_data.delay(data, request.user.pk)

    response = {
        "message": "Anonymization task has been scheduled.",
        "task_id": task.id
    }

    return Response(response, status=202)

@api_view(['POST'])
@parser_classes([JSONParser])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def anonymize_sync(request):
    """
    Endpoint to initiate an asynchronous anonymization task.

    Args:
        request (rest_framework.request.Request): The HTTP request object.

    Return:
        rest_framework.response.Response: The HTTP response object containing the processed data. 
    """
    data = request.data

    if not check_required_fields(data, ['execution_parameters', 'data']):
        return Response({"message": "Missing required attributes in the JSON data."}, status=400)

    try:
        response = json.dumps(str(sync_process_data(data)))
    except:
        response = {"Message": "An error occurred while processing the data. Use the asynchronous route for more details."}

    return Response(response)
