
# Anonymizer

this library 

## Running the program

On the root of the repository run:

```bash
  [...]
    cd de-id
    python -m venv venv
    venv/scripts/activate
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    python manage.py makemigrations
    python manage.py migrate
    python manage.py runserver
  [...]
```


```bash
  [...]
    cd de-id
    celery -A config worker --pool=solo -l info
  [...]
```
