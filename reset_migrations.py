# 1. Delete the existing SQLite database
import os
os.remove('db.sqlite3')

# 2. Delete all migration files except __init__.py
import glob
import os

for filepath in glob.glob('**/migrations/*.py', recursive=True):
    if not filepath.endswith('__init__.py'):
        os.remove(filepath)

for filepath in glob.glob('**/migrations/*.pyc', recursive=True):
    os.remove(filepath)

# 3. Make fresh migrations
os.system('python manage.py makemigrations')

# 4. Apply the migrations
os.system('python manage.py migrate')
