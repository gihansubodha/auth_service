import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        host='YOUR_AIVEN_HOST',
        user='YOUR_AIVEN_USER',
        password='YOUR_AIVEN_PASSWORD',
        database='cozy_comfort'
    )
