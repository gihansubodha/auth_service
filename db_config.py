import mysql.connector
import os

db_config = {
    'host': 'cozycomfort-gihansubodha-soc.c.aivencloud.com',
    'port': 26728,
    'user': 'avnadmin',
    'password': 'AVNS_i33CBpI3jeyig2mnoMR',
    'database': 'defaultdb',
    'ssl_disabled': False
}

def get_db_connection():
    conn = mysql.connector.connect(**db_config)
    return conn
