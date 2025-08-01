import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        host='cozycomfort-gihansubodha-soc.c.aivencloud.com',
        port=26728,
        user='avnadmin',
        password='AVNS_i33CBpI3jeyig2mnoMR',
        database='defaultdb'
    )
