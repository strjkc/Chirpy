import psycopg
from psycopg import sql


class DbClient:
    def __init__(self, db_host, db_name, db_user):
        self.client = psycopg.connect(f"host={db_host} dbname={db_name} user={db_user}")

    def select_cell(self, table, column, where_colum, where_value):
        with self.client.cursor() as curr:
            query = sql.SQL("select {} from {} where {} = %s").format(
                sql.Identifier(column),
                sql.Identifier(table),
                sql.Identifier(where_colum),
            )
            curr.execute(query, (where_value,))
            data = curr.fetchone()
            if data:
                return data[0]
            return None

    def cleanup(self, table, where_column, where_value):
        with self.client.cursor() as curr:
            query = sql.SQL("delete from {} where {} = %s").format(
                sql.Identifier(table), sql.Identifier(where_column)
            )
            curr.execute(query, (where_value,))
            deleted = curr.rowcount
        self.client.commit()
        return deleted

    def close(self):
        self.client.close()
