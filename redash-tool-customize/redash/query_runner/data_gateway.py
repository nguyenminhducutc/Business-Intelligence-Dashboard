import re
import datetime
from email import header
import json
import logging
from urllib import response
from wsgiref import headers

import requests
import yaml
from redash.query_runner import *
from redash.utils import json_dumps
import os
from dotenv import load_dotenv

logger = logging.getLogger(__name__)


# quannm7 parse query
def parse_gateway_query(query):
    query = yaml.safe_load(query)
    query = dict(query)
    params = ""
    for key, value in query.items():
        if isinstance(value, datetime.date):
            value = value.strftime('%Y-%m-%d')
        params = params + key + "=" +str(value) + "&"
    return params[0:-1]


def _transform_result(response):
    columns = (
        {"name": "Time::x", "type": TYPE_DATETIME},
        {"name": "value::y", "type": TYPE_FLOAT},
        {"name": "name::series", "type": TYPE_STRING},
    )

    rows = []

    for series in response.json():
        for values in series["datapoints"]:
            timestamp = datetime.datetime.fromtimestamp(int(values[1]))
            rows.append(
                {
                    "Time::x": timestamp,
                    "name::series": series["target"],
                    "value::y": values[0],
                }
            )

    data = {"columns": columns, "rows": rows}
    return json_dumps(data)


class data_gateway(BaseQueryRunner):
    should_annotate_query = False

    @classmethod
    def configuration_schema(cls):
        return {
            "type": "object",
            "properties": {
                "username": {"type": "string", "title": "Username"},
                "gmail": {"type": "string", "title": "Gmail"},
                "url": {"type": "string", "title": "Url", "default": ""},
            },
            "required": ["url"],
        }

    def __init__(self, configuration):
        super(data_gateway, self).__init__(configuration)
        self.syntax = "custom"
        # logger.info("abcd:", self.configuration["username"])
        # logger.info("abcde:", self.configuration["gmail"])
        # if "username" in self.configuration and self.configuration["username"]:
           #  self.auth = (self.configuration["username"], self.configuration["gmail"])
        # else:
        self.auth = None

        self.verify = self.configuration.get("gmail", True)
        self.base_url = "%s?format=json&" % self.configuration["url"]
        # self.base_url = "%s" % self.configuration["url"]

    def test_connection(self):
        r = requests.get(
            "{}".format(self.configuration["url"]),
            # "{}".format(self.configuration["url"]),
            auth=self.auth,
            verify=self.verify,
        )
        if r.status_code != 200:
            raise Exception(
                "Got invalid response from demo_bi (http status code: {0}).".format(
                    r.status_code
                )
            )

    def run_query(self, query, user):
        param_parser = parse_gateway_query(query)
        print("==============param_parser=========", param_parser)
        url = "%s" % (self.base_url + param_parser)

        logger.info("BI is about to execute query: %s", url)
        query = re.sub(r"/\*(.|\n)*?\*/", "", query).strip()
        print(logger.info)
        error = None
        try:
            logger.info("abc %s", user.email)
            headers = {"Content-Type": "application/json; charset=utf-8", "X-USER-EMAIL": user.email,
                       "X-USER-NAME": "ducnm", "X-APP-TOKEN": 'a65S22VUBtMaALsOieDs'}
            logger.info("abc %s", headers)
            response = requests.get(url=os.getenv('URL_GATEWAY'), auth=self.auth, verify=self.verify, headers=headers)
            logger.info("edf %s", response)
            data = response.json()
            logger.info("ket qua: %s", data)
            json_data = json_dumps(data)
        except Exception as err:
            logger.info("Error: %s", err)
            error = None
            data = {
                "columns": [{"name": "WARNING", "type": "TYPE_STRING"}],
                "rows": [{"WARNING": "KHÔNG CÓ DỮ LIỆU ĐỂ HIỂN THỊ", }]
            }
            json_data = json_dumps(data)
        return json_data, error

    # def get_schema(self, get_stats=False):
    #     query = """
    #     SELECT TABLE_SCHEMA,
    #            TABLE_NAME,
    #            COLUMN_NAME
    #     FROM INFORMATION_SCHEMA.COLUMNS
    #     WHERE TABLE_SCHEMA <> 'INFORMATION_SCHEMA'
    #     """

    #     results, error = self.run_query(query, None)

    #     if error is not None:
    #         raise Exception("Failed getting schema.")

    #     schema = {}
    #     results = json_dumps(results)

    #     for row in results["rows"]:
    #         table_name = "{}.{}".format(row["table_schema"], row["table_name"])

    #         if table_name not in schema:
    #             schema[table_name] = {"name": table_name, "columns": []}

    #         schema[table_name]["columns"].append(row["column_name"])

    #     return list(schema.values())


register(data_gateway)
