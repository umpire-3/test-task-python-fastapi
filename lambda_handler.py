from mangum import Mangum
from main import app


def handler_sqs(event):
    pass


def event_handler(event, context):
    if event.get("Records"):
        return handler_sqs(event)

    if event.get("httpMethod"):
        asgi_handler = Mangum(app)
        return asgi_handler(event, context)


def lambda_handler(event, context):
    return event_handler(event, context)
