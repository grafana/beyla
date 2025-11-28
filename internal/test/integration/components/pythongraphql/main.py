from fastapi import FastAPI
from ariadne import QueryType, make_executable_schema
from ariadne.asgi import GraphQL

type_defs = """
    type Query {
        testme: String!
    }
"""

query = QueryType()

@query.field("testme")
def resolve_testme(_, info):
    return "ok!"

schema = make_executable_schema(type_defs, query)

app = FastAPI()
app.mount("/graphql", GraphQL(schema, debug=True))
