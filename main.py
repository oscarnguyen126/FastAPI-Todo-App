from fastapi import FastAPI
from pydantic import BaseModel, Field
from typing import List
from fastapi.exceptions import HTTPException
from deta import Deta
from dotenv import load_dotenv
import os


load_dotenv()


class Todo(BaseModel):
    name: str
    is_done: bool = Field(default=False)

app = FastAPI()


PROJECT_KEY = os.environ.get('DETA_PROJECT_KEY')

deta = Deta(PROJECT_KEY)
db = deta.Base("Todos")

store_todos = []

@app.get('/')
async def home():
    return {"Welcome"}

@app.post('/todos/')
async def create_todo(todo: Todo):
    store_todos.append(todo)
    return todo


@app.get('/todos/', response_model=List[Todo])
async def get_all_todos():
    return store_todos


@app.get('/todos/{id}')
async def get_todo(id: int):
    try:
        return store_todos[id]
    except:
        raise HTTPException(status_code=404, detail="Todo not found")


@app.put('/todos/{id}')
async def update_todo(id: int, todo: Todo):
    try:
        store_todos[id] = todo
        return store_todos[id]
    except:
        raise HTTPException(status_code=404, detail="Todo not found")


@app.delete('/todos/{id}')
async def delete_todo(id: int):
    try:
        obj = store_todos[id]
        store_todos.pop(id)
        return obj
    except:
        raise HTTPException(status_code=404, detail="Todo not found")