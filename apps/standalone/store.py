import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

TERMINAL = {'completed', 'partial', 'failed', 'cancelled'}


class Store:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.root / 'tasks.sqlite3', check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, state TEXT NOT NULL, created REAL NOT NULL, body TEXT NOT NULL)')
        self.db.commit()

    def create(self, body):
        task_id = uuid.uuid4().hex
        task = dict(body, id=task_id, state='queued', created=time.time(), updated=time.time(), progress={})
        with self.lock, self.db:
            self.db.execute('INSERT INTO tasks VALUES (?, ?, ?, ?)', (task_id, task['state'], task['created'], json.dumps(task)))
        return task

    def get(self, task_id):
        with self.lock:
            row = self.db.execute('SELECT body FROM tasks WHERE id=?', (task_id,)).fetchone()
        if not row:
            raise KeyError(task_id)
        return json.loads(row[0])

    def update(self, task_id, **changes):
        with self.lock, self.db:
            task = self.get(task_id)
            task.update(changes, updated=time.time())
            self.db.execute('UPDATE tasks SET state=?, body=? WHERE id=?', (task['state'], json.dumps(task), task_id))
        return task

    def list(self, limit=50, offset=0):
        with self.lock:
            return [json.loads(row[0]) for row in self.db.execute('SELECT body FROM tasks ORDER BY created DESC LIMIT ? OFFSET ?', (limit, offset))]

    def active(self):
        with self.lock:
            return [json.loads(row[0]) for row in self.db.execute("SELECT body FROM tasks WHERE state NOT IN ('completed','partial','failed','cancelled') ORDER BY created")]
