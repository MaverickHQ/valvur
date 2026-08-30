"""Deliberately insecure sample: model output reaching sinks. Planted for tests."""

import os
import sqlite3

import anthropic

client = anthropic.Anthropic()


def run_generated_code(prompt):
    response = client.messages.create(model="claude-opus-5", messages=[{"role": "user", "content": prompt}])
    return eval(response.content[0].text)


def run_generated_command(prompt):
    response = client.messages.create(model="claude-opus-5", messages=[{"role": "user", "content": prompt}])
    return os.system(response.content[0].text)


def lookup(cur, name):
    return cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
