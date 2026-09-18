"""Deliberately insecure sample: model output reaching sinks. Planted for tests.

One function per model source valvur's taint rules know (task 23.5.3), each flowing
into one of the sinks the INFO rules inventory. The last function is the shape the
rules do NOT see, kept here so the limit is stated by a fixture rather than by a
sentence: Opengrep's taint tracking is intra-procedural, so a helper that returns
the model's text hides the flow from its caller.
"""

import os
import sqlite3
import subprocess

import anthropic
import google.generativeai as genai
import litellm
import ollama
import openai
import yaml
from langchain_openai import ChatOpenAI
from openai import OpenAI

client = anthropic.Anthropic()
oa = OpenAI()
cur = sqlite3.connect("app.db").cursor()


# --- Anthropic ---------------------------------------------------------------

def run_generated_code(prompt):
    response = client.messages.create(model="claude-opus-5", messages=[{"role": "user", "content": prompt}])
    return eval(response.content[0].text)


def run_generated_command(prompt):
    response = client.messages.create(model="claude-opus-5", messages=[{"role": "user", "content": prompt}])
    return os.system(response.content[0].text)


# --- OpenAI: chat completions, the Responses API, the pre-1.0 module API ------

def openai_chat(prompt):
    completion = oa.chat.completions.create(model="gpt-5", messages=[{"role": "user", "content": prompt}])
    exec(completion.choices[0].message.content)


def openai_responses(prompt):
    response = oa.responses.create(model="gpt-5", input=prompt)
    subprocess.run(response.output_text, shell=True)


def openai_legacy(prompt):
    reply = openai.ChatCompletion.create(model="gpt-4", messages=[{"role": "user", "content": prompt}])
    os.popen(reply["choices"][0]["message"]["content"])


# --- Gemini ------------------------------------------------------------------

def gemini(prompt):
    model = genai.GenerativeModel("gemini-2.5-pro")
    result = model.generate_content(prompt)
    return eval(result.text)


# --- LangChain ---------------------------------------------------------------

def langchain_query(prompt):
    llm = ChatOpenAI(model="gpt-5")
    answer = llm.invoke(prompt)
    return cur.execute(answer.content)


# --- litellm and ollama --------------------------------------------------------

def litellm_call(prompt):
    reply = litellm.completion(model="gpt-4o", messages=[{"role": "user", "content": prompt}])
    return yaml.load(reply.choices[0].message.content)


def ollama_call(prompt):
    reply = ollama.chat(model="llama3", messages=[{"role": "user", "content": prompt}])
    return os.system(reply["message"]["content"])


# --- String-built SQL: a sink on its own, inventoried at INFO ----------------

def lookup(name):
    return cur.execute(f"SELECT * FROM users WHERE name = '{name}'")


# --- The limit, as a fixture: NOT reported, and the tests say so ---------------

def ask(prompt):
    return client.messages.create(model="claude-opus-5", messages=[{"role": "user", "content": prompt}]).content[0].text


def run_via_helper(prompt):
    return exec(ask(prompt))
