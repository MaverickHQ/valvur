"""Deliberately insecure sample. Planted for scanner tests. Never real code."""

import hashlib
import subprocess

import yaml


def run_user_command(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True)


def evaluate(expression):
    return eval(expression)


def evaluate_again(other):
    return eval(other)


def load_config(text):
    return yaml.load(text)


def fingerprint(value):
    return hashlib.md5(value.encode()).hexdigest()


def first_duplicate(user_input):
    # Byte-identical to the next one on purpose: proves ordinal disambiguation.
    return eval(user_input)


def second_duplicate(user_input):
    return eval(user_input)
