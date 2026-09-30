"""Opt-in CLI framing. Process exit codes never stand in for service verdicts."""
import argparse
from contextlib import contextmanager
from contextvars import ContextVar
import json


_format = ContextVar('cli_output_format', default=('legacy', 'fin'))


@contextmanager
def rendering(format_name, service):
    token = _format.set((format_name, service))
    try:
        yield
    finally:
        _format.reset(token)


def structured():
    return _format.get()[0] == 'json-v1'


def emit(result, exit_code=0, *, indent=2, output_error=None):
    if structured():
        result = {'schema_version': 1, 'service': _format.get()[1],
                  'exit_code': exit_code % 256, 'result': result}
        if output_error:
            result['output_error'] = {'code': output_error}
    print(json.dumps(result, ensure_ascii=False, indent=indent))


def error(code, message, exit_code=2):
    emit({'error': code, 'message': message}, exit_code)
    return exit_code


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        if structured():
            # argparse messages can echo arbitrary option values. Never include
            # them in the machine response; --help documents the accepted input.
            error('invalid_arguments', '명령의 인자를 확인하세요. --help로 사용법을 볼 수 있습니다.')
            raise SystemExit(2)
        super().error(message)
