"""Business HTTP header formatting from explicit application/device inputs."""
import re

from .errors import GiroError


def business_user_agent(version_name, *, os_name, model, release):
    # The version helper tests for the literal suffix, then uses replaceAll's
    # regex. Keep that distinction; do not derive device fields from this host.
    if not all(isinstance(v, str) for v in (version_name, os_name, model, release)):
        raise GiroError('업무 헤더에 사용할 명시적인 기기 자료가 필요합니다.')
    if version_name.find('.test') > 0:
        version_name = re.sub(r'.test', '', version_name)
    value = (f'AndroidGiro/{version_name} ({os_name}; {model} AndroidGiro{version_name};'
             f' Android {release}; ko-kr)')
    # OkHttp's header-value check, not a new server acceptance condition.
    if any((ord(c) <= 31 and c != '\t') or ord(c) >= 127 for c in value):
        raise GiroError('업무 헤더로 전송할 수 없는 기기 자료입니다.')
    return value
