"""Android HttpCookie.parse/toString projection for CodeGuard, not a cookie jar.

Only caller-provided header strings; no account cookies, clock or persistence.
Expiration affects duplicate attribute assignment but Updater NEVER calls
hasExpired/domainMatches. Noncanonical HttpDate parsing remains a boundary.
"""
from dataclasses import dataclass, field
from datetime import datetime
import re

from .android_json import java_integer, NumberSyntaxError
from .codeguard_effects import JavaFault
from .codeguard_rule import AnalysisLimit

_RESERVED = frozenset(('comment','commenturl','discard','domain','expires','httponly',
                       'max-age','path','port','secure','version'))
_TRIM = ''.join(map(chr,range(33)))


def _failure(message):
    return JavaFault('IllegalArgumentException',message=message,
                     java_string='java.lang.IllegalArgumentException: '+message)


def _lower(value, language):
    if type(language) is not str or not language:
        raise AnalysisLimit('explicit Android default locale language required')
    if not value.isascii():
        raise AnalysisLimit('Android non-ASCII cookie locale lowercase unresolved')
    return (value.replace('I','ı') if language.lower() in ('tr','az') else value).lower()


def _strip_quotes(value):
    if value is not None and len(value)>2 and value[0] in ('"',"'") and value[-1]==value[0]:
        return value[1:-1]
    return value


def _expires_returns_normally(value):
    """Prove a bounded HttpDate parse return, without fabricating its date.

    On normal return the expires assignor always leaves maxAge != -1, even for
    an unparseable/expired date. That is all parse/toString subsequently needs.
    General lenient SimpleDateFormat/zone/runtime errors are NOT guessed.
    """
    if value=='': return  # every date pattern fails => HttpDate returns null
    if value is None:
        raise AnalysisLimit('HttpDate.parse(null) platform exception text unresolved')
    matched = re.fullmatch(r'(Mon|Tue|Wed|Thu|Fri|Sat|Sun), ([0-9]{2}) '
        r'(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-9]{4}) '
        r'([0-9]{2}):([0-9]{2}):([0-9]{2}) (GMT|UTC)',value)
    if matched:
        week,day,month,year,hour,minute,second,_ = matched.groups()
        months = 'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()
        try:
            date = datetime(int(year),months.index(month)+1,int(day),int(hour),int(minute),int(second))
            # Gregorian cutover/lenient/out-of-range parsing is outside subset.
            if date.year>=1900 and 'Mon Tue Wed Thu Fri Sat Sun'.split()[date.weekday()]==week:
                return
        except ValueError: pass
    raise AnalysisLimit('Android lenient HttpDate parse boundary')


@dataclass(frozen=True, repr=False)
class CookieValue:
    name: str
    value: str
    version: int
    path: str | None
    domain: str | None
    port: str | None
    projection_only: bool = field(default=True,init=False)

    def wire_text(self):
        if self.version==0: return self.name+'='+self.value
        result = self.name+'="'+self.value+'"'
        for key,value in (('Path',self.path),('Domain',self.domain),('Port',self.port)):
            if value is not None: result += ';$'+key+'="'+value+'"'
        return result


def _internal(header,version,language):
    # StringTokenizer ignores EMPTY tokens, but not whitespace-only tokens;
    # semicolons are delimiters even within quotes.
    parts = [item for item in header.split(';') if item]
    if not parts: raise _failure('Empty cookie header string')
    first,*attributes = parts
    if '=' not in first: raise _failure('Invalid cookie name-value pair')
    name,value = (s.strip(_TRIM) for s in first.split('=',1))
    if (not name or name.lower() in _RESERVED or name.startswith('$') or
            any(ord(c)<32 or ord(c)>=127 or c in ',;= \t' for c in name)):
        raise _failure('Illegal cookie name')
    value = _strip_quotes(value)
    path=domain=port=None
    maxage = -1
    for attribute in attributes:
        if '=' in attribute:
            key,val = (s.strip(_TRIM) for s in attribute.split('=',1))
        else: key,val = attribute.strip(_TRIM),None
        key,val = _lower(key,language),_strip_quotes(val)
        if key=='path' and path is None: path = val
        elif key=='domain' and domain is None: domain = _lower(val,language) if val is not None else None
        elif key=='port' and port is None: port = '' if val is None else val
        elif key=='max-age':
            try: number = java_integer(val)
            except NumberSyntaxError: raise _failure('Illegal cookie max-age attribute') from None
            # Even ignored duplicate max-age is parsed and can fail.
            if maxage==-1: maxage=number
        elif key=='version':
            try: number = java_integer(val,bits=32)
            except NumberSyntaxError: continue  # NFE swallowed, valid integer outside 0/1 is NOT
            if number not in (0,1): raise _failure('cookie version should be 0 or 1')
        elif key=='expires' and maxage==-1:
            _expires_returns_normally(val)
            maxage = 0  # abstract assigned/non--1 state; NOT a computed expiration
        # Other supported attributes cannot affect this toString projection.
    # parse overrides the successfully parsed version with its initial guess.
    return CookieValue(name,value,version,path,domain,port)


def parse_cookies(header, *, locale_language):
    if type(header) is not str:
        raise AnalysisLimit('HttpCookie null/type platform exception text unresolved')
    lower = _lower(header,locale_language)
    version = 0 if ('expires=' in lower or
        ('version=' not in lower and 'max-age' not in lower and not lower.startswith('set-cookie2:'))) else 1
    if header.lower().startswith('set-cookie2:'): header=header[12:]
    elif header.lower().startswith('set-cookie:'): header=header[11:]
    if version==0: return (_internal(header,0,locale_language),)
    pieces,start,quotes = [],0,0
    for index,char in enumerate(header):
        if char=='"': quotes+=1
        if char==',' and quotes%2==0:
            pieces.append(header[start:index])
            start=index+1
    pieces.append(header[start:])
    # No partial return: one bad cookie invalidates the entire header.
    return tuple(_internal(piece,1,locale_language) for piece in pieces)
