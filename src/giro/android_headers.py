"""Android OkHeaders/URLConnection response-header projection, no HTTP IO.

Input lines are already decoded readUtf8LineStrict results, not Python email
headers. In particular obsolete folds/colonless lines are NOT concatenated.
Only ASCII header-name comparison is implemented; values stay unchanged
except for addLenient's Java trim. Never print/repr header/cookie contents.
"""
from dataclasses import dataclass

from .codeguard_effects import Effect, JavaFault
from .codeguard_rule import AnalysisLimit

_TRIM=''.join(map(chr,range(33)))


def _key(name):
    if name is None: return None
    if type(name) is not str or not name.isascii():
        raise AnalysisLimit('Android non-ASCII header-name comparison boundary')
    return name.lower()  # String.CASE_INSENSITIVE_ORDER on the ASCII subset


@dataclass(frozen=True,repr=False)
class HeaderFields:
    """Ordered Headers names/values BEFORE OkHeaders.toMultimap.

    Direct construction accepts explicit platform pairs (including synthetic
    fixtures), not a claim that arbitrary HTTP-client parsers are equivalent.
    Status line is a separate null key, not the colonless/empty-name group.
    """
    pairs: tuple = ()
    status_line: str | None = None

    def entries(self):
        groups={}
        for name,value in self.pairs:
            if name is None or type(value) is not str:
                raise AnalysisLimit('explicit Android Headers name/value required')
            key=_key(name)
            if key not in groups: groups[key]=(name,[])
            groups[key][1].append(value)
        result=[]
        if self.status_line is not None:
            if type(self.status_line) is not str:
                raise AnalysisLimit('explicit Android status-line string required')
            result.append((None,(self.status_line,)))
        # TreeMap sorts keys, but EACH duplicate value list keeps wire order.
        result.extend((groups[key][0],tuple(groups[key][1])) for key in sorted(groups))
        return tuple(result)

    def get(self,name):
        wanted=_key(name)
        for key,values in self.entries():
            if _key(key)==wanted: return values
        return None  # map.get absent, NOT an empty list

    def last(self,name):
        """URLConnection.getHeaderField(name), not map.get(name)."""
        if name is None: return self.status_line
        values=self.get(name)
        return None if values is None else values[-1]


def read_header_lines(lines, *, status_line=None):
    """Http1xStream.readHeaders + Headers.Builder.addLenient(String).

    Consume only through the first EMPTY line. A whitespace-only line is an
    empty-name header, not a terminator or folded cookie. No name validation
    from the stricter Builder.add/Headers.of is imported into this path.
    Missing terminating observation is a boundary, not fabricated EOF text.
    """
    pairs=[]
    for line in lines:
        if type(line) is not str:
            raise AnalysisLimit('actual readUtf8LineStrict String required')
        if line=='': return HeaderFields(tuple(pairs),status_line)
        if '\n' in line:
            raise AnalysisLimit('header input must be already separated lines')
        separator=line.find(':',1)
        if separator>=0:
            name,value=line[:separator],line[separator+1:]
        elif line.startswith(':'):
            name,value='',line[1:]
        else:
            name,value='',line
        pairs.append((name,value.strip(_TRIM)))
    raise AnalysisLimit('header terminator/stream failure observation required')


def cookie_header_values_steps(connection,name):
    """getHeaderFields().get: IOException → EMPTY_MAP, other faults propagate."""
    try:
        fields=yield Effect('urlconnection_response_headers',(connection,))
    except JavaFault as fault:
        if fault.is_instance('IOException'): return None
        raise
    if not isinstance(fields,HeaderFields):
        raise AnalysisLimit('explicit Android header projection required')
    return fields.get(name)


def project_header_values_steps(generator):
    """Resolve existing Updater cookie-header effects from ordered observations.

    Raw HTTP/TLS/cache/stream/redirect behavior remains external. In particular
    Python HTTP errors aren't automatically Java IOException observations.
    """
    value,pending=None,None
    while True:
        try:
            effect=generator.throw(pending) if pending is not None else generator.send(value)
        except StopIteration as done:
            return done.value
        pending=None
        try:
            if effect.kind=='set_cookie_header_values':
                value=yield from cookie_header_values_steps(*effect.args)
            else:
                value=yield effect
        except Exception as fault:
            pending=fault
