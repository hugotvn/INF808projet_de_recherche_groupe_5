import argparse
import json
import random
import re
import string
from datetime import datetime, timedelta, timezone

import netaddr
import pandas as pd
from dateutil.parser import parse as parse_date
from lark import Lark, Transformer, v_args
from stix2.v20 import Bundle, Identity

from firepit.props import primary_prop, prop_metadata
from firepit.stix20 import get_grammar
from firepit.timestamp import timefmt
from firepit.woodchipper import dict2observation


def pattern2stix(pattern):
    grammar = get_grammar()
    return Lark(grammar,
                parser="lalr",
                transformer=_TranslateTree()).parse(pattern)


@v_args(inline=True)
class _TranslateTree(Transformer):
    """Transformer to convert relevant parts of STIX pattern to WHERE clause"""

    def disj(self, lhs, rhs):
        return random.choice([lhs, rhs])

    def conj(self, lhs, rhs):
        return lhs.update(rhs)

    def obs_disj(self, lhs, rhs):
        return random.choice([lhs, rhs])

    def obs_conj(self, lhs, rhs):
        return lhs.update(rhs)

    def comp_grp(self, exp):
        raise NotImplementedError('grouping')

    def simple_comp_exp(self, lhs, op, rhs):
        if op == '=':
            return {lhs: rhs}
        if op == '!=':
            #TODO: mutate rhs somehow?  Need to check ENTIRE bundle!
            pass
        if op == 'IN':
            return {lhs: random.choice(rhs)}
        if op == 'LIKE':
            #TODO: replace _ and % with...something
            pass
        if op == 'MATCHES':
            #TODO: create a string that matches rhs?
            #TODO: try xeger package; probably need to "filter" the output though
            pass
        raise NotImplementedError(op)

    def comp_disj(self, lhs, rhs):
        return random.choice([lhs, rhs])

    def comp_conj(self, lhs, rhs):
        return lhs.update(rhs)

    def op(self, value):
        return str(value)

    def quoted_str(self, value):
        return str(value)

    def lit_list(self, *args):
        return list(args)

    def start(self, exp, _qualifier):
        # For now, drop the qualifier.  Assume the query handled it.
        return f'{exp}'

    def object_path(self, sco_type, prop):
        return f'{sco_type}:{prop}'


def infer_protocols(dst_port: int) -> list:
    '''Try to guess a sensible list of protos based on destination port'''
    tcp = ['ipv4', 'tcp']
    udp = ['ipv4', 'udp']
    if dst_port in [80, 3128, 8080]:
        return tcp + ['http']
    if dst_port in [443]:
        return tcp + ['tls']
    if dst_port in [53, 500]:
        return udp
    # Default to tcp
    return tcp


# Do we want a bunch of specialized random data generating functions?
def random_src_port():
    return random.choice(range(49152, 65536))


def random_addr(net):
    pool = [str(a) for a in list(netaddr.IPNetwork(net))]  #TODO: Make this more efficient
    return random.choice(pool)


def random_url():
    return 'http://www{}.example.com/page/{}'.format(random.randint(1, 100), random.randint(1, 300))


# utility functions
def _make_stub(timestamp) -> dict:
    return {
        'first_observed': timefmt(timestamp, 6),
        'last_observed': timefmt(timestamp, 6),
        'number_observed': 1
    }


def _has_sco(obj: dict, sco_type: str) -> bool:
    return any(k for k in obj.keys() if k.startswith(f'{sco_type}:'))


HAS_VALUE_PROP = (
    'domain-name', 'email-addr', 'ipv4-addr', 'ipv6-addr', 'mac-addr', 'url',
)


def _complete_sco(obj: dict) -> dict:
    '''Fill in missing properties for SCO `obj`'''
    sco_type = obj['type']
    pprop = primary_prop(sco_type)  # Can return bogus "value" prop
    if pprop not in obj and sco_type in HAS_VALUE_PROP:
        meta = prop_metadata(sco_type, pprop)
        dtype = meta['dtype']
        if dtype == 'int':
            value = random.randint(0, 65535)
        else:
            value = ''.join([random.choice(string.ascii_letters) for i in range(8)])
        obj[pprop] = value
    return obj


def _make_obs(ident: dict, data: dict) -> dict:
    '''Take a dict of STIX object paths and return a STIX 2.0 observed-data object'''
    obj = dict2observation(ident, data)

    # Complete the SCOs, just in case
    scos = obj['objects']
    event = {'type': 'x-oca-event'}
    saw_event = False
    saw_types = set()
    ips = []
    for idx, sco in scos.items():
        scos[idx] = _complete_sco(sco)
        sco_type = sco['type']
        saw_types.add(sco_type)

        # Probably should do this earlier
        if sco_type == 'x-oca-event':
            saw_event = True
        else:
            if sco_type == 'x-oca-asset':
                event['host_ref'] = idx
            elif sco_type == 'url':
                event['url_ref'] = idx
            if sco_type == 'file':
                event['file_ref'] = idx
            if sco_type == 'process':
                #TODO: determine child vs. parent
                event['process_ref'] = idx
            elif sco_type == 'domain-name':
                event['domain_ref'] = idx
            elif sco_type == 'windows-registry-key':
                event['registry_ref'] = idx
            elif sco_type == 'network-traffic':
                event['network_ref'] = idx
            elif sco_type in ('ipv4-addr', 'ipv6-addr'):
                ips.append(idx)
            elif sco_type == 'user-account':
                event['user_ref'] = idx

    if not saw_event:
        if ips:
            event['ip_refs'] = ips
        if 'process' in saw_types and 'network-traffic' not in saw_types:
            event['action'] = 'Process Create'  #TODO: where to get strings?
        else:
            event['action'] = 'Network connection'  #TODO: where to get strings?
        scos[str(len(scos))] = event

    return obj


def _delta(s):
    '''Translate a relative time expression to a timedelta'''
    result = None
    m = re.match(r'([0-9]+)([dhms])', s)
    if m:
        value = int(m.group(1))
        unit = m.group(2)
        if unit == 'd':
            result = timedelta(days=value)
        elif unit == 'h':
            result = timedelta(hours=value)
        elif unit == 'm':
            result = timedelta(minutes=value)
        elif unit == 's':
            result = timedelta(seconds=value)
    return result


class Generator:
    '''Generate random STIX observed-data objects'''
    #TODO: move some of this junk out of constructor
    def __init__(self, ident, start_time, end_time,
                 src_net = '192.168.1.0/24', dst_net = '10.0.0.0/28',
                 assets = None, domains = None,
                 dests = None):
        self.ident = ident
        self.start_time = start_time
        self.end_time = end_time
        self.duration = end_time - start_time
        self.src_net = src_net
        self.dst_net = dst_net
        self.assets = assets
        self.domains = domains
        self.dests = dests
        self.conns = []
        self.scos = set()

    def random_timestamp(self):
        '''Get a random datetime in the appropriate range'''
        secs = random.choice(range(int(self.duration.total_seconds())))
        usecs = random.choice(range(100000))
        offset = timedelta(seconds=secs, microseconds=usecs)
        return self.start_time + offset

    def make_pairs(self):
        obj = _make_stub(self.random_timestamp())

        # Pick random asset and domain to make a conn
        if self.assets is not None:
            i = random.choice(range(len(self.assets.index)))
            obj.update(dict(self.assets.loc[i]))
            obj['network-traffic:src_ref'] = 'x-oca-asset:ip_refs[0]'
        else:
            obj['network-traffic:src_ref.value'] = random_addr(self.src_net)
        obj['network-traffic:src_port'] = random_src_port()

        if self.domains is not None:
            j = random.choice(range(len(self.domains.index)))
            obj.update(dict(self.domains.loc[j]))
            obj['network-traffic:dst_ref'] = 'domain-name:resolves_to_refs[0]'
            dst_port = random.choice([53, 443])
        elif self.dests is not None:
            j = random.choice(range(len(self.dests.index)))
            obj.update(dict(self.dests.loc[j]))
            # Use dst_port from input if available, else 443
            dst_port = obj.get('network-traffic:dst_port', 443)
        else:
            obj['network-traffic:dst_ref.value'] = random_addr(self.dst_net)
            dst_port = random.choice([22, 53, 80, 139, 443])
        obj['network-traffic:dst_port'] = dst_port

        obj['network-traffic:protocols'] = infer_protocols(dst_port)

        # Special hook for unencrypted HTTP:
        if dst_port == 80:
            obj['url:value'] = random_url()  #TODO: support a urls CSV as input?

        return obj

    def make_random(self):
        '''Return a single random observed-data object'''
        return _make_obs(self.ident, self.make_pairs())

    def make_from_pattern(self, pattern):
        '''Return a single observed-data object that matches `pattern`'''
        obj = self.make_pairs()
        tmp = pattern2stix(pattern)
        # First check if ipv4 and if in assets or domains
        # Why though?  I already forgot why I wanted to do that
        if _has_sco(tmp, 'domain-name'):
            #TODO: look in domains
            pass #print('DOMAIN')
        if _has_sco(tmp, 'ipv4-addr'):
            #TODO: look in assets?
            pass #print('ADDRESS')
        obj.update(tmp)
        return _make_obs(self.ident, obj)

    def make_beacons(self, beacon, num):
        src, dst, port, interval = tuple(beacon.split(','))
        port = int(port)
        ts = self.start_time
        increment = _delta(interval)
        obj = _make_stub(ts)
        obj.update({
            'network-traffic:dst_ref.value': dst,
            'network-traffic:dst_port': port,
            'network-traffic:protocols': infer_protocols(port)
        })
        df = self.assets
        found = False
        if df is not None and 'x-oca-asset:ip_refs[0].value' in df.columns:
            matches = df[df["x-oca-asset:ip_refs[0].value"] == src].to_dict(orient="records")
            if matches:
                obj.update(matches[0])
                found = True
        if found:
            obj['network-traffic:src_ref'] = 'x-oca-asset:ip_refs[0]'
        else:
            obj['network-traffic:src_ref.value'] = src
        results = []
        while ts < self.end_time and len(results) <= num:
            secs = random.choice(range(-2, 1))
            usecs = random.choice(range(999999))
            offset = timedelta(seconds=secs, microseconds=usecs)
            ts += increment + offset
            tmp = obj.copy()
            tmp['network-traffic:src_port'] = random_src_port()
            tmp['first_observed'] = timefmt(ts, 6)
            tmp['last_observed'] = timefmt(ts, 6)
            results.append(_make_obs(self.ident, tmp))
        return results


def main():
    parser = argparse.ArgumentParser('Generate a bundle of STIX observed-data')
    parser.add_argument('-n', '--num', metavar='N', default=2000, type=int)
    parser.add_argument('-s', '--start-time', metavar='DATETIME')
    parser.add_argument('-e', '--end-time', metavar='DATETIME')
    parser.add_argument('-a', '--assets', metavar='CSVFILE', default=None)
    parser.add_argument('-d', '--domains', metavar='CSVFILE', default=None)
    #TODO:parser.add_argument('-u', '--urls', metavar='CSVFILE', default=None)
    #TODO:parser.add_argument('-e', '--events', metavar='CSVFILE', default=None)
    parser.add_argument('--source-net', metavar='CIDR', default='192.168.1.0/24')
    parser.add_argument('--dest-net', metavar='CIDR', default='10.0.0.0/8')
    parser.add_argument('--dests', metavar='CSVFILE', default=None)
    #parser.add_argument('-u', '--add-user', action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument('-i', '--identity', metavar='NAME', default='firepit.generator')
    parser.add_argument('--seed', metavar='SEED', type=int)
    parser.add_argument('--pattern', metavar='PATTERN')
    parser.add_argument('--beacon', metavar='SRC,DST,PORT,INTERVAL')

    args = parser.parse_args()

    if args.seed:
        random.seed(args.seed)

    if args.end_time:
        end_time = parse_date(args.end_time)  # UTC "aware"
    else:
        end_time = datetime.now(timezone.utc)
    if args.start_time:
        s = _delta(args.start_time)
        if s:
            # Relative
            start_time = end_time - s
        else:
            # Absolute
            start_time = parse_date(args.start_time)  # UTC "aware"
    else:
        start_time = end_time - _delta('5m')

    if args.domains:
        domains = pd.read_csv(args.domains)
    else:
        domains = None

    if args.assets:
        assets = pd.read_csv(args.assets)
    else:
        assets = None

    if args.dests:
        dests = pd.read_csv(args.dests)
    else:
        dests = None

    ident = Identity(name=args.identity, identity_class='program')
    dgen = Generator(ident, start_time, end_time,
                     assets=assets, domains=domains,
                     dests=dests)
    objects = []
    num = args.num
    if args.pattern:
        # Generate 1 observation that will match the pattern
        obj = dgen.make_from_pattern(args.pattern)
        if obj:
            objects.append(obj)
            num -= 1

    if args.beacon:
        objects += dgen.make_beacons(args.beacon, num)
        num = max(0, num - len(objects))

    objects += [dgen.make_random() for i in range(num)]
    bundle = json.loads(str(Bundle(ident, objects=[])))

    # Replace empty objects array with the JSON ones we built above
    bundle['objects'] += sorted(objects, key=lambda i: i['first_observed'])
    print(json.dumps(bundle, indent=4))


if __name__ == '__main__':
    main()
