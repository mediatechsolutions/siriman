#!/usr/bin/env python
import os
import argparse
import logging
import subprocess
import csv
import xml.etree.ElementTree as ET
from collections import defaultdict
import yaml
from jinja2 import Environment, PackageLoader, select_autoescape


logger = logging.getLogger()
ERROR = logging.ERROR
WARNING = logging.WARNING
INFO = logging.INFO
DETAIL = logging.INFO - 1
DEBUG = logging.DEBUG
VERBOSITIES = [ERROR, WARNING, INFO, DETAIL, DEBUG]

def configure_logging(verbosity):
    level = VERBOSITIES[min(int(verbosity), len(VERBOSITIES) -1)]
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)

log_error = logger.error
log_warning = logger.warning
log_info = logger.info
log_detail = lambda x: logger.log(DETAIL, x)
log_debug = logger.debug
log_exception = logger.exception


class Constants:
    ACTION_SOURCES='sources'
    ACTION_DISCOVER='discover'
    ACTION_REPORT='report'
    ACTIONS = (
        ACTION_SOURCES,
        ACTION_DISCOVER,
        ACTION_REPORT,
    )


class ReportBuilder:
    pass


class HTMLReportBuilder(ReportBuilder):
    def __init__(self, templates, directory, defaults, active_groups=None):
        self.templates = templates
        self.directory = directory
        self.defaults = defaults
        self.active_groups = active_groups or []
        if not os.path.exists(directory):
            os.makedirs(directory)
        self.env = Environment(
            loader=PackageLoader('siriman', 'templates'),
            autoescape=select_autoescape(['html'])
        )

        def get_threat_for_active(active, code):
            for t in active['threats']:
                if t['code'] == code:
                    return t

        def risk_to_color(risk):
            if risk is None:
                return "#bbb"
            if isinstance(risk, str) and not risk.isdigit():
                return "#bbb"
            r = int(risk)
            colors = ('#94FFAD', '#CEE882', '#FFE795', '#E8B086', '#FF888B')
            return colors[int((4 * r) / 30)]

        def active_code_to_label(code):
            labels = dict(
                S="Service",
                HW="Hardware",
                SW="Software",
            )
            return labels.get(code, code)

        def get_impact(active, threat):
            impact = threat.get('impact')
            if impact is None:
                active_code = active.code if isinstance(active, Active) else active.get('code')
                return (self.defaults.get(active_code, threat.get('code')) or {}).get('impact')
            return impact

        def get_probability(active, threat):
            probability = threat.get('probability')
            if probability is None:
                active_code = active.code if isinstance(active, Active) else active.get('code')
                return (self.defaults.get(active_code, threat.get('code')) or {}).get('probability')
            return probability

        self.env.globals.update(get_threat_for_active=get_threat_for_active)
        self.env.globals.update(risk_to_color=risk_to_color)
        self.env.globals.update(active_code_to_label=active_code_to_label)
        self.env.globals.update(get_active_filename=self.get_active_filename)
        self.env.globals.update(get_impact=get_impact)
        self.env.globals.update(get_probability=get_probability)

    def get_file_for_writting_active(self, active, prepend=True):
        filename = self.get_active_filename(active.active_type['code'], active.name)
        if not prepend:
            return filename
        return os.path.join(self.directory, filename)

    def get_active_filename(self, active_code, active_name):
        return "active_%s_%s.html" % (active_code, active_name)

    def write_active(self, active):
        template = self.env.get_template('active.html')
        filename = self.get_file_for_writting_active(active)
        with open(filename, 'w+') as fd:
            log_debug("Writting file %s" % filename)
            fd.write(
                template.render(
                    active_groups=self.active_groups,
                    active=active
                )
            )

    def write_threats(self, threat_groups, actives):
        template = self.env.get_template('threats.html')
        filename = os.path.join(self.directory, 'threats.html')
        with open(filename, 'w+') as fd:
            log_debug("Writting file %s" % filename)
            fd.write(
                template.render(
                    active_groups=self.active_groups,
                    threat_groups=threat_groups,
                    actives=actives
                )
            )


class Active:
    def __init__(self, name, filename=None):
        self.name = name
        self.filename = filename
        self.active_type = dict(code=self.code)
        self.name = name
        self.related = dict()
        self.threats = []
        self.responsible = None

    @classmethod
    def build(cls, data_dict):
        result = cls(data_dict['name'])
        myvars = vars(result)
        for k, v in data_dict.items():
            if k == 'file_version':
                continue
            if k not in myvars:
                raise Exception("FIXME: %s is not a field for %s" % (k, cls))
            setattr(result, k, v)
        return result

    def as_dict(self):
        return vars(self)

    def add_related(self, active):
        if active.code not in self.related:
            self.related[active.code] = []
        if active.name not in self.related[active.code]:
            self.related[active.code].append(active.name)
            active.add_related(self)

class HardwareActive(Active):
    code = 'HW'
    def __init__(self, name, filename=None):
        super(HardwareActive, self).__init__(name, filename)
        self.addresses = list()
        self.hostnames = list()
        self.os = None
        self.state = None

    def __str__(self):
        return "{HOST %s - %s}" % (self.name, self.state)

    def add_address(self, address, address_type):
        self.addresses.append(
            {
                "address": address,
                "type": address_type,
            }
        )
   
    def add_hostname(self, hostname, host_type):
        self.hostnames.append(
            {
                "hostname": hostname,
                "type": host_type,
            } 
        )


class ServiceActive(Active):
    code = 'S'
    def __init__(self, name, filename=None):
        super(ServiceActive, self).__init__(name, filename)
        self.program = None
        self.product = None
        self.version = None
        self.os = None
        self.state = None
        self.host = None
        self.address = None


class SoftwareActive(Active):
    code = 'SW'
    def __init__(self, name, filename=None):
        super(SoftwareActive, self).__init__(name, filename)
        self.product = None
        self.version = None


ACTIVES = (HardwareActive, SoftwareActive, ServiceActive)


def active_builder(active_dict):
    kind = active_dict.get('active_type', {}).get('code')
    for at in ACTIVES:
        if at.code == kind:
            return at.build(active_dict)
    raise Exception ("FIXME: active type not recognized")


class Defaults:
    def __init__(self):
        self._defaults = {}

    def add(self, active_type_code, threat_code, probability, impact):
        probability = None if probability is None else int(probability)
        impact = None if impact is None else int(impact)
        self._defaults[(active_type_code, threat_code)] = dict(probability=probability, impact=impact)

    def get(self, active_type_code, threat_code):
        return self._defaults.get((active_type_code, threat_code))


class YamlPersistence:
    version = 1

    def __init__(self, directory):
        self.directory = directory
        self._threats_cache = None
        self._threats_defaults_cache = None

    @property
    def sourcesfile(self):
        return os.path.join(self.directory, 'sources.yaml')

    @property
    def threatsfile(self):
        return os.path.join(os.path.dirname(__file__), 'templates', 'magerit_v3.yaml')

    @property
    def threatsdefaultsfile(self):
        return os.path.join(os.path.dirname(__file__), 'templates', 'magerit_v3_defaults.csv')

    def read(self, filename):
        with open(filename) as fd:
            return yaml.load(fd)

    def write(self, filename, data):
        data['file_version'] = self.version
        with open(filename, 'w+') as fd:
            yaml.dump(data, fd, default_flow_style=False, encoding=('utf-8'), allow_unicode=True)

    def load_sources(self):
        for data in self.read(self.sourcesfile):
            yield source_builder(data, self.sourcesfile)
       
    def load_threats(self):
        if self._threats_cache is None:
            self._threats_cache = self.read(self.threatsfile)
        return self._threats_cache

    def load_threat_defaults(self):
        if self._threats_defaults_cache is None:
            result = Defaults()
            with open(self.threatsdefaultsfile, 'r') as csvfile:
                data = csv.reader(csvfile, delimiter=';', quotechar='|')
                for line in data:
                    break  # skip first line
                for line in data:
                    if len(line) != 4:
                        log_warning("Invalid default line that will be ignored: %s" % line)
                        continue
                    raw_type, raw_threat, probability, impact = line 
                    type_code, _, title = raw_type.partition('|')
                    threat_code, _, title = raw_threat.partition('|')

                    result.add(type_code, threat_code, probability, impact)

            self._threats_defaults_cache = result
        return self._threats_defaults_cache

    def get_defaults(self, active_type_code, threat_code):
        return self.load_threat_defaults().get((active_type_code, threat_code))

    def get_active_type_for_code(self, code):
        threats = self.load_threats()
        for active in threats['active_types']:
            if active['code'] == code:
                return active
        return None

    def get_threats_for_active_type(self, active_type, language):
        threats = self.load_threats()
        active_type = self.get_active_type_for_code(active_type)
        for group in threats['threat_groups']:
            for threat in group['threats']:
                if active_type in threat['active_types']:
                    yield dict(
                        code=threat['code'],
                        title=threat['title'][language],
                        probability=None,
                        impact=None,
                        #probability=threat.get('defaults', {}).get(active_type['code'], {}).get('probability'),
                        #impact=threat.get('defaults', {}).get(active_type, {}).get('impact'),
                        # dimensions=[
                        #     dict(code=x['code'], title=x['title'][language])
                        #     for x in threat['dimensions']
                        # ],
                    )

    def write_active(self, active):
        filename = os.path.join(self.directory, "%s_%s.yaml" % (active.active_type['code'], active.name))
        if os.path.exists(filename):
            log_debug("File %s already exists. Ignoring." % filename)
        else:
            log_debug("Writting active %s to file %s" % (active.name, filename))
            self.write(filename, active.as_dict())

    def list_actives(self):
        for filename in os.listdir(self.directory):
            fullpath = os.path.join(self.directory, filename)
            log_debug("Loading file %s" % fullpath)
            if filename == 'sources.yaml':
                continue
            yield self.read(fullpath)
 
class Source:
    pass


class URLSource(Source):
    def __init__(self, name, filename=None):
        self.name = name
        self.filename = filename
        self.addresses = []

    @classmethod
    def build_from_dict(self, data, filename):
        result = URLSource(data['name'], filename)
        result.addresses = data.get('addresses')  or []  # fixme: sanitize
        return result

    def __str__(self):
        return "URL:%s" % self.name

    def discover(self, callback):
        """Discover new actives and call Callback with any of them as only argument"""
        log_debug("discovering")
        for address in self.addresses:
            log_info("Discover for address %s" % address)
            ports = ','.join(str(x) for x in address['ports']) if address.get('ports') else '1-65535'
            log_debug("Scanning %s with ports %s" % (address, ports))
            data = subprocess.check_output(("nmap -sV -sT -Pn -oX - %s -p %s" % (address['address'], ports)).split())
            root = ET.fromstring(data)
            for host in root.iter('host'):
                newhost = HardwareActive(self.name)
                newhost.state = host.find('status').get('state')
                for addr in host.iter("address"):
                    newhost.add_address(addr.get('addr'), addr.get('addrtype'))
                for name in host.iter("hostname"):
                    newhost.add_hostname(name.get('name'), name.get('type'))
                for port in host.iter("port"):
                    service = ServiceActive("%s_%s_%s" % (address['address'], port.get('protocol'), port.get('portid')))
                    svc = port.find('service')
                    service.program = svc.get('name')
                    service.product = svc.get('product')
                    service.version = svc.get('version')
                    service.state = port.find('state').get('state')
                    service.os = svc.get('ostype')

                    software = SoftwareActive("%s_%s" % (svc.get('product'), svc.get('version')))
                    software.product = svc.get('product')
                    software.version = svc.get('version')
                 

                    newhost.add_related(service)
                    newhost.add_related(software) 
                    service.add_related(software) 

                    callback(service)
                    callback(software)
                callback(newhost)
            


def source_builder(data, filename):
    classes = dict(
        url=URLSource,
    )
    _type = data.get('type')
    if _type in classes:
        return classes[_type].build_from_dict(data, filename)
    raise Exception("Invalid type %s for source %s in file %s" % (_type, data['name'], data.get('name'), filename))


class Siriman:
    def __init__(self, args, persistence):
        self.args = args
        self.persistence = persistence
    
        if not os.path.exists(args.directory):
            os.makedirs(args.directory)

    def show_sources(self):
        sources = self.persistence.load_sources()

        for source in sources:
            print("\t- %s" % source)
       
    def discover(self):
        def save_active(active):
            log_debug("Discovered active %s" % active.name)
            active.threats = list(self.persistence.get_threats_for_active_type(active.active_type['code'], self.args.language))
            self.persistence.write_active(active)
            
        sources = self.persistence.load_sources()
        for source in sources:
            if not self.args.sources or source in self.args.sources:
                source.discover(save_active)

    def report(self, reporter):
        threat_groups = self.persistence.load_threats()['threat_groups']
        actives = []
        active_list = defaultdict(list)
        for active_data in self.persistence.list_actives():
            active = active_builder(active_data)
            active_list[active.active_type['code']].append(
                dict(
                    name=active.name,
                    filename=reporter.get_file_for_writting_active(active, False),
                )
            )
            actives.append(
                dict(
                    name=active.name,
                    code=active.code,
                    threats=active.threats,
                )
            )
           
        reporter.active_groups = active_list 
        for active_data in self.persistence.list_actives():
            active = active_builder(active_data)
            reporter.write_active(active)
        reporter.write_threats(threat_groups, actives)


def main():
    parser = argparse.ArgumentParser(description='Simple Risk Manager')
    parser.add_argument(
        'action',
        choices=Constants.ACTIONS,
        nargs='*',
        help="Action to be performed"
    )
    parser.add_argument(
        '--templates', 
        default=None,
        help='Directory to find templates; if a template is not found, it will be searched internally.'
    )
    parser.add_argument(
        '--language', 
        default="es",
        help='Language to be used'
    )
    parser.add_argument(
        '-d', '--directory',
        default="assessments",
        help='Work directory'
    )
    parser.add_argument(
        '--sources',
        nargs='*',
        help='Work directory'
    )
    parser.add_argument(
        '--output',
        default="report",
        help='Output directory for reports'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='count',
        dest='verbosity',
        default=0,
        help='Increase verbosity. Several increases even more.'
    )
    args = parser.parse_args()

    configure_logging(args.verbosity)

    persistence = YamlPersistence(args.directory)
    siriman = Siriman(args, persistence)
    for action in args.action:
        if action == Constants.ACTION_SOURCES:
            siriman.show_sources()
        elif action == Constants.ACTION_DISCOVER:
            siriman.discover()
        elif action == Constants.ACTION_REPORT:
            report_builder = HTMLReportBuilder(args.templates, args.output, persistence.load_threat_defaults())
            siriman.report(report_builder)
        else:
            log_error("Action '%s' is not supported. Stopping" % action)
            break


if __name__ == '__main__':
    main()
